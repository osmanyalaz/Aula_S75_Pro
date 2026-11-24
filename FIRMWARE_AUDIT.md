# AULA S75 Pro Firmware Reverse-Engineering Audit (`s75pro_fw_v1.03.bin`)

This document records the complete, firmware-verified and hardware-tested reverse-engineering findings for the AULA S75 Pro (`VID=0x0C45`, `PID=0x800A`, MCU firmware `v1.03`). All claims below are traced directly to ARM Cortex-M Thumb instructions and Ghidra decompilation of `s75pro_fw_v1.03.bin` (read-only analysis) and cross-checked against `DeviceDriver.exe.c`, Wireshark captures, and live USB hardware tests via [`test_underglow.py`](test_underglow.py).

---

## 1. Binary Provenance & USB Transport Architecture

### 1.1 Image & Vector Table Verification
- **Binary:** `s75pro_fw_v1.03.bin` (`262,144` bytes, `0x00000000–0x0003FFFF`, `ARM:LE:32:Cortex`)
- **SHA-256:** `7ef0d72f267621beef543a8068602db253872a5a2a0291e4ccdb1a651e669e22`
- **Confirmed load base address:** `0x00000000` (all vector pointers land on valid odd Thumb entry points inside the image):
  - Initial SP (`0x00000000`): `0x20002E68`
  - `Reset_Handler` (`0x00000004`): `0x00013AED` (`0x00013AEC` loads `0x000000C1` and branches via `bx r0`)
  - `NMI` (`0x00000008`): `0x00013B07`
  - `HardFault` (`0x0000000C`): `0x0000095D`
  - `SVCall` (`0x0000002C`): `0x00013B0B`
  - `PendSV` (`0x00000038`): `0x00013B0D`
  - `SysTick` (`0x0000003C`): `0x00006F9D` (`FUN_00006f9c`)
  - `IRQ1` / USB (`0x00000044`): `0x00000EDF` (`FUN_00000ede`)
  - `IRQ19` / LED-PWM (`0x0000008C`): `0x0000648D` (`FUN_0000648c`)
  - `IRQ31` (`0x000000BC`): `0x00000CFD` (`FUN_00000cfc`)

### 1.2 USB Interface & Endpoint Layout
From the USB descriptor table at `0x000140F0` (Configuration Descriptor at `0x00014056`, total length `0x74`, 4 interfaces):

| Interface | Descriptor Addr / Len | Endpoints | Role in Firmware |
|---|---|---|---|
| **Interface 0** | `0x00013F36` (`0x41` B) | `EP 0x81 IN` | Boot keyboard. Also accepts EP0 Control Feature `SET_REPORT` / `GET_REPORT` into the same HID command buffer (`0x2000135C`). |
| **Interface 1** | `0x00013F77` (`0x9E` B) | `EP 0x82 IN` | NKRO / Consumer / System / Mouse / Vendor IN reports. |
| **Interface 2** | `0x00014015` (`0x23` B) | `EP 0x84 IN` (64 B), `EP 0x03 OUT` (64 B) | Usage Page `0xFF68`, 4096 B Output Report `0x63`. **External SPI flash bulk data pipe ONLY.** EP0 Feature `SET_REPORT` on Interface 2 is stalled. |
| **Interface 3** | `0x00014038` (`0x1E` B) | `EP 0x86 IN` | Usage Page `0xFF13`, Usage `0x0001`. Primary control interface via EP0 Control Feature `SET_REPORT` (`0x00001B4A` → `0x00001B16` → `FUN_00001924`) and `GET_REPORT` (`0x00001CB4` → `0x00001C38`). |

#### EP 3 OUT (`Interface 2`) vs. EP0 Control (`Interface 3`)
- **EP 3 OUT is NOT a general HID command dispatcher.** In `FUN_00000ede` (USB ISR, bit 10) → `FUN_00000e78` → `FUN_00000b04`, every 64-byte packet received on `EP 3 OUT` is accumulated verbatim into a 4096-byte RAM staging buffer at `0x200002F4` (packet counter at `0x20000032`). After 64 packets (`4096` bytes), it sets `*(uint8_t*)0x20000030 = 1`.
- That staging buffer is consumed exclusively by **State 5** (`0x00003D54`) of the main HID state machine, which programs external SPI flash via `FUN_000079bc` and queues a 64-byte ACK (`01 5A 02 00 ...`) in `0x200012F4` (`0x20000031 = 1`), transmitted on `EP 0x84 IN` by `FUN_000002ec` via `FUN_00000a68(4, 0x200012F4, 0x40)`.
- **All configuration, lighting, info, battery, RTC, and streaming commands** arrive over **EP0 Control Feature `SET_REPORT` / `GET_REPORT`** on Interface 3 (or Interface 0), handled by `FUN_00001d2e` → `FUN_00001924` (RX) / `0x00001C38` (TX) and processed in the main loop by `FUN_00004622`.

#### EP0 Live RGB Streaming Fast-Path (`FUN_00001924`)
When `hid_ctx[0] == 2` (`0x200000BC`) and `hid_ctx[2] != 0` (`0x200000BE`, set by `0x2004`):
- `FUN_00001924` consumes each 64-byte `SET_REPORT` directly inside the USB ISR (clearing `usb_flags` bit 0).
- It unpacks 16 entries of `[light_index, R, G, B]`, maps `light_index` through lookup table `0x00014D2C` (`DAT_00001a78`), and writes directly to the live RGB RAM arrays (`uint16_t[0x93]` each):
  - Red: `0x20001838`
  - Green: `0x2000195E`
  - Blue: `0x20001A84`
- It decrements `*(uint16_t*)0x200000C8` (remaining chunks) and transitions `hid_ctx[0] = 3` when the counter reaches 0.

---

## 2. Main USB HID State Machine (`FUN_00004622`)

`FUN_00004622` is polled every main-loop iteration from `FUN_000002ec` (`0x0000036E`) and dispatches on `hid_ctx[0]` via `__ARM_common_switch8` at `0x0000462E`.

### 2.1 Core RAM Structures

| Address | Symbol / Field | Meaning |
|---|---|---|
| `0x2000003C` | `usb_flags` | Bit 0 (`0x01`): EP0 `SET_REPORT` received. Bit 1 (`0x02`): EP0 `GET_REPORT` completed/requested. |
| `0x2000135C` | `hid_buf[64]` | Shared 64-byte EP0 Feature report buffer (`0x20001348 + 0x14`). Used for both RX and TX. |
| `0x200000BC` | `hid_ctx[0]` | Current state (`0..6`). |
| `0x200000BD` | `hid_ctx[1]` | General settings bitfield (`0x9000..0x9004` packed bits: Alt+Tab, Alt+F4, Win-Lock). |
| `0x200000BE` | `hid_ctx[2]` | Live RGB streaming mode flag (`1` when entered via `0x2004`). |
| `0x200000BF` | `hid_ctx[3]` | Live-RGB read chunk index (used by `0xF504`). |
| `0x200000C0` | `hid_ctx[4]` | Live RGB streaming timeout counter (reloaded to `0x32` on `0x2004`). |
| `0x200000C1` | `hid_ctx[5]` | Control flags: bit 0 (`0x01`) = command active, bit 4 (`0x10`) = awaiting Phase-2 `GET_REPORT`, bit 6 (`0x40`) = bypass custom keymap/macros (`0x1804` clears, `0x1904` sets). |
| `0x200000C2` | `hid_ctx[6]` | Post-write reload/apply flag. |
| `0x200000C3` | `hid_ctx[7]` | `fn_switch` runtime copy (`0` = hold, `1` = sticky toggle). |
| `0x200000C4` | `hid_ctx[8]` | Underglow skip-reload flag (set on `0x1304` `0x20–0x24`). |
| `0x200000C5` | `hid_ctx[9]` | Blank-LEDs / transaction-busy flag (cleared by `0xF004` or idle watchdog). |
| `0x200000C6` | `hid_ctx[10]` | Live-RGB read flag (`1` when entered via `0xF504`). |
| `0x200000C8` | `hid_ctx + 0x0C` | `uint16_t` remaining chunk count. |
| `0x200000CA` | `hid_ctx + 0x0E` | `uint16_t` idle watchdog tick counter (`FUN_0000466a`, 1 ms ticks; resets state machine at `2000` ticks = 2.0 s). |
| `0x200000CC` | `hid_ctx + 0x10` | `uint32_t` running 32-bit byte-sum checksum returned in `0x0204` commit `resp[4..7]`. |
| `0x200000D0` | `hid_ctx + 0x14` | `uint32_t` internal MCU flash read/write cursor. |
| `0x200000D4` | `hid_ctx + 0x18` | `uint32_t` word offset within current transfer. |
| `0x200000D8` | `hid_ctx + 0x1C` | `uint32_t` external SPI flash cursor (`0x00000000` for `0x3804`, `0x00750000` for `0x7204`). |
| `0x200000DC` | `hid_ctx + 0x20` | `uint32_t` SPI flash 4096 B chunks completed. |
| `0x200000E0` | `hid_ctx + 0x24` | `uint32_t` SPI flash 4096 B chunks total. |

### 2.2 Idle Watchdog (`FUN_0000466a`)
Called every 1 ms from `FUN_0000042e`. When `hid_ctx[0] != 0` and no HID traffic resets `*(uint16_t*)0x200000CA`, after `2000` ms it zeroes `hid_buf`, sets `usb_flags = 0`, `hid_ctx[0] = 0`, and `hid_ctx[9] = 0`.

### 2.3 States 0–6

| State | Handler Address | Behavior |
|---|---|---|
| **0** | `0x00004330` | **Two-phase command dispatcher.**<br>• **Phase 1 (`SET_REPORT`, bit 0):** Validates `buf[0] == 0x04` and calls `0x000041E0(buf[1])`. On success (`1`), sets `buf[3] = 0x01`, `hid_ctx[5] \|= 0x11`; on failure (`0`), sets `buf[3] = 0xFF`, `hid_ctx[5] = 0`. Note: Flash-write commands (`0x11`, `0x13`, `0x15`, `0x17`, `0x23`, `0x27`) **erase their target flash page immediately inside `0x000041E0`**.<br>• **Phase 2 (`GET_REPORT`, bit 1 && `hid_ctx[5] & 0x10`):** Dispatches `buf[1]`, validates `chunks = buf[8] \| (buf[9] << 8)` via `0x000041C0(max)`, and configures `(addr, count, next_state)` via `0x000041B6`. |
| **1** | `FUN_0000407a` | **Read data phase.** On `usb_flags` bit 1, copies 64 bytes into `hid_buf` from internal flash (`hid_ctx+0x14`) or live RGB RAM (`hid_ctx[10] != 0`: `0x20001838`/`195E`/`1A84`), adds every byte into 32-bit `hid_ctx+0x10`, clears bit 1, decrements `hid_ctx+0x0C`, and transitions to **State 3** when `remaining == 1` prior to decrement. |
| **2** | `FUN_00003f42` | **Write data phase** (non-streaming, `hid_ctx[2] == 0`). On `usb_flags` bit 0, erases 1 KB flash page whenever `(addr & 0x3FF) == 0` (except the first page already erased in Phase 1), writes 64 bytes via `FUN_00001f8a`, applies live settings (`0x9000`) or lighting (`0x9800` → `FUN_00003eae`), special-cases `0x9800` with `(payload[0] >> 4) == 2` (`0x20–0x24`, skipping flash write!), sums the written/readback bytes into `hid_ctx+0x10`, and transitions to **State 3** when `remaining == 0`. |
| **3** | `0x00003E48` | **Commit (`04 02`).** On `SET_REPORT`: if `!(buf[0] == 0x04 && buf[1] == 0x02)` → `buf[3] = 0xFF`; else sets `buf[3] = 0x01`, writes **32-bit LE** `hid_ctx+0x10` to `buf[4..7]`, sets `hid_ctx[5] \|= 0x10`, and calls `FUN_00008c00`. On the following `GET_REPORT` (`0x00003E94–0x00003EA8`): clears `hid_ctx` **and sets `usb_flags = 0` (`0x00003EA6`)**, returning cleanly to State 0. |
| **4** | `0x00003E32` | **Single-packet sink (`0xAB04`).** Consumes one `SET_REPORT`, then transitions to State 3. |
| **5** | `0x00003D54` | **External SPI flash streamer (`0x3804` / `0x7204`).** Waits for `*(uint8_t*)0x20000030 == 1` (4096 B ready from `EP 3 OUT`), programs SPI flash at `hid_ctx+0x1C` via `FUN_000079bc`, sends `EP 0x84 IN` ACK (`01 5A 02 ...`), and transitions to State 3 when `done == total`. |
| **6** | `0x00003CFC` | **RTC write (`0x2804`).** Checks `buf[2] == 0x5A`, copies `buf[3..8]` (`yy, mm, dd, HH, MM, SS`) into `0x20000224[0, 1, 3, 4, 5, 6]`, calls `FUN_00008dee` and `FUN_0000fe96`, and transitions to State 3. Completely ignores `buf[0..1]` (`00 01`), `weekday`, and `AA 55`. |

### 2.4 Complete 27-Opcode Table (`buf[0] == 0x04`, `buf[1]` = opcode)

Wire command word is little-endian: `0xXX04` means `buf[0] = 0x04, buf[1] = 0xXX`.

| Opcode (`buf[1]`) | LE16 Word | Phase 1 (`0x000041E0`) | Phase 2 (`0x00004330`) Target / Max Chunks / Next State | Notes |
|---|---|---|---|---|
| `0x02` | `0x0204` | — (State 3 only) | State 3 (`0x00003E48`) → State 0 | Commit; writes 32-bit LE byte-sum to `resp[4..7]`, clears `usb_flags = 0` on `GET_REPORT`. |
| `0x05` | `0x0504` | Valid (`1`) | Flash `0x00008F80`, max `2`, `count = chunks + 1`, State 1 | **Device Info block.** Hardware-verified: `40 30 00 00 45 0C 0A 80 03 01 FF FF ...` (`VID=0x0C45`, `PID=0x800A`, `FW=v1.03`). |
| `0x10` | `0x1004` | Valid (`1`) | Flash `0x00009400`, max `9`, `count = chunks + 1`, State 1 | Read Base Keymap. |
| `0x11` | `0x1104` | **Erases `0x9400`** | Flash `0x00009400`, max `9`, State 2 | Write Base Keymap. `FUN_0000275c` checks `0x55AA0000` at `0x963C`. |
| `0x12` | `0x1204` | Valid (`1`) | Flash `0x00009800`, max `1`, `count = chunks + 1`, State 1 | **Read Lighting Config page (`0x9800`).** Used to inspect or save/restore USB lighting across underglow writes. |
| `0x13` | `0x1304` | **Erases `0x9800` (`0x00004290`)** | Flash `0x00009800`, max `1`, State 2 | Write Lighting Config (`0x00–0x13`, `0x80`) OR Row-6 Underglow (`payload[0] = 0x20–0x24`, skips flash write!). |
| `0x14` | `0x1404` | Valid (`1`) | Flash `0x0000A000`, max `0x30` (48), `count = chunks + 1`, State 1 | Read Macros. |
| `0x15` | `0x1504` | **Erases `0xA000`** | Flash `0x0000A000`, max `0x31` (49), State 2 | Write Macros. |
| `0x16` | `0x1604` | Valid (`1`) | Flash `0x00009000`, max `1`, `count = chunks + 1`, State 1 | Read General Settings. |
| `0x17` | `0x1704` | **Erases `0x9000`** | Flash `0x00009000`, max `1`, State 2 | Write General Settings (`0x00004540` ignores `buf[2..3]` profile index). |
| `0x18` | `0x1804` | Clears `hid_ctx[5]` bit 6 (`0x40`) | Stays State 0 | Enable custom keymap & macro interception (`FUN_00003412` via `DAT_000038e8`). |
| `0x19` | `0x1904` | Sets `hid_ctx[5]` bit 6 (`0x40`) | Stays State 0 | Bypass custom keymap & macro interception (raw matrix mode). |
| `0x20` | `0x2004` | Sets `hid_ctx[4] = 0x32` | `hid_ctx[2] = 1`, State 2 (ISR fast-path `FUN_00001924`) | Live per-key RGB streaming. Both `GET_REPORT`s in State 0 are required to enter State 2. |
| `0x22` | `0x2204` | Valid (`1`) | Flash `0x00009C00`, max `9`, `count = chunks + 1`, State 1 | Read Custom RGB Table (576 B = 9×64 B). |
| `0x23` | `0x2304` | **Erases `0x9C00`** | Flash `0x00009C00`, max `9`, State 2 | Write Custom RGB Table. Reader `0x0000CBBA` checks `(word & 0xFF) == slot_idx` only; `AA 55` is never checked. |
| `0x26` | `0x2604` | Valid (`1`) | Flash `0x0000AC00`, max `9`, `count = chunks + 1`, State 1 | Read Fn-Layer Keymap. |
| `0x27` | `0x2704` | **Erases `0xAC00`** | Flash `0x0000AC00`, max `9`, State 2 | Write Fn-Layer Keymap. `FUN_0000275c` checks `0x55AA0000` at `0xAE3C`. |
| `0x28` | `0x2804` | Valid (`1`) | State 6 (`0x00003CFC`) | RTC Write (`buf[2] == 0x5A`, `buf[3..8]` = `yy mm dd HH MM SS`). |
| `0x38` | `0x3804` | Valid (`1`) | SPI `0x00000000`, State 5 (`0x00003D54`) | **DANGEROUS / EXCLUDED:** Full external SPI flash overwrite (factory TFT assets). See §6. |
| `0x72` | `0x7204` | Valid (`1`) | SPI `0x00750000`, State 5 (`0x00003D54`) | User Screen Image / GIF upload. `0x000045D4` ignores `buf[2]` (`0x03`/`0x05`). |
| `0xAB` | `0xAB04` | Valid (`1`) | State 4 (`0x00003E32`) | 1-packet sink → State 3. |
| `0xE0` | `0xE004` | Valid (`1`) | Stays State 0 | No-op / Ping. |
| `0xF0` | `0xF004` | Calls `FUN_0000df18()`, clears `hid_ctx[9] = 0` | Stays State 0 | Finalize: commits runtime config snapshot to internal flash `0x8000` and unblanks LEDs. |
| `0xF1–0xF3` | `0xF104–0xF304` | Valid (`1`) | Stays State 0 | Reserved no-ops (`0xF4` returns `0` / rejected with `0xFF`). |
| `0xF5` | `0xF504` | **Clears `usb_flags` bit 1 (`0x000042FA`)** | `hid_ctx[10] = 1`, `count = chunks`, State 1 | **Read Live RGB RAM** (`0x20001838`/`195E`/`1A84`). Only State 1 read opcode that explicitly clears stale bit 1. |
| `0xF6` | `0xF604` | Copies `*(uint8_t*)0x200000F8` → `buf[4]` (`0x0000431C`) | Stays State 0 | **Battery Level Query (`0..5`)**, computed by `FUN_00004d8c` (`0`: `<6%`, `1`: `6–25%`, `2`: `26–50%`, `3`: `51–75%`, `4`: `76–95%`, `5`: `96–100%`). |

### 2.5 Stale Bit-1 Auto-Preload vs. Clean Bit-1 Read Behavior (`0x00004330` / `FUN_0000407a`)

This subtle firmware quirk was caught during live hardware testing of `0x0504` and fully root-caused in Ghidra:

1. **How stale bit 1 gets set:** Any `GET_REPORT` performed in State 0 when `hid_ctx[5] & 0x10 == 0` (for example: `AulaS75Pro.wait_until_idle()`, an `0x1804` + `GET_REPORT` probe, or `0xF604` + `GET_REPORT`) sets `usb_flags` bit 1 (`0x2000003C |= 2`). At `0x00004386`, State 0 sees `hid_ctx[5] & 0x10 == 0` and returns **without clearing bit 1**.
2. **Stale bit-1 auto-preload path (affects all 7 flash-read opcodes: `0x05`, `0x10`, `0x12`, `0x14`, `0x16`, `0x22`, `0x26`):**
   - Host sends `SET_REPORT` (e.g., `04 05 00 00 00 00 00 00 01 00 ...`).
   - Phase 1 (`0x00004354`) clears **only bit 0** (`bics r2, r6`), sets `buf[3] = 0x01`, `hid_ctx[5] |= 0x11`, and leaves stale bit 1 = `1`.
   - On the very next main-loop tick (~0.1 ms, long before the host's `GET_REPORT`), `0x00004380` sees bit 1 == `1` and `hid_ctx[5] & 0x10 == 1`, immediately transitions to **State 1** with `count = chunks + 1` **without clearing bit 1**.
   - On the following main-loop tick (~0.2 ms), `FUN_0000407a` sees bit 1 == `1`, immediately **preloads chunk 0** from flash into `hid_buf` (`0x2000135C`), clears bit 1, and decrements `count`.
   - Therefore, the host's **first `GET_REPORT`** returns chunk 0 directly (hardware-verified: `0x0504` returned `40 30 00 00 45 0C 0A 80 03 01 FF FF ...` on `GET` #1 instead of `04 05 00 01`).
3. **Clean bit-1 path:**
   - Immediately after a completed `0x0204` commit + `GET_REPORT`, State 3 (`0x00003EA6`) explicitly clears **`usb_flags = 0`**.
   - For the next flash-read command, bit 1 is `0` when `SET_REPORT` arrives, so `GET` #1 returns the normal `[04, cmd_hi, 00, 01, ...]` ACK and triggers State 1 preload; chunk 0 arrives on `GET` #2.
   - `0xF504` (`0x000042FA–0x00004302`) is the **only** read opcode where the firmware explicitly clears `usb_flags` bit 1 in Phase 1, forcing the clean path every time.
4. **Trailing-chunk checksum accounting (`count = chunks + 1`):**
   - For all 7 flash-read opcodes, Phase 2 sets `count = chunks + 1`, so on the host's final `GET_REPORT`, `FUN_0000407a` preloads and sums one extra trailing 64-byte flash block (e.g., `0x8FC0–0x8FFF` for `0x0504` or `0x9840–0x987F` for `0x1204`) before advancing to State 3.
   - Consequently, the 32-bit LE commit checksum in `0x0204` `resp[4..7]` equals either `sum(chunks)` (if the trailing 64 B block is `0x00`) or `sum(chunks) + 64 * 0xFF` (`+0x3FC0`, if the trailing block is erased `0xFF`).
5. **Host handling pattern** (implemented in [`test_underglow.py::_read_flash_chunks`](test_underglow.py#L106-L159)):
   - After `SET_REPORT`, inspect `resp1 = GET_REPORT`:
     - If `resp1[0:2] == [0x04, cmd_hi]` and `resp1[3] == 0xFF` → abort (rejected/busy).
     - If `resp1[0:2] == [0x04, cmd_hi]` and `resp1[3] == 0x01` → clean bit-1 path; read `chunks` additional `GET_REPORT`s.
     - Otherwise → stale bit-1 auto-preload path; `resp1` **is** chunk 0, so read `chunks - 1` additional `GET_REPORT`s.
   - Always conclude with `0x0204` commit + `GET_REPORT` so `0x00003EA6` leaves `usb_flags = 0`.

---

## 3. LED Matrix Topology, On-Board Hotkeys & Underglow Verification

### 3.1 Three Physical Hardware LED Zones
All LEDs share the single RGB RAM buffer (`0x20001838` R, `0x2000195E` G, `0x20001A84` B, clocked out by IRQ19 `FUN_0000648c`), split into three logical zones:

| Zone | LED Indices (`0x00014D2C` / RAM) | Runtime State & Renderer | Control Surface |
|---|---|---|---|
| **Main Keys (82 keys)** | Standard key matrix (`PHYSICAL_INDICES`) | Main effect engine (`0x20000190` / `0x8000` / `0x9800`) | USB `0x1304` (`0x00–0x13`, `0x80`), `0x2304`, `0x2004`, and on-board `Fn` lighting hotkeys |
| **Row-6 Side / Underglow (14 LEDs)** | `0x7E–0x8B` (14 contiguous LEDs) | State struct at `0x20000194` (mode `0..4`, color, brightness, speed); rendered by `FUN_0000e1fc` (`0x0000E0B8–0x0000E440`) directly into `0x20001838`/`195E`/`1A84` | **USB `0x1304` `payload[0] = 0x20–0x24`** (mode only) + **`Fn + Right Shift`** (cycle mode `0..4`) + **`Fn + /?`** (cycle preset color) |
| **Row-5 Accent Bar (5 LEDs)** | `0x6C, 0x6D, 0x6E, 0x70, 0x71` | State at `0x200001DC` (independent subsystem) | **`Fn + Z`** only — **no USB HID command exists** in `s75pro_fw_v1.03.bin` |

### 3.2 `0x1304` `0x20–0x24` Underglow Behavior & `SideLightsRed.pcapng` Forensics
- In `FUN_00003f42` (`0x00003F82`), when `hid_ctx+0x14 == 0x00009800` and `(payload[0] >> 4) == 2`:
  - Firmware reads **only `payload[0]`** (`mode = payload[0] & 0x0F`, valid `0..4`: `0`=flowing, `1`=spectrum, `2`=static, `3`=breathing, `4`=off), writes it to `*(uint8_t*)0x20000194`, sets `hid_ctx[8] = 1`, and skips writing flash `0x9800`.
  - Color, brightness, and speed bytes in `payload[1..63]` are **never read** by `FUN_00003f42` for `0x20–0x24`.
- **Why `wireshark/SideLightsRed.pcapng` frame 3987 had no visible effect:**
  - Frame 3987 sent a standard main-key `0x1304` payload (`payload[0] = 0x01` static red, not `0x20–0x24`) or targeted the wrong subsystem; furthermore, `DeviceDriver.exe` never exposes a per-color USB setter for `0x20000194` — only `0x20–0x24` mode selection exists in firmware.
- **Hardware verification (`test_underglow.py`):**
  - `python3 test_underglow.py --mode 4` turned the physical underglow LEDs **off** and returned the exact predicted 32-bit LE commit checksum **`0x00003C4F`**.
  - `python3 test_underglow.py --mode 0` restored the physical underglow LEDs to **flowing rainbow** and returned **`0x00003C4F`**.

---

## 4. Verified Fixes for `aula_s75pro.py`

All items below are verified against [`aula_s75pro.py`](aula_s75pro.py) and `s75pro_fw_v1.03.bin`.

### 4.1 Byte-Swapped `CMD_LIGHT_READ` (`aula_s75pro.py:72`, `PROTOCOL.md:37`)
- **Bug:** `CMD_LIGHT_READ = 0x04F5` puts `F5 04` on the wire (rejected with `0xFF`, because State 0 requires `buf[0] == 0x04`).
- **Fix:** Change to **`CMD_LIGHT_READ = 0xF504`** (wire bytes `04 F5`), which matches `0x000042FA` and reads live RGB RAM (`0x20001838`/`195E`/`1A84`) cleanly.

### 4.2 32-bit Little-Endian Commit Checksums (`resp[4..7]`)
- **Firmware (`0x00003E74–0x00003E82`):** `0x0204` commit writes the full **32-bit little-endian** accumulated byte sum (`hid_ctx+0x10`) into `resp[4..7]`.
- **Fix 1 — `write_general_settings()` ([`aula_s75pro.py:371-379`](aula_s75pro.py#L371-L379)):**
  - Currently compares `resp[4]` against `(fn_switch + sleep_time + key_response_time) & 0xFF`. This only passed by coincidence when all three enable flags were `False` because `0x01 + 0xAA + 0x55 == 0x100 == 0 (mod 256)`. As soon as any flag is `True`, the check fails with a false mismatch.
  - Replace with `mcu_sum = struct.unpack_from("<I", resp, 4)[0]` compared against `sum(written_64_byte_payload)`.
- **Fix 2 — `set_custom_lighting()` ([`aula_s75pro.py:518,571-573`](aula_s75pro.py#L518)):**
  - Currently truncates to 16-bit (`sum(table) & 0xFFFF` vs. `ack[4] | (ack[5] << 8)`).
  - Update to 32-bit (`expected_checksum = sum(table) & 0xFFFFFFFF` vs. `struct.unpack_from("<I", ack, 4)[0]`).

### 4.3 `0x1704` General Settings Bitfields & Redundant Loop ([`aula_s75pro.py:321-382`](aula_s75pro.py#L321-L382))
Traced from `FUN_00003f42` (writes `0x00009000`) → `FUN_00003412` / `FUN_000046d0` / `FUN_00003a08`:

| Payload Byte (`0x9000 + offset`) | Current Name in `aula_s75pro.py` | Actual Firmware Meaning |
|---|---|---|
| `payload[0..1]` | `0x0100` (`CMD_GENERAL_SETTINGS`) | Stored at `0x9000..0x9001` (packed into low bits of `hid_ctx[1]`) |
| `payload[2]` | `fn_enabled` (wrong) | **Disable `Alt+Tab`** (`1` = blocked; packed into `0x200000BD`) |
| `payload[3]` | `sleep_enabled` (wrong) | **Disable `Alt+F4`** (`1` = blocked; packed into `0x200000BD`) |
| `payload[4]` | `key_response_enabled` (wrong) | **Win-Lock** when `*(uint8_t*)0x2000004D == 0` (`1` = Win key locked; packed into `0x200000BD`) |
| `payload[5]` | `fn_switch` | `0` = normal hold Fn, `1` = sticky Fn toggle (`0x200000C3`) |
| `payload[6]` | `sleep_time` | `0` = off, `1` = 1 min (`600`), `2` = 5 min (`3000`), `3` = 30 min (`18000`) in 100 ms ticks (`FUN_000046d0`) |
| `payload[7]` | unused gap (`0`) | Unused |
| `payload[8]` | `key_response_time` | Debounce scan threshold (`FUN_00003a08`): `1` → 2, `2`/default → 3, `3` → 7, `4` → 10, `5` → 14 |

- **Redundant `for profile_index in (0, 1):` loop (`aula_s75pro.py:339-346`):** In `0x00004540`, `0x1704` completely ignores `buf[2..3]` (`1, profile_index`) and writes to `0x00009000` unconditionally. Sending it twice just erases and rewrites the same flash page twice; a single pass is sufficient.

### 4.4 New Verified Commands to Add to `aula_s75pro.py`
- **`CMD_DEVICE_INFO = 0x0504`:** Reads flash `0x00008F80` (`chunks=1` or `2`). Decodes `tag = u16[0]` (`0x3040`), `VID = u16[4]` (`0x0C45`), `PID = u16[6]` (`0x800A`), `fw_minor = byte[8]` (`3`), `fw_major = byte[9]` (`1`) → `v1.03`.
- **`CMD_BATTERY_LEVEL = 0xF604`:** Single `SET_REPORT` + `GET_REPORT` in State 0 (no commit). Returns quantized battery level `0–5` in `resp[4]` (`0`: `<6%`, `1`: `6–25%`, `2`: `26–50%`, `3`: `51–75%`, `4`: `76–95%`, `5`: `96–100%`).
- **`CMD_LIGHTING_READ = 0x1204`:** Reads the 64-byte flash lighting config page at `0x00009800` (`chunks=1`). Must use a helper handling both the stale bit-1 and clean bit-1 paths (see §2.5).

### 4.5 `0x1204` Save-and-Restore Workaround for the `0x1304` `0x20–0x24` Flash `0x9800` Erase Bug

#### Root Cause in Firmware
1. When setting underglow mode via `0x1304` + `payload[0] = 0x20 + mode`:
   - **Phase 1 (`0x00004290`)** unconditionally erases the 1 KB internal flash page at **`0x00009800`** (all bytes become `0xFF`) before inspecting the data payload.
   - **State 2 (`FUN_00003f42` at `0x00003F82`)** detects `(payload[0] >> 4) == 2`, updates `*(uint8_t*)0x20000194 = payload[0] & 0x0F`, sets `hid_ctx[8] = 1`, and **skips writing `0x00009800`**.
   - As a side effect, the uninitialized stack word `local_10` (`[sp, #0]`) still holds `r3 = 0x00004645` from `__ARM_common_switch8` in `FUN_00004622` (byte sum `0x45 + 0x46 = 0x8B`), while words `1..15` read 60 erased `0xFF` bytes from `0x9804..0x983F` (`60 * 0xFF = 0x3BC4`), producing the exact deterministic 32-bit LE commit checksum **`0x8B + 0x3BC4 = 0x00003C4F`** (verified on real hardware).
2. **Reboot impact (`0x0000DB48–0x0000DB8E`):**
   - On power-on, the firmware restores runtime lighting from flash `0x8000` (saved by `0xF004` / `FUN_0000df18()`).
   - If the active lighting was set via on-board hotkeys (`flash[0x8002] != 0xFF`), reboot restores from `0x8000` normally.
   - **If the active lighting was set via USB (`flash[0x8002] == 0xFF`)**, `0x0000DB86` calls `FUN_00003eae()`, which reads `DAT_00009800`. Because `0x9800` was left erased (`0xFF`), `FUN_00003eae()` returns early and **custom/USB main-key lighting is lost after reboot**.

#### Recommended Safe Workaround in `aula_s75pro.py`
When implementing `set_underglow_mode(mode: int)`:
1. **Save:** Read the current 64-byte lighting page at `0x9800` via `0x1204` + `0x0204` commit (using the bit-1-aware reader from §2.5).
2. **Apply underglow:** Send `0x1804` → `0x1304` (`chunks=1`) → `[0x20 + mode, 0, ...]` → `0x0204` commit (verifying `resp[4..7] == 0x00003C4F`) → `0xF004` finalize (persists `0x20000194` into `0x8000`).
3. **Restore `0x9800`:** If the saved 64-byte snapshot from step 1 is **not** all-`0xFF` and **not** all-`0x00` (i.e., valid USB main-key lighting was stored there), immediately rewrite that exact 64-byte payload back to `0x9800` via a standard `0x1304` write → `0x0204` commit → `0xF004` finalize.

### 4.6 Other Protocol Clarifications for `aula_s75pro.py` / `PROTOCOL.md`
- **`0x2004` Live Streaming:** Both `GET_REPORT` calls in State 0 are mandatory because Phase 2 (`0x00004380`) only transitions to State 2 on `GET_REPORT`.
- **`0x2304` Custom RGB Table:** `0x0000CBBA` only checks `(word & 0xFF) == slot_idx` per 4-byte slot and never inspects the `AA 55` trailer (unlike keymaps `0x1104` / `0x2704`, where `FUN_0000275c` checks `0x55AA0000` at `0x963C` / `0xAE3C`). Keeping `AA 55` at offsets `574–575` remains harmless and matches the official driver's checksum.
- **`0x2804` RTC Sync ([`aula_s75pro.py:620-660`](aula_s75pro.py#L620-L660)):** State 6 (`0x00003CFC`) only validates `buf[2] == 0x5A` and copies `buf[3..8]` (`yy, mm, dd, HH, MM, SS`); `buf[0..1]`, `weekday`, and `AA 55` are ignored.

---

## 5. Verified Fixes for `aula_s75pro_screen.py`

All items below are verified against [`aula_s75pro_screen.py`](screenUpload/aula_s75pro_screen.py) and `s75pro_fw_v1.03.bin`.

### 5.1 `WIRE_TICK_MS = 2` (NOT `20`) ([`aula_s75pro_screen.py:135`](screenUpload/aula_s75pro_screen.py#L135))
- **Clock-tree proof in firmware:**
  1. `FUN_00013bfa` configures PLL = **48 MHz**, HCLK prescaler = `1`.
  2. `FUN_00006f8c` sets SysTick `RVR = 23999` (`0x5DBF`) → `48,000,000 / 24,000 = 2000 Hz` = **0.5 ms** per SysTick IRQ (`FUN_00006f9c`).
  3. `FUN_000008e2` derives software timer ticks from SysTick:
     - `pbVar2[3]` = **1 ms** (every 2 SysTicks; drives `FUN_0000466a` 2000-tick = 2.0 s HID watchdog)
     - `pbVar2[2]` = **2 ms** (every 4 SysTicks)
  4. `FUN_0000042e` derives `pbVar2[5]` = **100 ms** (independently confirmed by `FUN_000046d0` sleep timeouts: `600` = 1 min, `3000` = 5 min, `18000` = 30 min).
  5. The TFT GIF animation scheduler **`FUN_00011a84`** increments its frame counter on **`pbVar2[2]` (2 ms)**.
- **Driver cross-check (`DeviceDriver.exe.c:30483`):** The official Windows driver stores GIF frame durations in **milliseconds** (not centiseconds) and divides by `2` to produce 2 ms ticks. `aula_s75pro_screen.py` mistakenly assumed the driver's internal field was in centiseconds, resulting in `WIRE_TICK_MS = 20` (10× too slow on-wire, making animations play **10× too fast**).
- **Fix:** Set **`WIRE_TICK_MS = 2`**.

### 5.2 Delay Floor `0x10` (32 ms) and Ceiling `0xFF` (510 ms) ([`aula_s75pro_screen.py:205,311,354`](screenUpload/aula_s75pro_screen.py#L311))
- **Firmware (`FUN_00011a84`):** Before comparing against the elapsed 2 ms counter, the firmware executes:
  ```c
  if (bVar1 < 0x10) {
      period = 0x19;  // silently replaces < 16 (32 ms) with 25 (50 ms)!
  }
  ```
- **Consequence:** Encoding any wire delay in `1..15` (`2..30 ms`) is silently overridden by the MCU to `0x19` (`50 ms` = 20 fps), causing unexpected slowdowns for high-FPS clips.
- **Fix:** Clamp encoded wire delay ticks to **`[0x10, 0xFF]`** (`16..255` ticks = **`32 ms – 510 ms`** per frame, i.e., `~1.96–31.25 fps`), and update CLI `--delay` help/units to clearly distinguish milliseconds vs. 2 ms wire ticks.

### 5.3 Hard Frame Cap = `191` Frames (NOT `254`) ([`aula_s75pro_screen.py:198,300,366`](screenUpload/aula_s75pro_screen.py#L198))
- **Firmware (`FUN_0001047c` → `FUN_00010460(0x750000)`):**
  - Calls `FUN_00007882(0x750000, 0xC0)`, reading only **`192` bytes (`0xC0`)** from the 256-byte SPI preamble into RAM at **`0x200021DA`**.
  - Byte `0` (`0x200021DA`) is `N_frames`; bytes `1..191` (`0x200021DB–0x20002299`) hold **191 delay slots**.
  - Uploading `192–254` frames causes `FUN_00011a84` to read frame delays **past the end of the 192-byte preamble buffer into live fuel-gauge / battery RAM at `0x200022A0+`**.
  - Note: Pixel data still begins at SPI offset **`0x750100`** (`DAT_00010874`, full 256-byte preamble on flash) with stride **`0x0000FD20`** (`64,800` bytes at `0x000117CE`). Only the maximum frame count `N` must be capped to **`191`** (`0xC0 - 1`); `PREAMBLE = 256` stays unchanged.
- **Fix:** Replace `254` with `MAX_FRAMES = 191` in `build_buffer()`, `extract_gif_frames()`, and `extract_video_frames()`.

### 5.4 Ignored `0x7204` `cmd[2]` Mode Byte ([`aula_s75pro_screen.py:162,167,175`](screenUpload/aula_s75pro_screen.py#L167))
- In firmware (`0x000045D4`), `0x7204` **never reads `buf[2]`** (`0x03` still vs. `0x05` GIF); it always sets SPI base = `0x00750000` and reads `chunks = buf[8] | (buf[9] << 8)`. In `DeviceDriver.exe.c:30381/30595`, `cmd[2]` was merely `LCDViewList::GetCurSel() + 1`. Keeping `0x03`/`0x05` is harmless for wire compatibility, but the firmware distinguishes still vs. GIF solely from `N_frames` at SPI `0x00750000`.

---

## 6. Explicit Safety Exclusions (DO NOT IMPLEMENT)

The following two firmware mechanisms exist in `s75pro_fw_v1.03.bin` and **must never be exposed** in user-facing scripts or accidentally triggered:

1. **Opcode `0x3804` (`04 38`, `0x0000459E` → State 5 `0x00003D54`):**
   - **Effect:** Opens the `EP 3 OUT` 4096-byte SPI flash writer with base address **`0x00000000`** instead of `0x00750000`.
   - **Risk:** Overwrites factory external SPI flash assets — boot splash animations, TFT menus, icons, and language tables (located at `0x00172444`, `0x00182164`, `0x00236B3C`, etc.) — permanently corrupting the display UI until a full factory SPI dump is reflashed.
   - **Rule:** Never send `04 38` from host tooling.

2. **EP0 ISP Bootloader Magic Sequence (`AA 42 89 5A FF 71 62 CC` → `FUN_00001924` / `FUN_0000187e` → `FUN_0000014c()`):**
   - **Effect:** Receiving the 8-byte signature `AA 42 89 5A FF 71 62 CC` on EP0 immediately disables interrupts/peripherals and jumps into the MCU ROM ISP firmware-update bootloader (`FUN_0000014c`).
   - **Risk:** Drops the keyboard off the normal USB HID bus into raw flash-programming mode; sending malformed data in ISP mode can brick the MCU.
   - **Rule:** Never construct, test, or transmit this magic byte sequence.
