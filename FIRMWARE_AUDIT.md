# AULA S75 Pro Firmware Reverse-Engineering Audit (`s75pro_fw_v1.03.bin`)

This document records the complete, firmware-verified and hardware-tested reverse-engineering findings for the AULA S75 Pro (`VID=0x0C45`, `PID=0x800A`, MCU firmware `v1.03`). All claims below are traced directly to ARM Cortex-M Thumb instructions and Ghidra decompilation of `s75pro_fw_v1.03.bin` (read-only analysis) and cross-checked against `DeviceDriver.exe.c`, Wireshark captures, and live USB hardware tests (now integrated into [`aula_s75pro.py`](aula_s75pro.py)).

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
5. **Host handling pattern** (implemented in [`AulaS75Pro._read_state1_chunks`](aula_s75pro.py)):
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
| **Main Keys (80 addressable RGB keys; 82 matrix positions)** | Standard key matrix (`PHYSICAL_INDICES`) | Main effect engine (`0x20000190` / `0x8000` / `0x9800`) | USB `0x1304` (`0x00–0x13`, `0x80`), `0x2304`, `0x2004`, and on-board `Fn` lighting hotkeys |
| **Row-6 Side / Underglow (14 LEDs)** | `0x7E–0x8B` (14 contiguous LEDs) | State struct at `0x20000194` (mode `0..4`, color, brightness, speed); rendered by `FUN_0000e1fc` (`0x0000E0B8–0x0000E440`) directly into `0x20001838`/`195E`/`1A84` | **USB `0x1304` `payload[0] = 0x20–0x24`** (mode only) + **`Fn + Right Shift`** (cycle mode `0..4`) + **`Fn + /?`** (cycle preset color) |
| **Row-5 Accent Bar (5 LEDs)** | `0x6C, 0x6D, 0x6E, 0x70, 0x71` | State at `0x200001DC` (independent subsystem) | **`Fn + Z`** only — **no USB HID command exists** in `s75pro_fw_v1.03.bin` |

### 3.2 `0x1304` `0x20–0x24` Underglow Behavior & `SideLightsRed.pcapng` Forensics
- In `FUN_00003f42` (`0x00003F82`), when `hid_ctx+0x14 == 0x00009800` and `(payload[0] >> 4) == 2`:
  - Firmware reads **only `payload[0]`** (`mode = payload[0] & 0x0F`, valid `0..4`: `0`=flowing, `1`=spectrum, `2`=static, `3`=breathing, `4`=off), writes it to `*(uint8_t*)0x20000194`, sets `hid_ctx[8] = 1`, and skips writing flash `0x9800`.
  - Color, brightness, and speed bytes in `payload[1..63]` are **never read** by `FUN_00003f42` for `0x20–0x24`. Consequently, **unlike main-key effects (`0x00–0x13` / `cli.py color`), the static underglow color (`0x22`) cannot be set over USB**; changing static/breathing underglow color is hardware-only via **`Fn + /?`**.
- **Why `wireshark/SideLightsRed.pcapng` frame 3987 had no visible effect:**
  - Frame 3987 sent a standard main-key `0x1304` payload (`payload[0] = 0x01` static red, not `0x20–0x24`) or targeted the wrong subsystem; furthermore, `DeviceDriver.exe` never exposes a per-color USB setter for `0x20000194` — only `0x20–0x24` mode selection exists in firmware.
- **Hardware verification (`AulaS75Pro.set_underglow_mode`):**
  - `python3 cli.py underglow off` (`mode=4`) turned the physical underglow LEDs **off** and returned the exact predicted 32-bit LE commit checksum **`0x00003C4F`** (and saved/restored flash `0x9800`).
  - `python3 cli.py underglow flowing` (`mode=0`) restored the physical underglow LEDs to **flowing rainbow** and returned **`0x00003C4F`**.

---

## 4. Verified Fixes Applied in `aula_s75pro.py`

All items below have been implemented and verified against [`aula_s75pro.py`](aula_s75pro.py) and `s75pro_fw_v1.03.bin`.

### 4.1 `CMD_LIGHT_READ = 0xF504` Wire Endianness
- **Previous bug:** `0x04F5` put `F5 04` on the wire (rejected with `0xFF`, because State 0 requires `buf[0] == 0x04`).
- **Implemented:** `CMD_LIGHT_READ = 0xF504` (wire bytes `04 F5`), matching `0x000042FA` and reading live RGB RAM (`0x20001838`/`195E`/`1A84`) cleanly via `read_live_rgb()`.

### 4.2 32-bit Little-Endian Commit Checksums (`resp[4..7]`)
- **Firmware (`0x00003E74–0x00003E82`):** `0x0204` commit writes the full **32-bit little-endian** accumulated byte sum (`hid_ctx+0x10`) into `resp[4..7]`.
- **Implemented:** `parse_commit_checksum(resp)` unpacks `<I` from `resp[4..7]` and is used consistently across `write_general_settings()`, `_write_lighting_sequence()`, `set_custom_lighting()`, `_read_state1_chunks()`, and `set_underglow_mode()`.

### 4.3 `0x1704` General Settings Bitfields & Single-Pass Write (`write_general_settings()`)
Traced from `FUN_00003f42` (writes `0x00009000`) → `FUN_00003412` / `FUN_000046d0` / `FUN_00003a08`:

| Payload Byte (`0x9000 + offset`) | Parameter in `aula_s75pro.py` | Firmware Meaning |
|---|---|---|
| `payload[0..1]` | `0x0100` (`CMD_GENERAL_SETTINGS`) | Stored at `0x9000..0x9001` (packed into low bits of `hid_ctx[1]`) |
| `payload[2]` | `disable_alt_tab` | **Disable `Alt+Tab`** (`1` = blocked; packed into `0x200000BD`) |
| `payload[3]` | `disable_alt_f4` | **Disable `Alt+F4`** (`1` = blocked; packed into `0x200000BD`) |
| `payload[4]` | `win_lock` | **Win-Lock** when `*(uint8_t*)0x2000004D == 0` (`1` = Win key locked; packed into `0x200000BD`) |
| `payload[5]` | `fn_switch` | `0` = normal hold Fn, `1` = sticky Fn toggle (`0x200000C3`) |
| `payload[6]` | `sleep_time` | `0` = off, `1` = 1 min (`600`), `2` = 5 min (`3000`), `3` = 30 min (`18000`) in 100 ms ticks (`FUN_000046d0`) |
| `payload[7]` | unused gap (`0`) | Unused |
| `payload[8]` | `key_response_time` | Debounce scan threshold (`FUN_00003a08`): `1` → 2, `2`/default → 3, `3` → 7, `4` → 10, `5` → 14 |

- **Single-pass write:** `0x00004540` ignores `buf[2..3]` and writes `0x00009000` unconditionally; `write_general_settings()` performs a single `0x1704` pass.

### 4.4 Verified Read & Query Commands in `aula_s75pro.py`
- **`CMD_DEVICE_INFO = 0x0504` (`read_device_info()`):** Reads flash `0x00008F80` (or 2.4G `0x02`), decoding `tag`, `VID`, `PID`, and `fw_version`.
- **`CMD_BATTERY_LEVEL = 0xF604` (`read_battery_level()`):** Single `SET_REPORT` + `GET_REPORT` in State 0 returning quantized level `0–5` in `resp[4]` (or exact `0–100%` over 2.4G `0x20`).
- **`CMD_LIGHTING_READ = 0x1204` (`read_lighting_config()`):** Reads flash lighting config page `0x00009800` via bit-1-aware `_read_state1_chunks()`.

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

#### Implemented Workaround in `AulaS75Pro.set_underglow_mode()`
1. **Save:** Reads the current 64-byte lighting page at `0x9800` via `0x1204` (`read_lighting_config()`).
2. **Apply underglow:** Sends `0x1804` → `0x1304` (`chunks=1`) → `[0x20 + mode, 0, ...]` → `0x0204` commit (checking `resp[4..7] == EXPECTED_UNDERGLOW_ERASED_CHECKSUM`) → `0xF004` finalize (persists `0x20000194` into `0x8000`).
3. **Restore `0x9800`:** If the saved snapshot is populated (neither all-`0xFF`, all-`0x00`, nor `0x20–0x24`), immediately rewrites that exact 64-byte payload back to `0x9800` via `_write_lighting_sequence()` (`0x1304` → `0x0204` → `0xF004`).

### 4.6 Other Protocol Clarifications for `aula_s75pro.py` / `PROTOCOL.md`
- **`0x2004` Live Streaming (`AulaStreamer`):** Both `GET_REPORT` calls in State 0 are mandatory because Phase 2 (`0x00004380`) only transitions to State 2 on `GET_REPORT`.
- **`0x2304` Custom RGB Table (`set_custom_lighting()`):** `0x0000CBBA` only checks `(word & 0xFF) == slot_idx` per 4-byte slot and never inspects the `AA 55` trailer (unlike keymaps `0x1104` / `0x2704`, where `FUN_0000275c` checks `0x55AA0000` at `0x963C` / `0xAE3C`). Keeping `AA 55` at offsets `574–575` remains harmless and matches the official driver's checksum.
- **`0x2804` RTC Sync (`sync_rtc()`):** State 6 (`0x00003CFC`) only validates `buf[2] == 0x5A` and copies `buf[3..8]` (`yy, mm, dd, HH, MM, SS`); `buf[0..1]`, `weekday`, and `AA 55` are ignored.

---

## 5. Verified Fixes Applied in `aula_s75pro_screen.py`

All items below are implemented and verified against [`aula_s75pro_screen.py`](screenUpload/aula_s75pro_screen.py) and `s75pro_fw_v1.03.bin`.

### 5.1 `WIRE_TICK_MS = 2`
- **Clock-tree proof in firmware:**
  1. `FUN_00013bfa` configures PLL = **48 MHz**, HCLK prescaler = `1`.
  2. `FUN_00006f8c` sets SysTick `RVR = 23999` (`0x5DBF`) → `48,000,000 / 24,000 = 2000 Hz` = **0.5 ms** per SysTick IRQ (`FUN_00006f9c`).
  3. `FUN_000008e2` derives software timer ticks from SysTick:
     - `pbVar2[3]` = **1 ms** (every 2 SysTicks; drives `FUN_0000466a` 2000-tick = 2.0 s HID watchdog)
     - `pbVar2[2]` = **2 ms** (every 4 SysTicks)
  4. `FUN_0000042e` derives `pbVar2[5]` = **100 ms** (independently confirmed by `FUN_000046d0` sleep timeouts: `600` = 1 min, `3000` = 5 min, `18000` = 30 min).
  5. The TFT GIF animation scheduler **`FUN_00011a84`** increments its frame counter on **`pbVar2[2]` (2 ms)**.
- **Driver cross-check (`DeviceDriver.exe.c:30483`):** The official Windows driver stores GIF frame durations in **milliseconds** and divides by `2` to produce 2 ms ticks.
- **Implemented:** `WIRE_TICK_MS = 2` in `screenUpload/aula_s75pro_screen.py`.

### 5.2 Delay Floor `0x10` (32 ms) and Ceiling `0xFF` (510 ms)
- **Firmware (`FUN_00011a84`):** Before comparing against the elapsed 2 ms counter, the firmware executes:
  ```c
  if (bVar1 < 0x10) {
      period = 0x19;  // silently replaces < 16 (32 ms) with 25 (50 ms)!
  }
  ```
- **Implemented:** `clamp_wire_delay()` and `ms_to_wire_delay()` clamp encoded wire delay ticks to **`[0x10, 0xFF]`** (`16..255` ticks = **`32 ms – 510 ms`** per frame, i.e., `~1.96–31.25 fps`), and CLI `--delay` accepts milliseconds (`32–510`).

### 5.3 Hard Frame Cap = `140` Frames (`16 MB` 24-Bit SPI Flash Boundary; RAM Preamble Holds `191`)
- **Primary Limit — 24-Bit SPI Flash Address Wrap (`FUN_00007858`, `FUN_000078be`, `FUN_00007964`):**
  - The external SPI flash helpers transmit 24-bit addresses (`0x000000–0xFFFFFF` = **16 MB** `0x01000000`). `0x7204` (`0x000045d4`) always starts writing at `0x00750000`, erasing/programming in `4 KB` (`0x1000`) chunks (`PREAMBLE = 256` bytes followed by pixel stride `0x0000FD20` = `64,800` bytes at `0x750100`).
  - `140` frames require `256 + 140 × 64,800 = 9,072,256` bytes → **`2,215` chunks (`0x008A7000`)**, ending cleanly at **`0x00750000 + 0x008A7000 = 0x00FF7000 <= 0x01000000`**.
  - `141` frames (matching OEM `rgb-keyboard.xml` `gif_maxframes="141"`) require **`2,231` chunks (`0x008B7000`)**, reaching **`0x01007000 > 0x01000000`** — wrapping **28 KB** past 16 MB back onto `0x00000000` and erasing factory TFT assets (`0x00000124–0x0028D44E`).
- **Secondary RAM Limit (`FUN_0001047c` → `FUN_00010460(0x750000)`):**
  - Calls `FUN_00007882(0x750000, 0xC0)`, reading only **`192` bytes (`0xC0`)** from the 256-byte SPI preamble into RAM at **`0x200021DA`** (`N_frames` + **`191` delay slots** at `0x200021DB–0x20002299`). Uploading `>= 192` frames would also read past `0x20002299` into live fuel-gauge / battery RAM at `0x200022A0+`.
- **VFR Video Deduplication:** `iio.imiter(..., plugin="FFMPEG")` decodes VFR clips (such as `4.0 s` MP4s reported with `fps=0.58`) into duplicated raw frames. `extract_video_frames()` derives actual `ms_per_raw = duration * 1000 / total_decoded_raw` when EOF duration disagrees with `meta['fps']`, collapses consecutive identical RGB565 runs via `collapse_video_runs()`, and splits holds `> 510 ms` into the minimum number of `<= 510 ms` copies (or 1 frame per unique run when `--delay` is given).
- **Implemented:** `MAX_FRAMES = 140` (with `PREAMBLE = 256`) enforced across `make_cmd_upload()`, `build_buffer()`, `extract_gif_frames()`, `extract_video_frames()`, and `webui/server.py`, plus State-3 `CMD_END` + `ctrl_get()` completion and mid-State-5 `2.1 s` watchdog recovery in `upload()`.

### 5.4 Ignored `0x7204` `cmd[2]` Mode Byte
- In firmware (`0x000045D4`), `0x7204` **never reads `buf[2]`** (`0x03` still vs. `0x05` GIF); it always sets SPI base = `0x00750000` and reads `chunks = buf[8] | (buf[9] << 8)`. In `DeviceDriver.exe.c:30381/30595`, `cmd[2]` was merely `LCDViewList::GetCurSel() + 1`. Keeping `0x03`/`0x05` is harmless for wire compatibility, but the firmware distinguishes still vs. GIF solely from `N_frames` at SPI `0x00750000`.

---

## 6. Explicit Safety Exclusions (DO NOT IMPLEMENT)

The following three firmware mechanisms exist in `s75pro_fw_v1.03.bin` and **must never be exposed** in user-facing scripts or accidentally triggered:

1. **Opcode `0x3804` (`04 38`, `0x0000459E` → State 5 `0x00003D54`):**
   - **Effect:** Opens the `EP 3 OUT` 4096-byte SPI flash writer with base address **`0x00000000`** instead of `0x00750000`.
   - **Risk:** Overwrites factory external SPI flash assets — boot splash animations, TFT menus, icons, and language tables (located at `0x00172444`, `0x00182164`, `0x00236B3C`, etc.) — permanently corrupting the display UI until a full factory SPI dump is reflashed.
   - **Rule:** Never send `04 38` from host tooling.

2. **EP0 ISP Bootloader Magic Sequence (`AA 42 89 5A FF 71 62 CC` → `FUN_00001924` / `FUN_0000187e` → `FUN_0000014c()`):**
   - **Effect:** Receiving `0x5A8942AA` / `0xCC6271FF` (`AA 42 89 5A FF 71 62 CC`) in EP0 `FUN_0000187e` (`0x00001894–0x000018D8`) erases/wipes internal MCU flash **`0x00000000–0x000000FF`** (the interrupt vector table!) via `FUN_00001234` (`0x000018AA`), disables interrupts (`0xE000E180`) and peripherals, and jumps to `FUN_0000014c()` (`0x0000014C` → ROM ISP `0x1FFF0301`).
   - **Risk:** Immediately bricks normal boot off the USB HID bus until valid firmware is reflashed via ISP.
   - **Rule:** Never construct, test, or transmit this magic byte sequence.

3. **Wireless 2.4G SPI Flash Streamer / OTA Opcodes (`0x7F`, `0x80–0x8F` in `FUN_00005990`):**
   - **Effect:** `0x7F` (`0x00005D60`) disables IRQ19 LED PWM (`0xE000E180 = 0x80000`) and arms external SPI base `0x00750000` with 24-bit `total_chunks` (`0x200000E0`); `0x80–0x8F` (`0x00005E24`, sent by `DeviceDriver.exe.c` `FUN_00423360`) writes 28-byte chunks via `FUN_000079f2` to **`0x00750000 + 20-bit_idx * 0x1C`** (`0..1,048,575` × `28` B = `29.36 MB`).
   - **Risk:** Because the external SPI flash helpers send 24-bit addresses (`16 MB` ceiling `0x01000000`), high chunk indices wrap past `0x01000000` onto `0x00000000` factory TFT assets; furthermore, interrupted or malformed RF streaming leaves LED PWM disabled and the display wedged in state `0x0E`.
   - **Rule:** Never construct, expose, or transmit `0x7F` or `0x80–0x8F` as 2.4G command IDs (note: `0x80` as `payload[0]` inside `0x05` is the safe custom-RGB lighting mode selector).

---

## 7. Complete 2.4GHz / UART Command Dispatcher Audit (`FUN_00005990`)

### 7.1 Transport, IRQ ISR & Mode Gating
- **UART ISR (`0x00013674`, vector `0x00000060 = 0x00013675`):** Reads incoming bytes from UART peripheral `0x40054000` into `0x200026BC` (`34`-byte frame buffer).
- **Main-loop dispatch (`FUN_00004798`, `0x00004D24–0x00004D46`):** Invokes `FUN_00005990()` at `0x00004D36` **only** when `DAT_200002b7 == 0x22` and `DAT_200000ea == 2` (2.4GHz mode). Bluetooth mode (`DAT_200000ea == 1`) is rejected before `0x00004D36` and has no vendor configuration dispatcher.
- **Framing check (`FUN_00005990` at `0x00005990`):** Verifies `DAT_200026bc == 0x81` (`-0x7f`) and 8-bit sum `DAT_200026dd == sum(DAT_200026bc[0..32]) & 0xFF`, copies `buf[1..32]` (`[cmd, len, seq, payload[0..28]]`) to `0x200014F5..0x20001514`, mirrors `[cmd, len, seq]` to TX buffer `0x200014D5..0x200014D7`, and sets `DAT_20000150 = 1`.

### 7.2 Complete 16-Opcode Table (`FUN_00005990`)

| Cmd (`DAT_200014f5`) | Ghidra Addr | `DeviceDriver.exe.c` Sender | Firmware Action | Implemented / Safe to Expose? |
|---|---|---|---|---|
| `0x02` | `0x00005A3A` | `FUN_0044f980` | Copies 28 B from internal flash `0x00008F80` into reply `0x200014D8..0x200014F3`. | **Implemented (`read_device_info()`)**. |
| `0x03` | `0x00005A54` | *(unused helper)* | Writes 4 B `payload[0..3]` to Base Keymap `0x00009400 + (seq << 2)` via `FUN_00001e88` and writes `0x55AA0000` (`00 00 AA 55`) at `0x0000963C`. | **Unimplemented; Yes** (safe if host enforces `seq <= 142`). |
| `0x05` | `0x00005A70` / `0x00005AA4` | `FUN_0042b170`, `FUN_00434900`, `FUN_0044bd70` | If `(payload[0] >> 4) == 2` (`0x20–0x24`): sets underglow mode `DAT_20000194 = payload[0] - 0x20`, calls `FUN_0000e1fc()` + `FUN_0000df18()` (**does not erase `0x00009800`**). Otherwise: writes 16 B to `0x00009800`, applies main effect (`< 0x14`, `0x00`, `0x80`), calls `FUN_0000b000()`, `FUN_0000d9c0()`, `FUN_0000b11a()`, `FUN_0000df18()`. | **Implemented (`set_color()`, `set_underglow_mode()`, `set_custom_lighting()`)**. |
| `0x07` | `0x00005B46` | `FUN_00414410` | Writes 28 B to General Settings `0x00009000`, updates Win-Lock bit in `0x20000050`, resets `0x200000BD`/`0x200000C3`, calls `FUN_000046d0()`. | **Implemented (`write_general_settings()`)**. |
| `0x09` | `0x00005BCC` | `FUN_0042db50` | Writes 28 B (`7 × 4 B`) to Macro flash `0x0000A000 + seq * 0x1C` via `FUN_000132fe`, erasing 1 KB page via `FUN_000132d0` when `(offset & 0x3FF) == 0`. | **Unimplemented; Yes with cap** (firmware does not bounds-check `seq`; **host must cap `seq <= 109`**, see §8.3). |
| `0x0B` | `0x00005C00` | `FUN_00432b00` | Sets `DAT_200000be = 1`, `DAT_200000c0 = 0x32`, renders 15×6 live music EQ via `FUN_00006766` (RAM-only). | **Implemented (`send_wireless_music_eq()`)**. |
| `0x0C` | `0x00005C60` | `FUN_00423bb0` | Validates `payload[2] == 0x5A`, copies `payload[3..8]` (`yy..SS`) into `0x20000224[0, 1, 3, 4, 5, 6]`, calls `FUN_00008dee()`, sets `DAT_20000239 = 1`, calls `FUN_0000fe96()` (ignores `payload[0..1]`, `weekday`, `AA 55`). | **Implemented (`sync_rtc()`)**. |
| `0x0D` | `0x00005C8C` | `FUN_00419130` | Writes 4 B `payload[0..3]` to Fn-Layer Keymap `0x0000AC00 + (seq << 2)` via `FUN_00001e88` and writes `0x55AA0000` at `0x0000AE3C`. | **Unimplemented; Yes** (safe if host enforces `seq <= 142`). |
| `0x0F` | `0x00005CAC` | `FUN_00434ee0` | Calls `FUN_0000de3c()` (`0x0000DE3C`), triggering temporary RAM-only mode `0x1D` self-test blink (zero flash writes). | **Unimplemented; Yes** (harmless visual feedback). |
| `0x10` | `0x00005CB8` | `FUN_00418df0` (`layer=0`) | Writes 28 B (`7 × 4 B`) to Base Keymap `0x00009400 + seq * 0x1C` (1 KB erase when `(offset & 0x3FF) == 0`). | **Unimplemented; Yes with cap** (host must cap `seq <= 20`, send `len=0x10` / zero `payload[16..27]` on `seq==20`, and include `00 00 AA 55` at `572..575`). |
| `0x12` | `0x00005CEC` | `FUN_00418df0` (`layer=1`) | Writes 28 B (`7 × 4 B`) to Fn-Layer Keymap `0x0000AC00 + seq * 0x1C` (1 KB erase when `(offset & 0x3FF) == 0`). | **Unimplemented; Yes with cap** (same `seq <= 20` & `00 00 AA 55` guard). |
| `0x14` | `0x00005D20` | `FUN_0044bd70`, `FUN_004349a0` | Writes 28 B (`7 × 4 B`) to Custom RGB table `0x00009C00 + seq * 0x1C` (1 KB erase when `(offset & 0x3FF) == 0`). | **Implemented (`set_custom_lighting()`, `seq = 0..20`)**. |
| `0x1F` | `0x00005CB2` | `FUN_00434230` (queue `0x0D` from `FUN_00414600`) | Calls `FUN_00001ece()` (`0x00001ECE`), erasing and zero-filling **only** Base (`0x00009400`) and Fn (`0x0000AC00`) keymap 1 KB pages so custom remaps revert to pass-through (leaves `0x8000`, `0x9000`, `0x9800`, `0x9C00` intact). | **Unimplemented; Yes** (erases user keymaps only; require explicit user action). |
| `0x20` | `0x00005D54` | `FUN_004357d0` | Returns `DAT_200000f9` (`0–100%` fuel-gauge SOC) in `resp[3]` (`0x200014D8`). | **Implemented (`read_battery_level()`)**. |
| `0x7F` | `0x00005D60` | `FUN_00423360` | Wireless SPI flash setup (`0x00750000`, `total_chunks`, disables LED PWM `0x80000`, enters state `0x0E`). | **NO / EXCLUDED** (see §6). |
| `0x80–0x8F` | `0x00005E24` | `FUN_00423360` | `(cmd >> 4) == 8`: writes 28 B chunks to `0x00750000 + 20-bit_idx * 0x1C` via `FUN_000079f2`, draws `"LOADING %"`, calls `FUN_0001047c()` at end. | **NO / EXCLUDED** (24-bit SPI address wrap risk; see §6). |

### 7.3 Internal UART & SPI RF Link Frames (Non-Host)
- **3-byte UART frames (`FUN_00004798`, `DAT_200002b7 == 3`):** `0x61 0x0D 0x0A` (link idle/ACK clear, `0x00004D0A`), `0x5A <byte>` (`0x00004CFC`), and `0x5B <0x21|0x22|0x23|0x31|0x32|0x33>` (`0x00004CE8`) are internal dongle/radio UART control messages, not exposed over the 32-byte HID pipe.
- **SPI RF pairing frame (`04 A1 <id_lo> <id_hi>` in `FUN_00005518` → `FUN_000054fc` at `0x000054FC`):** Persists the learned 2-byte RF pairing ID into MCU flash **`0x1FFF0C00`** (**UNSAFE**; internal RF link only).

---

## 8. `0x1304` / `0x1704` Bitfields, On-Board-Only `0x8000` Controls (incl. `0x2000023A` TFT Language) & Bounds Bugs

### 8.1 `0x1304` (`0x00009800`) & `0x1704` (`0x00009000`) Bitfield Completeness
- **`0x1304` Lighting (`FUN_00003eae` at `0x00003EAE` / `FUN_00005990` at `0x00005AA4`):** Firmware reads only `payload[0]` (`effect`: `< 0x14`, `0x00`, `0x80`, or `0x20–0x24` in `FUN_00003f42`), `payload[1..3]` (`R, G, B`), `payload[8]` (`option`: `0` single-color, `1` multicolor), `payload[9]` (`brightness`: `0..5` mapped by `FUN_0000b000`), `payload[10]` (`speed`: `0..5` mapped by `FUN_0000b11a`), and `payload[11]` (`direction`: `0x01`/`0x02` set `DAT_20000169 = 1`, else `0`). Bytes `4..7` and `12..63` (including `AA 55`) are ignored. Both `0x00` and `0x80` map to internal mode `0x14` (`0x00003F0E–0x00003F18` / `0x00005B08–0x00005B10`).
- **`0x1704` General Settings (`FUN_00003f42` at `0x00003FD4–0x00004044`):** Packs `0x9000..0x9004` into `hid_ctx[1]` (`0x200000BD`), toggles Win-Lock bit 0 of `0x20000050` when `DAT_2000004d == 0`, and copies `0x9005` (`fn_switch` → `0x200000C3`), `0x9006` (`sleep_time` → `0x200000FA`), and `0x9008` (`key_response_time` → `0x20000052`). Across the entire binary, `0x200000BD` is read **only** in `FUN_00003412` (`0x0000353E`, literal `0x000038EC`) for bit 5 (`0x20`, block `Alt+Tab`) and bit 6 (`0x40`, block `Alt+F4`). Bytes `0x9007` and `0x9009..0x903F` have no firmware consumers.

### 8.2 On-Board-Only `0x8000` Controls (`FUN_0000df18`) & Exhaustive `0x2000023A` TFT Language Audit
`FUN_0000df18` (`0x0000DF18`, restored at boot by `FUN_0000b086` at `0x0000B086`) writes a 20-byte runtime configuration snapshot (`0x20001823..0x20001836`, tag `0xA5`) to internal flash `0x00008000..0x00008013`. The following controls reside in this snapshot or dedicated RAM globals and have **no USB or 2.4G setter** in `s75pro_fw_v1.03.bin`:

1. **TFT Screen Language (`0x2000023A` = `DAT_2000023a` / `flash[0x800F]`):**
   - **Firmware proof (`s75pro_fw_v1.03.bin`):** Ghidra `get_xrefs_to("0x2000023a")` returns **37 direct references** across all 6 literal-pool entries (`0x000034C0`, `0x0000B430`, `0x0000DFCC`, `0x0000F1B8`, `0x0000FBE4`, `0x0000FFD8`): **36 `READ`s** and **1 direct `WRITE`** at **`0x0000B0E6`** (`FUN_0000b086` loading `DAT_2000023a = *(uint8_t*)(0x00008000 + 0x0F)` at boot/reset). Exhaustive ARMv6-M Thumb disassembly of every struct-offset and register-indexed store across the 256 KB binary finds **only two indirect writes**: **`0x00011754` and `0x00011772`** (`strb r5/r6, [r7, #6]` relative to `0x20000234`) inside `FUN_000104e0` (`case 0x0B` LCD language menu confirmation, `DAT_20000237 == 8 || 9`), which toggles `DAT_2000023a = (DAT_2000023a == 0)` (`0` = Chinese SPI bitmaps `0x001B18C4`/`0x00172444`/`0x00182164`/`0x0010D044` + `FUN_000127aa` glyphs; `1` = English SPI bitmaps `0x0026629C`/`0x00226E1C`/`0x00236B3C`/`0x002170FC` + `FUN_00012ab6` ASCII text) and calls `FUN_0000df18()` (`0x0001176C`) to persist `DAT_20001832 = DAT_2000023a` to `flash[0x800F]`. Factory reset `FUN_00001d98` (`0x00001D98`) copies template `0x0000700F = 0x00` (Chinese) to `0x0000800F`. Neither wired `FUN_00004622` nor 2.4G `FUN_00005990` can write `0x2000023A`.
   - **Windows driver cross-check (`DeviceDriver.exe.c`):** Auditing every caller of `HidD_SetFeature` (`FUN_00451350`), `WriteFile` (`FUN_00451130`), and every worker-queue task (`0x01..0x15` in `FUN_00434230`) confirms `DeviceDriver.exe` has **no** TFT screen language packet. On the **Settings (`icon_config.png`) tab** (`FUN_0043b3e0`, `L48606–48613`, adjacent to hardware `0x1704` controls), the Language `MComboBox` (`param_1 + 0x644` / `(LPCWSTR)param_1 + 0x322`, control ID `0x122`, handler `FUN_00414cb0` at `L20123–20130`) controls only the **PC driver GUI's own localization** (`DAT_00594180`, initialized from `config.xml` `<language.info default_lan="...">` at `L26317–26323`), writing Windows Registry `HKCU\<device>\LCID` via `FUN_0040bb60()` (`L12570`) and reloading UI text via `FUN_0043faa0()` with zero USB/2.4G writes. On the **TFT (`icon_tft.png`) tab** (`FUN_0043db10`, `L49738–50462`), the only hardware commands are RTC sync (`0x167` → `FUN_00423a80` `0x2804` / `FUN_00423bb0` `0x0C`, whose `LCDViewList` index at wired `payload[1]` / wireless `payload[0]` is ignored by `0x00003CFC` and `0x00005C60`) and image/GIF upload (`0x16a` → `0x7204` / `0x7F`+`0x80–0x8F`).
2. **OS Layout Mode (`0x2000004D` / `flash[0x800C]`):** `0`=Windows, `1`=Mac, `2`=iOS, `3`=Android — selected only via `Fn + Q / W / E / R` (`FUN_000029b2`).
3. **Row-5 Accent Bar (`0x200001DC`):** 5-LED Home/End strip — cycled (`0..10`) only via `Fn + Z` (`FUN_000029b2`).
4. **Row-6 Underglow Color, Brightness & Speed (`0x20000195`, `0x20000198`, `0x20000196` / `flash[0x8007..0x8009]`):** USB `0x1304` `0x20–0x24` and 2.4G `0x05` `0x20–0x24` set mode `0x20000194` only; color/brightness/speed require on-board `Fn + /?`.
5. **Knob UI Mode (`0x2000004E` / `flash[0x8010]`) & Active TFT Menu Page (`0x2000023B` / `flash[0x800D]`):** Toggled via `Fn + Knob Press` (`FUN_00002f88`) and on-board TFT menu navigation.
6. **Full Factory Reset (`FUN_00001d98` at `0x00001D98`):** Triggered only by holding `Fn + Esc` (`FUN_00002f88`, `DAT_20000046 == -0x2e`); restores `0x8000`/`0x8400` from `0x7000`/`0x7400`, zeroes `0x9400`/`0xAC00`, and resets `0x9000` (whereas 2.4G `0x1F` / `FUN_00001ece` only zeroes `0x9400`/`0xAC00`).

### 8.3 Firmware Bounds Bugs Requiring Host-Side Guards
1. **Wired `0x1504` Macro Write 49-Chunk Off-By-One (`0x00004512` → `0x0000AC00` erase):**
   - `0x1404` (`0x000044F8`) caps macro reads at `0x30` (`48` chunks = `3,072` B, `0x0000A000–0x0000ABFF`), immediately before the Fn-Layer Keymap page at `0x0000AC00`.
   - `0x1504` (`0x00004512`) mistakenly passes `max = 0x31` (`49` chunks) to `0x000041C0`. Writing chunk 49 advances the cursor to `0x0000AC00`, where `FUN_00003f42` sees `(0xAC00 & 0x3FF) == 0` and erases the entire `0x0000AC00` Fn-Layer Keymap page via `FUN_000132d0`.
   - **Host rule:** Never send `chunks > 48` (`0x30`) on `0x1504`.
2. **Unbounded 2.4G `seq` on `0x09`, `0x10`, `0x12`, `0x14` (`FUN_00005990`):**
   - None of the 4 wireless chunked flash writers bounds-check `seq` (`DAT_200014f7`), computing `offset = seq * 0x1C` (`0..7,140` B) and erasing any 1 KB boundary (`(offset & 0x3FF) == 0`) past the target partition (`0x9400`, `0x9800`, `0x9C00`, `0xA000`, `0xAC00`, `0xB000+`).
   - **Host rule:** Enforce `seq <= 109` on `0x09` (`3,052` B `< 3,072` B) and `seq <= 20` (with `len = 0x10` / zeroed `payload[16..27]` on `seq == 20`) on `0x10`, `0x12`, and `0x14`.

---

## 9. Keymap Trailer, Action Encoding & Macro Engine Summary (`FUN_0000275c` / `FUN_00002554`)

- **Enable / Bypass (`0x1804` / `0x1904`):** `0x1804` (`0x000042CC`) clears `hid_ctx[5]` bit 6 (`0x40`) so `FUN_00003412` invokes `FUN_0000275c`; `0x1904` (`0x000042D6`) sets bit 6 for raw-matrix bypass.
- **Mandatory `0x55AA0000` (`00 00 AA 55`) Trailer at Bytes `572..575`:** Unlike `0x2304` (where `0x0000CBBA` ignores `AA 55`), `FUN_0000275c` checks the full 32-bit word **`*(uint32_t *)0x0000963C == 0x55AA0000`** (`0x000027B4` for Base `0x1104`) and **`*(uint32_t *)0x0000AE3C == 0x55AA0000`** (`0x0000278A` for Fn `0x2704`). Bytes `572..575` (`0x963C–0x963F` / `0xAE3C–0xAE3F`) must therefore be `00 00 AA 55` (matching `DeviceDriver.exe.c` `FUN_00418550`, which places `0x55aa` at offset `574` inside a zeroed `0x30C` buffer), or the entire layer falls back to pass-through.
- **Slot Lookup & Action `switch8` (`0x000027D6` → `0x0000282E`):** Matrix index (`0..89`) maps via LUT `0x000141C8` to `slot_id` (`<= 0x8F`), reading `[b0, b1, b2, b3]` at `base + (slot_id << 2)`:
  - `b0 == 0` (`0x00002824` → `0x0000283C`): default pass-through.
  - `b0 == 1` (`0x00002840`): Mouse button/wheel (`0x20000060` + `0x20000099..`).
  - `b0 == 2` (`0x00002878`): Standard HID key (`b2`) + modifier mask (`b1`) dispatched via `FUN_00002398`.
  - `b0 == 3` (`0x0000289C`): Consumer Control 16-bit usage (`b1 | (b2 << 8)` → `DAT_2000007d`/`DAT_2000007e`, pending flag `DAT_20000061 = 1`).
  - `b0 == 4` (`0x000028B2`): System Control usage (`b1` → `DAT_20000079`, pending flag `DAT_20000062 = 1`).
  - `b0 == 5` (`0x000028CC`): Special (`b1=1` Fn/layer switch, `b1=2` lighting hotkey, `b1=3` disable key).
  - `b0 == 6`: Macro trigger (`b1` = macro slot into `0x0000A000 + b1 * 0x100`, `b2` = repeat count or `0xFE` hold-repeat / `0xFF` toggle-repeat, stepped every tick by `FUN_00002554` at `0x00002554`).
  - `b0 == 7`: Multi-key tap sequence (`b1, b2, b3`). `b0 >= 8`: disabled/no-op.
- **Pre-interception Priority (`FUN_00003412`):** `FUN_000032d4()`, `FUN_00002f88()`, and `FUN_000029b2()` execute **before** `FUN_0000275c()`, consuming `Fn` (`0xAF`) and hardcoded `Fn` system/mode/lighting combos prior to custom keymap translation.

---

## 10. Rotary Encoder & Knob Press Firmware Audit (`FUN_000021e0` / `FUN_00002f88`)

- **Quadrature Rotation CW / CCW (`FUN_000021e0` at `0x000021E0–0x000022AC`):**
  - Polls dedicated quadrature GPIO pins (`0x40046000` bit 0 and `0x40044000` bit 3) completely outside the key matrix scanner (`FUN_0000656e`) and never reads `0x00009400` or `0x0000AC00`.
  - When `DAT_2000004e == 0` (Volume mode): writes hardcoded Consumer usage **`0x00EA`** (`Volume Down`, `0x0000225E`) or **`0x00E9`** (`Volume Up`, `0x0000229C`) to `DAT_2000007d` (`DAT_2000007e = 0`), sets pending flag `DAT_20000061 = 1`, and arms the 10-tick release timer `DAT_2000005e = 10` cleared by `FUN_000022ae` (`0x000022AE–0x000022E2`).
  - When `DAT_2000004e != 0` (TFT Menu mode): queues UI scroll events `9` / `8` via `FUN_000104b0()`.
- **Knob Press (`FUN_00002f88` at `0x00002FBC → 0x00003014–0x00003066`):**
  - Scanned in the key matrix (base table slot `112` → internal keycode `0x98` at `0x00014270 + 0x70 = 0x000142E0`), but unconditionally intercepted in `FUN_00002f88` **before** `FUN_0000275c`:
    - **`Fn + Knob Press` (`DAT_20000048 != 0`):** Toggles `DAT_2000004e` (`0` ↔ `1`, Volume vs. TFT Menu mode), persists via `FUN_0000df18()`, and triggers LED feedback `FUN_0000e060(0)`.
    - **Plain Knob Press (`DAT_2000004e == 0`):** Emits hardcoded Consumer **`0x00E2`** (`Mute`, `DAT_20000061 = 1`, `DAT_2000007d = 0xe2`) on press and releases (`0`) on release; when `DAT_2000004e != 0`, queues TFT Menu confirm `0x0C`/`0x0D` (`0x0B` handler).
- **Conclusion:** Neither rotary encoder rotation (`0x00E9`/`0x00EA`) nor knob press (`0x00E2` / `Fn+Knob`) is remappable via `0x1104` / `0x2704` (consistent with `rgb-keyboard.xml` omitting the knob).
