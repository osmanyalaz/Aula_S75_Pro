# AULA S75 Pro — USB RGB Protocol (reverse-engineered)

Reverse-engineered control protocol for the AULA S75 Pro (VID `0x0C45`, PID `0x800A`,
wired USB mode). Built from Wireshark/usbmon captures of the official Windows driver
(running under Wine), the driver's Ghidra decompilation, the keyboard MCU firmware
(v1.03). Everything in the "verified"
sections was confirmed on real hardware unless marked otherwise.

## 1. Transport

From the firmware USB descriptor table (`0x000140F0`, Configuration Descriptor `0x00014056`, length `0x74`), the AULA S75 Pro (`VID=0x0C45`, `PID=0x800A`) exposes **4 USB HID interfaces**:

| Interface | Endpoints | Usage Page / Role |
|---|---|---|
| **Interface 0** (`0x00013F36`) | `EP 0x81 IN` | Boot keyboard. Also accepts EP0 Control Feature `SET_REPORT` / `GET_REPORT` into the shared control buffer (`0x2000135C`). |
| **Interface 1** (`0x00013F77`) | `EP 0x82 IN` | NKRO / Consumer / System / Mouse / Vendor IN reports. |
| **Interface 2** (`0x00014015`) | `EP 0x84 IN` (64 B), `EP 0x03 OUT` (64 B) | Usage Page `0xFF68`, 4096 B Output Report `0x63`. **External SPI flash bulk data pipe ONLY** (`FUN_00000ede` → `FUN_00000b04` accumulates 64×64 B into `0x200002F4` for State 5 SPI writes; `EP 0x84` returns `01 5A 02 ...` ACK). Stalls EP0 Feature `SET_REPORT`. |
| **Interface 3** (`0x00014038`) | `EP 0x86 IN` | Usage Page `0xFF13`, Usage `0x0001`. **Primary control interface** used by the official driver via EP0 Control Feature `SET_REPORT` / `GET_REPORT`: |

```
bmRequestType 0x21 | bRequest 0x09 (SET_REPORT) | wValue 0x0300 | wIndex 0x0003 | 64 bytes
bmRequestType 0xA1 | bRequest 0x01 (GET_REPORT) | wValue 0x0300 | wIndex 0x0003 | 64 bytes
```

Report ID 0; the 64-byte payload follows. hidapi: `send_feature_report(b"\x00" + payload)` / `get_feature_report(0, 65)`. Interface 0 shares the same EP0 handler (`FUN_00001d2e` → `FUN_00001924` / `0x00001C38`), while Interface 3 is the dedicated vendor control interface.

## 2. HID State Machine (`FUN_00004622`), Opcodes & Transaction Model

All EP0 Feature command traffic runs through the main-loop state machine `FUN_00004622` (context struct `hid_ctx` at `0x200000BC`, shared 64 B report buffer `hid_buf` at `0x2000135C`, USB event flags `usb_flags` at `0x2000003C` where bit 0 = RX `SET_REPORT` and bit 1 = TX `GET_REPORT`). A 1 ms watchdog (`FUN_0000466a`) resets `hid_ctx` and `usb_flags` back to idle after `2000` ticks (2.0 s) without HID activity.

| State | Handler | Role |
|---|---|---|
| **0** | `0x00004330` | Two-phase command dispatcher. **Phase 1 (`SET_REPORT`, bit 0):** checks `buf[0] == 0x04` and validates `0x000041E0(buf[1])` (erasing target flash pages immediately for write opcodes); sets `buf[3] = 0x01`, `hid_ctx[5] |= 0x11` (or `0xFF` on reject). **Phase 2 (`GET_REPORT`, bit 1 && `hid_ctx[5] & 0x10`):** validates `chunks = buf[8] | (buf[9] << 8)` and enters target state. |
| **1** | `FUN_0000407a` | Flash / Live-RGB RAM read phase. Accumulates 32-bit byte sum (for flash reads) into `hid_ctx+0x10`, decrements chunk counter `hid_ctx+0x0C`, transitions to State 3 at completion. |
| **2** | `FUN_00003f42` / `FUN_00001924` | Non-streaming (`hid_ctx[2] == 0`) internal flash write (`FUN_00003f42`), OR live per-key RGB ISR fast-path (`hid_ctx[2] == 1` via `FUN_00001924`). Transitions to State 3 when `count == 0`. |
| **3** | `0x00003E48` | Commit (`04 02`). `SET_REPORT` writes `0x01` to `buf[3]` and full **32-bit LE byte sum** (`hid_ctx+0x10`) to **`buf[4..7]`**. Subsequent `GET_REPORT` (`0x00003EA6`) clears `hid_ctx` **and sets `usb_flags = 0`**, returning to State 0. |
| **4** | `0x00003E32` | Single-packet sink (`0xAB04`) → State 3. |
| **5** | `0x00003D54` | External SPI flash bulk programmer (`EP 3 OUT` 4096 B chunks at `0x200002F4` → `FUN_000079bc` → `EP 0x84` `01 5A 02` ACK) → State 3. |
| **6** | `0x00003CFC` | RTC write (`0x2804`) → State 3. |

### Complete 27-Opcode Table (`buf[0] == 0x04`, `buf[1]` = opcode; wire LE16 = `0xXX04`)

| Opcode | LE16 Word | Phase 1 (`0x000041E0`) | Phase 2 / Target / Max Chunks / Next State | Purpose |
|---|---|---|---|---|
| `0x02` | `0x0204` | — (State 3 only) | State 3 (`0x00003E48`) → State 0 | Commit; returns 32-bit LE checksum in `resp[4..7]`, clears `usb_flags = 0`. |
| `0x05` | `0x0504` | Valid (`1`) | Flash `0x00008F80`, max `2`, `count=chunks+1`, State 1 | **Device Info block** (`tag=0x3040`, `VID=0x0C45`, `PID=0x800A`, `FW=v1.03`). |
| `0x10` | `0x1004` | Valid (`1`) | Flash `0x00009400`, max `9`, `count=chunks+1`, State 1 | Read Base Keymap. |
| `0x11` | `0x1104` | **Erases `0x9400`** | Flash `0x00009400`, max `9`, State 2 | Write Base Keymap (`FUN_0000275c` checks `0x55AA0000` at `0x963C`). |
| `0x12` | `0x1204` | Valid (`1`) | Flash `0x00009800`, max `1`, `count=chunks+1`, State 1 | **Read Lighting Config page (`0x9800`).** |
| `0x13` | `0x1304` | **Erases `0x9800`** | Flash `0x00009800`, max `1`, State 2 | Write Lighting Config (`0x00–0x13`, `0x80`) or Row-6 Underglow (`0x20–0x24`, skips flash write). |
| `0x14` | `0x1404` | Valid (`1`) | Flash `0x0000A000`, max `48`, `count=chunks+1`, State 1 | Read Macros. |
| `0x15` | `0x1504` | **Erases `0xA000`** | Flash `0x0000A000`, max `49`, State 2 | Write Macros. |
| `0x16` | `0x1604` | Valid (`1`) | Flash `0x00009000`, max `1`, `count=chunks+1`, State 1 | **Read General Settings page (`0x9000`).** |
| `0x17` | `0x1704` | **Erases `0x9000`** | Flash `0x00009000`, max `1`, State 2 | Write General Settings (`0x00004540` ignores `buf[2..3]` profile index). |
| `0x18` | `0x1804` | Clears `hid_ctx[5]` bit 6 (`0x40`) | Stays State 0 | Enable custom keymap & macro interception (`FUN_00003412`). |
| `0x19` | `0x1904` | Sets `hid_ctx[5]` bit 6 (`0x40`) | Stays State 0 | Bypass custom keymap & macro interception. |
| `0x20` | `0x2004` | Sets `hid_ctx[4] = 0x32` | `hid_ctx[2] = 1`, State 2 (`FUN_00001924`) | Live per-key RGB streaming. |
| `0x22` | `0x2204` | Valid (`1`) | Flash `0x00009C00`, max `9`, `count=chunks+1`, State 1 | Read Saved Custom RGB Table (576 B = 9×64 B). |
| `0x23` | `0x2304` | **Erases `0x9C00`** | Flash `0x00009C00`, max `9`, State 2 | Write Custom RGB Table (`0x0000CBBA` checks `(word & 0xFF) == slot_idx` only). |
| `0x26` | `0x2604` | Valid (`1`) | Flash `0x0000AC00`, max `9`, `count=chunks+1`, State 1 | Read Fn-Layer Keymap. |
| `0x27` | `0x2704` | **Erases `0xAC00`** | Flash `0x0000AC00`, max `9`, State 2 | Write Fn-Layer Keymap (`FUN_0000275c` checks `0x55AA0000` at `0xAE3C`). |
| `0x28` | `0x2804` | Valid (`1`) | State 6 (`0x00003CFC`) | RTC Write (`buf[2] == 0x5A`, `buf[3..8] = yy mm dd HH MM SS`). |
| `0x38` | `0x3804` | Valid (`1`) | SPI `0x00000000`, State 5 (`0x00003D54`) | **DANGEROUS / EXCLUDED:** Full external SPI flash overwrite (factory TFT assets). See §9. |
| `0x72` | `0x7204` | Valid (`1`) | SPI `0x00750000`, State 5 (`0x00003D54`) | User Screen Image / GIF upload (`0x000045D4` ignores `buf[2]`). |
| `0xAB` | `0xAB04` | Valid (`1`) | State 4 (`0x00003E32`) | 1-packet sink → State 3. |
| `0xE0` | `0xE004` | Valid (`1`) | Stays State 0 | No-op / Ping. |
| `0xF0` | `0xF004` | Calls `FUN_0000df18()`, clears `hid_ctx[9] = 0` | Stays State 0 | Finalize: saves runtime config snapshot to internal flash `0x8000`. |
| `0xF1–0xF3` | `0xF104–0xF304` | Valid (`1`) | Stays State 0 | Reserved no-ops (`0xF4` returns `0xFF`). |
| `0xF5` | `0xF504` | **Clears `usb_flags` bit 1 (`0x000042FA`)** | `hid_ctx[10] = 1`, `count=chunks`, State 1 | **Read Live RGB RAM** (`0x20001838`/`195E`/`1A84`; commit checksum `0`). Wire bytes `04 F5` (note: previously miswritten as `0x04F5` in Python). |
| `0xF6` | `0xF604` | Copies `*(uint8_t*)0x200000F8` → `buf[4]` (`0x0000431C`) | Stays State 0 | **Battery Level Query (`0..5`)**: `0=<6%`, `1=6–25%`, `2=26–50%`, `3=51–75%`, `4=76–95%`, `5=96–100%`. |

### Stale Bit-1 Auto-Preload vs. Clean Bit-1 Read Behavior (`0x00004330` / `FUN_0000407a`)

- **Stale bit-1 auto-preload (`0x05`, `0x10`, `0x12`, `0x14`, `0x16`, `0x22`, `0x26`):** Any prior `GET_REPORT` in State 0 with `hid_ctx[5] & 0x10 == 0` (e.g., `wait_until_idle()`, `0x1804 + GET`, or `0xF604 + GET`) leaves `usb_flags` (`0x2000003C`) bit 1 set (`0x00004386`). When a flash-read `SET_REPORT` arrives, Phase 1 (`0x00004354`) clears only bit 0 (`bics r2, r6`). On the next main-loop tick (~0.1 ms), State 0 (`0x00004380`) sees stale bit 1 == `1`, enters State 1 **without clearing bit 1** (`count = chunks + 1`), and on the following tick `FUN_0000407a` preloads chunk 0 into `hid_buf` (`0x2000135C`) and clears bit 1. Consequently, the host's **first `GET_REPORT`** returns chunk 0 directly (hardware-verified on `0x0504`!).
- **Clean bit-1 path:** Immediately after a completed `0x0204` commit + `GET_REPORT`, `0x00003EA6` clears `usb_flags = 0`, so the next flash read returns `[04, cmd_hi, 00, 01, ...]` on `GET` #1 and chunk 0 on `GET` #2. `0xF504` (`0x000042FA`) is the only read opcode that explicitly clears `usb_flags` bit 1 in Phase 1, always taking the clean path.
- **Trailing preload checksum (`count = chunks + 1`):** All 7 flash-read opcodes set `count = chunks + 1`, so the final `GET_REPORT` causes `FUN_0000407a` to also preload and sum one trailing 64 B flash block (e.g., `0x8FC0–0x8FFF` or `0x9840–0x987F`). Commit checksum `resp[4..7]` therefore lies in `[sum(chunks), sum(chunks) + 64 * 0xFF]`. (`0xF504` uses `count = chunks` and does not sum into `hid_ctx+0x10`, returning checksum `0`.)

### Commit Checksums & General Settings Bitfields (`0x1704` / `0x1604`)

- **32-bit LE Commit Checksums (`0x00003E74–0x00003E82`):** `0x0204` commit returns the full 32-bit little-endian sum in `resp[4..7]` (over all 64 written bytes on single-page `0x1704`/`0x1304` writes, all 576 bytes on `0x2304`, or read+trailing flash bytes on State 1 reads).
- **General Settings (`0x1704` write / `0x1604` read, flash `0x00009000`):** Verified from `FUN_00003f42` → `FUN_00003412` / `FUN_000046d0` / `FUN_00003a08`:
  - `payload[0..1]`: `00 01`
  - `payload[2]`: **Disable `Alt+Tab`** (`1` = blocked; packed into `0x200000BD`)
  - `payload[3]`: **Disable `Alt+F4`** (`1` = blocked; packed into `0x200000BD`)
  - `payload[4]`: **Win-Lock** when `*(uint8_t*)0x2000004D == 0` (`1` = locked; packed into `0x200000BD`)
  - `payload[5]`: `fn_switch` (`0` = hold Fn, `1` = sticky Fn toggle at `0x200000C3`)
  - `payload[6]`: `sleep_time` (`0` = off, `1` = 1 min / `600`, `2` = 5 min / `3000`, `3` = 30 min / `18000` in 100 ms ticks)
  - `payload[7]`: `0` (unused)
  - `payload[8]`: `key_response_time` (debounce scan threshold: `1`→2, `2`/default→3, `3`→7, `4`→10, `5`→14)
  - `payload[62..63]`: `AA 55`
  - Only **one** `0x1704` write pass is needed (`0x00004540` ignores `buf[2..3]` profile index and always writes `0x00009000`).

**Status-byte semantics:** `resp[3] == 0x01` = well-formed/accepted; `0xFF` = rejected/busy; all-zeros during commit polling can occur transiently during flash housekeeping (especially on RTC / lighting / custom table commits).

## 3. Lighting effects (0x1304 page)

Write payload (64 bytes): `[effect, r, g, b, 0,0,0,0, option, brightness, speed,
direction, 0,0, aa, 55]`. Effects `0x00–0x13`: off, static, single_on, single_off,
glittering, fluttering, colourful, breath, spectrum, outward, scrolling, rolling,
rotating, explode, launch, ripples, flowing, pulsating, tilt, shuttle. Verified
against per-effect captures.

Quirks:
- **Effect byte `0x00` reloads the stored config from flash** — the board re-runs the
  saved effect. It is NOT "custom mode".
- Effect byte `0x14` is rejected by the dispatcher (not `< 0x14`) — a silent no-op.
- Internal mode `0x14` (= factory default, "custom light") is selected by host bytes
  `0x00`/`0x80` per the firmware's command-5 mapping, but see the note above — from
  the USB side, `0x00` behaves as reload-stored.

### Effect IDs and Modifiers

| Decimal | Hex | Effect Name | Notes (Direction / Option Flags) |
| :--- | :--- | :--- | :--- |
| 0 | `0x00` | LedOff | Requires pure `00` payload |
| 1 | `0x01` | Static | |
| 2 | `0x02` | SingleOn | |
| 3 | `0x03` | SingleOff | |
| 4 | `0x04` | Glittering | |
| 5 | `0x05` | Fluttering | |
| 6 | `0x06` | Colourful | |
| 7 | `0x07` | Breath | |
| 8 | `0x08` | Spectrum | |
| 9 | `0x09` | Outward | |
| 10 | `0x0A` | Scrolling | **Directions:** `00` = Down, `02` = Up |
| 11 | `0x0B` | Rolling | **Directions:** `00` = Right, `01` = Left |
| 12 | `0x0C` | Rotating | **Directions:** `00` = Right, `01` = Left |
| 13 | `0x0D` | Explode | |
| 14 | `0x0E` | Launch | |
| 15 | `0x0F` | Ripples | |
| 16 | `0x10` | Flowing | **Directions:** `00` = Right, `01` = Left |
| 17 | `0x11` | Pulsating | |
| 18 | `0x12` | Tilt | **Directions:** `00` = Right, `01` = Left |
| 19 | `0x13` | Shuttle | |

**Direction & Option Flags:**
- **`direction` (byte 11):** `0x00` = Right/Down, `0x01` = Left, `0x02` = Up. The visual axis (horizontal vs. vertical) depends on the chosen effect.
- **`option` (byte 8):** The "Hardware Multi-color" flag. Setting `0x01` overrides the provided RGB values and tells the MCU to generate multi-colored animations. 
  - *Hardware quirk:* The visual result depends entirely on how the MCU's firmware implemented the effect. For example, `Static` (`0x01`) becomes a fixed rainbow gradient, `SingleOff` (`0x03`) assigns random colors to individual keys, and effects that are natively rainbow like `Colourful` (`0x06`) simply ignore the byte. `0x00` forces the preset to strictly use the provided RGB bytes.

### Physical RGB Zones, Underglow (`0x1304` `0x20–0x24`) & Flash `0x9800` Erase Quirk

All LEDs share the single RGB RAM arrays (`0x20001838` R, `0x2000195E` G, `0x20001A84` B, clocked out by IRQ19 `FUN_0000648c`), split into **3 independent logical zones**:

1. **Main Keys (82 physical keys):** Controlled by `0x1304` (`0x00–0x13`, `0x80`), `0x2304`, `0x2004`, and `Fn` main-lighting hotkeys.
2. **Row-6 Side / Underglow (14 LEDs, indices `0x7E–0x8B`):** Runtime struct at `0x20000194`, rendered by `FUN_0000e1fc` (`0x0000E0B8–0x0000E440`). Controlled via **`Fn + Right Shift`** (cycle mode `0..4`), **`Fn + /?`** (cycle preset color), and **USB `0x1304` `payload[0] = 0x20 + mode`** (`0`=flowing, `1`=spectrum, `2`=static, `3`=breathing, `4`=off). `FUN_00003f42` (`0x00003F82`) reads **only `payload[0]`** (RGB/brightness/speed bytes are ignored for `0x20–0x24`). Hardware-verified (`--mode 4` / `--mode 0`).
3. **Row-5 Accent Bar (5 LEDs, indices `0x6C, 0x6D, 0x6E, 0x70, 0x71`, Home/End strip):** Runtime state at `0x200001DC`. Controlled **only by `Fn + Z`** — **no USB HID command exists** in `s75pro_fw_v1.03.bin`.

**`0x1304` `0x20–0x24` `0x9800` Erase Bug & Save-and-Restore Workaround:**
- Phase 1 (`0x00004290`) unconditionally erases flash page `0x00009800` to `0xFF` before Phase 2/State 2 sees `payload[0]`, and `FUN_00003f42` (`0x00003F82`) skips writing `0x9800` for `0x20–0x24` (`hid_ctx[8] = 1`).
- Side effect: `local_10` still holds `0x00004645` (`0x45+0x46 = 0x8B`) and `0x9804..0x983F` reads 60 erased `0xFF` bytes (`60 * 0xFF = 0x3BC4`), producing deterministic commit checksum **`0x00003C4F`** (hardware-verified).
- On reboot (`0x0000DB48–0x0000DB8E`), if main lighting was set via USB (`flash[0x8002] == 0xFF`), `0x0000DB86` calls `FUN_00003eae()`, which exits early on erased `0x9800` and fails to restore USB lighting.
- **Workaround:** Before sending `0x1304` `0x20–0x24`, read `0x9800` via `0x1204`; after `0xF004` finalize, if the saved snapshot was populated (neither all `0xFF` nor all `0x00`), rewrite it via `0x1304` + commit + `0xF004`.

## 4. Streaming (0x2004) — the live per-key path — VERIFIED

This is the dynamic RGB path used by the driver's "music rhythm" mode.
Frames are pushed in full, repeatedly; the MCU renders the RAM tables as-is. No mode
entry, no handshake — it renders from **any** board state, even on top of running
hardware animations.

### Per-frame sequence (order and timing both matter)

```
1. SET  04 20 00 00 00 00 00 00 08            (frame header; payload[8] = 8 for RGB,
                                                3 for non-RGB keyboards)
2. wait ~6-10 ms, then GET_REPORT              (*** REQUIRED — see discoveries ***)
3. SET  8 x 64-byte raw reports, ~2-3.3 ms apart:
        each = 16 x [light_index, R, G, B]    (key slot order = rgb-keyboard.xml
        DOCUMENT ORDER; pad with zeros to fill 128 slots / 8 packets)
4. SET  04 02 00 …                            (commit)
5. wait ~6-10 ms, then GET_REPORT              (*** REQUIRED ***)
```

Early versions inserted an extra all-zero report between the last chunk and
the commit; it is tolerated by the firmware but does not appear in captures.
Removed 2026-09-29 after an isolation test confirmed rendering is unaffected.

The two GETs are **mandatory handshakes**, not status polls: the identical byte
sequence without them renders nothing in any board state (fresh power-cycle included);
with them it renders reliably. A feature GET returns the device's current report
buffer immediately — the wait is MCU processing time, not I/O, so do not replace the
sleep with a "blocking read".

Re-confirmed by negative test (2026-09-28): a stripped sequence (no GETs, no zero report, no chunk delays) rendered nothing even in a warm session immediately after full handshake frames had been running — the GETs are per-frame mandatory, not session priming.

### Key layout

80 keys; slot i of the frame corresponds to the i-th `<key>` in `rgb-keyboard.xml`
(document order), addressed by its `light_index`. (Sorting by `light_index` also works
for this board since key_index == light_index in the XML, but document order is what
the wire format specifies.)

### Timing reference (measured)

| quantity | observed floor | official driver | shipped default |
|---|---|---|---|
| header/commit -> GET | ≤ 3 ms | ~6 ms | **10 ms** (margin over both) |
| chunk -> chunk | ≤ 1-2 ms (load-tested) | ~3.2 ms | **2 ms** |
| full frame | — | ~60 ms (~8-21 fps, beat-driven) | ~36 ms (~28 fps) |

~15-20 fps is perceptually smooth for lighting; 20-30 fps for reactive effects.
Event-type effects (alerts) care about latency (<100-200 ms), not rate.

### Do not remove the GET handshakes — hardware-proven
The two GET_REPORT polls in the 0x2004 frame sequence look like status
polling and have repeatedly been misread as removable latency (including by
code-review tools). They are not. Negative test, 2026-09-28: a stripped
sequence (no GETs, no zero report, no chunk delays) rendered NOTHING, in a
warm session immediately after full handshake frames had been running.
Earlier replay attempts without GETs also rendered nothing in any board
state. Streaming works at ~28 fps with them and at 0 fps without. If a
suggestion proposes removing them or replacing the sleep+GET with a blocking
read, it is wrong — treat it as a known trap.

## 5. Custom-light table (0x2304) — the "save" path — VERIFIED

Writes the per-key custom lighting table to non-volatile flash. This is slow, wears
flash, and re-applies with a visible reload. Use it for static layouts only; never for
dynamic effects (use 0x2004 streaming instead).

Verified against `escToRed.pcapng` and `DeviceDriver.exe.c` (`FUN_0044b7f0`, `FUN_0044b900`, `FUN_0044edb0`).

### Full Application Sequence (Two Back-to-Back Transactions)

The official driver does not upload the table in isolation; it applies custom lighting
in two distinct transactions, and executes this entire two-transaction sequence **twice**
to ensure the MCU animation pointers and flash buffers latch cleanly:

```
[Transaction A: Select Mode 0x80]
1. SET 04 18 ...                       (open / 0x1804)
2. SET 04 13 00 00 00 00 00 00 01 ...  (probe lighting page 0x1304)
3. SET 80 00 00 00 00 00 00 00 00 05 00 00 00 00 aa 55 (mode 0x80 = custom light, brightness 5)
4. SET 04 02 ...                       (commit / 0x0204)
5. SET 04 f0 ...                       (finalize / 0xF004)

[Transaction B: Upload 576-byte Custom Table]
6. SET 04 18 ...                       (open / 0x1804)
7. SET 04 23 00 00 00 00 00 00 09 ...  (probe custom-light table page, payload[8]=9 for RGB, 3 for mono)
8. SET 9 x 64-byte raw chunks (~35 ms apart, no 0x0100 wrapper):
       each = 16 x [light_index, R, G, B]
       chunk 9 ends with AA 55 trailer at bytes 62-63
9. SET 04 02 ...                       (commit / 0x0204)
10. wait ~35 ms, then GET_REPORT       (commit ACK: status 0x01 + 16-bit table checksum)
11. wait ~35 ms, then SET 04 f0 ...    (finalize / 0xF004)
```

### Table Structure & Chunking
* **Total size**: 576 bytes (`0x240`), transferred as 9 consecutive 64-byte feature reports
  ($9 \times 64 = 576$). (Non-RGB mono keyboards use 192 bytes / 3 chunks with probe parameter `0x03`).
* **No `0x0100` page header**: Unlike general settings or RTC sync, custom table chunks
  are **raw streams** of 16-entry `[light_index, R, G, B]` records ($16 \times 4 = 64$ bytes
  per report) without a report command prefix.
* **Buffer Slot Layout**: Each key is placed at fixed byte offset $\text{light\_index} \times 4$
  in the 576-byte buffer:
  * Offset $\text{light\_index} \times 4 + 0$: `light_index`
  * Offset $\text{light\_index} \times 4 + 1$: `Red` (0–255)
  * Offset $\text{light\_index} \times 4 + 2$: `Green` (0–255)
  * Offset $\text{light\_index} \times 4 + 3$: `Blue` (0–255)
  * Offset 0–3 is `00 00 00 00` (unused key index 0).
  * Example: Esc (`light_index=1`) is located at offset 4: `01 FF 00 00` for Red.
* **Slot Capacity**: 144 slots total ($9 \times 16$). Slots beyond the keyboard's physical
  keys (indices 80–143) are zero-filled padding.

### Trailer Location
* The trailer `AA 55` is located at **bytes 62 and 63 of Chunk 9** (byte offsets 574 and 575
  of the 576-byte buffer).
* It replaces the last 2 bytes of the final padding slot (slot 143), terminating the table write.

### Commit Handshake & 32-bit Table Checksum
* ~35 ms after sending `04 02` (Commit), the host issues a `GET_REPORT`.
* The MCU echoes:
  `04 02 00 01 <sum_b0> <sum_b1> <sum_b2> <sum_b3> ...`
  * `resp[0:2] = 04 02`: Command echo.
  * `resp[3] = 0x01`: Well-formed transaction indicator.
  * `resp[4..7]`: **32-bit little-endian sum of all 576 bytes** (`0x00003E74–0x00003E82`, $\sum_{i=0}^{575} \text{byte}_i \pmod{2^{32}}$).
    * Note: For `0x2304`, firmware reader `0x0000CBBA` only checks `(word & 0xFF) == slot_idx` and never checks `AA 55` (unlike keymaps `0x1104`/`0x2704`, where `FUN_0000275c` checks `0x55AA0000` at `0x963C`/`0xAE3C`). Keeping `AA 55` at offsets 574–575 remains harmless and matches vendor captures.
    * Verified against `escToRed.pcapng`: Esc=Red returned `0x12D9` (sum = 4,825); Esc=Off returned `0x11DA` (sum = 4,570). Tables whose byte sum exceeds `0xFFFF` use bytes `resp[6..7]` as well.
* Host sends `04 f0` (Finalize) ~35 ms after the commit ACK.


## 6. RTC sync (0x2804 page) — VERIFIED

`04 18` -> `04 28 00 00 00 00 00 00 01` -> `00 01 5a yy mm dd HH MM SS 00 wd … aa 55`
-> `04 02`. State 6 (`0x00003CFC`) only validates `buf[2] == 0x5A` and copies `buf[3..8]` (`[yy, mm, dd, HH, MM, SS]`) into `0x20000224[0, 1, 3, 4, 5, 6]`; `buf[0..1]`, `weekday`, and `AA 55` are ignored by firmware.

## 7. TFT Screen Upload (`0x7204`, Interface 2 `EP 3 OUT` / `EP 0x84 IN`) — FIRMWARE-VERIFIED

- **Upload handshake:** `04 18` (open) → `04 72 <mode> ... <chunks_le16 at 8..9>` (probe; `0x000045D4` ignores `buf[2]`, always sets external SPI base = `0x00750000`, and determines still vs. animated solely from `N_frames` at `0x750000`) → `chunks` × 4096 B packets on `EP 0x03 OUT` (each ACKed by `01 5A 02 ...` on `EP 0x84 IN`) → `04 02` commit.
- **Delay unit = `2 ms` per tick (clock-tree proven):** `FUN_00013bfa` (PLL = 48 MHz) → `FUN_00006f8c` (SysTick `RVR = 23999` → 0.5 ms) → `FUN_000008e2` (`pbVar2[2] = 2 ms`) → `FUN_00011a84` (GIF hold scheduler). Valid wire range is **`0x10–0xFF` (`32–510 ms`)**; `FUN_00011a84` silently replaces any value `< 0x10` with `0x19` (`50 ms`).
- **Hard frame limit = `191` frames (`0xC0 - 1`):** `FUN_00010460(0x750000)` calls `FUN_00007882(0x750000, 0xC0)`, copying only `192` bytes (`0xC0`) into RAM `0x200021DA` (`N_frames` + 191 delay slots). Uploading `192–254` frames overflows past `0x20002299` into live fuel-gauge RAM at `0x200022A0+`. Flash pixel data still starts at `0x00750100` (256-byte flash preamble, stride `64,800` bytes).

## 8. Hard-won discoveries (read before modifying the code)

1. **The GETs gate the frame.** Treated as mandatory handshakes in `0x2004` streaming (`0x00004380` transitions Phase 2 only on `GET_REPORT`).
2. **Ghidra's auto-analysis misses Keil `switch8` jump-table functions** (such as `0x000041E0`, `0x00004330`, `0x00003CFC–0x00003EAE`, and `0x0000DB44–0x0000DB8E`); direct Thumb disassembly recovered all missing dispatchers.
3. **The in-firmware consumer of `0x2004` frames IS located:** `FUN_00001924` (EP0 `SET_REPORT` ISR consumer when `hid_ctx[0] == 2` and `hid_ctx[2] != 0`) maps 16×`[light_index, R, G, B]` entries through `0x00014D2C` directly into live RGB RAM (`0x20001838` R, `0x2000195E` G, `0x20001A84` B).

## 9. Provenance & Explicit Safety Exclusions

### Provenance
- `musicRGB.pcapng` / `musicRGB2.pcapng`, `escToRed.pcapng`, `UserLightning-singleKeyChange.pcapng`, `Static.pcapng`, `SideLightsRed.pcapng`.
- `DeviceDriver.exe.c` & `s75pro_fw_v1.03.bin` (SHA-256 `7ef0d72f267621beef543a8068602db253872a5a2a0291e4ccdb1a651e669e22`, base `0x00000000`; see [`FIRMWARE_AUDIT.md`](FIRMWARE_AUDIT.md)).

### Explicit Safety Exclusions (DO NOT IMPLEMENT OR EXPOSE)
- **Opcode `0x3804` (`04 38`, `0x0000459E` → State 5):** Writes `EP 3 OUT` 4096 B chunks to external SPI flash starting at **`0x00000000`**, overwriting factory TFT splash screens, menus, icons, and language tables (`0x00172444`, `0x00182164`, `0x00236B3C`).
- **EP0 ISP Bootloader Magic (`AA 42 89 5A FF 71 62 CC` → `FUN_00001924` / `FUN_0000187e` → `FUN_0000014c()`):** Immediately disables interrupts/peripherals and jumps into the MCU ROM ISP bootloader; malformed writes can brick the keyboard.
- **Safe idioms:** `0x2004` streaming writes RAM only (zero flash wear); keep flash-writing commands (`0x11`, `0x13`, `0x15`, `0x17`, `0x23`, `0x27`) for occasional config updates and `0x7204` (`0x00750000` only) within the `191`-frame / `32–510 ms` bounds.
