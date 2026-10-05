# AULA S75 Pro — USB RGB Protocol (reverse-engineered)

Reverse-engineered control protocol for the AULA S75 Pro (VID `0x0C45`, PID `0x800A`,
wired USB mode). Built from Wireshark/usbmon captures of the official Windows driver
(running under Wine), the driver's Ghidra decompilation, the keyboard MCU firmware
(v1.03). Everything in the "verified"
sections was confirmed on real hardware unless marked otherwise.

## 1. Transport

All control reports are 64-byte HID **feature reports** on **interface 3**
(usage page `0xFF13`, usage `0x0001`):

```
bmRequestType 0x21 | bRequest 0x09 (SET_REPORT) | wValue 0x0300 | wIndex 0x0003 | 64 bytes
```

Report ID 0; the 64-byte payload follows. hidapi: `send_feature_report(b"\x00" + payload)`.
Interface 0 also answers some commands, but interface 3 is the vendor interface the
official software use it.

## 2. Transaction model (page probes)

Most operations follow: **open -> page-probe -> payload-write -> commit -> (finalize)**.
The probe selects which page a following `00 01` write lands on:

| Report prefix | Command | Purpose |
|---|---|---|
| `04 18` | 0x1804 | open / begin transaction |
| `04 13` | 0x1304 | probe: lighting/settings page |
| `04 23` | 0x2304 | probe: custom-light table page (`payload[8]=9` for RGB keyboards) |
| `04 28` | 0x2804 | probe: RTC page |
| `00 01 <body> … aa 55` | 0x0100 | single-page write (settings, RTC; trailer `AA 55` on 64-byte buffer) |
| raw 64-byte chunks | — | multi-chunk table upload (0x2304 custom table: 9 raw 64-byte chunks) |
| `04 02` | 0x0204 | commit |
| `04 f0` | 0xF004 | finalize (ends custom-table and lighting apply transactions) |
| `04 f5` | 0x04F5 | read current table back (`payload[8]=9` for RGB) |

Settings transactions use ~36 ms per step (the driver's `cmd_delaytime=35` from
`config.xml`). ACKs/status arrive via GET_REPORT: the device echoes the command word
with a status-style byte (`… 00 01 …` = OK in most captures).

**Status-byte semantics (refined 2026-09-29, RTC page, likely general):** the
status-style byte is a *well-formedness* indicator, not an apply
acknowledgement. `0x01` = the transaction was well-formed (probe parameter at
payload[8], body where the page expects it). `0x00` — or an all-zeros status
buffer — means malformed/unparsed, and crucially **never means "rejected":
the preceding write may still have applied.** Verify by effect, not by
status. Evidence: the RTC page accepts any timestamp including years in the
past (a 2020 date visibly set the clock); lighting writes whose commit read
`0x00` were later found to have applied anyway. An all-zeros status buffer
during commit polling has also been seen when the MCU was busy with flash
housekeeping — patience and retry, not abandonment.

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

### Commit Handshake & 16-bit Table Checksum
* ~35 ms after sending `04 02` (Commit), the host issues a `GET_REPORT`.
* The MCU echoes:
  `04 02 00 01 <checksum_lo> <checksum_hi> 00 00 ...`
  * `resp[0:2] = 04 02`: Command echo.
  * `resp[3] = 0x01`: Well-formed transaction indicator.
  * `resp[4:6]`: **16-bit little-endian sum of all 576 bytes** in the uploaded table
    ($\sum_{i=0}^{575} \text{byte}_i \pmod{65536}$).
    * Verified against `escToRed.pcapng`: Esc=Red returned `0x12D9` (sum = 4,825); Esc=Off
      returned `0x11DA` (sum = 4,570, exactly $0x12D9 - 0xFF$).
* Host sends `04 f0` (Finalize) ~35 ms after the commit ACK.


## 6. RTC sync (0x2804 page) — VERIFIED

`04 18` -> `04 28 00 00 00 00 01` -> `00 01 5a yy mm dd HH MM SS 00 wd … aa 55`
-> `04 02`. Body decodes as `[0x5A, year-2000, month, day, hour, minute, second,
0x00, weekday(Sun=0)]`. The driver's UI syncs the keyboard clock with this whenever a
page is opened. Note: ~~the commit status byte does NOT mean accepted/rejected here —
the clock applies even when it reads 0.~~

Note (revised 2026-09-29): the commit status byte is a well-formedness
indicator, not accepted/rejected. With the corrected page probe
(`04 28 00 00 00 00 00 00 01` — parameter at payload[8], like every other
page probe) the status reads `0x01`. The old `04 28 00 00 00 00 01`
(parameter at payload[6]) produced `0x00` while the write still applied — a
malformed-transaction signal, not a rejection. Stale timestamps are accepted
unconditionally (verified: 2020-01-01 visibly set the clock), so freshness
is the host's job.

## 7. Hard-won discoveries (read before modifying the code)

1. **The GETs gate the frame.** Discovered after a week of failed replays; every
   analysis pass (frame format, interfaces, cadence, modes) was correct — the missing
   piece was treating the driver's status polls as part of the frame.
2. **Ghidra's auto-analysis misses Keil `switch8` jump-table functions** (the mode/arm
   dispatchers and several table writers are absent from the exported `.c`). If a
   function seems missing, search the raw binary (function-start patterns, or the
   byte-tables the switches index) rather than trusting the decompile.
3. The **in-firmware consumer of 0x2004 frames was never located by static analysis**
   (likely ROM-resident or in un-decompiled code). The per-frame sequence in section 4
   is hardware-verified end-to-end; treat it as the specification.

## 8. Provenance

- `musicRGB.pcapng` / `musicRGB2.pcapng` — official driver streaming (device 58 / 26).
- `escToRed.pcapng`, `UserLightning-singleKeyChange.pcapng` — custom-light apply.
- `Static.pcapng` + `effects/*.pcapng` (20 effect captures) — lighting writes & readback.
- `DeviceDriver.exe.c` — Ghidra decompile of the official software (frame senders
  `FUN_00427f60`/`FUN_004328c0`; effect apply `FUN_00434980`; custom light mode apply
  `FUN_0044b7f0`; custom light table builder & sender `FUN_0044b900`/`FUN_0044edb0`;
  capability flag `0x7ac` = XML `rgb_keyboard`).
- `s75pro_fw_v1.03.bin` — keyboard MCU firmware (Sonix); the running firmware is
  byte-identical to a file distributed as "1.20" (regional naming).

## 9. Safety notes

- Streaming writes RAM only — no flash wear; safe for 24/7 use.
- The 0x2304 save path writes flash; keep it for occasional static layouts.
- Avoid full-brightness strobing in the 5-20 Hz range (photosensitivity); breathing
  (period >= 1 s) is the safe idiom for alerts.
