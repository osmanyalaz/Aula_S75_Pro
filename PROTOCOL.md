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
| `00 01 <body> … aa 55` | 0x0100 | page write (trailer `AA 55` on the 64-byte buffer) |
| `04 02` | 0x0204 | commit |
| `04 f0` | 0xF004 | finalize (ends custom-table apply transactions) |
| `04 f5` | 0x04F5 | read current table back (`payload[8]=9` for RGB) |

Settings transactions use ~36 ms per step (the driver's `cmd_delaytime=35` from
`config.xml`). ACKs/status arrive via GET_REPORT: the device echoes the command word
with a status-style byte (`… 00 01 …` = OK in most captures).

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
4. SET  one all-zero 64-byte report
5. SET  04 02 00 …                            (commit)
6. wait ~6-10 ms, then GET_REPORT              (*** REQUIRED ***)
```

The two GETs are **mandatory handshakes**, not status polls: the identical byte
sequence without them renders nothing in any board state (fresh power-cycle included);
with them it renders reliably. A feature GET returns the device's current report
buffer immediately — the wait is MCU processing time, not I/O, so do not replace the
sleep with a "blocking read".

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

## 5. Custom-light table (0x2304) — the "save" path

`04 18` -> `04 23 … 09` -> table (`[idx,r,g,b]` entries, `AA 55` trailer, 576 bytes
total for RGB) -> `04 02` -> `04 f0`. This **writes the stored config (flash)** —
slow, wears flash, and re-applies with a visible reload. Use it for static layouts
only; never for dynamic content (that's what 0x2004 is for).

## 6. RTC sync (0x2804 page) — VERIFIED

`04 18` -> `04 28 00 00 00 00 01` -> `00 01 5a yy mm dd HH MM SS 00 wd … aa 55`
-> `04 02`. Body decodes as `[0x5A, year-2000, month, day, hour, minute, second,
0x00, weekday(Sun=0)]`. The driver's UI syncs the keyboard clock with this whenever a
page is opened. Note: the commit status byte does NOT mean accepted/rejected here —
the clock applies even when it reads 0.

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
  `FUN_00427f60`/`FUN_004328c0`; effect apply `FUN_00434980`; capability flag `0x7ac`
  = XML `rgb_keyboard`).
- `s75pro_fw_v1.03.bin` — keyboard MCU firmware (Sonix); the running firmware is
  byte-identical to a file distributed as "1.20" (regional naming).

## 9. Safety notes

- Streaming writes RAM only — no flash wear; safe for 24/7 use.
- The 0x2304 save path writes flash; keep it for occasional static layouts.
- Avoid full-brightness strobing in the 5-20 Hz range (photosensitivity); breathing
  (period >= 1 s) is the safe idiom for alerts.
