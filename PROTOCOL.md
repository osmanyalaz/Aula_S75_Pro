# AULA S75Pro — Protocol Notes

Built from: `config.xml`, `rgb-keyboard.xml`, `decomiledFromExe.txt` (Ghidra decompile of
the Windows driver), and two tshark captures (`KeyResponseTimeLogs.txt`, `TimeToSleepLogs.txt`).

## 1. Transport

| Item | Value |
|---|---|
| VID | `0x0C45` |
| PID (wired USB) | `0x800A`, HID interface `MI_00` (interface 0) |
| PID (2.4G dongle) | `0xFEFE`, HID interface `MI_03` (interface 3) |
| Report type | **Feature Report**, Report ID `0x00` |
| Report size | 64 bytes of payload (`wLength = 0x40`) |
| Write | `SET_REPORT`: bmRequestType `0x21`, bRequest `0x09`, wValue `0x0300`, wIndex=interface |
| Read | `GET_REPORT`: bmRequestType `0xA1`, bRequest `0x01`, same wValue/wIndex/wLength |

Confirmed directly from the two provided pcaps (control transfer setup packets `09 00 03
03 00 40 00 ...` = bRequest=SET_REPORT(9), wValue=0x0300, wIndex=0x0003, wLength=0x0040).

Every 64-byte payload begins with a **little-endian 16-bit command word**
(`byte[0]` = low byte, `byte[1]` = high byte). E.g. command `0x1804` is transmitted
as bytes `04 18 ...`.

## 2. The write/commit pattern

Nearly every settings-writing function in the decompiled driver follows the same shape:

```
SET  cmd 0x1804                       -- "open" / begin
GET  (ack, echoes similar data)
SET  cmd 0x1704  body=[01 00 00 00 00 01]   -- fixed probe/ack (always this exact body)
GET  (ack)
SET  cmd <the actual data for this feature>
SET  cmd 0x0204                       -- commit / select page for read-back
GET  <page 0x0204 response - used to confirm the write>
[SET cmd 0xF004]                      -- "finalize", seen on some (bulkier) writes
```

This was verified byte-for-byte for the "general settings" write (see §3). The
lighting/macro functions in the decompile follow the same skeleton but with a
different payload in the middle (see §4, unverified).

## 3. VERIFIED: General settings write (fn-switch / sleep-timer / key-response-time)

Decompiled source: `FUN_004141a0` (matches `<function fn_layer="1" sleep_time="1"
key_respondtime="1" />` in `rgb-keyboard.xml` — this is the settings panel with those
three controls).

Command `0x0100` payload layout (all offsets are payload-byte indices, 0-based):

| Byte(s) | Meaning | Observed in captures |
|---|---|---|
| 0-1 | command word `0x0100` (LE: `00 01`) | always `00 01` |
| 2 | "fn layer" checkbox enabled (0/1) | always `0` |
| 3 | "sleep timer" checkbox enabled (0/1) | always `0` |
| 4 | "key response" checkbox enabled (0/1) | always `0` |
| 5 | fn_switch value | always `0` in both logs (untouched) |
| 6 | sleep_time value | varies: `1`, `2`, `3` — dropdown confirmed as Never=`0`, 1 min=`1`, 5 min=`2`, (30 min=`3`, unconfirmed) |
| 7 | *(unused/padding)* | always `0` |
| 8 | key_response_time value | varies: `1`, `2`, `3` |
| 9-61 | padding | `0` |
| 62-63 | trailer `0xAA 0x55` | always present |

The 3 "checkbox enabled" bytes never got set to 1 in either capture (the user never
toggled those specific checkboxes while testing the sliders/dropdowns), so we can't
100% confirm they're required — captures show the write succeeds with them at 0.

### Per-profile writes

The device stores these settings **per profile** (0 = wired, 1 = wireless) — the
`0x1704` probe's 2nd byte is a profile selector. To make a setting stick
regardless of which mode the keyboard is currently in, the whole
open→probe→write→commit sequence must be repeated once per profile.
`write_general_settings()` does this automatically (loops `profile_index in (0, 1)`).

### What we could NOT fully pin down

After the commit (`0x0204`), the device responds with a report whose **byte 4** was,
in *every single one* of the 6 capture sessions across both files, exactly equal to:

```
response[4] == (fn_switch_value + sleep_time_value + key_response_time_value) & 0xFF
```

This held even when the individual `sleep_time`/`key_response_time` values sent were
identical between two sessions but arrived at the same sum via different splits. That
strongly suggests **this response byte is a write-acknowledgement checksum**, not a
literal echo of "the key response time," so it should not be read as a settings query.
The tool's `write_general_settings(verify=True)` uses this as a sanity check.

We could **not** determine the human-meaning of the raw level values (e.g. does
`key_response_time=3` mean "3 ms", "level 3 of N", or something else) — the official
driver UI wasn't available to us, only the raw wire traffic. Cross-check the actual
slider/dropdown positions in your AULA driver against what gets sent (use
`raw-get`/Wireshark side-by-side) to build your own value table.

## 4. INFERRED / UNVERIFIED: Per-key custom lighting

No lighting traffic was captured (the two provided logs only cover the settings
above), so this section is built purely from reading the decompiled code
(`FUN_0044b900` write / `FUN_0042adb0` read) and should be treated as a hypothesis,
not fact:

- Write command family `0x23xx`, e.g. `0x2304`, with a "mode" byte — `3` for basic
  on/off lighting, `9` for full RGB (matches `light rgb_keyboard="1"` in the XML).
- Followed by a big table of per-key entries **indexed by each key's `light_index`**
  attribute (see `rgb-keyboard.xml` — every key has a unique `light_index` 1-120).
  - Basic mode: 1 byte per key (`0xFF` = on, `0x00` = off) → table size ~0xC0 (192) bytes
  - RGB mode: 4 bytes per key (`[type, R, G, B]`) → table size ~0x240 (576) bytes
  - `type` byte guessed as `2` for "static color" based on a parallel table in the
    decompile that maps effect-type indices to type codes (`1`=off, `2`=static,
    `3`=breathing, etc. — see the big `if/else` chain in `FUN_00418550`).
  - Because a single feature report only carries 64 bytes, the real driver must
    split this table across several reports — the exact chunk headers were not
    observed, so `ExperimentalLighting.apply_colors()` currently just sends raw
    64-byte slices with no extra per-chunk framing. **This is the most likely part
    to be wrong** — verify with your own capture.
- Read-back command `0x04F5` for fetching the currently stored light table.
- Ends with `0x0204` (commit) then `0xF004` (finalize), same as other writes.

### Macro / key remap (also unverified)

`FUN_00418550` shows a page-select word that depends on connection mode:
`CONCAT(mode_byte, 0x04)` where `mode_byte = 0x27` in 2.4G mode vs `0x11` in wired
mode (i.e. commands `0x2704` / `0x1104`). Each remapped key becomes a small tagged
record (type + up to 3 payload bytes) — types seen in the decompile:

| type | meaning (guessed) |
|---|---|
| 1 | (0-length marker / disabled?) |
| 2 | multimedia/consumer key (2-byte HID usage) |
| 3 | mouse button |
| 6 | modifier + keycode combo |
| 7 | plain keyboard key + modifier |
| 0xd | 3-byte custom payload |

This table is incomplete — treat it as a starting point for your own capture-driven
reverse engineering, not a finished spec.

## 5. How to extend this yourself

See `CAPTURING.md` for how to record more traffic (lighting, macros, firmware
version query, etc.) and feed it back into this tool. The general workflow that
worked for the two settings we did verify:

1. Capture a `tshark`/Wireshark USB trace while changing **one thing at a time** in
   the official driver.
2. Filter to `usb.bus_id == X && usb.device_address == Y` for the keyboard.
3. Diff the SET_REPORT payloads between two captures that differ by exactly one
   setting value — the byte(s) that change are your answer.
4. Cross-check with the matching function in `decomiledFromExe.txt` to understand
   *why* that byte is there (variable name, surrounding checkbox/dropdown logic).
