# AULA S75 Pro — Linux control library

Reverse-engineered USB & 2.4GHz wireless dongle control for the AULA S75 Pro keyboard:
lighting effects, per-key RGB streaming (RAM-only, ~28 fps wired; 15×6 music EQ over
2.4G), custom-light tables, general settings, and RTC sync. No official software required.

## Connection modes (`--mode auto|usb|dongle`)
- **Auto (CLI default `--mode auto`):** Prefers wired USB (`0x0C45:0x800A`), falls back to the 2.4GHz wireless dongle (`0x05AC:0x024F` `"2.4G Dongle"`, Interface 3; `0x0C45:0xFEFE` fallback).
- **Wired USB (`--mode usb`):** Full feature set including flash/RAM read-back (`read ...`), `raw-send`/`raw-get`, `0x2004` freeform per-key streaming (`AulaStreamer`), and TFT image/GIF upload (`screenUpload/aula_s75pro_screen.py`).
- **2.4GHz Dongle (`--mode dongle`):** Supports `info`, exact `%` `battery` readout (`0x20`), global `color`, `underglow` (no flash `0x9800` erase quirk), `custom` RGB upload, `set-key-response` / `set-sleep-time`, `sync-clock`, `scan`, and `send_wireless_music_eq()` (`0x0B`). Flash/RAM read-back and TFT screen uploads require a wired USB connection.
- **Bluetooth mode:** Standard Bluetooth HID works for typing, but keyboard firmware v1.03 (`FUN_00004798`) gates wireless control commands on 2.4G mode (`DAT_200000ea == 2`) — keyboard configuration over Bluetooth is unsupported in firmware.

## Features
- Global lighting effects (20) with color/brightness/speed/direction (`cli.py color`)
- Row-6 side/underglow mode control (`cli.py underglow flowing|spectrum|static|breathing|off`, `0x1304` `0x20–0x24` wired / `0x05` 2.4G — note: firmware ignores RGB/brightness/speed bytes for underglow, so `static` color is set on-board via `Fn + /?` rather than over USB)
- Live per-key RGB streaming — wired `0x2004` "music rhythm" path (`AulaStreamer`), or 15×6 bar EQ over 2.4G (`send_wireless_music_eq`)
- Per-key custom light table (save path, wired & 2.4G)
- Device info (`cli.py info`), battery level (`cli.py battery` — tier `0–5` wired, exact `%` over 2.4G), wired flash/live-RAM read-back (`cli.py read ...`), and keyboard RTC sync

## Quick start
    pip install -r requirements.txt   # hidapi
    python cli.py scan                # verify USB or 2.4G Dongle visibility
    python cli.py info                # auto-detects wired USB or 2.4G Dongle
    python cli.py battery             # exact % on 2.4G, quantized level on USB
    python cli.py color 255 0 0 --effect 1      # static red (main keys)
    python cli.py underglow static              # set underglow to static (color via Fn + /?)
    python test.py                               # WASD blink (wired streaming demo)

## Linux `udev` rules (non-root access)
Create `/etc/udev/rules.d/70-aula-s75pro.rules` (must be numbered below `73` so `TAG+="uaccess"` runs before systemd's `73-seat-late.rules`):

    # AULA S75 Pro - Wired USB (HID config + PyUSB TFT screen upload)
    SUBSYSTEM=="usb", ATTR{idVendor}=="0c45", ATTR{idProduct}=="800a", TAG+="uaccess"
    SUBSYSTEM=="hidraw", ATTRS{idVendor}=="0c45", ATTRS{idProduct}=="800a", TAG+="uaccess"

    # AULA S75 Pro - 2.4GHz Dongle (scoped by product string)
    SUBSYSTEM=="usb", ATTR{idVendor}=="05ac", ATTR{idProduct}=="024f", ATTR{product}=="2.4G Dongle", TAG+="uaccess"
    SUBSYSTEM=="hidraw", ATTRS{idVendor}=="05ac", ATTRS{idProduct}=="024f", ATTRS{product}=="2.4G Dongle", TAG+="uaccess"

    # AULA S75 Pro - 2.4GHz Dongle (fallback VID:PID from config.xml)
    SUBSYSTEM=="usb", ATTR{idVendor}=="0c45", ATTR{idProduct}=="fefe", TAG+="uaccess"
    SUBSYSTEM=="hidraw", ATTRS{idVendor}=="0c45", ATTRS{idProduct}=="fefe", TAG+="uaccess"

> **Non-systemd / headless systems:** `TAG+="uaccess"` relies on `systemd-logind` to grant ACL access to the active local seat. On systems without `systemd`/`logind` (or for headless/SSH access without a local seat), replace `TAG+="uaccess"` with `MODE="0666"`.

Reload rules:

    sudo udevadm control --reload && sudo udevadm trigger

## Docs
See [PROTOCOL.md](PROTOCOL.md) for the full reverse-engineered protocol, and [FIRMWARE_AUDIT.md](FIRMWARE_AUDIT.md) for firmware verification details and safety exclusions.

## TO-DO
- **`aula_streamer.py` polish:**
  - Clamp RGB values (`0..255`) in `set_color()` and `set_all()`.
  - Keep `keymap` in `AulaStreamer` and add a `set_key(name, r, g, b)` helper.
  - Add a context manager / `stop()` cleanup to reload the saved hardware lighting (`0x1304` `0x00`) on exit instead of leaving the last frame frozen.
  - Guard against an unopened `kb.dev` handle and check `raw_get()` replies for `0xFF` rejections.
  - Expose a streaming subcommand in `cli.py` (and clean up legacy relative paths / unclosed handles in `test.py` and `test2.py`).
- **Streaming plugins (`0x2004`):**
  - Audio visualizer
  - System temperature / CPU-load monitor
  - Notification / alert blinker
- **Remaining protocol features (low priority / optional):**
  - Macros and keymap remapping (`0x1104` / `0x2704`)
  - Factory reset and TFT/keyboard language selection
  - *(Note: `0x3804` full SPI flash write and the EP0 ISP bootloader magic sequence remain intentionally excluded for safety.)*

## Credits
Reverse-engineered from USB captures of the official driver, its decompilation,
the keyboard MCU firmware.
