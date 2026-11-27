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
    pip install -r requirements.txt   # hidapi, Pillow, pyusb
    python cli.py scan                # verify USB or 2.4G Dongle visibility
    python cli.py info                # auto-detects wired USB or 2.4G Dongle
    python cli.py battery             # exact % on 2.4G, quantized level on USB
    python cli.py color 255 0 0 --effect 1      # static red (main keys)
    python cli.py underglow static              # set underglow to static (color via Fn + /?)

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

## Local WebUI
Start the zero-dependency offline WebUI (binds strictly to `127.0.0.1`):

    python cli.py web                 # starts on http://127.0.0.1:8765 and opens browser
    python cli.py web --port 9000 --no-open
    python cli.py --mode dongle web   # force 2.4GHz dongle mode

Features include interactive 80-key per-key RGB painting (`keyboard-layout.json` + `keymap.py`), global lighting effects & underglow, general settings + RTC clock sync, and 135×240 portrait TFT image/GIF/video preview & wired upload. Flash/RAM read-back and TFT screen uploads require a wired USB connection.

- **HTTP routes:** `GET /` (plus `/static/...`), `GET /api/meta`, `GET /api/status`, `GET /api/lighting`, `GET /api/custom-table`, `GET /api/settings`, and `POST` handlers for `/api/lighting`, `/api/underglow`, `/api/custom-table`, `/api/settings`, `/api/sync-clock`, `/api/screen/preview`, and `/api/screen/upload`.
- **PyUSB / `hidraw` handoff on TFT uploads:** `POST /api/screen/upload` (and `screenUpload/aula_s75pro_screen.py`) temporarily detaches Linux kernel `usbhid` drivers on Interface 3 and Interface 2, completes the State-3 `0x0204` + `GET_REPORT` commit (or waits `2.1 s` past the `2.0 s` MCU watchdog on mid-transfer abort), releases and re-attaches the kernel drivers, and polls up to `2.5 s` under `hw_lock` for `hidraw`/`udevd` rebind before subsequent `hidapi` operations run.

## Docs
See [PROTOCOL.md](PROTOCOL.md) for the full reverse-engineered protocol, and [FIRMWARE_AUDIT.md](FIRMWARE_AUDIT.md) for firmware verification details and safety exclusions.

## TO-DO
- **`aula_streamer.py` polish:**
  - Add a `set_key(name, r, g, b)` helper (using `keymap.KEYMAP`).
  - Add a context manager / `stop()` cleanup to reload the saved hardware lighting (`0x1304` `0x00`) on exit instead of leaving the last frame frozen.
  - Expose a streaming subcommand in `cli.py`.
- **Streaming plugins (`0x2004`):**
  - Audio visualizer
  - System temperature / CPU-load monitor
  - Notification / alert blinker
- **Remaining protocol features (low priority / optional):**
  - Macros (`0x1404` / `0x1504` capped at `<= 48` chunks wired, `0x09` over 2.4G) and keymap remapping (`0x1004`/`0x1104` base & `0x2604`/`0x2704` Fn-layer with `00 00 AA 55` trailer at bytes `572..575`, `0x1904` bypass, and 2.4G `0x03`/`0x0D`/`0x10`/`0x12`/`0x1F`)
  - Optional 2.4G `0x0F` temporary test-blink helper (`FUN_0000de3c`, RAM-only)
  - *(On-board-only hardware controls in firmware `v1.03`: rotary encoder CW/CCW/press `0x00E9`/`0x00EA`/`0x00E2`, TFT screen language `0x2000023A` toggled on the keyboard LCD menu — `DeviceDriver.exe`'s Settings language dropdown only sets its own PC GUI `LCID`, OS layout mode `Fn+Q/W/E/R`, Row-5 accent bar `Fn+Z`, underglow static/breathing color `Fn+/?`, and full `Fn+Esc` factory reset have no USB/2.4G setter; `0x3804` full SPI flash write, the EP0 ISP bootloader magic sequence, and wireless `0x7F` / `0x80–0x8F` SPI streaming remain intentionally excluded for safety.)*

## Credits
Reverse-engineered from USB captures of the official driver, its decompilation,
and the keyboard MCU firmware.
