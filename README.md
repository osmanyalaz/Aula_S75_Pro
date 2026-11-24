# AULA S75 Pro — Linux control library

Reverse-engineered USB control for the AULA S75 Pro keyboard: lighting effects,
per-key RGB **streaming** (RAM-only, ~28 fps, no flash wear), custom-light tables,
and RTC sync. No official software required.

## Features
- Global lighting effects (20) with color/brightness/speed/direction (`cli.py color`)
- Row-6 side/underglow mode control (`cli.py underglow flowing|spectrum|static|breathing|off`, `0x1304` `0x20–0x24` — note: firmware ignores RGB/brightness/speed bytes for underglow, so `static` color is set on-board via `Fn + /?` rather than over USB)
- Live per-key RGB streaming — the "music rhythm" path, usable for any dynamic effect
  (audio visualizers, system monitors, notification blinkers)
- Per-key custom light table (save path)
- Device info (`cli.py info`), battery level (`cli.py battery`), flash/live-RAM read-back (`cli.py read ...`), and keyboard RTC sync

## Quick start
    pip install -r requirements.txt   # hidapi
    python cli.py color 255 0 0 --effect 1      # static red (main keys)
    python cli.py underglow static              # set underglow to static (color via Fn + /?)
    python test.py                               # WASD blink (streaming demo)

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
