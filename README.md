# AULA S75 Pro — Linux control library

Reverse-engineered USB control for the AULA S75 Pro keyboard: lighting effects,
per-key RGB **streaming** (RAM-only, ~28 fps, no flash wear), custom-light tables,
and RTC sync. No official software required.

## Features
- Global lighting effects (20) with color/brightness/speed/direction
- Live per-key RGB streaming — the "music rhythm" path, usable for any dynamic effect
  (audio visualizers, system monitors, notification blinkers)
- Per-key custom light table (save path)
- Keyboard RTC sync to PC time

## Quick start
    pip install -r requirements.txt   # hidapi
    python cli.py color 255 0 0 --effect 1      # static red
    python test.py                               # WASD blink (streaming demo)

## Docs
See [PROTOCOL.md](PROTOCOL.md) for the full reverse-engineered protocol.

## Credits
Reverse-engineered from USB captures of the official driver, its decompilation,
the keyboard MCU firmware, and SignalRGB's SONIX integration.
