# AULA S75Pro — Reverse-Engineered Control Tool

A Python tool for talking directly to the AULA S75Pro keyboard's HID protocol,
built by reverse-engineering the official Windows driver (decompiled binary +
USB packet captures you supplied).

## What works (verified against real captures)

- Low-level raw HID Feature Report send/receive (`raw_send` / `raw_get`)
- Setting **key response time** and **sleep timer** (`write_general_settings`,
  `set_key_response_time`, `set_sleep_time`)
- Loading the full key layout from `rgb-keyboard.xml` (scan codes, light indices,
  positions)

## What's experimental (structurally inferred, not capture-verified)

- Per-key custom RGB lighting (`ExperimentalLighting`)
- Macro/key-remap command family

See **PROTOCOL.md** for the full technical write-up (what's proven vs. guessed),
and **CAPTURING.md** for how to capture more traffic yourself to nail down the
experimental parts.

## Install

```bash
pip install -r requirements.txt
```

On Linux, raw HID access usually needs either `sudo` or a udev rule granting
your user access to the device (VID `0c45`).

## Usage

### As a library

```python
from aula_s75pro import AulaS75Pro

with AulaS75Pro(mode="usb") as kb:          # or mode="dongle" for the 2.4G receiver
    # IMPORTANT: this writes fn_switch/sleep_time/key_response_time TOGETHER.
    # Pass the current values of the ones you don't want to change.
    kb.set_key_response_time(value=3, sleep_time=2, fn_switch=0)
```

### CLI

```bash
python cli.py info
python cli.py list-keys
python cli.py set-key-response 3 --sleep 2 --fn 0
python cli.py set-sleep-time 2 --keyresponse 3 --fn 0
python cli.py raw-send 04 18 00 00           # low-level: send a raw report (auto zero-padded to 64 bytes)
python cli.py raw-get                        # low-level: read back a report
```

## Safety notes

- These are HID **Feature Reports** to configure firmware settings — not firmware
  flashing — so the risk of "bricking" the keyboard is low, but always know what
  you're sending. Prefer `raw-get` before/after to sanity-check state.
- `write_general_settings` writes all three values (fn/sleep/key-response) in one
  report at once. If you don't pass the current values of the ones you're not
  changing, you may reset them.
- The exact meaning of raw level numbers (e.g. is `3` "3ms" or "the 3rd option in
  a dropdown") was not fully determined — see PROTOCOL.md §3.

## Files

| File | Purpose |
|---|---|
| `aula_s75pro.py` | Core protocol library |
| `cli.py` | Command-line interface |
| `PROTOCOL.md` | Full protocol write-up (verified vs. inferred) |
| `CAPTURING.md` | How to capture more traffic to extend this |
| `rgb-keyboard.xml` | Bundled copy of the key layout (from your upload) |
| `config.xml` | Bundled copy of device identification metadata |
# Aula_S75_Pro
