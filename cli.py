#!/usr/bin/env python3
"""
Command-line interface for aula_s75pro.py

Examples:
    python cli.py info
    python cli.py battery
    python cli.py read lighting
    python cli.py read settings
    python cli.py read live-rgb
    python cli.py underglow flowing
    python cli.py raw-send 04 18 00 00 ...            # send an arbitrary 64-byte report
    python cli.py raw-get
    python cli.py set-key-response 3 --sleep 2 --fn 0
    python cli.py set-sleep-time 2 --keyresponse 3 --fn 0
    python cli.py list-keys
"""
import argparse
import sys

from aula_s75pro import (
    AulaS75Pro,
    DONGLE_PRODUCT_NAME,
    EFFECTS,
    INTERFACE_DONGLE,
    KEYMAP,
    PHYSICAL_INDICES,
    PID_DONGLE,
    PID_DONGLE_FALLBACK,
    REPORT_LEN,
    UNDERGLOW_MODES,
    UnsupportedModeError,
    VID,
    VID_DONGLE,
)

EFFECT_NOTES = {
    0: "LedOff (pure 0x00 payload; firmware reloads stored flash effect)",
    1: "Static (solid RGB when --opt 0; fixed rainbow gradient when --opt 1)",
    2: "SingleOn (light key on press)",
    3: "SingleOff (light off on press; random per-key colors when --opt 1)",
    4: "Glittering",
    5: "Fluttering",
    6: "Colourful (natively rainbow; ignores --opt)",
    7: "Breath",
    8: "Spectrum",
    9: "Outward",
    10: "Scrolling (--dir: 0=Down, 2=Up)",
    11: "Rolling (--dir: 0=Right, 1=Left)",
    12: "Rotating (--dir: 0=Right, 1=Left)",
    13: "Explode",
    14: "Launch",
    15: "Ripples",
    16: "Flowing (--dir: 0=Right, 1=Left)",
    17: "Pulsating",
    18: "Tilt (--dir: 0=Right, 1=Left)",
    19: "Shuttle",
}


def format_effects_table() -> str:
    """Return a human-readable table of all 20 main-key lighting effects."""
    id_to_name = {eid: name for name, eid in EFFECTS.items()}
    lines = ["Available effect IDs (0-19):"]
    for eid in sorted(id_to_name):
        name = id_to_name[eid]
        note = EFFECT_NOTES.get(eid, "")
        lines.append(f"  {eid:>2} (0x{eid:02X})  {name:<12}  {note}")
    lines.extend([
        "",
        "Parameter notes:",
        "  r g b         RGB color channels (0-255 each; used when --opt 0)",
        "  --effect      Effect ID (0-19) or name (e.g. static, breath, flowing)",
        "  --brightness  LED brightness level (0-5, default 5)",
        "  --speed       Animation speed (0-5, default 3)",
        "  --dir         Direction: 0=Right/Down, 1=Left, 2=Up (effect-dependent)",
        "  --opt         Color mode: 0=Solid RGB (use r g b), 1=Hardware multi-color/rainbow",
    ])
    return "\n".join(lines)


def _parse_effect(value: str) -> int:
    key = value.strip().lower()
    if key in EFFECTS:
        return EFFECTS[key]
    try:
        eid = int(key, 0)
    except ValueError as exc:
        valid = ", ".join(f"{eid}:{name}" for name, eid in sorted(EFFECTS.items(), key=lambda kv: kv[1]))
        raise argparse.ArgumentTypeError(f"unknown effect {value!r}; expected 0-19 or name ({valid})") from exc
    if not (0 <= eid <= 19):
        raise argparse.ArgumentTypeError(f"effect ID {eid} out of range (must be 0-19)")
    return eid


class _AvailableEffectsAction(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(format_effects_table())
        parser.exit(0)



def cmd_info(args):
    with AulaS75Pro(mode=args.mode) as kb:
        print(
            f"Connected ({kb.active_mode}): "
            f"VID={kb.vid:04X} PID={kb.pid:04X} interface={kb.interface}"
        )
        info = kb.read_device_info()
    if info.get("checksum") is None:
        print(
            f"Device Info (2.4G 0x02): tag={info['tag']:#06x} VID={info['vid']:04X} "
            f"PID={info['pid']:04X} FW=v{info['fw_version']}"
        )
    else:
        print(
            f"Device Info (0x0504): tag={info['tag']:#06x} VID={info['vid']:04X} "
            f"PID={info['pid']:04X} FW=v{info['fw_version']} (checksum={info['checksum']:#010x})"
        )
    if args.raw:
        print(f"Raw (0x8F80): {info['raw'].hex()}")


def cmd_battery(args):
    with AulaS75Pro(mode=args.mode) as kb:
        batt = kb.read_battery_level()
    if batt.get("percent") is not None:
        print(
            f"Battery (2.4G 0x20): {batt['percent']}% "
            f"(level {batt['level']}/5, {batt['percent_range']})"
        )
    else:
        print(f"Battery (0xF604): {batt['level']}/5 ({batt['percent_range']})")
    if args.raw:
        print(f"Raw: {batt['raw'].hex()}")


def cmd_read(args):
    key_names = {idx: name for name, idx in KEYMAP.items()}
    with AulaS75Pro(mode=args.mode) as kb:
        if args.target == "lighting":
            cfg = kb.read_lighting_config()
            if cfg["erased"]:
                print("Lighting Config (0x1204 / 0x9800): ERASED (all 0xFF)")
            elif cfg["zeroed"]:
                print("Lighting Config (0x1204 / 0x9800): ZEROED (all 0x00)")
            else:
                print(
                    f"Lighting Config (0x1204 / 0x9800): effect={cfg['effect']:#04x}, "
                    f"RGB={cfg['rgb']}, option={cfg['option']:#04x}, "
                    f"brightness={cfg['brightness']}, speed={cfg['speed']}, "
                    f"direction={cfg['direction']}, trailer={cfg['trailer'].hex()}"
                )
            print(f"Checksum: {cfg['checksum']:#010x}")
            if args.raw:
                print(f"Raw: {cfg['raw'].hex()}")

        elif args.target == "settings":
            st = kb.read_general_settings()
            if st["erased"]:
                print("General Settings (0x1604 / 0x9000): ERASED (all 0xFF)")
            elif st["zeroed"]:
                print("General Settings (0x1604 / 0x9000): ZEROED (all 0x00)")
            else:
                print(
                    f"General Settings (0x1604 / 0x9000):\n"
                    f"  disable_alt_tab={st['disable_alt_tab']}, disable_alt_f4={st['disable_alt_f4']}, "
                    f"win_lock={st['win_lock']}\n"
                    f"  fn_switch={st['fn_switch']}, sleep_time={st['sleep_time']} ({st['sleep_label']}), "
                    f"key_response_time={st['key_response_time']} ({st['debounce_scans']} scans)"
                )
            print(f"Checksum: {st['checksum']:#010x}")
            if args.raw:
                print(f"Raw: {st['raw'].hex()}")

        elif args.target in ("live-rgb", "custom-table"):
            if args.target == "live-rgb":
                data = kb.read_live_rgb()
                title = "Live RGB RAM (0xF504)"
            else:
                data = kb.read_custom_lighting_table()
                title = "Saved Custom RGB Table (0x2204 / 0x9C00)"
            slots = sorted(data["keys"]) if args.all else sorted(
                s for s in data["keys"] if s in PHYSICAL_INDICES and data["keys"][s] != (0, 0, 0)
            )
            print(f"{title}: {len(data['keys'])} slot(s) decoded, showing {len(slots)} entry/entries")
            for s in slots:
                r, g, b = data["keys"][s]
                label = key_names.get(s, f"slot_{s}")
                print(f"  {s:>3} ({label:<9}): RGB({r:3d}, {g:3d}, {b:3d})")
            if "trailer" in data:
                print(f"Trailer: {data['trailer'].hex()}")
            print(f"Checksum: {data['checksum']:#010x}")
            if args.raw:
                print(f"Raw ({len(data['raw'])}B): {data['raw'].hex()}")


def cmd_underglow(args):
    preserve = not args.no_preserve
    with AulaS75Pro(mode=args.mode) as kb:
        res = kb.set_underglow_mode(args.underglow_mode, preserve_lighting=preserve)
    if res.get("checksum") is None:
        print(
            f"Underglow mode {res['mode']} ({res['mode_name']}) applied via 2.4G dongle (0x05); "
            "flash 0x9800 untouched."
        )
        return
    status = "MATCH" if res["checksum_matched"] else "MISMATCH (warning issued)"
    print(
        f"Underglow mode {res['mode']} ({res['mode_name']}) applied; "
        f"commit checksum={res['checksum']:#010x} ({status})"
    )
    if res["restored_lighting"]:
        print("Main-key lighting flash 0x9800: restored")
    else:
        print("Main-key lighting flash 0x9800: not restored (empty or --no-preserve)")


def cmd_scan(args):
    """List every HID device hidapi can see, and flag AULA USB / 2.4G dongle nodes."""
    import hid
    devices = hid.enumerate()
    if not devices:
        print("hidapi sees NO HID devices at all. This is almost always a permissions "
              "issue (see README/CAPTURING.md for the udev rule), or hidapi itself "
              "isn't installed correctly.")
        return
    found_aula = False
    for d in devices:
        vid, pid = d["vendor_id"], d["product_id"]
        iface = d.get("interface_number")
        product = d.get("product_string") or ""
        marker = ""
        if vid == VID and pid == PID_DONGLE_FALLBACK:
            found_aula = True
            marker = f"  <-- AULA 2.4G fallback (iface {iface})"
        elif vid == VID:
            found_aula = True
            marker = "  <-- AULA (0C45)"
        elif vid == VID_DONGLE and pid == PID_DONGLE and product.strip() == DONGLE_PRODUCT_NAME:
            found_aula = True
            if iface == INTERFACE_DONGLE:
                marker = "  <-- AULA 2.4G Dongle control (iface 3)"
            else:
                marker = f"  <-- AULA 2.4G Dongle ({DONGLE_PRODUCT_NAME}, iface {iface})"
        print(f"VID={vid:04X} PID={pid:04X} iface={iface} "
              f"usage_page={d.get('usage_page')} usage={d.get('usage')} "
              f"product={product!r} path={d['path']!r}{marker}")
    if not found_aula:
        print("\nNo AULA USB (0C45:800A) or 2.4G Dongle (05AC:024F '2.4G Dongle') device was found. "
              "Either the keyboard/dongle isn't connected, it's in Bluetooth mode, or permissions "
              "are blocking it (see README.md for udev rules).")


def cmd_raw_send(args):
    payload = bytes.fromhex("".join(args.bytes))
    if len(payload) < REPORT_LEN:
        payload = payload + bytes(REPORT_LEN - len(payload))
    elif len(payload) > REPORT_LEN:
        sys.exit(f"Payload too long: {len(payload)} > {REPORT_LEN} bytes")
    with AulaS75Pro(mode=args.mode) as kb:
        kb.raw_send(payload)
    print("Sent:", payload.hex())


def cmd_raw_get(args):
    with AulaS75Pro(mode=args.mode) as kb:
        data = kb.raw_get()
    print("Received:", data.hex())


def cmd_set_key_response(args):
    with AulaS75Pro(mode=args.mode) as kb:
        resp = kb.set_key_response_time(
            args.value,
            sleep_time=args.sleep,
            fn_switch=args.fn,
            disable_alt_tab=args.disable_alt_tab,
            disable_alt_f4=args.disable_alt_f4,
            win_lock=args.win_lock,
        )
    print("Device ack:", resp.hex())


def cmd_set_sleep_time(args):
    with AulaS75Pro(mode=args.mode) as kb:
        resp = kb.set_sleep_time(
            args.value,
            key_response_time=args.keyresponse,
            fn_switch=args.fn,
            disable_alt_tab=args.disable_alt_tab,
            disable_alt_f4=args.disable_alt_f4,
            win_lock=args.win_lock,
        )
    print("Device ack:", resp.hex())


def cmd_list_keys(args):
    for name, idx in sorted(KEYMAP.items(), key=lambda kv: kv[1]):
        print(f"{idx:>3}  {name}")


def cmd_set_color(args):
    with AulaS75Pro(mode=args.mode) as kb:
        kb.set_global_lighting(
            effect=args.effect, 
            r=args.r, 
            g=args.g, 
            b=args.b, 
            brightness=args.brightness, 
            speed=args.speed, 
            direction=args.dir, 
            option=args.opt
        )
    print(f"Set color to RGB({args.r}, {args.g}, {args.b}) using effect ID {args.effect}")

def cmd_custom_lighting(args):
    from aula_s75pro import PHYSICAL_INDICES

    if not args.all and not args.keys:
        print("error: supply either --all or --keys KEY [KEY ...]", file=sys.stderr)
        sys.exit(1)

    color = (args.r, args.g, args.b)

    if args.all:
        key_colors = {idx: color for idx in PHYSICAL_INDICES}
        label = f"all {len(PHYSICAL_INDICES)} keys"
    else:
        key_colors = {}
        unknown = []
        for name in args.keys:
            if name in KEYMAP:
                key_colors[KEYMAP[name]] = color
            else:
                unknown.append(name)
        if unknown:
            print(
                f"warning: unknown key name(s) skipped: {', '.join(unknown)}\n"
                "  Run 'list-keys' to see valid names."
            )
        if not key_colors:
            print("error: no valid keys specified — nothing to do.", file=sys.stderr)
            sys.exit(1)
        label = ", ".join(f"{n}({KEYMAP[n]})" for n in args.keys if n in KEYMAP)

    with AulaS75Pro(mode=args.mode) as kb:
        kb.set_custom_lighting(key_colors, brightness=args.brightness)
    print(f"Applied RGB{color} to {label}")


def cmd_sync_clock(args):

    with AulaS75Pro(mode=args.mode) as kb:
        kb.sync_rtc()
    print("Keyboard RTC synced to PC time")


def cmd_web(args):
    from webui.server import run_server

    run_server(port=args.port, mode=args.mode, open_browser=not args.no_open)

def main():
    p = argparse.ArgumentParser(description="Aula S75Pro reverse-engineered control tool")
    p.add_argument(
        "--mode",
        choices=["auto", "usb", "dongle"],
        default="auto",
        help="connection mode: auto (default, prefers wired usb), usb, or dongle",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sp_info = sub.add_parser("info", help="connect and query device/firmware info (0x0504 / 2.4G 0x02)")
    sp_info.add_argument("--raw", action="store_true", help="print raw 0x8F80 info block")
    sp_info.set_defaults(func=cmd_info)

    sp_batt = sub.add_parser("battery", help="query battery level (0-5 wired 0xF604, exact %% over 2.4G 0x20)")
    sp_batt.add_argument("--raw", action="store_true", help="print raw response")
    sp_batt.set_defaults(func=cmd_battery)

    sp_read = sub.add_parser("read", help="read back lighting, settings, live RGB RAM, or custom table")
    sp_read.add_argument(
        "target",
        choices=["lighting", "settings", "live-rgb", "custom-table"],
        help="page/table to read (0x1204, 0x1604, 0xF504, 0x2204)",
    )
    sp_read.add_argument("--raw", action="store_true", help="print raw hex bytes")
    sp_read.add_argument("--all", action="store_true", help="for RGB tables, include black/non-physical slots")
    sp_read.set_defaults(func=cmd_read)

    sp_ug = sub.add_parser("underglow", help="set Row-6 side/underglow lighting mode (0x1304 0x20-0x24)")
    sp_ug.add_argument(
        "underglow_mode",
        metavar="MODE",
        choices=list(UNDERGLOW_MODES.keys()) + ["0", "1", "2", "3", "4"],
        help="flowing (0), spectrum (1), static (2), breathing (3), off (4)",
    )
    sp_ug.add_argument(
        "--no-preserve",
        action="store_true",
        help="skip saving and restoring flash page 0x9800 main-key lighting",
    )
    sp_ug.set_defaults(func=cmd_underglow)

    sub.add_parser("scan", help="list all HID devices hidapi can see (debugging)").set_defaults(func=cmd_scan)

    sp = sub.add_parser("raw-send", help="send a raw 64-byte feature report (hex bytes)")
    sp.add_argument("bytes", nargs="+", help="hex bytes, e.g. 04 18 00 00 ...")
    sp.set_defaults(func=cmd_raw_send)

    sub.add_parser("raw-get", help="read back a raw 64-byte feature report").set_defaults(func=cmd_raw_get)

    sp = sub.add_parser("set-key-response", help="set the key response time")
    sp.add_argument("value", type=int, help="raw value to send (see PROTOCOL.md)")
    sp.add_argument("--sleep", type=int, default=0, help="current sleep_time value to preserve")
    sp.add_argument("--fn", type=int, default=0, help="current fn_switch value to preserve")
    sp.add_argument("--disable-alt-tab", action="store_true", help="disable Alt+Tab")
    sp.add_argument("--disable-alt-f4", action="store_true", help="disable Alt+F4")
    sp.add_argument("--win-lock", action="store_true", help="enable Win-Lock")
    sp.set_defaults(func=cmd_set_key_response)

    sp = sub.add_parser("set-sleep-time", help="set the sleep timer")
    sp.add_argument("value", type=int, help="raw value to send (see PROTOCOL.md)")
    sp.add_argument("--keyresponse", type=int, default=0, help="current key_response_time value to preserve")
    sp.add_argument("--fn", type=int, default=0, help="current fn_switch value to preserve")
    sp.add_argument("--disable-alt-tab", action="store_true", help="disable Alt+Tab")
    sp.add_argument("--disable-alt-f4", action="store_true", help="disable Alt+F4")
    sp.add_argument("--win-lock", action="store_true", help="enable Win-Lock")
    sp.set_defaults(func=cmd_set_sleep_time)

    sp = sub.add_parser("list-keys", help="list the keyboard's key/light index map")
    sp.set_defaults(func=cmd_list_keys)


    parser_color = sub.add_parser(
        'color',
        help='Set global lighting effect',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Set the main-key global lighting effect (0x1304, effect IDs 0-19).',
        epilog=format_effects_table(),
    )
    parser_color.add_argument('r', type=int, help='Red channel (0-255)')
    parser_color.add_argument('g', type=int, help='Green channel (0-255)')
    parser_color.add_argument('b', type=int, help='Blue channel (0-255)')
    parser_color.add_argument(
        '--effect', type=_parse_effect, default=1, metavar='ID_OR_NAME',
        help='Effect ID (0-19) or name (default: 1=static); see list below',
    )
    parser_color.add_argument(
        '--available-effects', '--available-effect',
        action=_AvailableEffectsAction,
        help='Show all available effect IDs (0-19) and parameter details, then exit',
    )
    parser_color.add_argument(
        '--brightness', type=int, default=5,
        help='Brightness level 0-5 (0=dimmest/off, 5=max; default: 5)',
    )
    parser_color.add_argument(
        '--speed', type=int, default=3,
        help='Animation speed 0-5 (0=slowest, 5=fastest; default: 3)',
    )
    parser_color.add_argument(
        '--dir', type=int, default=0,
        help='Animation direction: 0=Right/Down, 1=Left, 2=Up (default: 0)',
    )
    parser_color.add_argument(
        '--opt', type=int, default=0,
        help='Color option: 0=Solid RGB (use r g b), 1=Hardware multi-color/rainbow (default: 0)',
    )
    parser_color.set_defaults(func=cmd_set_color)

    parser_custom = sub.add_parser(
        'custom',
        help='Save a per-key colour table to flash (use --keys or --all)',
        description=(
            'Write a custom per-key lighting table to flash.  '
            'Specify individual keys with --keys, or paint every key with --all.  '
            'Run \'list-keys\' to see all valid key names.'
        ),
    )
    parser_custom.add_argument('r', type=int, help='Red component (0-255)')
    parser_custom.add_argument('g', type=int, help='Green component (0-255)')
    parser_custom.add_argument('b', type=int, help='Blue component (0-255)')
    parser_custom.add_argument(
        '--keys', nargs='+', metavar='KEY',
        help='Key names to colour (e.g. --keys Esc W A S D Enter Space)',
    )
    parser_custom.add_argument(
        '--all', action='store_true',
        help='Apply the colour to every physical key on the board',
    )
    parser_custom.add_argument('--brightness', type=int, default=5,
                               help='Custom-mode brightness (0-5, default 5)')
    parser_custom.set_defaults(func=cmd_custom_lighting)


    sub.add_parser("sync-clock", help="sync keyboard RTC to PC time").set_defaults(func=cmd_sync_clock)

    sp_web = sub.add_parser("web", help="start local WebUI server on 127.0.0.1")
    sp_web.add_argument(
        "--port",
        type=int,
        default=8765,
        help="local TCP port on 127.0.0.1 (default: 8765)",
    )
    sp_web.add_argument(
        "--no-open",
        action="store_true",
        help="do not automatically open the browser",
    )
    sp_web.set_defaults(func=cmd_web)


    args = p.parse_args()
    try:
        args.func(args)
    except UnsupportedModeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
