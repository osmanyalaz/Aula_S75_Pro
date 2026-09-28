#!/usr/bin/env python3
"""
Command-line interface for aula_s75pro.py

Examples:
    python cli.py info
    python cli.py raw-send 04 18 00 00 ...            # send an arbitrary 64-byte report
    python cli.py raw-get
    python cli.py set-key-response 3 --sleep 2 --fn 0
    python cli.py set-sleep-time 2 --keyresponse 3 --fn 0
    python cli.py list-keys
"""
import argparse
import sys
from pathlib import Path

from aula_s75pro import AulaS75Pro, load_keymap, REPORT_LEN, EFFECTS, DIRECTIONS

HERE = Path(__file__).parent


def cmd_info(args):
    with AulaS75Pro(mode=args.mode) as kb:
        print(f"Connected: VID={kb.vid:04X} PID={kb.pid:04X} interface={kb.interface}")


def cmd_scan(args):
    """List every HID device hidapi can see, and flag anything matching VID 0C45."""
    import hid
    devices = hid.enumerate()
    if not devices:
        print("hidapi sees NO HID devices at all. This is almost always a permissions "
              "issue (see README/CAPTURING.md for the udev rule), or hidapi itself "
              "isn't installed correctly.")
        return
    found_045 = False
    for d in devices:
        vid, pid = d["vendor_id"], d["product_id"]
        marker = ""
        if vid == 0x0C45:
            found_045 = True
            marker = "  <-- AULA (0C45)"
        print(f"VID={vid:04X} PID={pid:04X} iface={d.get('interface_number')} "
              f"usage_page={d.get('usage_page')} usage={d.get('usage')} "
              f"path={d['path']!r}{marker}")
    if not found_045:
        print("\nNo device with VID 0C45 was found. Either the keyboard/dongle isn't "
              "connected, it's in a different mode than expected, or permissions are "
              "blocking it from being visible at all (see README/CAPTURING.md).")


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
        resp = kb.set_key_response_time(args.value, sleep_time=args.sleep, fn_switch=args.fn)
    print("Device ack:", resp.hex())


def cmd_set_sleep_time(args):
    with AulaS75Pro(mode=args.mode) as kb:
        resp = kb.set_sleep_time(args.value, key_response_time=args.keyresponse, fn_switch=args.fn)
    print("Device ack:", resp.hex())


def cmd_list_keys(args):
    xml_path = args.xml or (HERE / "rgb-keyboard.xml")
    keymap = load_keymap(str(xml_path))
    for name, info in sorted(keymap.items(), key=lambda kv: kv[1].light_index):
        print(f"{info.light_index:>3}  {name:<12} code={info.code:#04x} row={info.row} col={info.col}")

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

def cmd_sync_clock(args):
    with AulaS75Pro(mode=args.mode) as kb:
        kb.sync_rtc()
    print("Keyboard RTC synced to PC time")

def main():
    p = argparse.ArgumentParser(description="Aula S75Pro reverse-engineered control tool")
    p.add_argument("--mode", choices=["usb", "dongle"], default="usb",
                    help="connection mode (default: usb)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="connect and print device info").set_defaults(func=cmd_info)

    sub.add_parser("scan", help="list all HID devices hidapi can see (debugging)").set_defaults(func=cmd_scan)

    sp = sub.add_parser("raw-send", help="send a raw 64-byte feature report (hex bytes)")
    sp.add_argument("bytes", nargs="+", help="hex bytes, e.g. 04 18 00 00 ...")
    sp.set_defaults(func=cmd_raw_send)

    sub.add_parser("raw-get", help="read back a raw 64-byte feature report").set_defaults(func=cmd_raw_get)

    sp = sub.add_parser("set-key-response", help="set the key response time")
    sp.add_argument("value", type=int, help="raw value to send (see PROTOCOL.md)")
    sp.add_argument("--sleep", type=int, default=0, help="current sleep_time value to preserve")
    sp.add_argument("--fn", type=int, default=0, help="current fn_switch value to preserve")
    sp.set_defaults(func=cmd_set_key_response)

    sp = sub.add_parser("set-sleep-time", help="set the sleep timer")
    sp.add_argument("value", type=int, help="raw value to send (see PROTOCOL.md)")
    sp.add_argument("--keyresponse", type=int, default=0, help="current key_response_time value to preserve")
    sp.add_argument("--fn", type=int, default=0, help="current fn_switch value to preserve")
    sp.set_defaults(func=cmd_set_sleep_time)

    sp = sub.add_parser("list-keys", help="list the keyboard's key/light index map")
    sp.add_argument("--xml", help="path to rgb-keyboard.xml (defaults to the bundled copy)")
    sp.set_defaults(func=cmd_list_keys)

    parser_color = sub.add_parser('color', help='Set global lighting effect')
    parser_color.add_argument('r', type=int, help='Red (0-255)')
    parser_color.add_argument('g', type=int, help='Green (0-255)')
    parser_color.add_argument('b', type=int, help='Blue (0-255)')
    parser_color.add_argument('--effect', type=int, default=1, help='Effect ID (0-19)')
    parser_color.add_argument('--brightness', type=int, default=5, help='Brightness (0-5)')
    parser_color.add_argument('--speed', type=int, default=3, help='Speed (0-5)')
    parser_color.add_argument('--dir', type=int, default=0, help='Direction: 0(Right/Down), 1(Left), 2(Up)')
    parser_color.add_argument('--opt', type=int, default=0, help='Option flag (1=Rainbow/Cycle, 0=Solid)')
    parser_color.set_defaults(func=cmd_set_color)

    sub.add_parser("sync-clock", help="sync keyboard RTC to PC time").set_defaults(func=cmd_sync_clock)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
