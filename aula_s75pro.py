"""
aula_s75pro.py
==============

Reverse-engineered control library for the AULA S75 Pro keyboard protocol
across wired USB (0x0C45:0x800A) and the 2.4GHz wireless dongle (0x05AC:0x024F).

Built from USB/HID traffic captures, `lsusb` descriptors, and read-only
analysis of the official Windows driver and keyboard MCU firmware v1.03
(raw vendor binaries, XML configs, and captures are intentionally omitted
from this repository).

See PROTOCOL.md and FIRMWARE_AUDIT.md in this folder for full protocol details.
"""

from __future__ import annotations

import struct
import time
import warnings
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional

from keymap import PHYSICAL_INDICES, KEYMAP  # noqa: F401 (KEYMAP re-exported for callers)

EFFECTS = {
    "off": 0, "static": 1, "single_on": 2, "single_off": 3,
    "glittering": 4, "fluttering": 5, "colourful": 6, "breath": 7,
    "spectrum": 8, "outward": 9, "scrolling": 10, "rolling": 11,
    "rotating": 12, "explode": 13, "launch": 14, "ripples": 15,
    "flowing": 16, "pulsating": 17, "tilt": 18, "shuttle": 19
}
DIRECTIONS = {"right": 0, "down": 0, "left": 1, "up": 2}

try:
    import hid  # pip install hidapi
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "This tool needs the 'hidapi' package. Install it with:\n"
        "    pip install hidapi\n"
        "(On Linux you may also need udev rules / root to access the raw HID device.)"
    ) from e


# --------------------------------------------------------------------------------------
# Device identification (lsusb, DeviceDriver.exe, and config.xml)
# --------------------------------------------------------------------------------------
VID = 0x0C45

PID_USB = 0x800A       # wired USB (SONiX AULA-S75Pro)
INTERFACE_USB = 3

# Real 2.4GHz wireless dongle (confirmed by lsusb & DeviceDriver.exe):
# VID=0x05AC PID=0x024F, product_string="2.4G Dongle", Interface 3 (32 B Interrupt).
# Interface 4 on 05AC:024F is a separate 64 B vendor interface and must not be matched.
VID_DONGLE = 0x05AC
PID_DONGLE = 0x024F
DONGLE_PRODUCT_NAME = "2.4G Dongle"
VID_DONGLE_FALLBACK = 0x0C45
PID_DONGLE_FALLBACK = 0xFEFE    # config.xml placeholder fallback
INTERFACE_DONGLE = 3

REPORT_ID = 0x00
REPORT_LEN = 64        # wired EP0 Feature payload length (wLength = 0x40), excluding report-id
DONGLE_PACKET_LEN = 33 # 2.4G Interrupt OUT/IN transfer length: 1 B report-id (0x00) + 32 B frame
DONGLE_PAYLOAD_LEN = 28
DONGLE_SETTINGS_LEN = 0x10

# Wired USB command words (little-endian on the wire: byte0=lo, byte1=hi)
CMD_COMMIT = 0x0204             # commit / read 32-bit LE checksum in resp[4..7]
CMD_DEVICE_INFO = 0x0504        # read device info block from flash 0x00008F80 (max 2 chunks)
CMD_LIGHTING_READ = 0x1204      # read lighting config page from flash 0x00009800 (max 1 chunk)
CMD_LIGHTING_WRITE = 0x1304     # write flash 0x00009800 or Row-6 underglow mode (0x20-0x24)
CMD_SETTINGS_READ = 0x1604      # read general settings page from flash 0x00009000 (max 1 chunk)
CMD_SETTINGS_WRITE = 0x1704     # write general settings page to flash 0x00009000 (max 1 chunk)
CMD_PROBE = CMD_SETTINGS_WRITE  # backwards-compatible alias
CMD_OPEN = 0x1804               # generic "begin" ping & enable custom keymap/macro interception
CMD_GENERAL_SETTINGS = 0x0100   # general settings / RTC write payload prefix
CMD_CUSTOM_LIGHT_READ = 0x2204  # read saved flash custom RGB table (0x00009C00, max 9 chunks)
CMD_LIGHT_APPLY_BASE = 0x2304   # write custom RGB table to flash (0x00009C00, payload[8]=9 for RGB)
CMD_RTC_WRITE = 0x2804          # select RTC write page (State 6)
CMD_FINALIZE = 0xF004           # finalize: persist runtime snapshot to flash 0x8000
CMD_LIGHT_READ = 0xF504         # wire 04 F5: read live RGB RAM (0x20001838/195E/1A84; checksum=0)
CMD_BATTERY_LEVEL = 0xF604      # wire 04 F6: read quantized battery level (0-5) in resp[4]
CMD_STREAM_FRAME = 0x2004       # frame update for dynamic RGB music mode (ISR fast-path)

# 2.4GHz Dongle Interrupt command IDs (FUN_00005990 / FUN_0044f980)
DONGLE_CMD_INFO = 0x02          # len=0x00 -> echoes 28 B device info block from flash 0x00008F80
DONGLE_CMD_LIGHTING = 0x05      # len=0x10 -> 16 B global lighting OR Row-6 underglow (0x20-0x24)
DONGLE_CMD_SETTINGS = 0x07      # len=0x10 -> 16 B general settings
DONGLE_CMD_MUSIC_EQ = 0x0B      # len=0x1C -> 15-col x 6-row wireless music EQ frame
DONGLE_CMD_RTC = 0x0C           # len=0x10 -> 16 B RTC sync
DONGLE_CMD_CUSTOM_RGB = 0x14    # 21 chunks (seq 0..19 len=0x1C, seq 20 len=0x10) after 0x05 0x80
DONGLE_CMD_BATTERY = 0x20       # len=0x01 -> echoes exact battery % (0-100) in reply[3]

TRAILER = b"\xAA\x55"     # observed at the very end of the 64-byte buffer on writes

# Custom lighting table dimensions (verified against escToRed.pcapng, PROTOCOL.md §5)
TABLE_SIZE   = 576  # 144 slots × 4 bytes each (light_index, R, G, B)
TABLE_CHUNKS = 9    # 576 / 64 bytes-per-report

# Row-6 side / underglow modes (0x1304 or 2.4G 0x05 with payload[0] = 0x20 + mode_id)
UNDERGLOW_MODES = {
    "flowing": 0,
    "spectrum": 1,
    "static": 2,
    "breathing": 3,
    "off": 4,
}
UNDERGLOW_MODE_NAMES = {v: k for k, v in UNDERGLOW_MODES.items()}
# Phase 1 erases 0x9800 and FUN_00003f42 skips writing it for 0x20-0x24:
# 0x00004645 stack word (0x45 + 0x46 = 0x8B) + 60 * 0xFF (0x3BC4) = 0x00003C4F.
EXPECTED_UNDERGLOW_ERASED_CHECKSUM = 0x00003C4F

BATTERY_RANGES = {
    0: "<6%",
    1: "6–25%",
    2: "26–50%",
    3: "51–75%",
    4: "76–95%",
    5: "96–100%",
}
SLEEP_TIME_LABELS = {0: "off", 1: "1 min", 2: "5 min", 3: "30 min"}
DEBOUNCE_SCANS = {1: 2, 2: 3, 3: 7, 4: 10, 5: 14}


class McuRejectedError(RuntimeError):
    """Raised immediately when the MCU responds with explicit error status 0xFF."""


class UnsupportedModeError(NotImplementedError):
    """Raised when an operation is only supported in wired USB or 2.4G dongle mode."""


def _le16(cmd: int) -> bytes:
    """Encode a command word as little-endian bytes (byte0=lo, byte1=hi)."""
    return bytes([cmd & 0xFF, (cmd >> 8) & 0xFF])


def _validate_int_range(val: int, name: str, lo: int, hi: int) -> int:
    """Validate that val is an int (not bool) within inclusive bounds [lo, hi]."""
    if isinstance(val, bool) or not isinstance(val, int) or not (lo <= val <= hi):
        raise ValueError(f"{name} must be an integer in range {lo}..{hi}, got {val!r}")
    return val


def parse_commit_checksum(resp: bytes) -> int:
    """Decode the 32-bit little-endian byte-sum checksum from CMD_COMMIT resp[4..7]."""
    if len(resp) < 8:
        raise ValueError(f"Commit ACK too short ({len(resp)} bytes) for 32-bit LE checksum")
    return struct.unpack_from("<I", resp, 4)[0]


def build_report(cmd: int, body: bytes = b"", trailer: bool = False, size: int = REPORT_LEN) -> bytearray:
    """Build a full 64-byte report: [cmd_lo, cmd_hi, ...body..., zero padding, (AA 55)?]"""
    buf = bytearray(size)
    buf[0:2] = _le16(cmd)
    buf[2:2 + len(body)] = body
    if trailer:
        buf[-2:] = TRAILER
    return buf


def build_dongle_packet(cmd: int, length: int, seq: int = 0, payload: bytes = b"") -> bytes:
    """Build a 33-byte 2.4G Interrupt OUT report: [0x00, cmd, len, seq, payload[0..27], sum(0..31)&0xFF]."""
    if not (0 <= cmd <= 0xFF):
        raise ValueError(f"2.4G cmd must be 0..255, got {cmd}")
    if not (0 <= length <= DONGLE_PAYLOAD_LEN):
        raise ValueError(f"2.4G length must be 0..{DONGLE_PAYLOAD_LEN}, got {length}")
    if not (0 <= seq <= 0xFF):
        raise ValueError(f"2.4G seq must be 0..255, got {seq}")
    if len(payload) > DONGLE_PAYLOAD_LEN:
        raise ValueError(f"2.4G payload max {DONGLE_PAYLOAD_LEN} bytes, got {len(payload)}")
    pkt = bytearray(DONGLE_PACKET_LEN)
    pkt[0] = REPORT_ID
    pkt[1] = cmd
    pkt[2] = length
    pkt[3] = seq
    pkt[4:4 + len(payload)] = payload
    pkt[32] = sum(pkt[:32]) & 0xFF
    return bytes(pkt)


def parse_dongle_reply(raw) -> bytes:
    """Normalize a 2.4G Interrupt IN read (32 B hidraw or 33 B Report-ID-0 prefixed) to 32 B."""
    if not raw:
        return b""
    data = bytes(raw)
    if len(data) == DONGLE_PACKET_LEN and data[0] == REPORT_ID:
        return data[1:33]
    return data[:32]


def battery_percent_to_level(percent: int) -> int:
    """Convert exact percentage (0-100) to firmware's 0-5 quantized tier (FUN_00004d8c)."""
    if percent < 6:
        return 0
    if percent < 26:
        return 1
    if percent < 51:
        return 2
    if percent < 76:
        return 3
    if percent < 96:
        return 4
    return 5


def _parse_underglow_mode(mode: int | str) -> int:
    if isinstance(mode, bool):
        raise ValueError(f"Invalid underglow mode: {mode!r}")
    if isinstance(mode, str):
        key = mode.strip().lower()
        if key in UNDERGLOW_MODES:
            mode_id = UNDERGLOW_MODES[key]
        elif key.isdigit():
            mode_id = int(key)
        else:
            raise ValueError(
                f"Unknown underglow mode {mode!r}; "
                f"expected {', '.join(UNDERGLOW_MODES)} or 0-4."
            )
    elif isinstance(mode, int):
        mode_id = mode
    else:
        raise ValueError(f"Invalid underglow mode type: {type(mode).__name__}")
    if not (0 <= mode_id <= 4):
        raise ValueError(f"Underglow mode must be 0-4, got {mode_id}")
    return mode_id


# --------------------------------------------------------------------------------------
# Keyboard layout (from rgb-keyboard.xml) - useful for the lighting experiments
# --------------------------------------------------------------------------------------
@dataclass
class KeyInfo:
    code: int
    name: str
    key_index: int
    light_index: int
    row: int
    col: int


def load_keymap(xml_path: str) -> dict:
    """Parse rgb-keyboard.xml into {name: KeyInfo}."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    keymap = {}
    for key in root.iter("key"):
        row_col = key.get("row_col", "0#0")
        row, col = (int(x) for x in row_col.split("#"))
        info = KeyInfo(
            code=int(key.get("code"), 16),
            name=key.get("name"),
            key_index=int(key.get("key_index")),
            light_index=int(key.get("light_index")),
            row=row,
            col=col,
        )
        keymap[info.name] = info
    return keymap


# --------------------------------------------------------------------------------------
# Main controller
# --------------------------------------------------------------------------------------
class AulaS75Pro:
    def __init__(self, mode: str = "usb", vid: Optional[int] = None, path: Optional[bytes] = None):
        """
        mode: 'auto' (wired USB preferred, 2.4G dongle fallback),
              'usb' (wired, 0x0C45:0x800A interface 3), or
              'dongle' (2.4G, 0x05AC:0x024F '2.4G Dongle' interface 3; 0x0C45:0xFEFE fallback).
        path: if you already know the exact hidapi device path, pass it directly.
        """
        if mode not in ("auto", "usb", "dongle"):
            raise ValueError("mode must be 'auto', 'usb', or 'dongle'")
        self.mode = mode
        self._explicit_vid = vid
        self._transport = "dongle" if mode == "dongle" else "usb"
        if mode == "dongle":
            self.vid = VID_DONGLE if vid is None else vid
            self.pid = PID_DONGLE
            self.interface = INTERFACE_DONGLE
        else:
            self.vid = VID if vid is None else vid
            self.pid = PID_USB
            self.interface = INTERFACE_USB
        self._path = path
        self.dev: Optional["hid.device"] = None

    @property
    def active_mode(self) -> str:
        """Resolved transport mode ('usb' or 'dongle')."""
        return self._transport

    @property
    def is_dongle(self) -> bool:
        return self._transport == "dongle"

    def _require_wired(self, op_name: str) -> None:
        if self.is_dongle:
            raise UnsupportedModeError(
                f"{op_name} is only supported in wired USB mode (0x0C45:0x800A); "
                "the 2.4G wireless dongle does not support 64-byte Feature flash/RAM read-back."
            )

    def _require_dongle(self, op_name: str) -> None:
        if not self.is_dongle:
            raise UnsupportedModeError(
                f"{op_name} is only supported over the 2.4G wireless dongle; "
                "use live 0x2004 streaming (AulaStreamer) in wired USB mode."
            )

    @staticmethod
    def _find_usb_candidate(vid: int) -> Optional[tuple[int, int, bytes]]:
        candidates = hid.enumerate(vid, PID_USB)
        if not candidates:
            return None

        # 1. Best: Match by Vendor-Defined Usage Page (Windows, macOS, hidapi-libusb)
        for d in candidates:
            if (d.get("usage_page") or 0) >= 0xFF00:
                return (vid, PID_USB, d["path"])

        # 2. Linux hidraw: usage_page is always 0, so fall back to interface 3.
        for d in candidates:
            if d.get("interface_number") == INTERFACE_USB:
                return (vid, PID_USB, d["path"])

        # 3. Active probe fallback (wired USB only; interface 3 accepts 64-byte feature reports)
        for d in candidates:
            test_dev = hid.device()
            try:
                test_dev.open_path(d["path"])
                try:
                    test_dev.get_feature_report(0, 65)
                finally:
                    test_dev.close()
                return (vid, PID_USB, d["path"])
            except (IOError, OSError, ValueError):
                continue

        return (vid, PID_USB, candidates[0]["path"])

    @staticmethod
    def _pick_dongle_interface3(candidates: list[dict]) -> Optional[bytes]:
        # Explicitly require interface_number == 3: 05AC:024F exposes Interface 4
        # as a separate 64-byte vendor interface, so matching usage_page >= 0xFF00 alone fails.
        iface3 = [d for d in candidates if d.get("interface_number") == INTERFACE_DONGLE]
        if not iface3:
            return None
        for d in iface3:
            if (d.get("usage_page") or 0) >= 0xFF00:
                return d["path"]
        return iface3[0]["path"]

    def _find_dongle_candidate(self) -> Optional[tuple[int, int, bytes]]:
        if self._explicit_vid is None or self._explicit_vid == VID_DONGLE:
            primary = [
                d for d in hid.enumerate(VID_DONGLE, PID_DONGLE)
                if (d.get("product_string") or "").strip() == DONGLE_PRODUCT_NAME
            ]
            path = self._pick_dongle_interface3(primary)
            if path is not None:
                return (VID_DONGLE, PID_DONGLE, path)

        fb_vid = VID_DONGLE_FALLBACK if self._explicit_vid is None else self._explicit_vid
        fb = hid.enumerate(fb_vid, PID_DONGLE_FALLBACK)
        path = self._pick_dongle_interface3(fb)
        if path is not None:
            return (fb_vid, PID_DONGLE_FALLBACK, path)
        return None

    def find_path(self) -> bytes:
        usb_vid = VID if self._explicit_vid is None else self._explicit_vid
        if self.mode in ("usb", "auto"):
            found = self._find_usb_candidate(usb_vid)
            if found is not None:
                self._transport = "usb"
                self.vid, self.pid, path = found
                self.interface = INTERFACE_USB
                return path
            if self.mode == "usb":
                raise IOError(f"No device found with VID={usb_vid:04X} PID={PID_USB:04X}")

        found = self._find_dongle_candidate()
        if found is not None:
            self._transport = "dongle"
            self.vid, self.pid, path = found
            self.interface = INTERFACE_DONGLE
            return path

        if self.mode == "auto":
            raise IOError(
                f"No AULA S75 Pro found in wired USB (VID={usb_vid:04X} PID={PID_USB:04X}) "
                f"or 2.4G dongle mode (VID={VID_DONGLE:04X} PID={PID_DONGLE:04X} "
                f"product={DONGLE_PRODUCT_NAME!r} iface={INTERFACE_DONGLE}, "
                f"fallback {VID_DONGLE_FALLBACK:04X}:{PID_DONGLE_FALLBACK:04X})"
            )
        raise IOError(
            f"No 2.4G dongle interface 3 found with VID={VID_DONGLE:04X} PID={PID_DONGLE:04X} "
            f"product={DONGLE_PRODUCT_NAME!r} (or fallback {VID_DONGLE_FALLBACK:04X}:{PID_DONGLE_FALLBACK:04X})"
        )


    def wait_until_idle(self):
        """
        Pre-flight check: polls the keyboard to confirm the MCU is idle
        (byte[3] != 0xFF in the GET_REPORT response) before issuing commands.

        If a previous script crashed mid-transaction the MCU stays in a
        half-open state (byte[3] == 0xFF); this method waits up to 2 s for it
        to settle naturally, then forces CMD_FINALIZE to abort.

        I/O errors (wrong interface, udev permission, device not present) are
        raised immediately as IOError — they are NOT retried, because retrying
        would only mask the real problem.
        """
        # --- First contact: any IOError here means a connection/permissions
        #     problem, not a busy MCU. Surface it immediately.
        try:
            resp = self.raw_get()
        except (IOError, OSError) as e:
            raise IOError(
                f"Cannot communicate with the keyboard: {e}\n"
                "Check: USB cable, /etc/udev/rules.d/70-aula-s75pro.rules "
                '(SUBSYSTEM=="usb" and SUBSYSTEM=="hidraw", ATTR/ATTRS{idVendor}=="0c45", '
                'ATTR/ATTRS{idProduct}=="800a", TAG+="uaccess"), '
                "and that no other process holds the device."
            ) from e

        # Idle: byte[3] is present and is not 0xFF.
        if len(resp) >= 4 and resp[3] != 0xFF:
            return

        # byte[3] == 0xFF (or response is shorter than expected): the MCU is
        # busy with a flash operation. Wait up to 2 s for it to finish.
        for _ in range(20):
            time.sleep(0.1)
            try:
                resp = self.raw_get()
                if len(resp) >= 4 and resp[3] != 0xFF:
                    return
            except (IOError, OSError) as e:
                # Device dropped off the bus mid-wait — not a busy state.
                raise IOError(
                    f"Lost communication while waiting for the keyboard to become idle: {e}"
                ) from e

        # Still busy after 2 s: likely stuck from a crashed script.
        # Force the MCU to abort its current transaction.
        print("Board is stuck in BUSY state. Forcing a state-machine reset...")
        self.send_cmd(CMD_FINALIZE)

        for _ in range(20):
            time.sleep(0.1)
            try:
                resp = self.raw_get()
                if len(resp) >= 4 and resp[3] != 0xFF:
                    print("Board recovered successfully.")
                    return
            except (IOError, OSError) as e:
                raise IOError(
                    f"Lost communication while recovering the keyboard: {e}"
                ) from e

        raise RuntimeError(
            "Keyboard MCU is locked in a BUSY state even after a forced reset.\n"
            "Please unplug and reconnect the keyboard."
        )


    def open(self):
        path = self._path or self.find_path()
        self.dev = hid.device()
        self.dev.open_path(path)
        self.dev.set_nonblocking(False)

        if self.is_dongle:
            try:
                self.ping_dongle()
            except (IOError, OSError) as e:
                self.close()
                raise IOError(
                    f"Cannot communicate with the 2.4G dongle: {e}\n"
                    "Check: dongle plugged in, /etc/udev/rules.d/70-aula-s75pro.rules "
                    '(SUBSYSTEM=="hidraw", ATTRS{idVendor}=="05ac", ATTRS{idProduct}=="024f", '
                    'ATTRS{product}=="2.4G Dongle", TAG+="uaccess"), '
                    "and that no other process holds the device."
                ) from e
            except Exception:
                self.close()
                raise
            return self

        # Check board status and abort stuck transactions before we do anything
        self.wait_until_idle()

        return self

    def close(self):
        if self.dev:
            self.dev.close()
            self.dev = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()

    # ---- raw transport ------------------------------------------------------
    def raw_send(self, payload: bytes):
        """Send a raw 64-byte feature report (SET_REPORT; wired USB only)."""
        self._require_wired("raw_send()")
        if self.dev is None:
            raise RuntimeError("Device is not open; call open() or use a 'with' block first.")
        if len(payload) != REPORT_LEN:
            raise ValueError(f"payload must be exactly {REPORT_LEN} bytes, got {len(payload)}")
        data = bytes([REPORT_ID]) + bytes(payload)
        self.dev.send_feature_report(data)

    def raw_get(self) -> bytes:
        """Read back a 64-byte feature report (GET_REPORT; wired USB only). Returns payload without report id."""
        self._require_wired("raw_get()")
        if self.dev is None:
            raise RuntimeError("Device is not open; call open() or use a 'with' block first.")
        data = self.dev.get_feature_report(REPORT_ID, REPORT_LEN + 1)
        return bytes(data[1:1 + REPORT_LEN])

    def _dongle_transact(
        self,
        cmd: int,
        length: int,
        seq: int = 0,
        payload: bytes = b"",
        *,
        retries: int = 20,
        read_timeout_ms: int = 100,
    ) -> bytes:
        """Send one 33-byte 2.4G Interrupt OUT frame and wait for matching Interrupt IN echo."""
        self._require_dongle(f"2.4G command 0x{cmd:02X}")
        if self.dev is None:
            raise RuntimeError("Device is not open; call open() or use a 'with' block first.")

        for _ in range(2):
            try:
                if not self.dev.read(DONGLE_PACKET_LEN, 2):
                    break
            except (IOError, OSError):
                break

        pkt = build_dongle_packet(cmd, length, seq, payload)
        written = self.dev.write(pkt)
        if written <= 0:
            time.sleep(0.01)
            written = self.dev.write(pkt)
            if written <= 0:
                raise IOError(f"hid.write() failed for 2.4G cmd 0x{cmd:02X} (returned {written})")

        time.sleep(0.005)

        exp_cmd = cmd & 0xFF
        exp_len = length & 0xFF
        exp_seq = seq & 0xFF
        last_reply = b""
        for _ in range(retries):
            raw = self.dev.read(DONGLE_PACKET_LEN, read_timeout_ms)
            reply = parse_dongle_reply(raw)
            if reply:
                last_reply = reply
            if (
                len(reply) >= 3
                and reply[0] == exp_cmd
                and reply[1] == exp_len
                and reply[2] == exp_seq
            ):
                return reply
        raise RuntimeError(
            f"2.4G dongle did not respond to cmd 0x{cmd:02X} "
            f"(len=0x{length:02X}, seq={seq}); ensure the keyboard is switched to 2.4G and awake. "
            f"Last reply: {last_reply.hex() if last_reply else 'None'}"
        )

    def ping_dongle(self) -> bytes:
        """Probe the 2.4G wireless keyboard link via cmd 0x02 (len=0x00, seq=0x00)."""
        return self._dongle_transact(DONGLE_CMD_INFO, 0x00, 0x00)

    def send_cmd(self, cmd: int, body: bytes = b"", trailer: bool = False, delay: float = 0.005):
        self.raw_send(build_report(cmd, body, trailer))
        if delay:
            time.sleep(delay)

    def _wait_ack(
        self,
        expected_cmd: int,
        retries: int = 50,
        delay: float = 0.05,
        settle: float = 0.036,
    ) -> bytes:
        """Read GET_REPORT until the device ACKs the expected command word (byte[3] == 0x01) or rejects with 0xFF."""
        self._require_wired("_wait_ack()")
        if self.dev is None:
            raise RuntimeError("Device is not open; call open() or use a 'with' block first.")
        expected_lo = expected_cmd & 0xFF
        expected_hi = (expected_cmd >> 8) & 0xFF
        last_resp = b""
        for _ in range(retries):
            resp = b""
            try:
                resp = self.raw_get()
                last_resp = resp
            except (IOError, OSError):
                pass
            if len(resp) >= 4 and resp[0] == expected_lo and resp[1] == expected_hi:
                if resp[3] == 0xFF:
                    raise McuRejectedError(
                        f"MCU rejected cmd {expected_cmd:#06x} with status 0xFF. "
                        f"Raw response: {resp.hex()}"
                    )
                if resp[3] == 0x01:
                    # Wait after GET_REPORT so the MCU main loop finishes transitioning
                    # (State 0 Phase 2 -> State 2, or State 3 -> State 0) before the
                    # next SET_REPORT overwrites hid_buf (0x2000135C).
                    if settle:
                        time.sleep(settle)
                    return resp
            time.sleep(delay)
        raise RuntimeError(f"MCU did not ACK cmd {expected_cmd:#06x}. Last resp: {last_resp.hex() if last_resp else 'None'}")

    @staticmethod
    def _build_general_settings_body(
        fn_switch: int = 0,
        sleep_time: int = 0,
        key_response_time: int = 0,
        disable_alt_tab: bool = False,
        disable_alt_f4: bool = False,
        win_lock: bool = False,
    ) -> bytes:
        return bytes([
            1 if disable_alt_tab else 0,
            1 if disable_alt_f4 else 0,
            1 if win_lock else 0,
            fn_switch & 0xFF,
            sleep_time & 0xFF,
            0,  # unused gap byte, always 0 in captures
            key_response_time & 0xFF,
        ])

    # ---- verified: general settings (Alt+Tab / Alt+F4 / Win-Lock / fn switch / sleep / response) ----
    def write_general_settings(
        self,
        fn_switch: int = 0,
        sleep_time: int = 0,
        key_response_time: int = 0,
        disable_alt_tab: bool = False,
        disable_alt_f4: bool = False,
        win_lock: bool = False,
        verify: bool = True,
    ) -> bytes:
        """
        Write general settings (wired 0x1704 to flash 0x00009000, or 2.4G 0x07 len=0x10).
        """
        body = self._build_general_settings_body(
            fn_switch=fn_switch,
            sleep_time=sleep_time,
            key_response_time=key_response_time,
            disable_alt_tab=disable_alt_tab,
            disable_alt_f4=disable_alt_f4,
            win_lock=win_lock,
        )
        payload = bytes(build_report(CMD_GENERAL_SETTINGS, body, trailer=True))

        if self.is_dongle:
            return self._dongle_transact(
                DONGLE_CMD_SETTINGS, DONGLE_SETTINGS_LEN, 0x00, payload[:14] + TRAILER
            )

        # Wired USB:
        # 1) open/ping
        self.send_cmd(CMD_OPEN)
        self._wait_ack(CMD_OPEN)

        # 2) probe 0x1704 (flash 0x00009000; firmware ignores profile index bytes)
        self.send_cmd(CMD_SETTINGS_WRITE, bytes([1, 0, 0, 0, 0, 0, 1]))
        self._wait_ack(CMD_SETTINGS_WRITE)

        # 3) the actual settings write (64-byte payload)
        self.raw_send(payload)
        time.sleep(0.05)

        # 4) commit / read back
        self.send_cmd(CMD_COMMIT, delay=0.036)
        try:
            resp = self._wait_ack(CMD_COMMIT)
        except RuntimeError as e:
            raise RuntimeError(
                f"Device never returned a ready response after general settings commit: {e}"
            ) from e

        if verify:
            expected = sum(payload) & 0xFFFFFFFF
            got = parse_commit_checksum(resp)
            if got != expected:
                raise RuntimeError(
                    f"Write-back 32-bit checksum mismatch on general settings: "
                    f"expected {expected:#010x}, device returned {got:#010x}. "
                    f"Raw response: {resp.hex()}"
                )
        return resp

    def set_key_response_time(
        self,
        value: int,
        sleep_time: int = 0,
        fn_switch: int = 0,
        disable_alt_tab: bool = False,
        disable_alt_f4: bool = False,
        win_lock: bool = False,
    ) -> bytes:
        return self.write_general_settings(
            fn_switch=fn_switch,
            sleep_time=sleep_time,
            key_response_time=value,
            disable_alt_tab=disable_alt_tab,
            disable_alt_f4=disable_alt_f4,
            win_lock=win_lock,
        )

    def set_sleep_time(
        self,
        value: int,
        key_response_time: int = 0,
        fn_switch: int = 0,
        disable_alt_tab: bool = False,
        disable_alt_f4: bool = False,
        win_lock: bool = False,
    ) -> bytes:
        return self.write_general_settings(
            fn_switch=fn_switch,
            sleep_time=value,
            key_response_time=key_response_time,
            disable_alt_tab=disable_alt_tab,
            disable_alt_f4=disable_alt_f4,
            win_lock=win_lock,
        )

    def _write_lighting_sequence(self, payload: bytearray | bytes, verify: bool = True):
        """Internal helper: Open → Probe(0x1304) → Payload → Commit → Finalize.

        Commit polling: PROTOCOL.md §2 documents that the MCU can return
        all-zeros during flash housekeeping while the write is still being
        applied.  A commit-poll timeout is therefore a soft warning, not a
        hard error — the lighting write has already been applied.
        """
        payload_bytes = bytes(payload)
        self.send_cmd(CMD_OPEN)
        self._wait_ack(CMD_OPEN)

        self.send_cmd(CMD_LIGHTING_WRITE, bytes([0, 0, 0, 0, 0, 0, 1]))
        self._wait_ack(CMD_LIGHTING_WRITE)

        self.raw_send(payload_bytes)
        time.sleep(0.05)

        self.send_cmd(CMD_COMMIT, delay=0.036)
        ack_valid = True
        ack = b""
        try:
            ack = self._wait_ack(CMD_COMMIT, retries=60, delay=0.05)
        except McuRejectedError:
            raise
        except RuntimeError as e:
            resp = self.raw_get()
            if resp and any(b != 0 for b in resp):
                raise  # non-zero unexpected content — real error, re-raise
            print(
                f"warning: commit poll timed out ({e}); "
                "MCU is busy with flash housekeeping — lighting write has "
                "applied (PROTOCOL.md §2, verified behaviour)."
            )
            ack_valid = False

        if ack_valid and verify:
            expected = sum(payload_bytes) & 0xFFFFFFFF
            got = parse_commit_checksum(ack)
            if got != expected:
                raise RuntimeError(
                    f"Lighting write 32-bit checksum mismatch: "
                    f"expected {expected:#010x}, MCU returned {got:#010x}. "
                    f"Raw response: {ack.hex()}"
                )

        self.send_cmd(CMD_FINALIZE)
        time.sleep(0.1)


    def set_global_lighting(self, effect: int, r: int, g: int, b: int, brightness: int = 5, speed: int = 3, direction: int = 0, option: int = 0):
        effect = _validate_int_range(effect, "effect", 0, 19)
        payload = self._build_mode_payload(
            effect=effect, r=r, g=g, b=b,
            brightness=brightness, speed=speed,
            direction=direction, option=option,
        )
        if self.is_dongle:
            self._dongle_transact(
                DONGLE_CMD_LIGHTING, DONGLE_SETTINGS_LEN, 0x00, bytes(payload[:14]) + TRAILER
            )
            return
        # Wired USB: double sequence required to clear MCU animation pointers.
        # 0.5 s gap: the first CMD_FINALIZE can trigger a flash write that
        # takes several seconds; starting the second sequence too soon causes
        # the second commit poll to hit the all-zeros flash-busy window.
        for _ in range(2):
            self._write_lighting_sequence(payload)
            time.sleep(0.5)


    def set_custom_lighting(self, key_colors: dict, brightness: int = 5):
        """
        Apply a per-key custom colour table and save it to flash
        (wired 0x1304/0x2304 two-transaction flow or 2.4G 0x05 + 21x 0x14 chunks).

        Args:
            key_colors: {light_index (int): (r, g, b)} — keys not listed are
                        left dark (0, 0, 0).  light_index must be a member of
                        PHYSICAL_INDICES (keymap.py); any other value is
                        rejected to prevent accidentally corrupting the AA 55
                        trailer at slot 143.
            brightness: brightness byte passed to Transaction A's mode-select
                        write (0–5; default 5 matches the official driver).
        """
        # ---- validate --------------------------------------------------------
        # PHYSICAL_INDICES is the allowlist of safe light_index values derived
        # from rgb-keyboard.xml (hardcoded in keymap.py; no runtime XML parse).
        # Anything not in the set is either reserved (slot 0), a gap in the
        # keyboard matrix, or close enough to the trailer at offsets 574–575
        # (slot 143) to be unsafe.
        brightness = _validate_int_range(brightness, "brightness", 0, 5)
        for idx, rgb in key_colors.items():
            if idx not in PHYSICAL_INDICES:
                raise ValueError(
                    f"light_index {idx} is not a known physical key "
                    f"(see keymap.PHYSICAL_INDICES or run 'list-keys')."
                )
            r, g, b = rgb
            for name, val in (("r", r), ("g", g), ("b", b)):
                _validate_int_range(val, f"key {idx} {name}", 0, 255)

        # ---- build the 576-byte table buffer ---------------------------------
        table = bytearray(TABLE_SIZE)
        for idx in PHYSICAL_INDICES:            # pass 1: stamp every physical key's index byte
            table[idx * 4] = idx
        for idx, (r, g, b) in key_colors.items():   # pass 2: apply caller's colours
            off = idx * 4
            table[off]     = idx
            table[off + 1] = r
            table[off + 2] = g
            table[off + 3] = b
        table[574] = 0xAA
        table[575] = 0x55

        if self.is_dongle:
            mode_16 = bytes(self._build_mode_payload(effect=0x80, brightness=brightness)[:14]) + TRAILER
            self._dongle_transact(DONGLE_CMD_LIGHTING, DONGLE_SETTINGS_LEN, 0x00, mode_16)
            time.sleep(0.05)
            total_chunks = (len(table) + DONGLE_PAYLOAD_LEN - 1) // DONGLE_PAYLOAD_LEN
            for seq in range(total_chunks):
                chunk = bytes(table[seq * DONGLE_PAYLOAD_LEN : (seq + 1) * DONGLE_PAYLOAD_LEN])
                self._dongle_transact(DONGLE_CMD_CUSTOM_RGB, len(chunk), seq, chunk)
                if seq + 1 < total_chunks:
                    time.sleep(0.002)
            return

        # Compute full 32-bit byte-sum checksum returned in CMD_COMMIT resp[4..7].
        expected_checksum = sum(table) & 0xFFFFFFFF

        def _run_once():
            # -- Transaction A: switch board to custom-light mode (0x80) ------
            # Re-uses _write_lighting_sequence so we get the same soft-error
            # handling on its commit poll (all-zeros = flash busy, not rejected).
            self._write_lighting_sequence(
                self._build_mode_payload(effect=0x80, brightness=brightness)
            )
            time.sleep(0.5)

            # -- Transaction B: upload 576-byte table via 0x2304 page ---------
            self.send_cmd(CMD_OPEN)
            self._wait_ack(CMD_OPEN)

            # Probe 0x2304: payload[8] = 0x09 (RGB table, 576 bytes).
            # send_cmd places cmd at report[0:2], body at report[2:].
            # So body index 6 lands at report byte 8.
            self.send_cmd(CMD_LIGHT_APPLY_BASE, bytes([0, 0, 0, 0, 0, 0, 9]))
            self._wait_ack(CMD_LIGHT_APPLY_BASE)

            # Stream 9 raw 64-byte chunks — NO 0x0100 prefix (PROTOCOL.md §5).
            for chunk_idx in range(TABLE_CHUNKS):
                chunk = bytes(table[chunk_idx * REPORT_LEN : (chunk_idx + 1) * REPORT_LEN])
                self.raw_send(chunk)
                time.sleep(0.035)   # ~35 ms cadence matches official driver

            # Commit: send then wait ~35 ms before polling the ACK.
            self.send_cmd(CMD_COMMIT, delay=0.0)
            time.sleep(0.035)
            ack_valid = True
            try:
                ack = self._wait_ack(CMD_COMMIT, retries=60, delay=0.05)
            except McuRejectedError:
                raise
            except RuntimeError as e:
                # Same soft-error path as _write_lighting_sequence: all-zeros
                # during flash housekeeping is expected and the write applies.
                ack = self.raw_get()
                if ack and any(byte != 0 for byte in ack):
                    raise  # non-zero unexpected — real error, re-raise
                print(
                    f"warning: custom table commit poll timed out ({e}); "
                    "MCU busy with flash housekeeping — table write has "
                    "applied (PROTOCOL.md §5, verified behaviour). "
                    "Skipping checksum verification (ACK was all-zeros)."
                )
                ack_valid = False

            # Checksum verification (resp[4..7] = 32-bit LE sum).
            if ack_valid:
                if len(ack) >= 8:
                    mcu_checksum = parse_commit_checksum(ack)
                    if mcu_checksum != expected_checksum:
                        print(
                            f"warning: table checksum mismatch — "
                            f"host computed {expected_checksum:#010x}, "
                            f"MCU returned {mcu_checksum:#010x}. "
                            "The upload may have been corrupted; consider retrying."
                        )
                    else:
                        print(f"Custom table checksum OK ({mcu_checksum:#010x}).")
                else:
                    print("warning: ACK response too short to read checksum.")

            # Finalize: ~35 ms after commit ACK (PROTOCOL.md §5 step 11)
            time.sleep(0.035)
            self.send_cmd(CMD_FINALIZE)
            time.sleep(0.1)

        # Run the full two-transaction block twice, as the official driver does.
        _run_once()
        time.sleep(0.5)
        _run_once()

    @staticmethod
    def _build_mode_payload(effect: int, r: int = 0, g: int = 0, b: int = 0,
                            brightness: int = 5, speed: int = 3,
                            direction: int = 0, option: int = 0) -> bytearray:
        """Build the 64-byte payload for a 0x1304 lighting-mode write.

        Extracted from set_global_lighting so set_custom_lighting can call
        _write_lighting_sequence directly with the right mode (0x80).
        """
        if isinstance(effect, bool) or not isinstance(effect, int) or (not (0 <= effect <= 19) and effect != 0x80):
            raise ValueError(f"effect must be 0..19 or 0x80, got {effect!r}")
        r = _validate_int_range(r, "r", 0, 255)
        g = _validate_int_range(g, "g", 0, 255)
        b = _validate_int_range(b, "b", 0, 255)
        brightness = _validate_int_range(brightness, "brightness", 0, 5)
        speed = _validate_int_range(speed, "speed", 0, 5)
        direction = _validate_int_range(direction, "direction", 0, 2)
        option = _validate_int_range(option, "option", 0, 1)

        payload = bytearray(REPORT_LEN)
        payload[0] = effect
        if effect != 0:
            payload[1] = r
            payload[2] = g
            payload[3] = b
            payload[8] = option
            payload[9] = brightness
            payload[10] = speed
            payload[11] = direction
        payload[14] = 0xAA
        payload[15] = 0x55
        return payload


    def sync_rtc(self, when: Optional["datetime"] = None):
        """
        Sync the keyboard's RTC to the PC clock (wired 0x2804 or 2.4G 0x0C len=0x10).
        Pass `when` for deterministic tests.
        """
        from datetime import datetime
        t = when or datetime.now()
        body = bytes([0x5A, t.year - 2000, t.month, t.day,
                      t.hour, t.minute, t.second, 0x00, t.isoweekday() % 7])

        if self.is_dongle:
            payload_16 = _le16(CMD_GENERAL_SETTINGS) + body + bytes(3) + TRAILER
            return self._dongle_transact(DONGLE_CMD_RTC, DONGLE_SETTINGS_LEN, 0x00, payload_16)

        self.send_cmd(CMD_OPEN)
        self._wait_ack(CMD_OPEN)

        self.send_cmd(CMD_RTC_WRITE, bytes([0, 0, 0, 0, 0, 0, 1]))
        self._wait_ack(CMD_RTC_WRITE)

        payload = bytes(build_report(CMD_GENERAL_SETTINGS, body, trailer=True))
        self.raw_send(payload)
        time.sleep(0.036)

        self.send_cmd(CMD_COMMIT, delay=0.036)
        return self._wait_ack(CMD_COMMIT)

    # ---- State-1 read helpers & firmware info/battery/underglow -------------
    def _read_state1_chunks(
        self,
        cmd: int,
        chunks: int = 1,
        *,
        delay: float = 0.036,
        verify: bool = True,
        is_live_ram: bool = False,
    ) -> tuple[list[bytes], int]:
        """Execute a State-1 read transaction (wired USB only)."""
        self._require_wired(f"State-1 read 0x{cmd:04X}")
        if chunks < 1:
            raise ValueError(f"chunks must be >= 1, got {chunks}")

        exp_lo = cmd & 0xFF
        exp_hi = (cmd >> 8) & 0xFF
        probe = bytes(
            build_report(cmd, bytes([0, 0, 0, 0, 0, 0, chunks & 0xFF, (chunks >> 8) & 0xFF]))
        )
        self.raw_send(probe)
        if delay:
            time.sleep(delay)

        resp1 = self.raw_get()
        is_cmd_echo = len(resp1) >= 4 and resp1[0] == exp_lo and resp1[1] == exp_hi
        if is_cmd_echo and resp1[3] == 0xFF:
            raise McuRejectedError(
                f"MCU returned 0xFF (rejected/busy) on read cmd {cmd:#06x}. Raw: {resp1.hex()}"
            )

        data_chunks: list[bytes] = []
        if is_cmd_echo and resp1[3] == 0x01:
            for _ in range(chunks):
                if delay:
                    time.sleep(delay)
                data_chunks.append(self.raw_get())
        else:
            data_chunks.append(resp1)
            for _ in range(1, chunks):
                if delay:
                    time.sleep(delay)
                data_chunks.append(self.raw_get())

        # Let the final chunk's GET_REPORT bit-1 flag settle in FUN_0000407a
        # (preloading any trailing block and transitioning State 1 -> State 3)
        # before SET 0x0204 writes hid_buf, otherwise FUN_0000407a can clobber
        # 04 02 with trailing flash data and cause State 3 to return 0xFF.
        if delay:
            time.sleep(delay)

        self.raw_send(bytes(build_report(CMD_COMMIT)))
        if delay:
            time.sleep(delay)
        # Allow State 3 (0x00003E94-0x00003EA8) to finish clearing usb_flags = 0
        # and return to State 0 before an immediate follow-up command runs.
        commit_resp = self._wait_ack(CMD_COMMIT, retries=20, delay=delay, settle=delay)
        mcu_sum = parse_commit_checksum(commit_resp)

        if verify:
            if is_live_ram:
                if mcu_sum != 0:
                    raise RuntimeError(
                        f"Live RGB RAM commit checksum mismatch for {cmd:#06x}: "
                        f"expected 0x00000000, MCU returned {mcu_sum:#010x}."
                    )
            else:
                host_sum = sum(sum(c) for c in data_chunks)
                if not (host_sum <= mcu_sum <= host_sum + 64 * 0xFF):
                    raise RuntimeError(
                        f"Flash read commit checksum out of range for {cmd:#06x}: "
                        f"host chunk sum={host_sum:#010x}, MCU returned {mcu_sum:#010x} "
                        f"(expected [{host_sum:#010x}, {host_sum + 64 * 0xFF:#010x}])."
                    )

        return data_chunks, mcu_sum

    @staticmethod
    def _unpack_rgb_slots(raw: bytes, *, skip_zero_slot: bool) -> dict[int, tuple[int, int, int]]:
        keys: dict[int, tuple[int, int, int]] = {}
        for slot_idx in range(len(raw) // 4):
            off = slot_idx * 4
            if raw[off] == slot_idx and (not skip_zero_slot or slot_idx > 0):
                keys[slot_idx] = (raw[off + 1], raw[off + 2], raw[off + 3])
        return keys

    @staticmethod
    def _unpack_device_info_block(block: bytes) -> dict:
        tag = struct.unpack_from("<H", block, 0)[0]
        vid = struct.unpack_from("<H", block, 4)[0]
        pid = struct.unpack_from("<H", block, 6)[0]
        fw_minor = block[8]
        fw_major = block[9]
        return {
            "tag": tag,
            "vid": vid,
            "pid": pid,
            "fw_major": fw_major,
            "fw_minor": fw_minor,
            "fw_version": f"{fw_major}.{fw_minor:02d}",
        }

    def read_device_info(self) -> dict:
        """Read firmware/device info block from flash 0x00008F80 (wired 0x0504 or 2.4G 0x02)."""
        if self.is_dongle:
            reply = self._dongle_transact(DONGLE_CMD_INFO, 0x00, 0x00)
            block = reply[3:31]
            return {
                **self._unpack_device_info_block(block),
                "checksum": None,
                "transport": "dongle",
                "raw": block,
            }
        chunks, mcu_sum = self._read_state1_chunks(CMD_DEVICE_INFO, chunks=1)
        chunk = chunks[0]
        return {
            **self._unpack_device_info_block(chunk),
            "checksum": mcu_sum,
            "transport": "usb",
            "raw": chunk,
        }

    def read_battery_level(self, delay: float = 0.036) -> dict:
        """Read battery level: quantized 0-5 in wired mode (0xF604) or exact 0-100% over 2.4G (0x20)."""
        if self.is_dongle:
            reply = self._dongle_transact(DONGLE_CMD_BATTERY, 0x01, 0x00)
            if len(reply) < 4:
                raise RuntimeError(f"2.4G battery reply too short: {reply.hex()}")
            percent = reply[3]
            level = battery_percent_to_level(percent)
            return {
                "level": level,
                "percent": percent,
                "percent_range": BATTERY_RANGES.get(level, "unknown"),
                "transport": "dongle",
                "raw": reply,
            }
        self.raw_send(bytes(build_report(CMD_BATTERY_LEVEL)))
        if delay:
            time.sleep(delay)
        resp = self.raw_get()
        exp_lo = CMD_BATTERY_LEVEL & 0xFF
        exp_hi = (CMD_BATTERY_LEVEL >> 8) & 0xFF
        if len(resp) < 5 or resp[0] != exp_lo or resp[1] != exp_hi:
            raise RuntimeError(
                f"Unexpected response for CMD_BATTERY_LEVEL (0xF604): {resp.hex()}"
            )
        if resp[3] == 0xFF:
            raise McuRejectedError(f"MCU rejected 0xF604 battery query: {resp.hex()}")
        if resp[3] != 0x01:
            raise RuntimeError(
                f"Unexpected status 0x{resp[3]:02x} for 0xF604 battery query: {resp.hex()}"
            )
        level = resp[4]
        return {
            "level": level,
            "percent": None,
            "percent_range": BATTERY_RANGES.get(level, "unknown"),
            "transport": "usb",
            "raw": resp,
        }

    def read_lighting_config(self) -> dict:
        """Read saved main-key lighting config from flash 0x00009800 via CMD_LIGHTING_READ (0x1204)."""
        self._require_wired("read_lighting_config()")
        chunks, mcu_sum = self._read_state1_chunks(CMD_LIGHTING_READ, chunks=1)
        chunk = chunks[0]
        return {
            "raw": chunk,
            "erased": all(b == 0xFF for b in chunk),
            "zeroed": all(b == 0x00 for b in chunk),
            "effect": chunk[0],
            "rgb": (chunk[1], chunk[2], chunk[3]),
            "option": chunk[8],
            "brightness": chunk[9],
            "speed": chunk[10],
            "direction": chunk[11],
            "trailer": chunk[14:16],
            "checksum": mcu_sum,
        }

    def read_general_settings(self) -> dict:
        """Read saved general settings page from flash 0x00009000 via CMD_SETTINGS_READ (0x1604)."""
        self._require_wired("read_general_settings()")
        chunks, mcu_sum = self._read_state1_chunks(CMD_SETTINGS_READ, chunks=1)
        chunk = chunks[0]
        sleep_time = chunk[6]
        key_resp = chunk[8]
        return {
            "raw": chunk,
            "erased": all(b == 0xFF for b in chunk),
            "zeroed": all(b == 0x00 for b in chunk),
            "disable_alt_tab": bool(chunk[2]),
            "disable_alt_f4": bool(chunk[3]),
            "win_lock": bool(chunk[4]),
            "fn_switch": chunk[5],
            "sleep_time": sleep_time,
            "sleep_label": SLEEP_TIME_LABELS.get(sleep_time, "unknown"),
            "key_response_time": key_resp,
            "debounce_scans": DEBOUNCE_SCANS.get(key_resp, 3),
            "checksum": mcu_sum,
        }

    def read_live_rgb(self, chunks: int = TABLE_CHUNKS) -> dict:
        """Read live RGB RAM arrays (0x20001838/195E/1A84) via CMD_LIGHT_READ (0xF504)."""
        self._require_wired("read_live_rgb()")
        raw_chunks, mcu_sum = self._read_state1_chunks(
            CMD_LIGHT_READ, chunks=chunks, is_live_ram=True
        )
        raw = b"".join(raw_chunks)
        return {
            "keys": self._unpack_rgb_slots(raw, skip_zero_slot=False),
            "checksum": mcu_sum,
            "raw": raw,
        }

    def read_custom_lighting_table(self, chunks: int = TABLE_CHUNKS) -> dict:
        """Read saved custom RGB table from flash 0x00009C00 via CMD_CUSTOM_LIGHT_READ (0x2204)."""
        self._require_wired("read_custom_lighting_table()")
        raw_chunks, mcu_sum = self._read_state1_chunks(CMD_CUSTOM_LIGHT_READ, chunks=chunks)
        raw = b"".join(raw_chunks)
        return {
            "keys": self._unpack_rgb_slots(raw, skip_zero_slot=True),
            "trailer": raw[-2:],
            "checksum": mcu_sum,
            "raw": raw,
        }

    def set_underglow_mode(self, mode: int | str, preserve_lighting: bool = True) -> dict:
        """
        Set Row-6 side / underglow lighting mode (0=flowing, 1=spectrum, 2=static,
        3=breathing, 4=off) via wired 0x1304 or 2.4G 0x05 (payload[0] = 0x20 + mode).

        In wired mode, 0x1304 Phase 1 erases flash page 0x00009800 before FUN_00003f42
        skips writing it for 0x20-0x24, so preserve_lighting=True reads and restores 0x9800.
        Over 2.4G, FUN_00005990 opcode 0x05 updates 0x20000194 directly without erasing 0x9800.
        """
        mode_id = _parse_underglow_mode(mode)

        if self.is_dongle:
            payload_16 = bytes([0x20 + mode_id]) + bytes(13) + TRAILER
            self._dongle_transact(DONGLE_CMD_LIGHTING, DONGLE_SETTINGS_LEN, 0x00, payload_16)
            return {
                "mode": mode_id,
                "mode_name": UNDERGLOW_MODE_NAMES[mode_id],
                "checksum": None,
                "checksum_matched": None,
                "restored_lighting": False,
                "transport": "dongle",
            }

        saved = self.read_lighting_config() if preserve_lighting else None

        self.send_cmd(CMD_OPEN, delay=0.036)
        self._wait_ack(CMD_OPEN)

        self.send_cmd(CMD_LIGHTING_WRITE, bytes([0, 0, 0, 0, 0, 0, 1]), delay=0.036)
        self._wait_ack(CMD_LIGHTING_WRITE)

        payload = bytearray(REPORT_LEN)
        payload[0] = 0x20 + mode_id
        self.raw_send(bytes(payload))
        # Give FUN_00003f42 / FUN_0000df18() time to update flash 0x8000 and
        # transition State 2 -> State 3 before sending CMD_COMMIT (0x0204).
        time.sleep(0.12)

        self.send_cmd(CMD_COMMIT, delay=0.0)
        time.sleep(0.05)
        commit_resp = self._wait_ack(CMD_COMMIT, retries=20, delay=0.05)
        mcu_sum = parse_commit_checksum(commit_resp)
        checksum_matched = mcu_sum == EXPECTED_UNDERGLOW_ERASED_CHECKSUM
        if not checksum_matched:
            warnings.warn(
                f"Underglow commit checksum 0x{mcu_sum:08x} != expected "
                f"0x{EXPECTED_UNDERGLOW_ERASED_CHECKSUM:08x} "
                "(firmware may have shifted uninitialized stack word).",
                RuntimeWarning,
                stacklevel=2,
            )

        # Persist 0x20000194 underglow mode into flash 0x8000 and unblank LEDs.
        self.send_cmd(CMD_FINALIZE, delay=0.0)
        time.sleep(0.1)

        restored = False
        if (
            saved is not None
            and not saved["erased"]
            and not saved["zeroed"]
            and (saved["raw"][0] >> 4) != 2
        ):
            time.sleep(0.2)
            self._write_lighting_sequence(bytearray(saved["raw"]), verify=True)
            restored = True

        return {
            "mode": mode_id,
            "mode_name": UNDERGLOW_MODE_NAMES[mode_id],
            "checksum": mcu_sum,
            "checksum_matched": checksum_matched,
            "restored_lighting": restored,
            "transport": "usb",
        }

    def send_wireless_music_eq(
        self,
        heights,
        fg_style: int = 1,
        bg_style: int = 0,
        mode: int = 0,
    ) -> bytes:
        """Send a 15-column x 6-row 2.4G wireless music EQ frame via opcode 0x0B (len=0x1C).

        Firmware FUN_00005990 accepts fg_style/bg_style (0-11), mode (0-255),
        and 15 column heights clamped to 0-6 rows; per-key freeform RGB
        streaming (0x2004) is wired USB only.
        """
        self._require_dongle("send_wireless_music_eq (0x0B)")
        for label, val, hi in (("fg_style", fg_style, 11), ("bg_style", bg_style, 11), ("mode", mode, 255)):
            if isinstance(val, bool) or not isinstance(val, int) or not (0 <= val <= hi):
                raise ValueError(f"{label} must be an int in range 0..{hi}, got {val!r}")
        cols = list(heights)
        if len(cols) != 15:
            raise ValueError(f"heights must have exactly 15 columns, got {len(cols)}")
        clamped: list[int] = []
        for i, h in enumerate(cols):
            if isinstance(h, bool):
                raise ValueError(f"column {i} height must be int 0..6, got bool")
            clamped.append(max(0, min(6, int(h))))
        payload = bytes([fg_style, bg_style, mode] + clamped)
        return self._dongle_transact(DONGLE_CMD_MUSIC_EQ, DONGLE_PAYLOAD_LEN, 0x00, payload)


