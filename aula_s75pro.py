"""
aula_s75pro.py
==============

Reverse-engineered control library for the AULA S75Pro keyboard driver protocol.

Source material this was built from (all provided by the user):
  - config.xml            -> VID/PID/interface identifiers, driver metadata
  - rgb-keyboard.xml       -> full per-key layout (scan code / light_index / position)
  - decomiledFromExe.txt  -> Ghidra decompilation snippets of the official Windows driver
  - KeyResponseTimeLogs.txt / TimeToSleepLogs.txt
                            -> tshark USB captures of the driver changing the
                               "key response time" and "sleep timer" settings

See PROTOCOL.md in this folder for the full write-up of what was verified vs. inferred.
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional

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
# Device identification (from config.xml)
# --------------------------------------------------------------------------------------
VID = 0x0C45

PID_USB = 0x800A       # mode value="0" desc="USB"       hid_interface="VID_0C45&PID_800A&MI_00"
PID_DONGLE = 0xFEFE    # mode value="2" desc="2.4G TYPE-A" hid_interface="VID_0C45&PID_FEFE&MI_03"

# Interface number embedded in the Windows hid_interface string (MI_00 / MI_03)
INTERFACE_USB = 0
INTERFACE_DONGLE = 3

REPORT_ID = 0x00
REPORT_LEN = 64  # payload length (wLength = 0x40), NOT counting the HID report-id byte

# Command words (little-endian on the wire: byte0=lo, byte1=hi)
CMD_OPEN = 0x1804        # generic "begin" ping, sent before almost every write
CMD_PROBE = 0x1704       # fixed probe/ack, sent before the general settings write
CMD_GENERAL_SETTINGS = 0x0100   # fn-switch / sleep-timer / key-response write
CMD_COMMIT = 0x0204       # commit / select page for read-back
CMD_FINALIZE = 0xF004     # finalize, seen after bulk (lighting) writes
CMD_LIGHT_APPLY_BASE = 0x2304   # EXPERIMENTAL - "apply custom light" (mode byte varies)
CMD_LIGHT_READ = 0x04F5   # EXPERIMENTAL - readback current light table (GET)
CMD_STREAM_FRAME = 0x2004 # frame update for dynamic RGB music mode

TRAILER = b"\xAA\x55"     # observed at the very end of the 64-byte buffer on writes


def _le16(cmd: int) -> bytes:
    """Encode a command word as little-endian bytes (byte0=lo, byte1=hi)."""
    return bytes([cmd & 0xFF, (cmd >> 8) & 0xFF])


def build_report(cmd: int, body: bytes = b"", trailer: bool = False, size: int = REPORT_LEN) -> bytearray:
    """Build a full 64-byte report: [cmd_lo, cmd_hi, ...body..., zero padding, (AA 55)?]"""
    buf = bytearray(size)
    buf[0:2] = _le16(cmd)
    buf[2:2 + len(body)] = body
    if trailer:
        buf[-2:] = TRAILER
    return buf


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
    def __init__(self, mode: str = "usb", vid: int = VID, path: Optional[bytes] = None):
        """
        mode: 'usb' (wired, PID 0x800A, interface 0) or 'dongle' (2.4G, PID 0xFEFE, interface 3)
        path: if you already know the exact hidapi device path, pass it directly and
              `mode`/`vid` are ignored for opening.
        """
        self.mode = mode
        self.vid = vid
        if mode == "usb":
            self.pid, self.interface = PID_USB, INTERFACE_USB
        elif mode == "dongle":
            self.pid, self.interface = PID_DONGLE, INTERFACE_DONGLE
        else:
            raise ValueError("mode must be 'usb' or 'dongle'")
        self._path = path
        self.dev: Optional["hid.device"] = None

    # ---- connection -------------------------------------------------------
    def find_path(self) -> bytes:
        candidates = [
            d for d in hid.enumerate(self.vid, self.pid)
            if d.get("interface_number") == self.interface
        ]
        if not candidates:
            # fall back to any interface on that VID/PID, in case the OS numbers differently
            candidates = [d for d in hid.enumerate(self.vid, self.pid)]
        if not candidates:
            raise IOError(
                f"No HID device found for VID={self.vid:04X} PID={self.pid:04X}. "
                "Is the keyboard connected in the right mode (usb/dongle)?"
            )
        return candidates[0]["path"]

    def wait_until_idle(self):
        """
        Pre-flight check: Polls the keyboard to see if the MCU is 'Busy' (byte[3] == 0xFF).
        If a previous script crashed, it forces a reset command to clear the state machine.
        """
        try:
            resp = self.raw_get()
        except Exception:
            resp = b""

        # If byte 3 is NOT 0xFF, it's already idle and ready for commands.
        if len(resp) >= 4 and resp[3] != 0xFF:
            return

        # It's busy. Wait up to 2 seconds to see if it finishes writing to flash naturally.
        for _ in range(20):
            time.sleep(0.1)
            try:
                resp = self.raw_get()
                if len(resp) >= 4 and resp[3] != 0xFF:
                    return
            except Exception:
                pass

        # If it is STILL busy, it's likely permanently stuck in a half-open state 
        # from a crashed script. Send CMD_FINALIZE to force the MCU to abort and reset.
        print("Board is stuck in BUSY state. Forcing a state-machine reset...")
        self.send_cmd(CMD_FINALIZE)
        
        for _ in range(20):
            time.sleep(0.1)
            try:
                resp = self.raw_get()
                if len(resp) >= 4 and resp[3] != 0xFF:
                    print("Board recovered successfully.")
                    return
            except Exception:
                pass

        raise RuntimeError("Keyboard MCU is locked in a BUSY state. Please unplug and plug it back in.")

    def open(self):
        path = self._path or self.find_path()
        self.dev = hid.device()
        self.dev.open_path(path)
        self.dev.set_nonblocking(False)
        
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
        """Send a raw 64-byte feature report (SET_REPORT)."""
        if len(payload) != REPORT_LEN:
            raise ValueError(f"payload must be exactly {REPORT_LEN} bytes, got {len(payload)}")
        data = bytes([REPORT_ID]) + bytes(payload)
        self.dev.send_feature_report(data)

    def raw_get(self) -> bytes:
        """Read back a 64-byte feature report (GET_REPORT). Returns payload without report id."""
        data = self.dev.get_feature_report(REPORT_ID, REPORT_LEN + 1)
        return bytes(data[1:1 + REPORT_LEN])

    def send_cmd(self, cmd: int, body: bytes = b"", trailer: bool = False, delay: float = 0.005):
        self.raw_send(build_report(cmd, body, trailer))
        if delay:
            time.sleep(delay)

    def _wait_ack(self, expected_cmd: int, retries: int = 50, delay: float = 0.05) -> bytes:
        """Read GET_REPORT until the device ACKs the expected command word and signals ready (byte[3] == 0x01)."""
        expected_lo = expected_cmd & 0xFF
        expected_hi = (expected_cmd >> 8) & 0xFF
        last_resp = b""
        for attempt in range(retries):
            try:
                resp = self.raw_get()
                last_resp = resp
                if len(resp) >= 4 and resp[0] == expected_lo and resp[1] == expected_hi and resp[3] == 0x01:
                    return resp
            except Exception:
                pass
            time.sleep(delay)
        raise RuntimeError(f"MCU did not ACK cmd {expected_cmd:#06x}. Last resp: {last_resp.hex() if last_resp else 'None'}")

    # ---- verified: general settings (fn switch / sleep timer / key response) ----
    def write_general_settings(
        self,
        fn_switch: int = 0,
        sleep_time: int = 0,
        key_response_time: int = 0,
        fn_enabled: bool = False,
        sleep_enabled: bool = False,
        key_response_enabled: bool = False,
        verify: bool = True,
    ) -> bytes:
        """
        Replicates the exact sequence captured from the official driver
        (decompiled function FUN_004141a0) when it saves the "fn layer / sleep
        timer / key response time" settings panel.
        """
        final_resp = b""

        # Loop through both Profile 0 (Wired) and Profile 1 (Wireless)
        for profile_index in (0, 1):
            # 1) open/ping
            self.send_cmd(CMD_OPEN)
            self._wait_ack(CMD_OPEN)

            # 2) fixed probe (profile_index selects which profile's settings
            #    the following write applies to)
            self.send_cmd(CMD_PROBE, bytes([1, profile_index, 0, 0, 0, 0, 1]))
            self._wait_ack(CMD_PROBE)

            # 3) the actual settings write
            body = bytes([
                1 if fn_enabled else 0,
                1 if sleep_enabled else 0,
                1 if key_response_enabled else 0,
                fn_switch & 0xFF,
                sleep_time & 0xFF,
                0,  # unused gap byte, always 0 in captures
                key_response_time & 0xFF,
            ])
            self.send_cmd(CMD_GENERAL_SETTINGS, body, trailer=True)

            # 4) commit / read back
            self.send_cmd(CMD_COMMIT)
            try:
                resp = self._wait_ack(CMD_COMMIT)
            except RuntimeError as e:
                raise RuntimeError(
                    f"Device never returned a ready response after commit on "
                    f"profile {profile_index}: {e}"
                ) from e

            if verify:
                expected = (fn_switch + sleep_time + key_response_time) & 0xFF
                got = resp[4]
                if got != expected:
                    raise RuntimeError(
                        f"Write-back checksum mismatch on profile {profile_index}: "
                        f"expected {expected:#04x}, device returned {got:#04x}. "
                        f"Raw response: {resp.hex()}"
                    )
            final_resp = resp

        return final_resp

    def set_key_response_time(self, value: int, sleep_time: int = 0, fn_switch: int = 0) -> bytes:
        return self.write_general_settings(
            fn_switch=fn_switch, sleep_time=sleep_time, key_response_time=value
        )

    def set_sleep_time(self, value: int, key_response_time: int = 0, fn_switch: int = 0) -> bytes:
        return self.write_general_settings(
            fn_switch=fn_switch, sleep_time=value, key_response_time=key_response_time
        )

    def _write_lighting_sequence(self, payload: bytearray):
        """Internal helper to send one full Open -> Probe -> Payload -> Commit -> Finalize loop."""
        self.send_cmd(CMD_OPEN)
        self._wait_ack(CMD_OPEN)

        self.send_cmd(0x1304, bytes([0, 0, 0, 0, 0, 0, 1]))
        self._wait_ack(0x1304)

        self.raw_send(payload)
        time.sleep(0.05) 

        self.send_cmd(CMD_COMMIT)
        self._wait_ack(CMD_COMMIT, retries=60, delay=0.05)

        self.send_cmd(CMD_FINALIZE)
        time.sleep(0.1)

    def set_global_lighting(self, effect: int, r: int, g: int, b: int, brightness: int = 5, speed: int = 3, direction: int = 0, option: int = 0):
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

        # Double sequence required to clear MCU animation pointers
        for _ in range(2):
            self._write_lighting_sequence(payload)
            time.sleep(0.1)

    def sync_rtc(self, when: Optional["datetime"] = None):
        """
        Sync the keyboard's RTC to the PC clock.

        Verified against musicRGB2.pcapng (t=10.126-10.381s). NOTE: this
        transaction was originally misidentified as "music mode params";
        the bytes decode as a timestamp (5a yy mm dd HH MM SS 00 04) and
        replaying them visibly jumps the TFT clock. The driver's UI syncs
        the keyboard clock this way. The 0x2804 probe selects the RTC page,
        like 0x1304 selects the lighting page and 0x1704 the settings page.

        The commit status byte does NOT indicate accepted/rejected: a status of 0
        was once read as a "rejection" (replaying the capture's stale Sep-17
        timestamp), but the TFT clock advanced anyway. The write applies
        regardless, so this only warns instead of raising. Pass `when` for tests.

        Wire sequence (either interface works; the capture used 3):
            04 18                      open
            04 28 00 00 00 00 01       select RTC page
            00 01 5a <timestamp> ... aa 55
            04 02                      commit
        Cadence matters: ~36 ms SET->GET, ONE status GET per SET.
        """
        from datetime import datetime
        t = when or datetime.now()
        body = bytes([0x5A, t.year - 2000, t.month, t.day,
                      t.hour, t.minute, t.second, 0x00, t.isoweekday() % 7])

        def step(cmd, payload=b"", trailer=False):
            self.send_cmd(cmd, payload, trailer=trailer, delay=0.0)
            time.sleep(0.036)               # capture cadence: one GET per SET
            return self.raw_get()

        step(CMD_OPEN)                          # expect 04 18 00 01 ...
        step(0x2804, bytes([0, 0, 0, 0, 1]))    # expect 04 28 00 01 ...
        step(0x0100, body, trailer=True)        # expect echo of body
        resp = step(CMD_COMMIT)                 # expect 04 02 00 01
        if len(resp) >= 4 and resp[3] != 0x01:
            print(f"warning: commit status {resp[3]:#04x} (capture saw 0x01); "
                  "the RTC write appears to apply anyway - check the TFT clock.")


