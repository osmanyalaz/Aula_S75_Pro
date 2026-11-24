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
# Device identification (from config.xml)
# --------------------------------------------------------------------------------------
VID = 0x0C45

PID_USB = 0x800A       # mode value="0" desc="USB"       hid_interface="VID_0C45&PID_800A&MI_00"
PID_DONGLE = 0xFEFE    # mode value="2" desc="2.4G TYPE-A" hid_interface="VID_0C45&PID_FEFE&MI_03"

# Vendor HID interface for feature reports.
# NOTE: config.xml labels the USB mode as "MI_00" — that is the Windows HID path
# suffix for the *Boot Keyboard* interface, not the vendor control interface.
# USB captures (PROTOCOL.md §1) and all captures confirm that 64-byte feature
# reports are sent/received on **interface 3** in both wired and dongle modes.
INTERFACE_USB = 3
INTERFACE_DONGLE = 3

REPORT_ID = 0x00
REPORT_LEN = 64  # payload length (wLength = 0x40), NOT counting the HID report-id byte

# Command words (little-endian on the wire: byte0=lo, byte1=hi)
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

TRAILER = b"\xAA\x55"     # observed at the very end of the 64-byte buffer on writes

# Custom lighting table dimensions (verified against escToRed.pcapng, PROTOCOL.md §5)
TABLE_SIZE   = 576  # 144 slots × 4 bytes each (light_index, R, G, B)
TABLE_CHUNKS = 9    # 576 / 64 bytes-per-report

# Row-6 side / underglow modes (0x1304 with payload[0] = 0x20 + mode_id)
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


def _le16(cmd: int) -> bytes:
    """Encode a command word as little-endian bytes (byte0=lo, byte1=hi)."""
    return bytes([cmd & 0xFF, (cmd >> 8) & 0xFF])


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
        mode: 'usb' (wired, PID 0x800A, interface 3) or 'dongle' (2.4G, PID 0xFEFE, interface 3)
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
    # def find_path(self) -> bytes:
    #     candidates = [
    #         d for d in hid.enumerate(self.vid, self.pid)
    #         if d.get("interface_number") == self.interface
    #     ]
    #     if not candidates:
    #         # fall back to any interface on that VID/PID, in case the OS numbers differently
    #         candidates = [d for d in hid.enumerate(self.vid, self.pid)]
    #     if not candidates:
    #         raise IOError(
    #             f"No HID device found for VID={self.vid:04X} PID={self.pid:04X}. "
    #             "Is the keyboard connected in the right mode (usb/dongle)?"
    #         )
    #     return candidates[0]["path"]

    def find_path(self) -> bytes:
        candidates = hid.enumerate(self.vid, self.pid)
        if not candidates:
            raise IOError(f"No device found with VID={self.vid:04X} PID={self.pid:04X}")

        # 1. Best: Match by Vendor-Defined Usage Page (works on Windows, macOS, hidapi-libusb)
        for d in candidates:
            if (d.get("usage_page") or 0) >= 0xFF00:
                return d["path"]

        # 2. Linux hidraw: usage_page is always 0, so fall back to interface number.
        #    Now that INTERFACE_USB == 3 this directly selects the vendor interface.
        for d in candidates:
            if d.get("interface_number") == self.interface:
                return d["path"]

        # 3. Active Probe Fallback: Try opening candidates and sending a benign GET_REPORT.
        #    Only the vendor interface (interface 3) accepts a 64-byte feature report.
        for d in candidates:
            try:
                test_dev = hid.device()
                test_dev.open_path(d["path"])
                test_dev.get_feature_report(0, 65)
                test_dev.close()
                return d["path"]
            except Exception:
                continue
        # 4. Ultimate fallback: return the first candidate and let the caller fail loudly.
        return candidates[0]["path"]


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
                "Check: USB cable, udev rule "
                "(SUBSYSTEM==\"usb\", ATTR{{idVendor}}==\"0c45\", MODE=\"0666\"), "
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

    def _wait_ack(
        self,
        expected_cmd: int,
        retries: int = 50,
        delay: float = 0.05,
        settle: float = 0.036,
    ) -> bytes:
        """Read GET_REPORT until the device ACKs the expected command word (byte[3] == 0x01) or rejects with 0xFF."""
        expected_lo = expected_cmd & 0xFF
        expected_hi = (expected_cmd >> 8) & 0xFF
        last_resp = b""
        for _ in range(retries):
            resp = b""
            try:
                resp = self.raw_get()
                last_resp = resp
            except Exception:
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
        Write general settings to flash page 0x00009000 via 0x1704 and verify the
        32-bit little-endian commit checksum over all 64 written bytes.
        """
        # 1) open/ping
        self.send_cmd(CMD_OPEN)
        self._wait_ack(CMD_OPEN)

        # 2) probe 0x1704 (flash 0x00009000; firmware ignores profile index bytes)
        self.send_cmd(CMD_SETTINGS_WRITE, bytes([1, 0, 0, 0, 0, 0, 1]))
        self._wait_ack(CMD_SETTINGS_WRITE)

        # 3) the actual settings write (64-byte payload)
        body = bytes([
            1 if disable_alt_tab else 0,
            1 if disable_alt_f4 else 0,
            1 if win_lock else 0,
            fn_switch & 0xFF,
            sleep_time & 0xFF,
            0,  # unused gap byte, always 0 in captures
            key_response_time & 0xFF,
        ])
        payload = bytes(build_report(CMD_GENERAL_SETTINGS, body, trailer=True))
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
        payload = self._build_mode_payload(
            effect=effect, r=r, g=g, b=b,
            brightness=brightness, speed=speed,
            direction=direction, option=option,
        )
        # Double sequence required to clear MCU animation pointers.
        # 0.5 s gap: the first CMD_FINALIZE can trigger a flash write that
        # takes several seconds; starting the second sequence too soon causes
        # the second commit poll to hit the all-zeros flash-busy window.
        for _ in range(2):
            self._write_lighting_sequence(payload)
            time.sleep(0.5)


    def set_custom_lighting(self, key_colors: dict, brightness: int = 5):
        """
        Apply a per-key custom colour table and save it to flash.

        Implements the two-transaction sequence verified in escToRed.pcapng
        and documented in PROTOCOL.md §5.  The entire sequence is executed
        **twice** (matching the official driver) to ensure MCU animation
        pointers and flash buffers latch cleanly.

        Args:
            key_colors: {light_index (int): (r, g, b)} — keys not listed are
                        left dark (0, 0, 0).  light_index must be a member of
                        PHYSICAL_INDICES (keymap.py); any other value is
                        rejected to prevent accidentally corrupting the AA 55
                        trailer at slot 143.
            brightness: brightness byte passed to Transaction A's mode-select
                        write (0–5; default 5 matches the official driver).

        Wire flow per iteration (PROTOCOL.md §5):
            [Tx A] CMD_OPEN → 0x1304 probe → mode 0x80 payload → CMD_COMMIT
                   → CMD_FINALIZE
            [Tx B] CMD_OPEN → 0x2304 probe → 9×64-byte raw table chunks
                   → CMD_COMMIT → GET_REPORT (checksum verify) → CMD_FINALIZE
        """
        # ---- validate --------------------------------------------------------
        # PHYSICAL_INDICES is the allowlist of safe light_index values derived
        # from rgb-keyboard.xml (hardcoded in keymap.py; no runtime XML parse).
        # Anything not in the set is either reserved (slot 0), a gap in the
        # keyboard matrix, or close enough to the trailer at offsets 574–575
        # (slot 143) to be unsafe.
        for idx, rgb in key_colors.items():
            if idx not in PHYSICAL_INDICES:
                raise ValueError(
                    f"light_index {idx} is not a known physical key "
                    f"(see keymap.PHYSICAL_INDICES or run 'list-keys')."
                )
            r, g, b = rgb
            for name, val in (("r", r), ("g", g), ("b", b)):
                if not (0 <= val <= 255):
                    raise ValueError(
                        f"key {idx}: {name}={val} is not in range 0–255."
                    )


        # ---- build the 576-byte table buffer ---------------------------------
        # Layout: slot i occupies bytes [i*4 : i*4+4] = [light_index, R, G, B].
        #
        # The official driver (FUN_0044b900) writes the light_index byte into
        # slot[0] for EVERY physical key, even those that are off (RGB = 0).
        # Omitting these index bytes produces a checksum mismatch.  We replicate
        # this by iterating PHYSICAL_INDICES first, then overwriting RGB for
        # keys in key_colors.
        #
        # Slot 0 stays zero (reserved; byte-offsets 0–3 are never touched).
        # Trailer AA 55 replaces the last 2 bytes of slot 143 (offsets 574–575).
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
            # Only checked when _wait_ack returned a real ACK: an all-zeros
            # flash-housekeeping response carries no meaningful checksum and
            # would produce a false "mismatch" warning against 0x00000000.
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
        step(0x2804, bytes([0, 0, 0, 0, 0, 0, 1]))    # expect 04 28 00 01 ...
        step(0x0100, body, trailer=True)        # expect echo of body
        resp = step(CMD_COMMIT)                 # expect 04 02 00 01
        if len(resp) >= 4 and resp[3] != 0x01:
            print(f"warning: commit status {resp[3]:#04x} (capture saw 0x01); "
                  "the RTC write appears to apply anyway - check the TFT clock.")

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
        """Execute a State-1 read transaction (0x0504, 0x1004, 0x1204, 0x1404, 0x1604, 0x2204, 0x2604, 0xF504).

        Handles both firmware paths from 0x00004330 + FUN_0000407a:
          - Stale usb_flags bit 1: SET_REPORT auto-advances to State 1 and
            FUN_0000407a preloads chunk 0 before the first GET_REPORT, so GET #1
            returns chunk 0 directly.
          - Clean usb_flags bit 1 (after 0x0204+GET, or for 0xF504 which clears
            bit 1 in Phase 1): GET #1 returns [04, cmd_hi, 00, 01, ...], then
            chunks 0..N-1 follow on subsequent GET_REPORTs.
        """
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

    def read_device_info(self) -> dict:
        """Read firmware/device info block from flash 0x00008F80 via CMD_DEVICE_INFO (0x0504)."""
        chunks, mcu_sum = self._read_state1_chunks(CMD_DEVICE_INFO, chunks=1)
        chunk = chunks[0]
        tag = struct.unpack_from("<H", chunk, 0)[0]
        vid = struct.unpack_from("<H", chunk, 4)[0]
        pid = struct.unpack_from("<H", chunk, 6)[0]
        fw_minor = chunk[8]
        fw_major = chunk[9]
        return {
            "tag": tag,
            "vid": vid,
            "pid": pid,
            "fw_major": fw_major,
            "fw_minor": fw_minor,
            "fw_version": f"{fw_major}.{fw_minor:02d}",
            "checksum": mcu_sum,
            "raw": chunk,
        }

    def read_battery_level(self, delay: float = 0.036) -> dict:
        """Read quantized battery level (0-5) from RAM 0x200000F8 via CMD_BATTERY_LEVEL (0xF604)."""
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
            "percent_range": BATTERY_RANGES.get(level, "unknown"),
            "raw": resp,
        }

    def read_lighting_config(self) -> dict:
        """Read saved main-key lighting config from flash 0x00009800 via CMD_LIGHTING_READ (0x1204)."""
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
        3=breathing, 4=off) via CMD_LIGHTING_WRITE (0x1304, payload[0] = 0x20 + mode).

        Because 0x1304 Phase 1 erases flash page 0x00009800 before FUN_00003f42
        skips writing it for 0x20-0x24, preserve_lighting=True (default) reads
        0x9800 via 0x1204 beforehand and rewrites it afterward if populated.
        """
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
        }


