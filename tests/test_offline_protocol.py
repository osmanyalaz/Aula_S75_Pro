#!/usr/bin/env python3
"""Offline unit test suite for scripts/aula_s75pro/ against mocked HID transport."""

from __future__ import annotations

import contextlib
import io
import re
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE_DIR = Path(__file__).resolve().parent.parent
SCREEN_DIR = BASE_DIR / "screenUpload"
for path in (str(BASE_DIR), str(SCREEN_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

import aula_s75pro as lib  # noqa: E402
import cli  # noqa: E402
import aula_s75pro_screen as screen  # noqa: E402


class MockS75ProDevice:
    """
    Stateful in-memory simulator of the AULA S75 Pro USB HID state machine
    (FUN_00004622 / 0x00004330 / FUN_0000407a / FUN_00003f42 / 0x00003E48).
    """

    def __init__(
        self,
        *,
        initial_stale_bit1: bool = False,
        trailing_flash_byte: int = 0x00,
    ):
        self.state = 0
        self.usb_flags = 0x02 if initial_stale_bit1 else 0x00
        self.hid_ctx5 = 0
        self.buf = bytearray(64)
        self.checksum = 0

        # State 1 read tracking
        self.read_chunks: list[bytes] = []
        self.read_idx = 0
        self.read_total = 0
        self.is_live_ram_read = False
        self.trailing_flash_byte = trailing_flash_byte

        # State 2 write tracking
        self.write_target: int | None = None
        self.write_expected = 0
        self.write_received: list[bytes] = []

        # Simulated MCU flash pages & RAM
        info = bytearray([0xFF] * 64)
        info[0:10] = bytes.fromhex("40300000450c0a800301")
        self.flash_info = bytes(info)
        self.flash_9000 = bytes([0xFF] * 64)
        self.flash_9800 = bytes([0xFF] * 64)
        self.flash_9c00 = bytes([0x00] * 576)

        live = bytearray(576)
        for slot in range(144):
            live[slot * 4] = slot
        self.live_rgb = bytes(live)

        self.battery_level = 4

        # Fault / test-injection hooks
        self.reject_next_cmd: int | None = None
        self.override_commit_checksum: int | None = None
        self.zero_commit_acks = 0

        self.sent_reports: list[bytes] = []
        self.get_reports: list[bytes] = []

    def _flash_chunks_for(self, op: int, chunks: int) -> list[bytes]:
        if op == 0x05:
            pages = [self.flash_info]
        elif op == 0x12:
            pages = [self.flash_9800]
        elif op == 0x16:
            pages = [self.flash_9000]
        elif op == 0x22:
            pages = [self.flash_9c00[i * 64 : (i + 1) * 64] for i in range(9)]
        elif op == 0xF5:
            return [self.live_rgb[i * 64 : (i + 1) * 64] for i in range(chunks)]
        else:
            raise AssertionError(f"Unsupported mock read op {op:#04x}")
        trailing = bytes([self.trailing_flash_byte] * 64)
        return pages[:chunks] + [trailing]

    def _state1_load_next_chunk(self) -> None:
        if (self.usb_flags & 0x02) == 0:
            return
        self.usb_flags &= ~0x02
        if self.read_total > 0:
            chunk = self.read_chunks[self.read_idx]
            self.buf[:] = chunk
            if not self.is_live_ram_read:
                self.checksum = (self.checksum + sum(chunk)) & 0xFFFFFFFF
            self.read_idx += 1
        was_last = self.read_total == 1
        self.read_total -= 1
        if was_last:
            self.state = 3

    def _state0_phase2(self) -> None:
        if (self.usb_flags & 0x02) == 0 or (self.hid_ctx5 & 0x10) == 0:
            return
        op = self.buf[1]
        chunks = self.buf[8] | (self.buf[9] << 8)
        self.hid_ctx5 &= ~0x10

        if op in (0x05, 0x12, 0x16, 0x22):
            # All 7 flash-read opcodes leave bit 1 set and queue (chunks + 1) preloads
            self.is_live_ram_read = False
            self.checksum = 0
            self.read_chunks = self._flash_chunks_for(op, chunks)
            self.read_idx = 0
            self.read_total = chunks + 1
            self.state = 1
        elif op == 0xF5:
            # 0xF5 cleared bit 1 in Phase 1; Phase 2 (on GET) keeps bit 1 set so
            # FUN_0000407a immediately preloads chunk 0 with count=chunks.
            self.is_live_ram_read = True
            self.checksum = 0
            self.read_chunks = self._flash_chunks_for(op, chunks)
            self.read_idx = 0
            self.read_total = chunks
            self.state = 1
        elif op in (0x13, 0x17, 0x23):
            self.usb_flags &= ~0x02
            self.checksum = 0
            self.write_received = []
            self.write_expected = chunks
            self.write_target = {0x13: 0x9800, 0x17: 0x9000, 0x23: 0x9C00}[op]
            self.state = 2
        else:
            # 0x18, 0x19, 0xF0, 0xF6 stay State 0 and leave bit 1 as set
            self.state = 0

    def send_feature_report(self, data: bytes) -> None:
        assert len(data) == 65 and data[0] == 0x00
        payload = bytes(data[1:])
        self.sent_reports.append(payload)
        self.buf[:] = payload

        if self.state == 0:
            if payload[0] != 0x04:
                self.buf[3] = 0xFF
                self.hid_ctx5 = 0
                return
            op = payload[1]
            if self.reject_next_cmd == op:
                self.reject_next_cmd = None
                self.buf[3] = 0xFF
                self.hid_ctx5 = 0
                return
            valid_ops = {0x05, 0x12, 0x13, 0x16, 0x17, 0x18, 0x19, 0x22, 0x23, 0xF0, 0xF5, 0xF6}
            if op not in valid_ops:
                self.buf[3] = 0xFF
                self.hid_ctx5 = 0
                return

            if op == 0xF5:
                self.usb_flags &= ~0x02
            elif op == 0xF6:
                self.buf[4] = self.battery_level
            elif op == 0x13:
                self.flash_9800 = bytes([0xFF] * 64)
            elif op == 0x17:
                self.flash_9000 = bytes([0xFF] * 64)
            elif op == 0x23:
                self.flash_9c00 = bytes([0xFF] * 576)

            self.buf[3] = 0x01
            self.hid_ctx5 |= 0x11

            # Simulate main loop polling if stale bit 1 is already set
            if self.usb_flags & 0x02:
                self._state0_phase2()
                if self.state == 1 and (self.usb_flags & 0x02):
                    self._state1_load_next_chunk()
            return

        if self.state == 2:
            self.write_received.append(payload)
            if self.write_target == 0x9800 and (payload[0] >> 4) == 2:
                # 0x20..0x24 underglow skips writing flash 0x9800 (stays erased 0xFF)
                self.checksum = lib.EXPECTED_UNDERGLOW_ERASED_CHECKSUM
            else:
                self.checksum = (self.checksum + sum(payload)) & 0xFFFFFFFF
                if len(self.write_received) == self.write_expected:
                    blob = b"".join(self.write_received)
                    if self.write_target == 0x9800:
                        self.flash_9800 = blob
                    elif self.write_target == 0x9000:
                        self.flash_9000 = blob
                    elif self.write_target == 0x9C00:
                        self.flash_9c00 = blob
            if len(self.write_received) >= self.write_expected:
                self.state = 3
            return

        if self.state == 3:
            if payload[0] != 0x04 or payload[1] != 0x02:
                self.buf[3] = 0xFF
                return
            if self.reject_next_cmd == 0x02:
                self.reject_next_cmd = None
                self.buf[3] = 0xFF
                return
            self.buf[3] = 0x01
            chk = (
                self.override_commit_checksum
                if self.override_commit_checksum is not None
                else self.checksum
            )
            self.override_commit_checksum = None
            struct.pack_into("<I", self.buf, 4, chk & 0xFFFFFFFF)
            self.hid_ctx5 |= 0x10

    def get_feature_report(self, report_id: int, length: int) -> bytes:
        assert report_id == 0 and length == 65
        if self.state == 3 and self.zero_commit_acks > 0:
            self.zero_commit_acks -= 1
            out = bytes(64)
            self.get_reports.append(out)
            return b"\x00" + out

        out = bytes(self.buf)
        self.get_reports.append(out)
        self.usb_flags |= 0x02

        if self.state == 0:
            self._state0_phase2()
            if self.state == 1 and (self.usb_flags & 0x02):
                self._state1_load_next_chunk()
        elif self.state == 1:
            self._state1_load_next_chunk()
        elif self.state == 3:
            # 0x00003E98: State 3 ONLY resets to State 0 if (hid_ctx[5] & 0x10) != 0,
            # which is set solely by SET 04 02 at 0x00003E84.
            if self.hid_ctx5 & 0x10:
                self.checksum = 0
                self.hid_ctx5 = 0
                self.usb_flags = 0
                self.state = 0

        return b"\x00" + out

    def close(self) -> None:
        return None


def make_mock_kb(mock_dev: MockS75ProDevice) -> lib.AulaS75Pro:
    kb = lib.AulaS75Pro(mode="usb")
    kb.dev = mock_dev
    return kb


class SafetyAndConstantsTests(unittest.TestCase):
    def test_command_constants_and_wire_endianness(self):
        self.assertEqual(lib.CMD_LIGHT_READ, 0xF504)
        self.assertEqual(lib._le16(lib.CMD_LIGHT_READ), b"\x04\xf5")
        self.assertEqual(lib.CMD_CUSTOM_LIGHT_READ, 0x2204)
        self.assertEqual(lib.CMD_DEVICE_INFO, 0x0504)
        self.assertEqual(lib.CMD_LIGHTING_READ, 0x1204)
        self.assertEqual(lib.CMD_LIGHTING_WRITE, 0x1304)
        self.assertEqual(lib.CMD_SETTINGS_READ, 0x1604)
        self.assertEqual(lib.CMD_SETTINGS_WRITE, 0x1704)
        self.assertEqual(lib.CMD_PROBE, lib.CMD_SETTINGS_WRITE)
        self.assertEqual(lib.CMD_BATTERY_LEVEL, 0xF604)

    def test_no_dangerous_opcodes_or_bootloader_magic_in_python_sources(self):
        py_files = [
            BASE_DIR / "aula_s75pro.py",
            BASE_DIR / "cli.py",
            SCREEN_DIR / "aula_s75pro_screen.py",
        ]
        # Construct forbidden signatures dynamically so they do not literally match source scans elsewhere
        bad_opcode_hex = "3804"
        bad_wire = "04" + "38"
        bad_isp = "aa42" + "895a" + "ff71" + "62cc"
        for src_path in py_files:
            raw_text = src_path.read_text(encoding="utf-8").lower()
            compact_hex = re.sub(r"[^0-9a-f]", "", raw_text)
            self.assertNotIn(f"0x{bad_opcode_hex}", raw_text, f"{src_path.name} references excluded opcode")
            self.assertNotIn(bad_wire, compact_hex, f"{src_path.name} contains excluded SPI prefix bytes")
            self.assertNotIn(bad_isp, compact_hex, f"{src_path.name} contains ISP bootloader magic")


class ProtocolAndChecksumsTests(unittest.TestCase):
    def setUp(self):
        self.sleep_patcher = mock.patch("time.sleep", return_value=None)
        self.sleep_patcher.start()

    def tearDown(self):
        self.sleep_patcher.stop()

    def test_write_general_settings_bitfields_single_pass_32bit_checksum_and_readback(self):
        dev = MockS75ProDevice()
        kb = make_mock_kb(dev)

        resp = kb.write_general_settings(
            fn_switch=1,
            sleep_time=2,
            key_response_time=4,
            disable_alt_tab=True,
            disable_alt_f4=False,
            win_lock=True,
        )
        self.assertEqual(resp[3], 0x01)

        # Verify no redundant profile loop: only 1 x 0x1704 probe sent
        probes_17 = [r for r in dev.sent_reports if r[0:2] == b"\x04\x17"]
        self.assertEqual(len(probes_17), 1)

        # Find the written 0x0100 payload
        payload = next(r for r in dev.sent_reports if r[0:2] == b"\x00\x01")
        self.assertEqual(payload[2], 1)   # disable_alt_tab
        self.assertEqual(payload[3], 0)   # disable_alt_f4
        self.assertEqual(payload[4], 1)   # win_lock
        self.assertEqual(payload[5], 1)   # fn_switch
        self.assertEqual(payload[6], 2)   # sleep_time (5 min)
        self.assertEqual(payload[7], 0)   # gap
        self.assertEqual(payload[8], 4)   # key_response_time
        self.assertEqual(payload[62:64], b"\xaa\x55")

        # 32-bit LE sum = 0 + 1 + 1 + 0 + 1 + 1 + 2 + 0 + 4 + 0xAA + 0x55 = 265 (0x0109) > 0xFF
        expected_sum = sum(payload)
        self.assertEqual(expected_sum, 0x0109)
        self.assertEqual(lib.parse_commit_checksum(resp), expected_sum)

        # Verify read_general_settings (0x1604) round-trip
        st = kb.read_general_settings()
        self.assertFalse(st["erased"])
        self.assertTrue(st["disable_alt_tab"])
        self.assertFalse(st["disable_alt_f4"])
        self.assertTrue(st["win_lock"])
        self.assertEqual(st["fn_switch"], 1)
        self.assertEqual(st["sleep_time"], 2)
        self.assertEqual(st["sleep_label"], "5 min")
        self.assertEqual(st["key_response_time"], 4)
        self.assertEqual(st["debounce_scans"], 10)
        self.assertEqual(st["checksum"], expected_sum)

    def test_write_general_settings_upper_checksum_byte_corruption_raises(self):
        dev = MockS75ProDevice()
        kb = make_mock_kb(dev)
        # Same low byte (0x09) as valid sum 0x0109, wrong upper bytes -> old 8-bit check would pass!
        dev.override_commit_checksum = 0x00020009
        with self.assertRaises(RuntimeError):
            kb.write_general_settings(fn_switch=1, sleep_time=2, key_response_time=4, disable_alt_tab=True, win_lock=True)

    def test_set_key_response_and_sleep_forward_flags(self):
        dev = MockS75ProDevice()
        kb = make_mock_kb(dev)
        kb.set_key_response_time(5, sleep_time=3, fn_switch=1, disable_alt_tab=True, disable_alt_f4=True, win_lock=True)
        st = kb.read_general_settings()
        self.assertEqual(st["key_response_time"], 5)
        self.assertEqual(st["debounce_scans"], 14)
        self.assertTrue(st["disable_alt_tab"] and st["disable_alt_f4"] and st["win_lock"])

    def test_write_lighting_sequence_32bit_checksum_and_busy_fallback(self):
        dev = MockS75ProDevice()
        kb = make_mock_kb(dev)
        payload = kb._build_mode_payload(effect=1, r=255, g=128, b=64, brightness=5, speed=3)
        kb._write_lighting_sequence(payload)

        # Transient all-zeros flash-housekeeping ACKs -> warns and succeeds
        dev.zero_commit_acks = 65
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            kb._write_lighting_sequence(payload)
        self.assertIn("flash housekeeping", buf.getvalue())

        # Corrupted commit checksum raises
        dev.override_commit_checksum = 0xDEADBEEF
        with self.assertRaises(RuntimeError):
            kb._write_lighting_sequence(payload)

        # Explicit 0xFF rejection raises McuRejectedError immediately
        dev.reject_next_cmd = 0x13
        with self.assertRaises(lib.McuRejectedError):
            kb._write_lighting_sequence(payload)

    def test_set_custom_lighting_32bit_checksum_over_16bit_limit_and_readback(self):
        dev = MockS75ProDevice()
        kb = make_mock_kb(dev)
        all_white = {idx: (255, 255, 255) for idx in lib.PHYSICAL_INDICES}

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            kb.set_custom_lighting(all_white, brightness=5)
        out = buf.getvalue()
        # 80 * 3 * 255 + sum(PHYSICAL_INDICES) + 0xAA + 0x55 = 65,770 (0x000100ea) > 0xFFFF
        expected = (sum(lib.PHYSICAL_INDICES) + len(lib.PHYSICAL_INDICES) * 3 * 255 + 0xAA + 0x55) & 0xFFFFFFFF
        self.assertEqual(expected, 0x000100EA)
        self.assertIn(f"Custom table checksum OK ({expected:#010x}).", out)
        self.assertNotIn("mismatch", out.lower())

        tbl = kb.read_custom_lighting_table()
        self.assertEqual(len(tbl["keys"]), len(lib.PHYSICAL_INDICES))
        self.assertEqual(tbl["keys"][1], (255, 255, 255))
        self.assertEqual(tbl["trailer"], b"\xaa\x55")
        self.assertEqual(tbl["checksum"], expected)

    def test_state1_stale_vs_clean_bit1_and_trailing_preload_checksums(self):
        for trailing in (0x00, 0xFF):
            with self.subTest(trailing=hex(trailing)):
                # Stale bit-1 path (e.g., right after wait_until_idle())
                dev_stale = MockS75ProDevice(initial_stale_bit1=False, trailing_flash_byte=trailing)
                kb_stale = make_mock_kb(dev_stale)
                kb_stale.wait_until_idle()  # GET_REPORT leaves usb_flags bit 1 set
                info = kb_stale.read_device_info()
                self.assertEqual(info["vid"], 0x0C45)
                self.assertEqual(info["pid"], 0x800A)
                self.assertEqual(info["fw_version"], "1.03")
                self.assertEqual(info["tag"], 0x3040)
                # Verify first GET after 0x0504 returned chunk0 directly (stale path)
                self.assertEqual(dev_stale.get_reports[1][:8], bytes.fromhex("40300000450c0a80"))

                # After commit's GET_REPORT, usb_flags == 0 -> next flash read takes clean bit-1 path!
                dev_stale.flash_9800 = bytes(kb_stale._build_mode_payload(effect=1, r=10, g=20, b=30))
                cfg = kb_stale.read_lighting_config()
                self.assertEqual(cfg["rgb"], (10, 20, 30))
                expected_delta = 64 * trailing
                self.assertEqual(cfg["checksum"] - sum(cfg["raw"]), expected_delta)

        # Corrupted State-1 commit checksum raises
        dev_bad = MockS75ProDevice(initial_stale_bit1=True)
        dev_bad.override_commit_checksum = 1
        kb_bad = make_mock_kb(dev_bad)
        with self.assertRaises(RuntimeError):
            kb_bad.read_device_info()

        # Probe 0xFF rejection aborts
        dev_bad.reject_next_cmd = 0x12
        with self.assertRaises(lib.McuRejectedError):
            kb_bad.read_lighting_config()

    def test_state1_read_settling_delays_before_commit_and_between_chunks(self):
        def trace_read(initial_stale: bool, cmd: int, chunks: int) -> list[tuple]:
            dev = MockS75ProDevice(initial_stale_bit1=initial_stale)
            kb = make_mock_kb(dev)
            timeline: list[tuple] = []
            orig_send = dev.send_feature_report
            orig_get = dev.get_feature_report

            def wrapped_send(data: bytes) -> None:
                op = data[1] | (data[2] << 8)
                timeline.append(("SET", op))
                orig_send(data)

            def wrapped_get(report_id: int, length: int) -> bytes:
                timeline.append(("GET",))
                return orig_get(report_id, length)

            dev.send_feature_report = wrapped_send  # type: ignore[method-assign]
            dev.get_feature_report = wrapped_get    # type: ignore[method-assign]

            with mock.patch("time.sleep", side_effect=lambda s: timeline.append(("SLEEP", s))):
                kb._read_state1_chunks(cmd, chunks=chunks, delay=0.036)
            return timeline

        stale_timeline = trace_read(initial_stale=True, cmd=lib.CMD_SETTINGS_READ, chunks=1)
        self.assertEqual(
            stale_timeline,
            [
                ("SET", lib.CMD_SETTINGS_READ),
                ("SLEEP", 0.036),
                ("GET",),
                ("SLEEP", 0.036),
                ("SET", lib.CMD_COMMIT),
                ("SLEEP", 0.036),
                ("GET",),
                ("SLEEP", 0.036),
            ],
        )

        clean_timeline = trace_read(initial_stale=False, cmd=lib.CMD_CUSTOM_LIGHT_READ, chunks=2)
        self.assertEqual(
            clean_timeline,
            [
                ("SET", lib.CMD_CUSTOM_LIGHT_READ),
                ("SLEEP", 0.036),
                ("GET",),
                ("SLEEP", 0.036),
                ("GET",),
                ("SLEEP", 0.036),
                ("GET",),
                ("SLEEP", 0.036),
                ("SET", lib.CMD_COMMIT),
                ("SLEEP", 0.036),
                ("GET",),
                ("SLEEP", 0.036),
            ],
        )

    def test_state2_write_settling_delays_after_probe_ack_and_before_commit(self):
        def record(fn):
            dev = MockS75ProDevice()
            kb = make_mock_kb(dev)
            timeline: list[tuple] = []
            orig_send = dev.send_feature_report
            orig_get = dev.get_feature_report

            def wrapped_send(data: bytes) -> None:
                head = data[1] | (data[2] << 8)
                timeline.append(("SET", head))
                orig_send(data)

            def wrapped_get(report_id: int, length: int) -> bytes:
                timeline.append(("GET",))
                return orig_get(report_id, length)

            dev.send_feature_report = wrapped_send  # type: ignore[method-assign]
            dev.get_feature_report = wrapped_get    # type: ignore[method-assign]
            with mock.patch("time.sleep", side_effect=lambda s: timeline.append(("SLEEP", s))):
                fn(kb)
            return timeline

        # 1) set_underglow_mode(1, preserve_lighting=False)
        ug_tl = record(lambda kb: kb.set_underglow_mode(1, preserve_lighting=False))
        idx_1304 = ug_tl.index(("SET", lib.CMD_LIGHTING_WRITE))
        idx_1304_ack = ug_tl.index(("GET",), idx_1304)
        idx_payload = ug_tl.index(("SET", 0x0021))
        idx_commit = ug_tl.index(("SET", lib.CMD_COMMIT))
        idx_commit_ack = ug_tl.index(("GET",), idx_commit)
        idx_finalize = ug_tl.index(("SET", lib.CMD_FINALIZE))

        self.assertGreater(idx_payload, idx_1304_ack + 1)
        self.assertTrue(
            any(ev[0] == "SLEEP" and ev[1] >= 0.03 for ev in ug_tl[idx_1304_ack:idx_payload])
        )
        self.assertTrue(
            any(ev[0] == "SLEEP" and ev[1] >= 0.10 for ev in ug_tl[idx_payload:idx_commit])
        )
        self.assertTrue(
            any(ev[0] == "SLEEP" and ev[1] >= 0.03 for ev in ug_tl[idx_commit_ack:idx_finalize])
        )

        # 2) write_general_settings()
        gs_tl = record(lambda kb: kb.write_general_settings(sleep_time=1, key_response_time=2))
        gs_probe = gs_tl.index(("SET", lib.CMD_SETTINGS_WRITE))
        gs_probe_ack = gs_tl.index(("GET",), gs_probe)
        gs_payload = gs_tl.index(("SET", lib.CMD_GENERAL_SETTINGS))
        gs_commit = gs_tl.index(("SET", lib.CMD_COMMIT))
        self.assertTrue(
            any(ev[0] == "SLEEP" and ev[1] >= 0.03 for ev in gs_tl[gs_probe_ack:gs_payload])
        )
        self.assertTrue(
            any(ev[0] == "SLEEP" and ev[1] >= 0.03 for ev in gs_tl[gs_payload:gs_commit])
        )

        # 3) _write_lighting_sequence()
        wl_tl = record(
            lambda kb: kb._write_lighting_sequence(kb._build_mode_payload(effect=1, r=10, g=20, b=30))
        )
        wl_probe = wl_tl.index(("SET", lib.CMD_LIGHTING_WRITE))
        wl_probe_ack = wl_tl.index(("GET",), wl_probe)
        wl_payload = wl_tl.index(("SET", 0x0A01))  # effect=1, r=10 -> LE16 0x0A01
        wl_commit = wl_tl.index(("SET", lib.CMD_COMMIT))
        self.assertTrue(
            any(ev[0] == "SLEEP" and ev[1] >= 0.03 for ev in wl_tl[wl_probe_ack:wl_payload])
        )
        self.assertTrue(
            any(ev[0] == "SLEEP" and ev[1] >= 0.03 for ev in wl_tl[wl_payload:wl_commit])
        )

    def test_live_rgb_ram_0xF504_clean_path_144_slots_and_zero_checksum(self):
        dev = MockS75ProDevice(initial_stale_bit1=True)
        live = bytearray(576)
        for slot in range(144):
            live[slot * 4] = slot
        live[1 * 4 + 1 : 1 * 4 + 4] = bytes([255, 0, 128])
        live[39 * 4 + 1 : 39 * 4 + 4] = bytes([1, 2, 3])
        dev.live_rgb = bytes(live)
        kb = make_mock_kb(dev)

        res = kb.read_live_rgb()
        # Even with stale bit 1 initially set, Phase 1 of 0xF504 cleared it -> clean ACK on GET #1
        self.assertEqual(dev.get_reports[0][:4], b"\x04\xf5\x00\x01")
        self.assertEqual(len(res["keys"]), 144)
        self.assertEqual(res["keys"][1], (255, 0, 128))
        self.assertEqual(res["keys"][39], (1, 2, 3))
        self.assertEqual(res["checksum"], 0)

        dev.override_commit_checksum = 42
        with self.assertRaises(RuntimeError):
            kb.read_live_rgb()

    def test_battery_query_all_levels_and_rejection(self):
        dev = MockS75ProDevice(initial_stale_bit1=True)
        kb = make_mock_kb(dev)
        for level, expected_pct in lib.BATTERY_RANGES.items():
            dev.battery_level = level
            res = kb.read_battery_level()
            self.assertEqual(res["level"], level)
            self.assertEqual(res["percent_range"], expected_pct)

        dev.reject_next_cmd = 0xF6
        with self.assertRaises(lib.McuRejectedError):
            kb.read_battery_level()

    def test_underglow_save_and_restore_populated_9800(self):
        dev = MockS75ProDevice(initial_stale_bit1=True)
        kb = make_mock_kb(dev)
        original = bytes(kb._build_mode_payload(effect=16, r=0, g=255, b=128, brightness=4, speed=2, option=1))
        dev.flash_9800 = original

        res = kb.set_underglow_mode("off")
        self.assertEqual(res["mode"], 4)
        self.assertEqual(res["mode_name"], "off")
        self.assertEqual(res["checksum"], 0x00003C4F)
        self.assertTrue(res["checksum_matched"])
        self.assertTrue(res["restored_lighting"])
        self.assertEqual(dev.flash_9800, original)

        # Order check: 0x1204 -> underglow 0x1304 -> 0xF004 -> restore 0x1304 -> 0xF004
        ops = [r[0:2] for r in dev.sent_reports if r[0] == 0x04 and r[1] in (0x12, 0x13, 0xF0)]
        self.assertEqual(ops, [b"\x04\x12", b"\x04\x13", b"\x04\xf0", b"\x04\x13", b"\x04\xf0"])

    def test_underglow_skips_restore_when_erased_zeroed_or_no_preserve(self):
        # 1) Already erased (0xFF * 64)
        dev_ff = MockS75ProDevice()
        kb_ff = make_mock_kb(dev_ff)
        res_ff = kb_ff.set_underglow_mode(0)
        self.assertEqual(res_ff["mode_name"], "flowing")
        self.assertFalse(res_ff["restored_lighting"])
        self.assertEqual(len([r for r in dev_ff.sent_reports if r[0:2] == b"\x04\x13"]), 1)

        # 2) Factory zeroed (0x00 * 64)
        dev_00 = MockS75ProDevice()
        dev_00.flash_9800 = bytes(64)
        kb_00 = make_mock_kb(dev_00)
        res_00 = kb_00.set_underglow_mode("2")
        self.assertEqual(res_00["mode"], 2)
        self.assertFalse(res_00["restored_lighting"])
        self.assertEqual(len([r for r in dev_00.sent_reports if r[0:2] == b"\x04\x13"]), 1)

        # 3) Populated flash, but preserve_lighting=False skips 0x1204 and restore
        dev_np = MockS75ProDevice()
        dev_np.flash_9800 = bytes(kb_np._build_mode_payload(effect=1, r=1, g=2, b=3)) if False else bytes([1] * 64)
        kb_np = make_mock_kb(dev_np)
        res_np = kb_np.set_underglow_mode(3, preserve_lighting=False)
        self.assertFalse(res_np["restored_lighting"])
        self.assertEqual(dev_np.flash_9800, bytes([0xFF] * 64))
        self.assertFalse(any(r[0:2] == b"\x04\x12" for r in dev_np.sent_reports))

    def test_underglow_checksum_mismatch_warns_not_raises_and_invalid_modes(self):
        dev = MockS75ProDevice()
        kb = make_mock_kb(dev)
        original = bytes(kb._build_mode_payload(effect=1, r=200, g=10, b=20))
        dev.flash_9800 = original

        # Hook commit response on first 0x02 commit after 0x1304 underglow payload
        real_send = dev.send_feature_report

        def hooked_send(data: bytes) -> None:
            payload = data[1:]
            if payload[0] == 0x21 and len(payload) == 64 and all(b == 0 for b in payload[1:]):
                dev.override_commit_checksum = 0x00001234
            real_send(data)

        dev.send_feature_report = hooked_send  # type: ignore[method-assign]
        with self.assertWarns(RuntimeWarning):
            res = kb.set_underglow_mode(1)
        self.assertFalse(res["checksum_matched"])
        self.assertEqual(res["checksum"], 0x00001234)
        self.assertTrue(res["restored_lighting"])
        self.assertEqual(dev.flash_9800, original)

        for bad in (-1, 5, True, "unknown", 1.5):
            count_before = len(dev.sent_reports)
            with self.assertRaises(ValueError):
                kb.set_underglow_mode(bad)  # type: ignore[arg-type]
            self.assertEqual(len(dev.sent_reports), count_before)


class ScreenUploaderTests(unittest.TestCase):
    def test_constants_and_delay_clamping(self):
        self.assertEqual(screen.WIRE_TICK_MS, 2)
        self.assertEqual(screen.MIN_WIRE_DELAY, 0x10)
        self.assertEqual(screen.MAX_WIRE_DELAY, 0xFF)
        self.assertEqual(screen.MIN_DELAY_MS, 32)
        self.assertEqual(screen.MAX_DELAY_MS, 510)
        self.assertEqual(screen.MAX_FRAMES, 140)

        ms_cases = {
            0: 16,
            10: 16,
            30: 16,
            32: 16,
            50: 25,
            100: 50,
            510: 255,
            1000: 255,
        }
        for ms, expected_tick in ms_cases.items():
            self.assertEqual(screen.ms_to_wire_delay(ms), expected_tick)

        tick_cases = {0: 16, 1: 16, 15: 16, 16: 16, 255: 255, 300: 255}
        for raw_tick, clamped in tick_cases.items():
            self.assertEqual(screen.clamp_wire_delay(raw_tick), clamped)

    def test_frame_cap_and_build_buffer(self):
        frame = screen.solid_rgb565(255, 0, 0)
        self.assertEqual(len(frame), screen.PIXEL_BYTES)

        # Boundary valid counts: 1 and 140 (stays within 16 MB SPI 0x01000000 from 0x00750000)
        buf1 = screen.build_buffer([frame], [screen.DEFAULT_STILL_DELAY])
        self.assertEqual(buf1[0], 1)
        self.assertEqual(buf1[1], 0x19)
        self.assertEqual(buf1[screen.PREAMBLE : screen.PREAMBLE + 2], b"\x00\xf8")

        buf140 = screen.build_buffer([frame] * 140, [0x20] * 140)
        self.assertEqual(buf140[0], 140)
        self.assertEqual(list(buf140[1:141]), [0x20] * 140)
        self.assertEqual(buf140[141:256], bytes([0xFF] * 115))
        chunks_140 = len(buf140) // screen.CHUNK_SIZE
        self.assertEqual(chunks_140, 2215)
        self.assertLessEqual(0x00750000 + len(buf140), 0x01000000)
        cmd140 = screen.make_cmd_upload(140)
        self.assertEqual(cmd140[0:2], b"\x04\x72")
        self.assertEqual(int.from_bytes(cmd140[8:10], "little"), 2215)

        # Out-of-range tick warns and clamps to >= 0x10
        with self.assertWarns(UserWarning):
            buf_clamped = screen.build_buffer([frame], [5])
        self.assertEqual(buf_clamped[1], 0x10)

        # Invalid frame counts raise ValueError (141+ wraps 24-bit SPI past 0x01000000)
        for bad_n in (0, 141, 191, 254):
            with self.assertRaises(ValueError):
                screen.make_cmd_upload(bad_n)
            with self.assertRaises(ValueError):
                screen.build_buffer([frame] * bad_n, [0x20] * bad_n)

    def test_extract_gif_frames_truncates_at_140_and_clamps_delays(self):
        from PIL import Image

        with tempfile.NamedTemporaryFile(suffix=".gif") as tmp:
            imgs = [Image.new("RGB", (8, 8), (i % 256, 0, 0)) for i in range(150)]
            durations = [10 if i == 0 else (40 if i == 1 else (800 if i == 2 else 50)) for i in range(150)]
            imgs[0].save(
                tmp.name,
                save_all=True,
                append_images=imgs[1:],
                duration=durations,
                loop=0,
            )
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                frames, delays = screen.extract_gif_frames(tmp.name, fit=False, delay_override=None)

        self.assertEqual(len(frames), 140)
        self.assertEqual(len(delays), 140)
        self.assertEqual(delays[0], 0x10)  # 10 ms clamped up to 32 ms (0x10)
        self.assertEqual(delays[1], 0x14)  # 40 ms -> 20 ticks (0x14)
        self.assertEqual(delays[2], 0xFF)  # 800 ms clamped down to 510 ms (0xFF)
        self.assertIn("140-frame device limit", out.getvalue())

    def test_extract_video_frames_vfr_dedup_and_delay_splitting(self):
        import types
        from unittest import mock
        import numpy as np

        def make_raw(r: int, g: int, b: int):
            return np.full((4, 4, 3), (r, g, b), dtype=np.uint8)

        c0, c1, c2 = make_raw(255, 0, 0), make_raw(0, 255, 0), make_raw(0, 0, 255)
        vfr_frames = [c0] * 7 + [c1] * 9 + [c2] * 4
        cfr_short = [c0] * 2 + [c1] * 3 + [c2] * 5
        many_unique = [make_raw((k % 32) * 8, (k // 32) * 32, 0) for k in range(150)]

        scenarios = [
            # Case A: VFR (fps=0.58 disagrees with 20 frames in 4.0s -> 200 ms/raw, split >510ms)
            (
                {"fps": 0.58, "duration": 4.0},
                vfr_frames,
                None,
                9,
                [233] * 3 + [225] * 4 + [200] * 2,
            ),
            # Case B: Same VFR clip with --delay 100 -> 1 copy per unique run
            (
                {"fps": 0.58, "duration": 4.0},
                vfr_frames,
                100,
                3,
                [50, 50, 50],
            ),
            # Case C: Short runs <= 510ms combine directly without extra copies
            (
                {"fps": 10.0, "duration": 1.0},
                cfr_short,
                None,
                3,
                [100, 150, 250],
            ),
            # Case D: >140 unique frames truncated at MAX_FRAMES=140
            (
                {"fps": 30.0, "duration": 5.0},
                many_unique,
                None,
                140,
                [17] * 140,
            ),
        ]

        for meta, raw_seq, delay_override, exp_count, exp_delays in scenarios:
            fake_v3 = types.SimpleNamespace(
                immeta=lambda _path, plugin=None: meta,
                imiter=lambda _path, plugin=None: iter(raw_seq),
            )
            fake_pkg = types.SimpleNamespace(v3=fake_v3)
            out = io.StringIO()
            with mock.patch.dict(sys.modules, {"imageio": fake_pkg, "imageio.v3": fake_v3}):
                with contextlib.redirect_stdout(out):
                    frames, delays = screen.extract_video_frames(
                        "dummy.mp4",
                        fit=False,
                        delay_override=delay_override,
                        fps_override=None,
                        max_frames=None,
                    )
            self.assertEqual(len(frames), exp_count)
            self.assertEqual(delays, exp_delays)
            if exp_count == 140:
                self.assertIn("140-frame device limit", out.getvalue())


class CliMockTests(unittest.TestCase):
    def setUp(self):
        self.sleep_patcher = mock.patch("time.sleep", return_value=None)
        self.sleep_patcher.start()

    def tearDown(self):
        self.sleep_patcher.stop()

    def _run_cli(self, mock_dev: MockS75ProDevice, argv: list[str]) -> str:
        def fake_open(kb_self):
            kb_self.dev = mock_dev
            kb_self.wait_until_idle()
            return kb_self

        buf = io.StringIO()
        with (
            mock.patch.object(lib.AulaS75Pro, "open", fake_open),
            mock.patch.object(sys, "argv", ["cli.py"] + argv),
            contextlib.redirect_stdout(buf),
        ):
            cli.main()
        return buf.getvalue()

    def test_cli_info_battery_read_underglow_and_settings(self):
        dev = MockS75ProDevice()
        kb_tmp = lib.AulaS75Pro(mode="usb")
        dev.flash_9800 = bytes(kb_tmp._build_mode_payload(effect=1, r=255, g=0, b=0, brightness=5))
        dev.flash_9000 = bytes(
            lib.build_report(lib.CMD_GENERAL_SETTINGS, bytes([1, 0, 1, 1, 2, 0, 3]), trailer=True)
        )
        custom = bytearray(576)
        custom[1 * 4 : 1 * 4 + 4] = bytes([1, 12, 34, 56])
        custom[574:576] = b"\xaa\x55"
        dev.flash_9c00 = bytes(custom)
        live = bytearray(576)
        for s in range(144):
            live[s * 4] = s
        live[1 * 4 : 1 * 4 + 4] = bytes([1, 99, 88, 77])
        dev.live_rgb = bytes(live)

        out_info = self._run_cli(dev, ["info", "--raw"])
        self.assertIn("FW=v1.03", out_info)
        self.assertIn("Raw (0x8F80):", out_info)

        out_batt = self._run_cli(dev, ["battery"])
        self.assertIn("4/5 (76–95%)", out_batt)

        out_lit = self._run_cli(dev, ["read", "lighting"])
        self.assertIn("RGB=(255, 0, 0)", out_lit)

        out_set = self._run_cli(dev, ["read", "settings"])
        self.assertIn("disable_alt_tab=True", out_set)
        self.assertIn("win_lock=True", out_set)

        out_live = self._run_cli(dev, ["read", "live-rgb"])
        self.assertIn("Esc", out_live)
        self.assertIn("RGB( 99,  88,  77)", out_live)

        out_custom = self._run_cli(dev, ["read", "custom-table"])
        self.assertIn("RGB( 12,  34,  56)", out_custom)
        self.assertIn("Trailer: aa55", out_custom)

        out_ug = self._run_cli(dev, ["underglow", "off"])
        self.assertIn("Underglow mode 4 (off) applied", out_ug)
        self.assertIn("restored", out_ug)

        out_kr = self._run_cli(dev, ["set-key-response", "3", "--disable-alt-tab", "--win-lock"])
        self.assertIn("Device ack:", out_kr)


if __name__ == "__main__":
    unittest.main()
