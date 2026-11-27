#!/usr/bin/env python3
"""Offline unit & loopback HTTP integration tests for scripts/aula_s75pro/webui."""

from __future__ import annotations

import base64
import http.client
import io
import json
import re
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
BASE_DIR = TESTS_DIR.parent
SCREEN_DIR = BASE_DIR / "screenUpload"
for _p in (str(TESTS_DIR), str(BASE_DIR), str(SCREEN_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from PIL import Image  # noqa: E402

import aula_s75pro as lib  # noqa: E402
import aula_s75pro_screen as screen_mod  # noqa: E402
from keymap import KEYMAP, PHYSICAL_INDICES  # noqa: E402
from test_offline_protocol import MockDongleDevice, MockS75ProDevice  # noqa: E402
from webui import server as web_server  # noqa: E402


def _http_request(
    port: int,
    method: str,
    path: str,
    body: bytes | dict | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    hdrs = dict(headers or {})
    if isinstance(body, dict):
        raw_body = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif body is None:
        raw_body = b""
    else:
        raw_body = body

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=raw_body if raw_body else None, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, data
    finally:
        conn.close()


def _make_usb_factory(dev: MockS75ProDevice, *, fail_open: bool = False):
    def factory(mode: str) -> lib.AulaS75Pro:
        kb = lib.AulaS75Pro(mode="usb" if mode == "auto" else mode)

        def fake_open():
            if fail_open:
                raise IOError("No device found with VID=0C45 PID=800A")
            kb._transport = "usb"
            kb.vid = lib.VID
            kb.pid = lib.PID_USB
            kb.interface = lib.INTERFACE_USB
            kb.dev = dev
            kb.wait_until_idle()
            return kb

        kb.open = fake_open
        return kb

    return factory


def _make_dongle_factory(dev: MockDongleDevice):
    def factory(mode: str) -> lib.AulaS75Pro:
        kb = lib.AulaS75Pro(mode="dongle")

        def fake_open():
            kb._transport = "dongle"
            kb.vid = lib.VID_DONGLE
            kb.pid = lib.PID_DONGLE
            kb.interface = lib.INTERFACE_DONGLE
            kb.dev = dev
            kb.ping_dongle()
            return kb

        kb.open = fake_open
        return kb

    return factory


class KleLayoutMappingTests(unittest.TestCase):
    def test_kle_layout_maps_80_keys_one_to_one_with_keymap_physical_indices(self):
        raw_kle = json.loads(web_server.LAYOUT_PATH.read_text(encoding="utf-8"))
        parsed = web_server.parse_kle_layout(raw_kle)

        keys = parsed["keys"]
        decals = parsed["decals"]
        self.assertEqual(len(keys), 80)
        self.assertEqual(len(web_server.KLE_INDEX_TO_MATRIX_ID), 80)
        self.assertEqual(len(set(web_server.KLE_INDEX_TO_MATRIX_ID)), 80)
        self.assertEqual(set(web_server.KLE_INDEX_TO_MATRIX_ID), PHYSICAL_INDICES)

        decal_labels = [d["label"] for d in decals]
        self.assertIn("KNOB", decal_labels)
        self.assertIn("SCREEN", decal_labels)
        self.assertIn("", decal_labels)  # screen bezel

        # Anchor checks against KLE indices and keymap.py names
        anchors = {
            0: ("Esc", "Esc"),
            13: ("Delete", "Del"),
            27: ("Backspace", "Backspace"),
            28: ("Home", "Home"),
            42: ("|\\\n", "\\"),
            43: ("End", "End"),
            56: ("Enter", "Enter"),
            57: ("Shift", "Shift_L"),
            68: ("Shift", "Shift_R"),
            69: ("↑", "Up"),
            73: ("", "Space"),
            77: ("←", "Left"),
            78: ("↓", "Down"),
            79: ("→", "Right"),
        }
        for kle_idx, (_expected_kle_prefix, km_name) in anchors.items():
            self.assertEqual(
                web_server.KLE_INDEX_TO_MATRIX_ID[kle_idx],
                KEYMAP[km_name],
                f"KLE index {kle_idx} should map to {km_name}",
            )
        self.assertEqual(keys[0]["label"], "Esc")
        self.assertEqual(keys[73]["label"], "")  # blank Spacebar


class WebUiWiredApiTests(unittest.TestCase):
    def setUp(self):
        self.sleep_patcher = mock.patch("time.sleep", return_value=None)
        self.sleep_patcher.start()

        self.dev = MockS75ProDevice()
        self.disconnected = False
        self.uploaded_calls: list[tuple[list[bytes], list[int]]] = []
        self.backend_closed = False
        test_case = self

        class FakeBackend:
            def open(self):
                return self

            def close(self):
                test_case.backend_closed = True

        fake_screen = types.SimpleNamespace(
            SCREEN_W=screen_mod.SCREEN_W,
            SCREEN_H=screen_mod.SCREEN_H,
            PIXEL_BYTES=screen_mod.PIXEL_BYTES,
            CHUNK_SIZE=screen_mod.CHUNK_SIZE,
            MAX_FRAMES=screen_mod.MAX_FRAMES,
            MIN_DELAY_MS=screen_mod.MIN_DELAY_MS,
            MAX_DELAY_MS=screen_mod.MAX_DELAY_MS,
            WIRE_TICK_MS=screen_mod.WIRE_TICK_MS,
            DEFAULT_STILL_DELAY=screen_mod.DEFAULT_STILL_DELAY,
            VIDEO_EXTENSIONS=screen_mod.VIDEO_EXTENSIONS,
            pil_to_rgb565=screen_mod.pil_to_rgb565,
            ms_to_wire_delay=screen_mod.ms_to_wire_delay,
            extract_gif_frames=screen_mod.extract_gif_frames,
            extract_video_frames=screen_mod.extract_video_frames,
            total_chunks_needed=screen_mod.total_chunks_needed,
            make_backend=lambda: FakeBackend(),
            upload=lambda backend, frames, delays, verbose=False: self.uploaded_calls.append(
                (list(frames), list(delays))
            ),
        )

        def kb_factory(mode: str):
            return _make_usb_factory(self.dev, fail_open=self.disconnected)(mode)

        self.server = web_server.create_server(
            port=0,
            mode="usb",
            kb_factory=kb_factory,
            screen_module=fake_screen,
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.sleep_patcher.stop()

    def test_static_meta_status_lighting_settings_custom_and_rtc(self):
        # Static root and traversal protection
        st, hdrs, body = _http_request(self.port, "GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("text/html", hdrs["content-type"])
        self.assertIn(b"AULA S75 Pro", body)

        st_kle, _, body_kle = _http_request(self.port, "GET", "/static/keyboard-layout.json")
        self.assertEqual(st_kle, 200)
        self.assertEqual(len(web_server.parse_kle_layout(json.loads(body_kle))["keys"]), 80)

        st_trav, _, _ = _http_request(self.port, "GET", "/static/../aula_s75pro.py")
        self.assertEqual(st_trav, 403)

        # Metadata
        st_meta, _, raw_meta = _http_request(self.port, "GET", "/api/meta")
        self.assertEqual(st_meta, 200)
        meta = json.loads(raw_meta)
        self.assertEqual(len(meta["kle_to_matrix"]), 80)
        self.assertEqual(meta["screen"]["width"], 135)
        self.assertEqual(meta["screen"]["height"], 240)
        self.assertEqual(len(meta["effects"]), 20)

        # Status (wired)
        st_status, _, raw_status = _http_request(self.port, "GET", "/api/status")
        self.assertEqual(st_status, 200)
        status = json.loads(raw_status)
        self.assertTrue(status["connected"])
        self.assertEqual(status["mode"], "usb")
        self.assertEqual(status["info"]["fw_version"], "1.03")
        self.assertTrue(status["capabilities"]["can_read"])
        self.assertTrue(status["capabilities"]["can_upload_screen"])

        # Lighting POST + GET
        st_lit, _, raw_lit = _http_request(
            self.port,
            "POST",
            "/api/lighting",
            {"effect": 7, "r": 12, "g": 34, "b": 56, "brightness": 4, "speed": 2, "direction": 1, "option": 1},
        )
        self.assertEqual(st_lit, 200)
        self.assertTrue(json.loads(raw_lit)["ok"])
        st_get_lit, _, raw_get_lit = _http_request(self.port, "GET", "/api/lighting")
        self.assertEqual(st_get_lit, 200)
        got_lit = json.loads(raw_get_lit)
        self.assertEqual(got_lit["effect"], 7)
        self.assertEqual(got_lit["rgb"], [12, 34, 56])
        self.assertEqual(got_lit["option"], 1)

        # Underglow preserves 0x9800 lighting
        st_ug, _, raw_ug = _http_request(
            self.port, "POST", "/api/underglow", {"mode": "breathing", "preserve_lighting": True}
        )
        self.assertEqual(st_ug, 200)
        ug = json.loads(raw_ug)
        self.assertEqual(ug["mode"], 3)
        self.assertTrue(ug["restored_lighting"])

        # Custom table POST + GET
        esc_id = str(KEYMAP["Esc"])
        w_id = str(KEYMAP["W"])
        st_cust, _, _ = _http_request(
            self.port,
            "POST",
            "/api/custom-table",
            {"keys": {esc_id: [255, 0, 0], w_id: [0, 200, 100]}, "brightness": 4},
        )
        self.assertEqual(st_cust, 200)
        st_get_cust, _, raw_get_cust = _http_request(self.port, "GET", "/api/custom-table")
        self.assertEqual(st_get_cust, 200)
        got_cust = json.loads(raw_get_cust)
        self.assertEqual(got_cust["keys"][esc_id], [255, 0, 0])
        self.assertEqual(got_cust["keys"][w_id], [0, 200, 100])

        # Settings POST + GET + RTC sync
        st_set, _, _ = _http_request(
            self.port,
            "POST",
            "/api/settings",
            {
                "key_response_time": 4,
                "sleep_time": 2,
                "fn_switch": 1,
                "disable_alt_tab": True,
                "disable_alt_f4": False,
                "win_lock": True,
            },
        )
        self.assertEqual(st_set, 200)
        st_get_set, _, raw_get_set = _http_request(self.port, "GET", "/api/settings")
        self.assertEqual(st_get_set, 200)
        got_set = json.loads(raw_get_set)
        self.assertEqual(got_set["key_response_time"], 4)
        self.assertEqual(got_set["sleep_time"], 2)
        self.assertEqual(got_set["fn_switch"], 1)
        self.assertTrue(got_set["disable_alt_tab"])
        self.assertTrue(got_set["win_lock"])

        st_clk, _, raw_clk = _http_request(self.port, "POST", "/api/sync-clock", {})
        self.assertEqual(st_clk, 200)
        self.assertTrue(json.loads(raw_clk)["ok"])

    def test_screen_preview_png_and_animated_gif_and_upload_and_temp_cleanup(self):
        # 1. PNG preview (135x240)
        png_buf = io.BytesIO()
        Image.new("RGB", (60, 100), (255, 0, 0)).save(png_buf, format="PNG")

        created_temps: list[str] = []
        orig_ntf = tempfile.NamedTemporaryFile

        def tracking_ntf(*args, **kwargs):
            handle = orig_ntf(*args, **kwargs)
            created_temps.append(handle.name)
            return handle

        with mock.patch("tempfile.NamedTemporaryFile", side_effect=tracking_ntf):
            st, _, raw = _http_request(
                self.port,
                "POST",
                "/api/screen/preview?filename=test.png&fit=1",
                png_buf.getvalue(),
                {"Content-Type": "application/octet-stream"},
            )
        self.assertEqual(st, 200)
        prev = json.loads(raw)
        self.assertEqual((prev["width"], prev["height"]), (135, 240))
        self.assertEqual(prev["frame_count"], 1)
        self.assertEqual(prev["chunk_count"], 16)
        self.assertEqual(prev["preview_mime"], "image/png")
        self.assertFalse(prev["truncated"])
        decoded_png = Image.open(io.BytesIO(base64.b64decode(prev["preview_base64"])))
        self.assertEqual(decoded_png.size, (135, 240))
        self.assertTrue(created_temps)
        for p in created_temps:
            self.assertFalse(Path(p).exists(), f"Temp file {p} was not cleaned up")

        # 2. Animated GIF preview (3 frames, custom delay)
        gif_frames = [
            Image.new("RGB", (135, 240), col)
            for col in ((255, 0, 0), (0, 255, 0), (0, 0, 255))
        ]
        gif_buf = io.BytesIO()
        gif_frames[0].save(
            gif_buf,
            format="GIF",
            save_all=True,
            append_images=gif_frames[1:],
            duration=100,
            loop=0,
        )
        st_gif, _, raw_gif = _http_request(
            self.port,
            "POST",
            "/api/screen/preview?filename=anim.gif&delay=60",
            gif_buf.getvalue(),
            {"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(st_gif, 200)
        gif_prev = json.loads(raw_gif)
        self.assertEqual(gif_prev["frame_count"], 3)
        self.assertEqual(gif_prev["delays_ms"], [60, 60, 60])
        self.assertEqual(gif_prev["preview_mime"], "image/gif")
        decoded_gif = Image.open(io.BytesIO(base64.b64decode(gif_prev["preview_base64"])))
        self.assertEqual(decoded_gif.n_frames, 3)

        # 3. Screen upload calls backend cleanly, waits for HID reattach, and allows immediate status check
        open_attempts = 0
        orig_disconnected = self.disconnected
        orig_kb_factory = self.server.kb_factory

        def transient_reattach_factory(mode: str):
            nonlocal open_attempts
            open_attempts += 1
            kb = orig_kb_factory(mode)
            if open_attempts <= 2:
                def transient_fail():
                    raise IOError("Waiting for udevd / hidraw rebind")

                kb.open = transient_fail
            return kb

        self.server.kb_factory = transient_reattach_factory
        try:
            st_up, _, raw_up = _http_request(
                self.port,
                "POST",
                "/api/screen/upload?filename=test.png",
                png_buf.getvalue(),
                {"Content-Type": "application/octet-stream"},
            )
            self.assertEqual(st_up, 200)
            up = json.loads(raw_up)
            self.assertTrue(up["ok"])
            self.assertTrue(up["hid_reattached"])
            self.assertEqual(open_attempts, 3)
            self.assertEqual(len(self.uploaded_calls), 1)
            self.assertEqual(len(self.uploaded_calls[0][0][0]), 135 * 240 * 2)
            self.assertTrue(self.backend_closed)

            st_after, _, raw_after = _http_request(self.port, "GET", "/api/status")
            self.assertEqual(st_after, 200)
            after = json.loads(raw_after)
            self.assertTrue(after["connected"])
            self.assertEqual(after["mode"], "usb")

            # 4. Error path: upload failure still closes backend and waits for HID reattach under hw_lock
            self.backend_closed = False
            reattach_calls = 0

            def counting_reattach_factory(mode: str):
                nonlocal reattach_calls
                reattach_calls += 1
                return orig_kb_factory(mode)

            self.server.kb_factory = counting_reattach_factory
            orig_upload = self.server.screen_module.upload

            def failing_upload(*args, **kwargs):
                raise IOError("Simulated bulk chunk failure")

            self.server.screen_module.upload = failing_upload
            try:
                st_err, _, raw_err = _http_request(
                    self.port,
                    "POST",
                    "/api/screen/upload?filename=test.png",
                    png_buf.getvalue(),
                    {"Content-Type": "application/octet-stream"},
                )
            finally:
                self.server.screen_module.upload = orig_upload

            self.assertEqual(st_err, 503)
            self.assertIn("Simulated bulk chunk failure", json.loads(raw_err)["error"])
            self.assertTrue(self.backend_closed)
            self.assertGreaterEqual(reattach_calls, 1)
        finally:
            self.server.kb_factory = orig_kb_factory
            self.disconnected = orig_disconnected

    def test_validation_and_disconnected_errors(self):
        # 400 bad effect / bad key / empty upload
        st1, _, _ = _http_request(self.port, "POST", "/api/lighting", {"effect": 99})
        self.assertEqual(st1, 400)
        st2, _, _ = _http_request(self.port, "POST", "/api/custom-table", {"keys": {"999": [1, 2, 3]}})
        self.assertEqual(st2, 400)
        st3, _, _ = _http_request(
            self.port,
            "POST",
            "/api/screen/preview?filename=bad.png",
            b"",
            {"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(st3, 400)

        # 413 oversized upload rejected before reading body
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.putrequest("POST", "/api/screen/preview?filename=huge.png")
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(web_server.MAX_UPLOAD_BYTES + 1))
            conn.endheaders()
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 413)
        finally:
            conn.close()

        # Disconnected: /api/status returns 200 connected=False, writes return 503
        self.disconnected = True
        st_disc, _, raw_disc = _http_request(self.port, "GET", "/api/status")
        self.assertEqual(st_disc, 200)
        disc = json.loads(raw_disc)
        self.assertFalse(disc["connected"])
        self.assertEqual(disc["mode"], "disconnected")

        st_503, _, _ = _http_request(self.port, "POST", "/api/sync-clock", {})
        self.assertEqual(st_503, 503)


class WebUiDongleApiTests(unittest.TestCase):
    def setUp(self):
        self.sleep_patcher = mock.patch("time.sleep", return_value=None)
        self.sleep_patcher.start()
        self.dev = MockDongleDevice(battery_percent=78)
        self.dongle_screen_exit = False
        test_case = self

        class DongleFailScreenBackend:
            def __init__(self):
                if test_case.dongle_screen_exit:
                    sys.exit("AULA S75 Pro 2.4G wireless dongle detected (VID=0x05ac PID=0x024f)")
                sys.exit("Keyboard not found (VID=0x0c45 PID=0x800a)")

        fake_screen = types.SimpleNamespace(
            SCREEN_W=screen_mod.SCREEN_W,
            SCREEN_H=screen_mod.SCREEN_H,
            PIXEL_BYTES=screen_mod.PIXEL_BYTES,
            CHUNK_SIZE=screen_mod.CHUNK_SIZE,
            MAX_FRAMES=screen_mod.MAX_FRAMES,
            MIN_DELAY_MS=screen_mod.MIN_DELAY_MS,
            MAX_DELAY_MS=screen_mod.MAX_DELAY_MS,
            WIRE_TICK_MS=screen_mod.WIRE_TICK_MS,
            DEFAULT_STILL_DELAY=screen_mod.DEFAULT_STILL_DELAY,
            VIDEO_EXTENSIONS=screen_mod.VIDEO_EXTENSIONS,
            pil_to_rgb565=screen_mod.pil_to_rgb565,
            ms_to_wire_delay=screen_mod.ms_to_wire_delay,
            extract_gif_frames=screen_mod.extract_gif_frames,
            extract_video_frames=screen_mod.extract_video_frames,
            total_chunks_needed=screen_mod.total_chunks_needed,
            make_backend=lambda: DongleFailScreenBackend(),
            upload=lambda *a, **kw: None,
        )

        self.server = web_server.create_server(
            port=0,
            mode="dongle",
            kb_factory=_make_dongle_factory(self.dev),
            screen_module=fake_screen,
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.sleep_patcher.stop()

    def test_dongle_status_writes_and_409_wired_only_guards(self):
        st, _, raw = _http_request(self.port, "GET", "/api/status")
        self.assertEqual(st, 200)
        status = json.loads(raw)
        self.assertTrue(status["connected"])
        self.assertEqual(status["mode"], "dongle")
        self.assertEqual(status["battery"]["percent"], 78)
        self.assertFalse(status["capabilities"]["can_read"])
        self.assertFalse(status["capabilities"]["can_upload_screen"])

        # Supported writes over 2.4G
        self.assertEqual(
            _http_request(self.port, "POST", "/api/lighting", {"effect": "static", "r": 1, "g": 2, "b": 3})[0],
            200,
        )
        self.assertEqual(
            _http_request(self.port, "POST", "/api/underglow", {"mode": "flowing"})[0],
            200,
        )
        self.assertEqual(
            _http_request(self.port, "POST", "/api/custom-table", {"keys": {str(KEYMAP["Esc"]): [9, 8, 7]}})[0],
            200,
        )
        self.assertEqual(
            _http_request(self.port, "POST", "/api/settings", {"key_response_time": 2, "sleep_time": 1})[0],
            200,
        )
        self.assertEqual(
            _http_request(self.port, "POST", "/api/sync-clock", {})[0],
            200,
        )

        # Offline preview works even on dongle mode
        png_buf = io.BytesIO()
        Image.new("RGB", (40, 40), (0, 255, 0)).save(png_buf, format="PNG")
        st_prev, _, _ = _http_request(
            self.port,
            "POST",
            "/api/screen/preview?filename=ok.png",
            png_buf.getvalue(),
            {"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(st_prev, 200)

        # Wired-only endpoints return 409 Conflict
        for method, path, body in (
            ("GET", "/api/custom-table", None),
            ("GET", "/api/lighting", None),
            ("GET", "/api/settings", None),
        ):
            code, _, err_raw = _http_request(self.port, method, path, body)
            self.assertEqual(code, 409, f"{method} {path} should return 409 on 2.4G")
            self.assertIn("error", json.loads(err_raw))

        st_up_409, _, _ = _http_request(
            self.port,
            "POST",
            "/api/screen/upload?filename=ok.png",
            png_buf.getvalue(),
            {"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(st_up_409, 409)

        # Also check auto mode maps PyUSB dongle SystemExit -> 409 and missing -> 503
        self.server.kb_mode = "auto"
        self.dongle_screen_exit = True
        self.assertEqual(
            _http_request(
                self.port,
                "POST",
                "/api/screen/upload?filename=ok.png",
                png_buf.getvalue(),
                {"Content-Type": "application/octet-stream"},
            )[0],
            409,
        )
        self.dongle_screen_exit = False
        self.assertEqual(
            _http_request(
                self.port,
                "POST",
                "/api/screen/upload?filename=ok.png",
                png_buf.getvalue(),
                {"Content-Type": "application/octet-stream"},
            )[0],
            503,
        )


class WebUiSafetyTests(unittest.TestCase):
    def test_server_safety_and_loopback_constraint(self):
        srv_text = (BASE_DIR / "webui" / "server.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*(?:import|from)\s+cgi\b", srv_text, re.MULTILINE))
        compact = re.sub(r"[^0-9a-f]", "", srv_text.lower())
        self.assertNotIn("04" + "38", compact)
        self.assertNotIn("0x" + "3804", srv_text.lower())
        self.assertNotIn("aa42" + "895a" + "ff71" + "62cc", compact)

        with self.assertRaises(ValueError):
            web_server.create_server(port=0, host="0.0.0.0")


if __name__ == "__main__":
    unittest.main()
