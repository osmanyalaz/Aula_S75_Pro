#!/usr/bin/env python3
"""Zero-dependency local HTTP backend for the AULA S75 Pro WebUI."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import mimetypes
import os
import re
import struct
import sys
import tempfile
import threading
import time
import webbrowser
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
SCREEN_DIR = BASE_DIR / "screenUpload"
for _p in (str(BASE_DIR), str(SCREEN_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import aula_s75pro as hw  # noqa: E402
import aula_s75pro_screen as default_screen_mod  # noqa: E402
from cli import EFFECT_NOTES  # noqa: E402
from keymap import KEYMAP, PHYSICAL_INDICES  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MiB

STATIC_DIR = Path(__file__).resolve().parent / "static"
LAYOUT_PATH = STATIC_DIR / "keyboard-layout.json"

# Strict 1:1 ordered mapping from non-decal KLE key index (0..79) in
# static/keyboard-layout.json to firmware light_index IDs in keymap.py.
KLE_INDEX_TO_MATRIX_ID: tuple[int, ...] = (
    # Row 0 (Function row): Esc, F1..F12, Delete [0..13]
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 119,
    # Row 1 (Number row): ~`, !1..+=, Backspace, Home [14..28]
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 103, 117,
    # Row 2 (Top alpha): Tab, Q..}], |\, End [29..43]
    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 67, 120,
    # Row 3 (Home row): CapsLock, A..'", Enter [44..56]
    55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 85,
    # Row 4 (Bottom alpha): Shift_L, Z../?, Shift_R [57..68]
    73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
    # Row 4b (Up arrow): ↑ [69]
    101,
    # Row 5 (Modifiers & Space): Ctrl_L, Win_L, Alt_L, Space, Alt_R, Fn, Ctrl_R [70..76]
    91, 92, 93, 94, 95, 96, 98,
    # Row 5b (Arrows): ←, ↓, → [77..79]
    99, 100, 102,
)

assert len(KLE_INDEX_TO_MATRIX_ID) == 80, "KLE mapping must contain 80 keys"
assert frozenset(KLE_INDEX_TO_MATRIX_ID) == PHYSICAL_INDICES, (
    "KLE mapping must cover keymap.PHYSICAL_INDICES 1:1"
)

_SAFE_EXT_RE = re.compile(r"^\.[a-z0-9]{1,8}$")


class _HttpMappedError(Exception):
    """Internal exception carrying an explicit HTTP status code."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def parse_kle_layout(raw_kle: list[Any]) -> dict[str, Any]:
    """Parse standard KLE JSON into positioned keys (indexed 0..79) and decals."""
    if not isinstance(raw_kle, list):
        raise ValueError("KLE layout root must be a JSON list")

    y = -1.0
    rx = 0.0
    ry = 0.0
    c = "#cccccc"
    t = "#000000"
    a = 4
    f = 3
    r = 0.0

    keys: list[dict[str, Any]] = []
    decals: list[dict[str, Any]] = []
    max_x = 0.0
    max_y = 0.0

    for idx, row in enumerate(raw_kle):
        if idx == 0 and isinstance(row, dict):
            continue
        if not isinstance(row, list):
            raise ValueError(f"Expected KLE row list at index {idx}")

        y += 1.0
        x = rx
        w = 1.0
        h = 1.0
        decal = False

        for item in row:
            if isinstance(item, dict):
                if "rx" in item:
                    rx = float(item["rx"])
                    x = rx
                if "ry" in item:
                    ry = float(item["ry"])
                    y = ry
                if "r" in item:
                    r = float(item["r"])
                if "x" in item:
                    x += float(item["x"])
                if "y" in item:
                    y += float(item["y"])
                if "w" in item:
                    w = float(item["w"])
                if "h" in item:
                    h = float(item["h"])
                if "c" in item:
                    c = str(item["c"])
                if "t" in item:
                    t = str(item["t"])
                if "a" in item:
                    a = int(item["a"])
                if "f" in item:
                    f = int(item["f"])
                if "d" in item:
                    decal = bool(item["d"])
            elif isinstance(item, str):
                entry: dict[str, Any] = {
                    "x": round(x, 4),
                    "y": round(y, 4),
                    "w": round(w, 4),
                    "h": round(h, 4),
                    "c": c,
                    "t": t,
                    "a": a,
                    "f": f,
                    "r": r,
                    "label": item,
                    "decal": decal,
                }
                max_x = max(max_x, x + w)
                max_y = max(max_y, y + h)
                if decal:
                    decals.append(entry)
                else:
                    entry["kle_index"] = len(keys)
                    keys.append(entry)

                x += w
                w = 1.0
                h = 1.0
                decal = False
            else:
                raise ValueError(f"Unsupported KLE item type: {type(item).__name__}")

    return {
        "keys": keys,
        "decals": decals,
        "width": round(max_x, 4),
        "height": round(max_y, 4),
    }


def sanitize_extension(filename: str) -> str:
    """Return a validated lowercase suffix ('.png', '.gif', '.mp4', etc.) or '.bin'."""
    ext = Path(filename or "").suffix.lower()
    return ext if _SAFE_EXT_RE.match(ext) else ".bin"


def _require_int(value: Any, name: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer in range {lo}..{hi}")
    if not (lo <= value <= hi):
        raise ValueError(f"{name} must be in range {lo}..{hi}, got {value}")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _parse_effect_value(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("effect must be an ID (0..19) or valid effect name")
    if isinstance(value, int):
        return _require_int(value, "effect", 0, 19)
    if isinstance(value, str):
        key = value.strip().lower()
        if key in hw.EFFECTS:
            return hw.EFFECTS[key]
        try:
            eid = int(key, 0)
        except ValueError as exc:
            raise ValueError(f"Unknown effect: {value!r}") from exc
        return _require_int(eid, "effect", 0, 19)
    raise ValueError("effect must be an integer (0..19) or name")


def rgb565_to_pil(frame_bytes: bytes, width: int, height: int):
    """Reconstruct a portrait RGB PIL Image from RGB565 little-endian bytes."""
    from PIL import Image

    expected = width * height * 2
    if len(frame_bytes) != expected:
        raise ValueError(f"Expected {expected} RGB565 bytes, got {len(frame_bytes)}")

    try:
        import numpy as np

        vals = np.frombuffer(frame_bytes, dtype="<u2").reshape(height, width)
        r5 = (vals >> 11) & 0x1F
        g6 = (vals >> 5) & 0x3F
        b5 = vals & 0x1F
        r8 = ((r5 << 3) | (r5 >> 2)).astype(np.uint8)
        g8 = ((g6 << 2) | (g6 >> 4)).astype(np.uint8)
        b8 = ((b5 << 3) | (b5 >> 2)).astype(np.uint8)
        rgb = np.stack((r8, g8, b8), axis=-1)
        return Image.fromarray(rgb, mode="RGB")
    except ImportError:
        rgb_out = bytearray(width * height * 3)
        for i, (val,) in enumerate(struct.iter_unpack("<H", frame_bytes)):
            r5 = (val >> 11) & 0x1F
            g6 = (val >> 5) & 0x3F
            b5 = val & 0x1F
            base = i * 3
            rgb_out[base] = (r5 << 3) | (r5 >> 2)
            rgb_out[base + 1] = (g6 << 2) | (g6 >> 4)
            rgb_out[base + 2] = (b5 << 3) | (b5 >> 2)
        return Image.frombytes("RGB", (width, height), bytes(rgb_out))


def encode_preview(
    frames_rgb565: list[bytes], delays_ticks: list[int], screen_mod: Any
) -> tuple[str, str]:
    """Encode RGB565 frames back to base64 PNG (1 frame) or animated GIF (N frames)."""
    imgs = [
        rgb565_to_pil(frame, screen_mod.SCREEN_W, screen_mod.SCREEN_H)
        for frame in frames_rgb565
    ]
    buf = io.BytesIO()
    if len(imgs) == 1:
        imgs[0].save(buf, format="PNG")
        mime = "image/png"
    else:
        durations_ms = [int(d) * screen_mod.WIRE_TICK_MS for d in delays_ticks]
        imgs[0].save(
            buf,
            format="GIF",
            save_all=True,
            append_images=imgs[1:],
            duration=durations_ms,
            loop=0,
            disposal=2,
        )
        mime = "image/gif"
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return mime, b64


def decode_screen_media(
    tmp_path: str,
    screen_mod: Any,
    *,
    fit: bool = False,
    delay_override: Optional[int] = None,
    fps_override: Optional[float] = None,
    max_frames: Optional[int] = None,
) -> tuple[list[bytes], list[int], bool]:
    """Decode uploaded image/GIF/video into (frames_rgb565, delays_ticks, truncated)."""
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:
        raise _HttpMappedError(500, "Pillow is required for screen decoding (pip install Pillow)") from exc

    ext = Path(tmp_path).suffix.lower()
    cap = (
        min(max_frames, screen_mod.MAX_FRAMES)
        if max_frames is not None
        else screen_mod.MAX_FRAMES
    )
    cap = max(1, cap)
    truncated = False
    stdout_buf = io.StringIO()

    if ext in screen_mod.VIDEO_EXTENSIONS:
        try:
            with contextlib.redirect_stdout(stdout_buf):
                frames, delays = screen_mod.extract_video_frames(
                    tmp_path,
                    fit=fit,
                    delay_override=delay_override,
                    fps_override=fps_override,
                    max_frames=cap,
                )
        except SystemExit as exc:
            raise ValueError(str(exc) or "Failed to decode video") from exc
        except Exception as exc:
            raise ValueError(f"Failed to decode video: {exc}") from exc
        if "device limit, truncating" in stdout_buf.getvalue() or (
            max_frames is not None and max_frames > screen_mod.MAX_FRAMES
        ):
            truncated = True
        return frames, delays, truncated

    try:
        with Image.open(tmp_path) as img:
            is_gif = getattr(img, "is_animated", False) or img.format == "GIF"
            n_src_frames = getattr(img, "n_frames", 1)
            if not is_gif:
                frame = screen_mod.pil_to_rgb565(img, fit=fit)
                delay_ticks = (
                    screen_mod.ms_to_wire_delay(delay_override)
                    if delay_override is not None
                    else screen_mod.DEFAULT_STILL_DELAY
                )
                return [frame], [delay_ticks], False
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError(f"Unsupported or corrupt media file: {exc}") from exc

    with contextlib.redirect_stdout(stdout_buf):
        frames, delays = screen_mod.extract_gif_frames(
            tmp_path, fit=fit, delay_override=delay_override
        )
    if not frames:
        raise ValueError("GIF contained no decodable frames")
    frames = frames[:cap]
    delays = delays[:cap]
    truncated = n_src_frames > len(frames)
    return frames, delays, truncated


def parse_screen_query(query: str, screen_mod: Any) -> dict[str, Any]:
    """Validate query parameters for /api/screen/preview and /api/screen/upload."""
    qs = parse_qs(query, keep_blank_values=False)

    filename = qs.get("filename", ["upload.png"])[0]
    fit_raw = qs.get("fit", ["0"])[0].strip().lower()
    fit = fit_raw in ("1", "true", "yes", "on")

    delay_override: Optional[int] = None
    if "delay" in qs and qs["delay"][0].strip() != "":
        try:
            delay_val = int(qs["delay"][0])
        except ValueError as exc:
            raise ValueError("delay query parameter must be an integer (ms)") from exc
        if delay_val <= 0:
            raise ValueError("delay must be a positive integer (ms)")
        delay_override = max(
            screen_mod.MIN_DELAY_MS, min(screen_mod.MAX_DELAY_MS, delay_val)
        )

    fps_override: Optional[float] = None
    if "fps" in qs and qs["fps"][0].strip() != "":
        try:
            fps_override = float(qs["fps"][0])
        except ValueError as exc:
            raise ValueError("fps query parameter must be numeric") from exc
        if fps_override <= 0:
            raise ValueError("fps must be > 0")

    max_frames: Optional[int] = None
    if "max_frames" in qs and qs["max_frames"][0].strip() != "":
        try:
            max_frames = int(qs["max_frames"][0])
        except ValueError as exc:
            raise ValueError("max_frames query parameter must be an integer") from exc
        if max_frames < 1:
            raise ValueError("max_frames must be >= 1")

    return {
        "filename": filename,
        "fit": fit,
        "delay_override": delay_override,
        "fps_override": fps_override,
        "max_frames": max_frames,
    }


def build_meta_payload(screen_mod: Any) -> dict[str, Any]:
    """Return UI metadata including exact 80-key KLE mapping and firmware tables."""
    id_to_name = {eid: name for name, eid in hw.EFFECTS.items()}
    effects = [
        {
            "id": eid,
            "name": id_to_name[eid],
            "note": EFFECT_NOTES.get(eid, ""),
        }
        for eid in sorted(id_to_name)
    ]
    underglow_modes = [
        {"id": mid, "name": hw.UNDERGLOW_MODE_NAMES[mid]}
        for mid in sorted(hw.UNDERGLOW_MODE_NAMES)
    ]
    return {
        "kle_to_matrix": list(KLE_INDEX_TO_MATRIX_ID),
        "keymap": dict(KEYMAP),
        "matrix_to_name": {str(v): k for k, v in KEYMAP.items()},
        "effects": effects,
        "directions": dict(hw.DIRECTIONS),
        "underglow_modes": underglow_modes,
        "sleep_labels": {str(k): v for k, v in hw.SLEEP_TIME_LABELS.items()},
        "debounce_scans": {str(k): v for k, v in hw.DEBOUNCE_SCANS.items()},
        "screen": {
            "width": screen_mod.SCREEN_W,
            "height": screen_mod.SCREEN_H,
            "pixel_bytes": screen_mod.PIXEL_BYTES,
            "chunk_size": screen_mod.CHUNK_SIZE,
            "max_frames": screen_mod.MAX_FRAMES,
            "min_delay_ms": screen_mod.MIN_DELAY_MS,
            "max_delay_ms": screen_mod.MAX_DELAY_MS,
            "wire_tick_ms": screen_mod.WIRE_TICK_MS,
            "max_upload_bytes": MAX_UPLOAD_BYTES,
        },
    }


class AulaWebServer(ThreadingHTTPServer):
    """Threaded loopback HTTP server carrying shared lock and injected backends."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        *,
        kb_mode: str = "auto",
        kb_factory: Optional[Callable[[str], hw.AulaS75Pro]] = None,
        screen_module: Any = None,
    ):
        self.kb_mode = kb_mode
        self.hw_lock = threading.Lock()
        self.kb_factory = kb_factory or (lambda m: hw.AulaS75Pro(mode=m))
        self.screen_module = screen_module or default_screen_mod
        super().__init__(server_address, RequestHandlerClass)


class AulaRequestHandler(BaseHTTPRequestHandler):
    """REST + static asset handler for the local WebUI."""

    protocol_version = "HTTP/1.1"
    server: AulaWebServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Keep console clean while still logging explicit request errors.
        return

    # ---- low-level I/O helpers ---------------------------------------------
    def _send_bytes(
        self, status: int, content_type: str, body: bytes
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if status >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: Any) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", encoded)

    def _read_raw_body(self, *, allow_empty: bool = False) -> bytes:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            if allow_empty:
                return b""
            raise _HttpMappedError(HTTPStatus.BAD_REQUEST, "Missing Content-Length header")
        try:
            length = int(raw_len)
        except ValueError as exc:
            raise _HttpMappedError(HTTPStatus.BAD_REQUEST, "Invalid Content-Length") from exc
        if length < 0:
            raise _HttpMappedError(HTTPStatus.BAD_REQUEST, "Negative Content-Length")
        if length > MAX_UPLOAD_BYTES:
            raise _HttpMappedError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit",
            )
        if length == 0:
            if allow_empty:
                return b""
            raise _HttpMappedError(HTTPStatus.BAD_REQUEST, "Request body is empty")
        data = self.rfile.read(length)
        if len(data) != length:
            raise _HttpMappedError(HTTPStatus.BAD_REQUEST, "Incomplete request body")
        return data

    def _read_json_body(self) -> dict[str, Any]:
        raw = self._read_raw_body(allow_empty=True)
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _HttpMappedError(HTTPStatus.BAD_REQUEST, f"Invalid JSON body: {exc}") from exc
        if not isinstance(obj, dict):
            raise _HttpMappedError(HTTPStatus.BAD_REQUEST, "JSON body must be an object")
        return obj

    def _with_hardware(self, fn: Callable[[hw.AulaS75Pro], Any]) -> Any:
        with self.server.hw_lock:
            try:
                with self.server.kb_factory(self.server.kb_mode) as kb:
                    return fn(kb)
            except hw.UnsupportedModeError as exc:
                raise _HttpMappedError(HTTPStatus.CONFLICT, str(exc)) from exc
            except hw.McuRejectedError as exc:
                raise _HttpMappedError(HTTPStatus.CONFLICT, str(exc)) from exc
            except (IOError, OSError, RuntimeError) as exc:
                raise _HttpMappedError(HTTPStatus.SERVICE_UNAVAILABLE, str(exc)) from exc

    # ---- static serving ----------------------------------------------------
    def _serve_static(self, rel_path: str) -> None:
        clean = unquote(rel_path).lstrip("/")
        if not clean:
            clean = "index.html"
        static_root = STATIC_DIR.resolve()
        candidate = (static_root / clean).resolve()
        if not candidate.is_relative_to(static_root):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Access denied"})
            return
        if not candidate.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Static asset not found: {clean}"})
            return
        ctype, _ = mimetypes.guess_type(str(candidate))
        if candidate.suffix == ".js":
            ctype = "application/javascript; charset=utf-8"
        elif candidate.suffix == ".css":
            ctype = "text/css; charset=utf-8"
        elif candidate.suffix == ".html":
            ctype = "text/html; charset=utf-8"
        elif candidate.suffix == ".json":
            ctype = "application/json; charset=utf-8"
        self._send_bytes(HTTPStatus.OK, ctype or "application/octet-stream", candidate.read_bytes())

    # ---- HTTP dispatch -----------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/":
                self._serve_static("index.html")
            elif path.startswith("/static/"):
                self._serve_static(path[len("/static/") :])
            elif path in ("/index.html", "/app.js", "/style.css", "/keyboard-layout.json"):
                self._serve_static(path.lstrip("/"))
            elif path == "/api/meta":
                self._send_json(HTTPStatus.OK, build_meta_payload(self.server.screen_module))
            elif path == "/api/status":
                self._handle_status()
            elif path == "/api/lighting":
                self._handle_get_lighting()
            elif path == "/api/custom-table":
                self._handle_get_custom_table()
            elif path == "/api/settings":
                self._handle_get_settings()
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})
        except _HttpMappedError as exc:
            self._send_json(exc.status, {"error": exc.message})
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def _allowed_loopback_hosts(self) -> set[str]:
        port = self.server.server_address[1]
        hosts = {f"{DEFAULT_HOST}:{port}", f"localhost:{port}"}
        if port == 80:
            hosts.update({DEFAULT_HOST, "localhost"})
        return hosts

    def _validate_post_host_and_origin(self) -> None:
        allowed_hosts = self._allowed_loopback_hosts()
        host_hdr = (self.headers.get("Host") or "").strip().lower()
        if host_hdr not in allowed_hosts:
            raise _HttpMappedError(
                HTTPStatus.FORBIDDEN,
                f"Rejected Host header for POST request: {host_hdr or '<missing>'}",
            )

        origin_hdr = self.headers.get("Origin")
        if origin_hdr is not None:
            origin_clean = origin_hdr.strip().rstrip("/").lower()
            allowed_origins = {f"http://{h}" for h in allowed_hosts}
            if origin_clean not in allowed_origins:
                raise _HttpMappedError(
                    HTTPStatus.FORBIDDEN,
                    f"Rejected cross-origin POST from Origin: {origin_hdr!r}",
                )

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            self._validate_post_host_and_origin()
            if path == "/api/lighting":
                self._handle_post_lighting()
            elif path == "/api/underglow":
                self._handle_post_underglow()
            elif path == "/api/custom-table":
                self._handle_post_custom_table()
            elif path == "/api/settings":
                self._handle_post_settings()
            elif path == "/api/sync-clock":
                self._handle_post_sync_clock()
            elif path == "/api/screen/preview":
                self._handle_post_screen_preview(parsed.query)
            elif path == "/api/screen/upload":
                self._handle_post_screen_upload(parsed.query)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})
        except _HttpMappedError as exc:
            self._send_json(exc.status, {"error": exc.message})
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    # ---- endpoint handlers -------------------------------------------------
    def _handle_status(self) -> None:
        with self.server.hw_lock:
            try:
                with self.server.kb_factory(self.server.kb_mode) as kb:
                    info = kb.read_device_info()
                    batt = kb.read_battery_level()
                    mode = kb.active_mode
                    is_usb = mode == "usb"
                    payload = {
                        "connected": True,
                        "mode": mode,
                        "configured_mode": self.server.kb_mode,
                        "device": {
                            "vid": f"{kb.vid:04X}",
                            "pid": f"{kb.pid:04X}",
                            "interface": kb.interface,
                        },
                        "info": {
                            "tag": info["tag"],
                            "vid": f"{info['vid']:04X}",
                            "pid": f"{info['pid']:04X}",
                            "fw_major": info["fw_major"],
                            "fw_minor": info["fw_minor"],
                            "fw_version": info["fw_version"],
                            "checksum": info.get("checksum"),
                        },
                        "battery": {
                            "level": batt["level"],
                            "percent": batt.get("percent"),
                            "percent_range": batt["percent_range"],
                        },
                        "capabilities": {
                            "can_read": is_usb,
                            "can_upload_screen": is_usb,
                            "can_stream": is_usb,
                            "can_music_eq": not is_usb,
                        },
                    }
                    self._send_json(HTTPStatus.OK, payload)
            except (IOError, OSError, RuntimeError) as exc:
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "connected": False,
                        "mode": "disconnected",
                        "configured_mode": self.server.kb_mode,
                        "error": str(exc),
                        "device": None,
                        "info": None,
                        "battery": None,
                        "capabilities": {
                            "can_read": False,
                            "can_upload_screen": False,
                            "can_stream": False,
                            "can_music_eq": False,
                        },
                    },
                )

    def _handle_get_lighting(self) -> None:
        def op(kb: hw.AulaS75Pro) -> dict[str, Any]:
            cfg = kb.read_lighting_config()
            return {
                "erased": cfg["erased"],
                "zeroed": cfg["zeroed"],
                "effect": cfg["effect"],
                "rgb": list(cfg["rgb"]),
                "option": cfg["option"],
                "brightness": cfg["brightness"],
                "speed": cfg["speed"],
                "direction": cfg["direction"],
                "checksum": cfg["checksum"],
            }

        self._send_json(HTTPStatus.OK, self._with_hardware(op))

    def _handle_post_lighting(self) -> None:
        body = self._read_json_body()
        if "effect" not in body:
            raise ValueError("Missing 'effect'")
        effect = _parse_effect_value(body["effect"])
        r = _require_int(body.get("r", 255), "r", 0, 255)
        g = _require_int(body.get("g", 255), "g", 0, 255)
        b = _require_int(body.get("b", 255), "b", 0, 255)
        brightness = _require_int(body.get("brightness", 5), "brightness", 0, 5)
        speed = _require_int(body.get("speed", 3), "speed", 0, 5)
        direction = _require_int(body.get("direction", 0), "direction", 0, 2)
        option = _require_int(body.get("option", 0), "option", 0, 1)

        def op(kb: hw.AulaS75Pro) -> dict[str, Any]:
            kb.set_global_lighting(
                effect=effect,
                r=r,
                g=g,
                b=b,
                brightness=brightness,
                speed=speed,
                direction=direction,
                option=option,
            )
            return {
                "ok": True,
                "mode": kb.active_mode,
                "effect": effect,
                "rgb": [r, g, b],
                "brightness": brightness,
                "speed": speed,
                "direction": direction,
                "option": option,
            }

        self._send_json(HTTPStatus.OK, self._with_hardware(op))

    def _handle_post_underglow(self) -> None:
        body = self._read_json_body()
        if "mode" not in body:
            raise ValueError("Missing 'mode'")
        mode = body["mode"]
        preserve = body.get("preserve_lighting", True)
        _require_bool(preserve, "preserve_lighting")
        mode_id = hw._parse_underglow_mode(mode)

        def op(kb: hw.AulaS75Pro) -> dict[str, Any]:
            res = kb.set_underglow_mode(mode_id, preserve_lighting=preserve)
            return {"ok": True, **res}

        self._send_json(HTTPStatus.OK, self._with_hardware(op))

    def _handle_get_custom_table(self) -> None:
        def op(kb: hw.AulaS75Pro) -> dict[str, Any]:
            data = kb.read_custom_lighting_table()
            keys = {
                str(idx): list(data["keys"].get(idx, (0, 0, 0)))
                for idx in sorted(PHYSICAL_INDICES)
            }
            return {
                "keys": keys,
                "checksum": data["checksum"],
            }

        self._send_json(HTTPStatus.OK, self._with_hardware(op))

    def _handle_post_custom_table(self) -> None:
        body = self._read_json_body()
        raw_keys = body.get("keys")
        if not isinstance(raw_keys, dict):
            raise ValueError("'keys' must be an object mapping matrix index to [r, g, b]")
        brightness = _require_int(body.get("brightness", 5), "brightness", 0, 5)

        parsed_keys: dict[int, tuple[int, int, int]] = {}
        for k_raw, rgb_raw in raw_keys.items():
            try:
                if isinstance(k_raw, bool):
                    raise ValueError
                idx = int(k_raw)
            except ValueError as exc:
                raise ValueError(f"Invalid matrix key index: {k_raw!r}") from exc
            if idx not in PHYSICAL_INDICES:
                raise ValueError(f"Matrix index {idx} is not in PHYSICAL_INDICES")
            if not isinstance(rgb_raw, (list, tuple)) or len(rgb_raw) != 3:
                raise ValueError(f"Key {idx} RGB must be a 3-element array [r, g, b]")
            r = _require_int(rgb_raw[0], f"key {idx} r", 0, 255)
            g = _require_int(rgb_raw[1], f"key {idx} g", 0, 255)
            b = _require_int(rgb_raw[2], f"key {idx} b", 0, 255)
            parsed_keys[idx] = (r, g, b)

        def op(kb: hw.AulaS75Pro) -> dict[str, Any]:
            kb.set_custom_lighting(parsed_keys, brightness=brightness)
            return {
                "ok": True,
                "mode": kb.active_mode,
                "key_count": len(parsed_keys),
                "brightness": brightness,
            }

        self._send_json(HTTPStatus.OK, self._with_hardware(op))

    def _handle_get_settings(self) -> None:
        def op(kb: hw.AulaS75Pro) -> dict[str, Any]:
            st = kb.read_general_settings()
            return {
                "erased": st["erased"],
                "zeroed": st["zeroed"],
                "disable_alt_tab": st["disable_alt_tab"],
                "disable_alt_f4": st["disable_alt_f4"],
                "win_lock": st["win_lock"],
                "fn_switch": st["fn_switch"],
                "sleep_time": st["sleep_time"],
                "sleep_label": st["sleep_label"],
                "key_response_time": st["key_response_time"],
                "debounce_scans": st["debounce_scans"],
                "checksum": st["checksum"],
            }

        self._send_json(HTTPStatus.OK, self._with_hardware(op))

    def _handle_post_settings(self) -> None:
        body = self._read_json_body()
        key_response_time = _require_int(
            body.get("key_response_time", 2), "key_response_time", 0, 5
        )
        sleep_time = _require_int(body.get("sleep_time", 0), "sleep_time", 0, 3)
        fn_switch = _require_int(body.get("fn_switch", 0), "fn_switch", 0, 1)
        disable_alt_tab = _require_bool(body.get("disable_alt_tab", False), "disable_alt_tab")
        disable_alt_f4 = _require_bool(body.get("disable_alt_f4", False), "disable_alt_f4")
        win_lock = _require_bool(body.get("win_lock", False), "win_lock")

        def op(kb: hw.AulaS75Pro) -> dict[str, Any]:
            kb.write_general_settings(
                fn_switch=fn_switch,
                sleep_time=sleep_time,
                key_response_time=key_response_time,
                disable_alt_tab=disable_alt_tab,
                disable_alt_f4=disable_alt_f4,
                win_lock=win_lock,
            )
            return {
                "ok": True,
                "mode": kb.active_mode,
                "key_response_time": key_response_time,
                "sleep_time": sleep_time,
                "fn_switch": fn_switch,
                "disable_alt_tab": disable_alt_tab,
                "disable_alt_f4": disable_alt_f4,
                "win_lock": win_lock,
            }

        self._send_json(HTTPStatus.OK, self._with_hardware(op))

    def _handle_post_sync_clock(self) -> None:
        self._read_raw_body(allow_empty=True)
        now = datetime.now()

        def op(kb: hw.AulaS75Pro) -> dict[str, Any]:
            kb.sync_rtc(when=now)
            return {
                "ok": True,
                "mode": kb.active_mode,
                "synced_at": now.isoformat(timespec="seconds"),
            }

        self._send_json(HTTPStatus.OK, self._with_hardware(op))

    def _decode_request_screen_media(self, query: str) -> tuple[list[bytes], list[int], bool]:
        screen_mod = self.server.screen_module
        params = parse_screen_query(query, screen_mod)
        raw_bytes = self._read_raw_body(allow_empty=False)
        suffix = sanitize_extension(params["filename"])

        tmp_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(raw_bytes)
                tmp_path = tmp.name
            return decode_screen_media(
                tmp_path,
                screen_mod,
                fit=params["fit"],
                delay_override=params["delay_override"],
                fps_override=params["fps_override"],
                max_frames=params["max_frames"],
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _handle_post_screen_preview(self, query: str) -> None:
        screen_mod = self.server.screen_module
        frames, delays_ticks, truncated = self._decode_request_screen_media(query)
        mime, b64 = encode_preview(frames, delays_ticks, screen_mod)
        frame_count = len(frames)
        chunk_count = screen_mod.total_chunks_needed(frame_count)
        total_bytes = chunk_count * screen_mod.CHUNK_SIZE
        delays_ms = [int(d) * screen_mod.WIRE_TICK_MS for d in delays_ticks]
        est_sec = round(chunk_count * 0.025 + 1.8, 2)

        self._send_json(
            HTTPStatus.OK,
            {
                "width": screen_mod.SCREEN_W,
                "height": screen_mod.SCREEN_H,
                "frame_count": frame_count,
                "chunk_count": chunk_count,
                "total_bytes": total_bytes,
                "estimated_upload_seconds": est_sec,
                "delays_ms": delays_ms,
                "delays_ticks": [int(d) for d in delays_ticks],
                "truncated": truncated,
                "preview_mime": mime,
                "preview_base64": b64,
                "preview_data_url": f"data:{mime};base64,{b64}",
            },
        )

    def _wait_for_hid_reattach(
        self, timeout_s: float = 2.5, poll_interval_s: float = 0.1
    ) -> bool:
        """Poll briefly for usbhid/hidraw and udev ACLs after PyUSB releases interfaces."""
        max_attempts = max(1, int(timeout_s / max(poll_interval_s, 0.01)) + 1)
        deadline = time.monotonic() + timeout_s
        for attempt in range(max_attempts):
            try:
                with self.server.kb_factory("usb"):
                    return True
            except (IOError, OSError, RuntimeError):
                if attempt + 1 >= max_attempts or time.monotonic() >= deadline:
                    return False
                time.sleep(poll_interval_s)
        return False

    def _handle_post_screen_upload(self, query: str) -> None:
        if self.server.kb_mode == "dongle":
            raise _HttpMappedError(
                HTTPStatus.CONFLICT,
                "TFT screen upload (0x7204 / Interface 2 bulk pipe) is wired USB only; "
                "switch out of 2.4G dongle mode and connect USB.",
            )

        screen_mod = self.server.screen_module
        frames, delays_ticks, truncated = self._decode_request_screen_media(query)
        chunk_count = screen_mod.total_chunks_needed(len(frames))
        delays_ms = [int(d) * screen_mod.WIRE_TICK_MS for d in delays_ticks]

        hid_reattached = False
        with self.server.hw_lock:
            try:
                backend = screen_mod.make_backend()
                opened = False
                try:
                    backend.open()
                    opened = True
                    screen_mod.upload(backend, frames, delays_ticks, verbose=False)
                finally:
                    had_usb_session = opened or bool(getattr(backend, "_detached", None))
                    backend.close()
                    if had_usb_session:
                        try:
                            hid_reattached = self._wait_for_hid_reattach()
                        except Exception:
                            hid_reattached = False
            except SystemExit as exc:
                msg = str(exc) or "Screen backend aborted"
                low = msg.lower()
                if "dongle" in low:
                    raise _HttpMappedError(HTTPStatus.CONFLICT, msg) from exc
                if "not found" in low:
                    raise _HttpMappedError(HTTPStatus.SERVICE_UNAVAILABLE, msg) from exc
                raise _HttpMappedError(HTTPStatus.INTERNAL_SERVER_ERROR, msg) from exc
            except (IOError, OSError, RuntimeError) as exc:
                raise _HttpMappedError(HTTPStatus.SERVICE_UNAVAILABLE, str(exc)) from exc

        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "width": screen_mod.SCREEN_W,
                "height": screen_mod.SCREEN_H,
                "frame_count": len(frames),
                "chunk_count": chunk_count,
                "delays_ms": delays_ms,
                "truncated": truncated,
                "hid_reattached": hid_reattached,
            },
        )


def create_server(
    port: int = DEFAULT_PORT,
    mode: str = "auto",
    *,
    host: str = DEFAULT_HOST,
    kb_factory: Optional[Callable[[str], hw.AulaS75Pro]] = None,
    screen_module: Any = None,
) -> AulaWebServer:
    """Create a configured loopback ThreadingHTTPServer instance."""
    if host != DEFAULT_HOST:
        raise ValueError(f"WebUI server must bind strictly to {DEFAULT_HOST}, got {host!r}")
    if mode not in ("auto", "usb", "dongle"):
        raise ValueError(f"mode must be 'auto', 'usb', or 'dongle', got {mode!r}")
    return AulaWebServer(
        (host, port),
        AulaRequestHandler,
        kb_mode=mode,
        kb_factory=kb_factory,
        screen_module=screen_module,
    )


def run_server(
    port: int = DEFAULT_PORT,
    mode: str = "auto",
    open_browser: bool = True,
) -> None:
    """Start the local WebUI HTTP server on 127.0.0.1 until Ctrl-C."""
    httpd = create_server(port=port, mode=mode)
    actual_port = httpd.server_address[1]
    url = f"http://{DEFAULT_HOST}:{actual_port}/"
    print(f"AULA S75 Pro WebUI running at {url} (mode={mode}) — press Ctrl+C to stop")
    if open_browser:
        threading.Timer(0.25, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down WebUI...")
    finally:
        httpd.shutdown()
        httpd.server_close()


def _main() -> None:
    import argparse

    p = argparse.ArgumentParser(description="AULA S75 Pro local WebUI server")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port on 127.0.0.1")
    p.add_argument("--mode", choices=["auto", "usb", "dongle"], default="auto", help="connection mode")
    p.add_argument("--no-open", action="store_true", help="do not automatically open browser")
    args = p.parse_args()
    run_server(port=args.port, mode=args.mode, open_browser=not args.no_open)


if __name__ == "__main__":
    _main()
