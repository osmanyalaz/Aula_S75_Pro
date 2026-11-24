#!/usr/bin/env python3
"""
Aula S75 Pro – Screen uploader  (still image + animated GIF)
Reverse-engineered from USB/HID traffic captures (usbmon + Wireshark).

┌─ Device ───────────────────────────────────────────────────────────────┐
│  Vendor : VID=0x0C45  PID=0x800A  (reported as SONiX)    │
│  Screen : 135 × 240 px, RGB565 little-endian (portrait)   │
│           pixel[0] = top-left corner, row-major                                         │
│           red  = 0xF800 → bytes 0x00 0xF8                              │
│           green= 0x07E0 → bytes 0xE0 0x07                              │
│           blue = 0x001F → bytes 0x1F 0x00                              │
└────────────────────────────────────────────────────────────────────────┘

┌─ Wire protocol ─────────────────────────────────────────────────────────┐
│  EP0  SET_REPORT [Feature] → cmd_begin  (04 18 00…)                     │
│  EP0  GET_REPORT [Feature] ← ack                                        │
│  EP0  SET_REPORT [Feature] → cmd_upload (04 72 <mode> 00… <chunks> …)   │
│         note: cmd[2] (0x03/0x05) is ignored by firmware 0x000045D4;     │
│         chunks = ceil((256 + N_frames × 64800) / 4096)                  │
│  EP0  GET_REPORT [Feature] ← ack                                        │
│  ×chunks:                                                               │
│    EP 0x03  write(4096 bytes)  → image chunk                            │
│    EP 0x84  read (64 bytes)    ← ack  01 5A 02 00…                      │
│  EP0  SET_REPORT [Feature] → cmd_end   (04 02 00…)                      │
└─────────────────────────────────────────────────────────────────────────┘

┌─ Transfer buffer layout  (ceil((256 + N_frames × 64800) / 4096) × 4096) ┐
│  [N_frames]  [delay_0] … [delay_{N-1}]  [0xFF × (255-N)]   256 bytes    │
│  [frame_0 pixels: 64 800 bytes = 135×240×2]                             │
│  [frame_1 pixels: 64 800 bytes]                                         │
│  …                                                                      │
│  [frame_{N-1} pixels: 64 800 bytes]                                     │
│  [0xFF × tail]    pads total transfer to a multiple of 4096 bytes       │
│                                                                         │
│  delay unit: 2 ms wire ticks (0x10..0xFF = 32..510 ms). Values < 0x10   │
│  are silently replaced with 0x19 (50 ms) by firmware FUN_00011a84.      │
│  Max N_frames = 191 (0xC0 - 1): MCU reads 192 B (0xC0) into RAM         │
│  0x200021DA; > 191 frames overflows past 0x20002299 into fuel-gauge RAM.│
│  Still image uses delay=0x19=25 ticks (50 ms).                         │
└─────────────────────────────────────────────────────────────────────────┘

Transport: pyusb only. An experimental hidapi backend was tried and dropped -
sending the image-chunk data as a HID Output Report over hidapi got the
firmware's upload state machine stuck badly enough to require a factory
reset, without even updating the display. Do not resurrect that path
without a hidraw-level packet capture to confirm the exact report framing
first. pyusb's raw endpoint access (with kernel driver detach) is the only
confirmed-safe way to do the bulk chunk transfer on this device.

  Post-mortem detail (useful if you ever revisit this): the write() call
  reported success, but the screen itself never changed at all - not even
  garbled. What broke instead was general key typing, fixed by a factory
  reset that left the screen's stored image completely untouched. This
  strongly suggests hidapi's write() on interface 3 was never reaching the
  same pipe pyusb's EP_OUT 0x03 does - it was very likely silently accepted
  by some other, smaller legitimate Output Report this interface exposes
  (e.g. keyboard LED state), and a 4096-byte buffer landing there is a
  plausible way to scramble general key handling while leaving the (clearly
  separate, non-volatile) screen image store untouched. This also confirms
  the screen's image storage and the keyboard's general HID/behavior state
  are on separate persistent stores - a factory reset only clears the latter.

Requirements:
    pip install Pillow pyusb
    pip install imageio imageio-ffmpeg       # only needed for video (.mp4 etc.) input

udev rule (so you can run without sudo):
    SUBSYSTEM=="usb", ATTR{idVendor}=="0c45", ATTR{idProduct}=="800a", MODE="0666"
    # after writing: sudo udevadm control --reload && sudo udevadm trigger

Usage:
    python3 aula_s75pro_screen.py photo.jpg          # still image
    python3 aula_s75pro_screen.py photo.jpg --fit    # letterbox to fit
    python3 aula_s75pro_screen.py anim.gif           # animated GIF (up to 191 frames)
    python3 aula_s75pro_screen.py anim.gif --delay 50  # override frame delay (ms, 32-510)
    python3 aula_s75pro_screen.py clip.mp4           # video, auto-converted
    python3 aula_s75pro_screen.py clip.mp4 --fps 10 --max-frames 60
    python3 aula_s75pro_screen.py --test-color red   # solid colour test
    python3 aula_s75pro_screen.py anim.gif --dry-run # inspect buffer, no USB
"""

import argparse
import math
import struct
import sys
import time
import warnings
from pathlib import Path

# ── Device constants ──────────────────────────────────────────────────────────
VENDOR_ID  = 0x0C45
PRODUCT_ID = 0x800A

SCREEN_W   = 135   # portrait: 135 px wide
SCREEN_H   = 240   # portrait: 240 px tall
CHUNK_SIZE = 4096           # bytes per interrupt-OUT transfer
PREAMBLE   = 256            # SPI flash header size before pixel_0 at 0x750100
PIXEL_BYTES = SCREEN_W * SCREEN_H * 2  # 64 800  (135×240×2)
# Firmware FUN_00010460(0x750000) calls FUN_00007882(0x750000, 0xC0), copying only
# 192 bytes (0xC0) into RAM 0x200021DA: byte 0 = N_frames, bytes 1..191 = 191 delay
# slots. Uploading >= 192 frames reads past 0x20002299 into fuel-gauge RAM (0x200022A0+).
MAX_FRAMES = 191            # 0xC0 - 1

# HID endpoints (confirmed from captures)
HID_IFACE  = 3
EP_OUT     = 0x03
EP_IN      = 0x84

# Control-transfer constants
BM_REQ_SET = 0x21   # Class | Interface | Host-to-Device
BM_REQ_GET = 0xA1   # Class | Interface | Device-to-Host
SET_REPORT = 0x09
GET_REPORT = 0x01
W_VALUE    = 0x0300  # Feature report, id=0

# Fixed commands
CMD_BEGIN = bytes([0x04, 0x18]) + bytes(62)
CMD_END   = bytes([0x04, 0x02]) + bytes(62)

# Clock-tree verified firmware tick rate (`s75pro_fw_v1.03.bin`):
#   1. FUN_00013bfa configures PLL = 48 MHz, HCLK div 1.
#   2. FUN_00006f8c sets SysTick RVR = 23999 (0x5DBF) -> 0.5 ms SysTick IRQ (FUN_00006f9c).
#   3. FUN_000008e2 derives pbVar2[2] = 2 ms (every 4 SysTicks).
#   4. FUN_00011a84 ticks GIF frame hold durations on pbVar2[2] = 2 ms.
# DeviceDriver.exe.c:30483 stores GIF delays in milliseconds and divides by 2.
WIRE_TICK_MS = 2
MIN_WIRE_DELAY = 0x10                       # 16 ticks = 32 ms (FUN_00011a84 overrides < 0x10 to 0x19)
MAX_WIRE_DELAY = 0xFF                       # 255 ticks = 510 ms
MIN_DELAY_MS = MIN_WIRE_DELAY * WIRE_TICK_MS  # 32 ms
MAX_DELAY_MS = MAX_WIRE_DELAY * WIRE_TICK_MS  # 510 ms
DEFAULT_STILL_DELAY = 0x19                  # 25 ticks = 50 ms — default for single-frame


def clamp_wire_delay(ticks: int) -> int:
    """Clamp raw wire delay ticks to firmware range 0x10..0xFF (32..510 ms)."""
    return max(MIN_WIRE_DELAY, min(MAX_WIRE_DELAY, int(ticks)))


def ms_to_wire_delay(ms: float) -> int:
    """Convert milliseconds to clamped 2 ms firmware wire ticks (0x10..0xFF)."""
    return clamp_wire_delay(round(ms / WIRE_TICK_MS))


def total_chunks_needed(n_frames: int) -> int:
    """
    Number of 4096-byte chunks for an n-frame upload.

    IMPORTANT: this is ceil(total_bytes / 4096) over the WHOLE buffer, not
    n_frames*16. Frame data is 64 800 bytes = 15.8203125 chunks - the real
    driver (confirmed from the decompiled source, FUN_00422ac0) computes a
    single ceil() over preamble+all-frames combined, with only ONE trailing
    padding region at the very end, not one per frame. The two formulas
    agree up to n=5 frames, then n*16 over-declares (and would over-send)
    an increasing number of extra all-0xFF filler chunks - e.g. +45 chunks
    (184 320 wasted bytes) at n=254. Always use this function, never
    "n_frames * 16", for both the cmd_upload chunk-count field and the
    actual buffer size - they must match what the real driver sends.
    """
    total_bytes = PREAMBLE + PIXEL_BYTES * n_frames
    return -(-total_bytes // CHUNK_SIZE)  # ceil division


# ── Protocol helpers ──────────────────────────────────────────────────────────
def make_cmd_upload(n_frames: int) -> bytes:
    """
    Build the 64-byte cmd_upload packet (0x7204).
      B1    = 0x72   upload command (writes external SPI flash at 0x00750000)
      B2    = 0x03   still / 0x05 animated — ignored by firmware 0x000045D4
                     (retained for vendor-driver wire parity; MCU checks N_frames
                     at SPI 0x00750000 instead)
      B8-B9 = total chunk count as 16-bit little-endian.
              Must equal total_chunks_needed(n_frames).
    """
    if not (1 <= n_frames <= MAX_FRAMES):
        raise ValueError(
            f"Frame count must be 1–{MAX_FRAMES} (MCU copies only 0xC0=192 preamble bytes "
            f"into RAM 0x200021DA..0x20002299), got {n_frames}."
        )
    mode   = 0x03 if n_frames == 1 else 0x05  # ignored by 0x000045D4; wire parity only
    chunks = total_chunks_needed(n_frames)
    if chunks > 0xFFFF:
        raise ValueError(f"Frame count {n_frames} produces {chunks} chunks, "
                         "which exceeds the 16-bit field capacity.")
    cmd = bytearray(64)
    cmd[0] = 0x04
    cmd[1] = 0x72
    cmd[2] = mode
    cmd[8] = chunks & 0xFF          # low byte
    cmd[9] = (chunks >> 8) & 0xFF   # high byte
    return bytes(cmd)


def build_buffer(frames_rgb565: list, delays: list) -> bytes:
    """
    Assemble the complete transfer buffer for N frames (1 <= N <= MAX_FRAMES = 191).

    frames_rgb565 : list of bytes objects, each PIXEL_BYTES long
    delays        : list of int, per-frame hold duration in 2 ms wire ticks
                    (clamped to 0x10..0xFF = 32..510 ms)

    Buffer layout:
        [N] [d0] [d1] … [d_{N-1}] [0xFF × (255-N)]   ← 256-byte flash preamble (0x750000)
        [frame_0]                                       ← 64 800 bytes (starts at 0x750100)
        [frame_1]                                       ←  "
        …
        [frame_{N-1}]
        [0xFF × tail]     ← pads to total_chunks_needed(n)*4096 bytes total
    """
    n = len(frames_rgb565)
    if n != len(delays):
        raise ValueError(f"frames ({n}) and delays ({len(delays)}) must have the same length")
    if not (1 <= n <= MAX_FRAMES):
        raise ValueError(
            f"Frame count must be 1–{MAX_FRAMES} (0xC0 - 1; >191 overflows past "
            f"0x20002299 into fuel-gauge RAM), got {n}."
        )

    total = total_chunks_needed(n) * CHUNK_SIZE
    tail_len = total - PREAMBLE - n * PIXEL_BYTES
    if tail_len < 0:
        raise ValueError("Internal error: negative tail")

    clamped_delays = []
    out_of_range = False
    for d in delays:
        di = int(d)
        cd = clamp_wire_delay(di)
        if cd != di:
            out_of_range = True
        clamped_delays.append(cd)
    if out_of_range:
        warnings.warn(
            f"Clamped frame delay(s) to firmware range 0x{MIN_WIRE_DELAY:02X}–0x{MAX_WIRE_DELAY:02X} "
            f"ticks ({MIN_DELAY_MS}–{MAX_DELAY_MS} ms; < 0x10 is overridden to 0x19 = 50 ms by firmware).",
            UserWarning,
            stacklevel=2,
        )

    # Preamble: [N_frames][delay_0..delay_{N-1}][0xFF padding]
    preamble = bytes([n] + clamped_delays + [0xFF] * (255 - n))
    assert len(preamble) == PREAMBLE

    buf = bytearray()
    buf += preamble
    for frame in frames_rgb565:
        if len(frame) != PIXEL_BYTES:
            raise ValueError(f"Frame must be {PIXEL_BYTES} bytes, got {len(frame)}")
        buf += frame
    buf += bytes([0xFF] * tail_len)

    assert len(buf) == total, f"Buffer size mismatch: {len(buf)} != {total}"
    return bytes(buf)


# ── Image conversion ──────────────────────────────────────────────────────────
def rgb_to_rgb565_le(r: int, g: int, b: int) -> bytes:
    val = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
    return struct.pack('<H', val)


def pil_to_rgb565(img, fit: bool = False) -> bytes:
    """Resize/crop a PIL image to SCREEN_W×SCREEN_H and convert to RGB565 LE.

    Vectorised: avoids per-pixel Python calls by working on the packed bytes
    returned by img.tobytes().  Two paths, same output:
      • numpy available  → bit-ops on uint16 arrays  (~0.5 ms / frame)
      • numpy absent     → struct bulk-unpack + int bit-ops  (~2-4 ms / frame)
    Both are dramatically faster than the previous getpixel() generator which
    made 32 400 Python function calls per frame (~15-25 ms).
    """
    img = img.convert('RGB')
    if fit:
        img.thumbnail((SCREEN_W, SCREEN_H), resample=3)  # LANCZOS
        bg = __import__('PIL').Image.new('RGB', (SCREEN_W, SCREEN_H), (0, 0, 0))
        bg.paste(img, ((SCREEN_W - img.width) // 2, (SCREEN_H - img.height) // 2))
        img = bg
    else:
        img = img.resize((SCREEN_W, SCREEN_H), resample=3)

    raw = img.tobytes()  # packed RGBRGB… — one C-level memcpy, no Python loop

    try:
        import numpy as np
        # Interpret the flat byte string as an (N, 3) uint8 array.
        px = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
        r = px[:, 0].astype(np.uint16)
        g = px[:, 1].astype(np.uint16)
        b = px[:, 2].astype(np.uint16)
        # Pack into RGB565 little-endian: RRRRRGGGGGGBBBBB
        rgb565 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        # Write each 16-bit value in little-endian byte order.
        return rgb565.astype('<u2').tobytes()

    except ImportError:
        # Pure-Pillow fallback: unpack the flat RGB bytes three at a time.
        n_pixels = SCREEN_W * SCREEN_H
        out = bytearray(n_pixels * 2)
        raw_mv = memoryview(raw)           # zero-copy slice access
        out_mv = memoryview(out).cast('H') # view as uint16 (host-endian)
        for i in range(n_pixels):
            base = i * 3
            r = raw_mv[base]
            g = raw_mv[base + 1]
            b = raw_mv[base + 2]
            val = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            # struct.pack_into with '<H' writes the value in little-endian
            # without a separate byte-swap step on big-endian platforms.
            struct.pack_into('<H', out, i * 2, val)
        return bytes(out)


def solid_rgb565(r: int, g: int, b: int) -> bytes:
    return rgb_to_rgb565_le(r, g, b) * (SCREEN_W * SCREEN_H)


def extract_gif_frames(path: str, fit: bool, delay_override: int | None):
    """
    Extract frames from a GIF, return (frames_rgb565, delays_ticks).

    Capped at MAX_FRAMES (191 = 0xC0 - 1) — the firmware copies only 192 preamble
    bytes from SPI 0x750000 into RAM 0x200021DA..0x20002299.

    delay_override: optional override in milliseconds (clamped to 32-510 ms).
    delays_ticks: per-frame delay in 2 ms wire ticks (clamped to 0x10-0xFF).
    Pillow exposes frame duration in milliseconds via img.info['duration'].
    """
    from PIL import Image, ImageSequence
    frames_rgb565 = []
    delays_ticks = []

    if delay_override is not None and not (MIN_DELAY_MS <= delay_override <= MAX_DELAY_MS):
        print(
            f"  ! --delay {delay_override} ms out of firmware range; "
            f"clamping to {MIN_DELAY_MS}–{MAX_DELAY_MS} ms "
            f"(0x{MIN_WIRE_DELAY:02X}–0x{MAX_WIRE_DELAY:02X} ticks)."
        )

    with Image.open(path) as gif:
        for frame in ImageSequence.Iterator(gif):
            # Check the limit before converting: avoids wasted pixel work on
            # frame 192+ and prevents exceeding MAX_FRAMES.
            if len(frames_rgb565) >= MAX_FRAMES:
                print(f"  ! reached the {MAX_FRAMES}-frame device limit, truncating")
                break

            rgb565 = pil_to_rgb565(frame, fit=fit)
            frames_rgb565.append(rgb565)

            if delay_override is not None:
                delay_ticks = ms_to_wire_delay(delay_override)
            else:
                dur_ms = frame.info.get('duration', 100)
                delay_ticks = ms_to_wire_delay(dur_ms)
            delays_ticks.append(delay_ticks)

    return frames_rgb565, delays_ticks


VIDEO_EXTENSIONS = {'.mp4', '.mov', '.webm', '.mkv', '.avi', '.m4v'}


def extract_video_frames(path: str, fit: bool, delay_override: int | None,
                          fps_override: float | None, max_frames: int | None):
    """
    Decode a video file (mp4/mov/webm/...) frame-by-frame and convert each
    frame through the same pil_to_rgb565() pipeline used for GIFs/stills.

    Requires: pip install imageio imageio-ffmpeg
    (imageio-ffmpeg bundles a portable ffmpeg binary - no system install needed)

    fps_override: if given, frames are decimated to approximate this rate
    instead of using every decoded frame (videos are usually 24-60fps, which
    is far more frames than useful on a 191-frame-max, single-color-depth
    LCD upload - a lower fps keeps the transfer size/time sane).
    delay_override: optional override in milliseconds (clamped to 32-510 ms).
    """
    try:
        import imageio.v3 as iio
    except ImportError:
        sys.exit("imageio not installed:  pip install imageio imageio-ffmpeg")
    from PIL import Image

    try:
        meta = iio.immeta(path, plugin="FFMPEG")
    except ImportError:
        sys.exit("Video decoding backend missing:  pip install imageio-ffmpeg")
    src_fps = meta.get('fps') or 24.0
    target_fps = fps_override or src_fps
    # keep every Nth source frame to approximate target_fps
    step = max(1, round(src_fps / target_fps))

    if delay_override is not None:
        if not (MIN_DELAY_MS <= delay_override <= MAX_DELAY_MS):
            print(
                f"  ! --delay {delay_override} ms out of firmware range; "
                f"clamping to {MIN_DELAY_MS}–{MAX_DELAY_MS} ms "
                f"(0x{MIN_WIRE_DELAY:02X}–0x{MAX_WIRE_DELAY:02X} ticks)."
            )
        delay_ticks = ms_to_wire_delay(delay_override)
    else:
        effective_fps = src_fps / step
        ms_per_frame = 1000.0 / effective_fps
        delay_ticks = ms_to_wire_delay(ms_per_frame)

    if max_frames is not None and max_frames > MAX_FRAMES:
        print(f"  ! --max-frames {max_frames} exceeds device limit; capping at {MAX_FRAMES}")
    effective_max = min(max_frames, MAX_FRAMES) if max_frames is not None else MAX_FRAMES

    frames_rgb565 = []
    delays_ticks = []
    for i, frame in enumerate(iio.imiter(path, plugin="FFMPEG")):
        if i % step != 0:
            continue
        if len(frames_rgb565) >= effective_max:
            if max_frames is None:
                print(f"  ! reached the {MAX_FRAMES}-frame device limit, truncating")
            break
        img = Image.fromarray(frame)
        frames_rgb565.append(pil_to_rgb565(img, fit=fit))
        delays_ticks.append(delay_ticks)

    if not frames_rgb565:
        sys.exit(f"No frames could be decoded from {path}")
    return frames_rgb565, delays_ticks


# ── USB I/O (pyusb only - see note at top of file re: hidapi) ────────────────
class PyUsbBackend:
    name = "pyusb"

    def __init__(self):
        try:
            import usb.core
        except ImportError:
            sys.exit("pyusb not installed:  pip install pyusb")
        self._usb = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
        if self._usb is None:
            sys.exit(f"Keyboard not found (VID={VENDOR_ID:#06x} PID={PRODUCT_ID:#06x}) via pyusb.\n"
                      "Check the USB cable and udev rules.")
        self._detached = []
        self.last_write_n = None

    def open(self):
        self._detached = self._detach_kernel_drivers()
        return self

    def info(self) -> str:
        return f"{self._usb.manufacturer} / {self._usb.product}"

    def ctrl_set(self, data: bytes):
        self._usb.ctrl_transfer(BM_REQ_SET, SET_REPORT, W_VALUE, HID_IFACE, data, timeout=2000)

    def ctrl_get(self) -> bytes:
        return bytes(self._usb.ctrl_transfer(BM_REQ_GET, GET_REPORT, W_VALUE, HID_IFACE, 64, timeout=2000))

    def write_chunk(self, chunk: bytes) -> bytes:
        self.last_write_n = self._usb.write(EP_OUT, chunk, timeout=3000)
        return bytes(self._usb.read(EP_IN, 64, timeout=3000))

    def close(self):
        for n in self._detached:
            try:
                self._usb.attach_kernel_driver(n)
            except Exception:
                pass

    # def _detach_kernel_drivers(self) -> list:
    #     """
    #     Detach the kernel HID driver from all interfaces.
    #
    #     Why not just claim one interface:
    #       pyusb's dev.write() resolves the owning interface internally and calls
    #       managed_claim_interface(). If we pre-claimed via usb.util.claim_interface()
    #       that is not tracked in _ctx.managed_interfaces, so the managed path tries
    #       to claim it again -> EBUSY (errno 16). The fix: only detach drivers and let
    #       pyusb handle claiming automatically on the first write/read.
    #     """
    #     detached = []
    #     try:
    #         cfg = self._usb.get_active_configuration()
    #     except Exception:
    #         self._usb.set_configuration()
    #         cfg = self._usb.get_active_configuration()
    #     for intf in cfg:
    #         n = intf.bInterfaceNumber
    #         try:
    #             if self._usb.is_kernel_driver_active(n):
    #                 self._usb.detach_kernel_driver(n)
    #                 detached.append(n)
    #         except Exception:
    #             pass
    #     return detached

    def _detach_kernel_drivers(self) -> list:
        try:
            cfg = self._usb.get_active_configuration()
        except Exception:
            self._usb.set_configuration()
            cfg = self._usb.get_active_configuration()

        needed = {HID_IFACE}  # interface 3, used by ctrl_set/ctrl_get
        for intf in cfg:
            for ep in intf:
                if ep.bEndpointAddress in (EP_OUT, EP_IN):
                    needed.add(intf.bInterfaceNumber)

        detached = []
        for n in sorted(needed):
            try:
                if self._usb.is_kernel_driver_active(n):
                    self._usb.detach_kernel_driver(n)
                    detached.append(n)
            except Exception:
                pass
        return detached

def make_backend() -> PyUsbBackend:
    return PyUsbBackend()


def upload(backend, frames_rgb565: list, delays_cs: list, verbose: bool = True):
    """
    Full upload sequence for 1-N frames.
    CMD_END is always sent (in finally), so firmware RGB LEDs are restored
    even if the transfer fails or is interrupted.
    """
    n = len(frames_rgb565)
    buf = build_buffer(frames_rgb565, delays_cs)
    n_chunks = total_chunks_needed(n)
    chunks = [buf[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE] for i in range(n_chunks)]

    try:
        # Pre-flight reset: send cmd_end to bring the keyboard back to idle.
        # After a large GIF transfer the board stays busy for a while, so we
        # retry with backoff instead of silently swallowing the error.
        for attempt in range(6):
            try:
                backend.ctrl_set(CMD_END)
                break                           # board is now idle
            except Exception:
                if attempt < 5:
                    time.sleep(0.3 * (attempt + 1))   # 0.3, 0.6, 0.9, 1.2, 1.5 s

        if verbose:
            print(f"  -> cmd_begin")
        backend.ctrl_set(CMD_BEGIN)
        _wait_ready(backend, "cmd_begin")

        cmd_upload = make_cmd_upload(n)
        mode_str = "still" if n == 1 else f"animated, {n} frames"
        if verbose:
            print(f"  -> cmd_upload  ({mode_str}, {n_chunks} chunks)")
        backend.ctrl_set(cmd_upload)
        _wait_ready(backend, "cmd_upload")

        for i, chunk in enumerate(chunks):
            if verbose:
                # frame index from byte offset, NOT i // constant - chunks-per-frame
                # isn't constant once the shared (not per-frame) tail padding kicks in
                byte_off = i * CHUNK_SIZE
                frame_idx = min(n, max(1, (byte_off - PREAMBLE) // PIXEL_BYTES + 1))
                print(f"  chunk {i+1:3d}/{n_chunks}  [frame {frame_idx}/{n}]          ", end='\r')
            _write_chunk_with_retry(backend, chunk, i, n_chunks)

        if verbose:
            print(f"  all {n_chunks} chunks sent" + " " * 20)

        # Settle: give the keyboard time to apply the image before cmd_end.
        # Large GIFs (many frames) need proportionally more time.
        time.sleep(min(0.05 * n, 2.0))

    finally:
        if verbose:
            print("\n  -> cmd_end")
        for attempt in range(4):
            try:
                backend.ctrl_set(CMD_END)
                time.sleep(1.5)
                break
            except Exception as e:
                if attempt == 3:
                    print(f"  ! cmd_end failed after retries: {e}")
                else:
                    time.sleep(0.4 * (attempt + 1))


def _wait_ready(backend, step: str, retries: int = 10, delay: float = 0.02):
    """
    Read back after a control command until the device signals it's actually
    ready (rather than blindly trusting whatever the first GET_REPORT returns).
    We don't have a confirmed "ready" byte for this LCD command family the way
    we do for the settings protocol (byte[3]==0x01 there) - this just retries
    on read errors/empty responses as a defensive minimum. If you find the
    real ready/busy indicator byte for these responses, tighten this check.
    """
    last_exc = None
    for _ in range(retries):
        try:
            resp = backend.ctrl_get()
            return resp
        except Exception as e:
            last_exc = e
            time.sleep(delay)
    print(f"  ! warning: no usable response after {step} ({last_exc}); continuing anyway")
    return b""


def _write_chunk_with_retry(backend, chunk: bytes, index: int, total: int, retries: int = 3):
    """
    Don't advance past a bad chunk ack - retry the SAME chunk a few times
    before giving up, instead of silently sending the next one on a NAK
    (which would desync the firmware's upload state machine).
    """
    last_ack = None
    for attempt in range(retries):
        ack = backend.write_chunk(chunk)
        last_ack = ack
        if len(ack) >= 2 and ack[0] == 0x01 and ack[1] == 0x5A:
            return
        n = getattr(backend, "last_write_n", "?")
        print(f"\n  ! chunk {index+1}/{total} attempt {attempt+1}: write() returned {n} bytes, "
              f"ack={'(none/timeout)' if not ack else ack.hex()}")
        time.sleep(0.05 * (attempt + 1))
    raise IOError(
        f"Chunk {index+1}/{total} was not acknowledged after {retries} attempts "
        f"(last ack: {last_ack.hex() if last_ack else 'none'}). Aborting - do not "
        f"retry blindly; check the physical connection before trying again."
    )


# ── CLI ───────────────────────────────────────────────────────────────────────
NAMED_COLORS = {
    'red':     (255,   0,   0),
    'green':   (  0, 255,   0),
    'blue':    (  0,   0, 255),
    'white':   (255, 255, 255),
    'black':   (  0,   0,   0),
    'cyan':    (  0, 255, 255),
    'magenta': (255,   0, 255),
    'yellow':  (255, 255,   0),
}


def main():
    parser = argparse.ArgumentParser(
        description='Upload a still image or animated GIF to the Aula S75 Pro screen (135×240, portrait).',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument('image', nargs='?',
                     help='Image or GIF file to upload')
    src.add_argument('--test-color', metavar='COLOR',
                     help=f'Solid colour: {", ".join(NAMED_COLORS)}')

    parser.add_argument('--fit', action='store_true',
                        help='Letterbox/pillarbox to 135×240 instead of stretching')
    parser.add_argument('--delay', type=int, metavar='MS',
                        help=f'Override per-frame delay in milliseconds ({MIN_DELAY_MS}–{MAX_DELAY_MS} ms; '
                             f'encoded as {WIRE_TICK_MS} ms ticks 0x{MIN_WIRE_DELAY:02X}–0x{MAX_WIRE_DELAY:02X}, '
                             f'clamped if out of range). Default: read from GIF header or derived from --fps.')
    parser.add_argument('--fps', type=float, metavar='N',
                        help=f'Video only: decimate frames to approximately this rate '
                             f'(default: the video\'s native fps - usually far more frames '
                             f'than useful on a {MAX_FRAMES}-frame-max upload, consider e.g. --fps 10)')
    parser.add_argument('--max-frames', type=int, default=None,
                        help=f'Limit number of frames to upload (default: all, capped at {MAX_FRAMES})')
    parser.add_argument('--dry-run', action='store_true',
                        help='Build the buffer and print diagnostics, do NOT touch USB')
    args = parser.parse_args()

    try:
        from PIL import Image
    except ImportError:
        sys.exit("Pillow not installed:  pip install Pillow")

    # ── Build frame list ──────────────────────────────────────────────────────
    if args.test_color:
        color = args.test_color.lower()
        if color not in NAMED_COLORS:
            sys.exit(f"Unknown colour '{color}'. Choose from: {', '.join(NAMED_COLORS)}")
        r, g, b = NAMED_COLORS[color]
        print(f"Solid {color}  ({r}, {g}, {b})")
        frames   = [solid_rgb565(r, g, b)]
        delays   = [DEFAULT_STILL_DELAY]

    elif Path(args.image).suffix.lower() in VIDEO_EXTENSIONS:
        # PIL can't open video containers - route these before Image.open()
        frames, delays = extract_video_frames(
            args.image, fit=args.fit, delay_override=args.delay,
            fps_override=args.fps, max_frames=args.max_frames,
        )
        n = len(frames)
        ms_preview = [d * WIRE_TICK_MS for d in delays[:8]]
        print(f"Video: {n} frame{'s' if n != 1 else ''}  "
              f"delays: {delays[:8]}{'…' if n > 8 else ''} ticks ({ms_preview} ms)")

    else:
        img = Image.open(args.image)
        is_gif = getattr(img, 'is_animated', False) or img.format == 'GIF'

        if is_gif:
            frames, delays = extract_gif_frames(args.image, fit=args.fit,
                                                delay_override=args.delay)
            if args.max_frames:
                if args.max_frames > MAX_FRAMES:
                    print(f"  ! --max-frames {args.max_frames} exceeds device limit; capping at {MAX_FRAMES}")
                cap = min(args.max_frames, MAX_FRAMES)
                frames  = frames[:cap]
                delays  = delays[:cap]
            n = len(frames)
            ms_preview = [d * WIRE_TICK_MS for d in delays[:8]]
            print(f"GIF: {img.size}  {n} frame{'s' if n!=1 else ''}  "
                  f"delays: {delays[:8]}{'…' if n>8 else ''} ticks ({ms_preview} ms)")
        else:
            # Still image
            print(f"Image: {img.size} {img.mode}  →  {SCREEN_W}×{SCREEN_H} (portrait)")
            frames = [pil_to_rgb565(img, fit=args.fit)]
            delays = [DEFAULT_STILL_DELAY]

    # ── Dry-run diagnostics ───────────────────────────────────────────────────
    if args.dry_run:
        n = len(frames)
        buf = build_buffer(frames, delays)
        n_chunks = total_chunks_needed(n)
        tail_len = n_chunks * CHUNK_SIZE - PREAMBLE - n * PIXEL_BYTES
        print(f"\nDry-run: {n} frame(s) (max {MAX_FRAMES})")
        print(f"  Buffer : {len(buf)} bytes  ({n_chunks} × {CHUNK_SIZE})")
        print(f"  Preamble: {buf[:4].hex()}…  "
              f"[frame_count={buf[0]} delays={list(buf[1:1+n])} "
              f"({[d * WIRE_TICK_MS for d in buf[1:1+n]]} ms @ {WIRE_TICK_MS}ms/tick)]")
        print(f"  Frame 0 pixel[0]: {buf[PREAMBLE:PREAMBLE+2].hex()}")
        if n > 1:
            f1_start = PREAMBLE + PIXEL_BYTES
            print(f"  Frame 1 pixel[0]: {buf[f1_start:f1_start+2].hex()}")
        print(f"  Tail    : {tail_len} bytes  ({buf[-4:].hex()}…)")
        cmd = make_cmd_upload(n)
        print(f"  cmd_upload: {cmd[:12].hex()}  "
              f"[mode=0x{cmd[2]:02x} chunks=0x{cmd[9]:02x}{cmd[8]:02x}={cmd[9]<<8|cmd[8]}]")
        return

    # ── Upload ────────────────────────────────────────────────────────────────
    backend = make_backend().open()
    print(f"Found: {backend.info()}")
    print(f"Uploading {len(frames)} frame(s)…")
    t0 = time.time()
    try:
        upload(backend, frames, delays)
    finally:
        backend.close()
    print(f"Done in {time.time()-t0:.2f}s")


if __name__ == '__main__':
    main()
