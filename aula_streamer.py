"""
aula_streamer.py
================

Dynamic RGB frame streaming for the AULA S75Pro (music/stream mode).

STATUS: the frame format is verified byte-exact against musicRGB.pcapng
(header 04 20 ... 08 -> 8 x 64-byte key chunks -> commit 04 02 00 00).
Protocol notes (verified):
  * header payload[3] is 0 on every frame - there is no arm packet and
    no per-frame counter; earlier theories of both were artifacts of
    reading GET_REPORT replies as SET headers.
  * ~3.3 ms between chunk SETs in the capture.
  * key slot order = rgb-keyboard.xml document order.
"""

import time


class StreamFault(IOError):
    """A frame could not be fully delivered. The next update() retries
    the whole frame; repeated faults mean the device is NAKing - back off."""


class AulaStreamer:
    CHUNKS = 8                 # header's payload[8] advertises 8 chunks
    KEYS_PER_CHUNK = 16        # 64-byte payload / 4 bytes per key
    MAX_KEYS = CHUNKS * KEYS_PER_CHUNK   # 128 slots; S75Pro uses ~104

    _CMD_STREAM = b"\x04\x20"   # 0x2004 - dynamic RGB frame header
    _CMD_COMMIT = b"\x04\x02"   # 0x0204 - commit / latch

    # Verified cadence — see PROTOCOL.md for the full measurement table.
    # get_delay:  floor <= 0.003 (observed), vendor streams at ~0.006,
    #             shipped default 0.010 = margin over both.
    # chunk_delay: 0.002 verified under key-spam load; vendor uses ~0.0032.
    DEFAULT_GET_DELAY = 0.010
    DEFAULT_CHUNK_DELAY = 0.002

    def __init__(self, kb, keymap, get_delay=DEFAULT_GET_DELAY, chunk_delay=DEFAULT_CHUNK_DELAY):

        self.kb = kb

        # MCU-side processing windows (see update()): the GET polls must not
        # arrive faster than this after the header/commit, and chunks need
        # spacing. Verified floor recorded in PROTOCOL.md.

        self.get_delay = get_delay
        self.chunk_delay = chunk_delay

        # Frame header: 04 20 00 00 00 00 00 00 08 00...
        h0 = bytearray(65)
        h0[0] = 0x00                     # REPORT_ID
        h0[1:3] = self._CMD_STREAM
        h0[9] = self.CHUNKS              # payload[8] = chunk count
        self._cached_header = bytes(h0)

        # Commit: 04 02 00 00 00...
        commit = bytearray(65)
        commit[0] = 0x00                 # REPORT_ID
        commit[1:3] = self._CMD_COMMIT
        self._cached_commit = bytes(commit)

        # One flat buffer: 8 chunks back-to-back, 65 bytes each
        # ([report ID 0] + 64-byte payload). Zero-fill = black padding.
        self.buffer = bytearray(65 * self.CHUNKS)

        keys = list(keymap.values())[: self.MAX_KEYS]

        max_idx = max((k.light_index for k in keys), default=0)
        self._offsets = [0] * (max_idx + 1)
        for i, key in enumerate(keys):
            chunk_idx = i // self.KEYS_PER_CHUNK
            key_in_chunk = i % self.KEYS_PER_CHUNK
            offset = (chunk_idx * 65) + 1 + (key_in_chunk * 4)
            self.buffer[offset] = key.light_index
            self._offsets[key.light_index] = offset

    def set_color(self, light_index, r, g, b):
        """Set one key's colour. Out-of-range/negative indices ignored."""
        if 0 <= light_index < len(self._offsets):
            off = self._offsets[light_index]
            if off:
                self.buffer[off + 1] = r
                self.buffer[off + 2] = g
                self.buffer[off + 3] = b

    def set_all(self, r, g, b):
        buf = self.buffer
        for off in self._offsets:
            if off:
                buf[off + 1] = r
                buf[off + 2] = g
                buf[off + 3] = b

    def update(self):
        """Send one full frame — HARDWARE-VERIFIED sequence.

        The two GET_REPORT polls are NOT optional: the MCU's receive path
        only processes/latches frame data around them (empirically proven —
        the identical sequence without GETs renders nothing, in any board
        state, including fresh power-cycles; with GETs it renders even on
        top of running hardware animations).

        Per frame: header -> GET (~10 ms) -> 8 chunks (~2 ms apart) ->
        commit -> GET. Verified byte-exact against musicRGB.pcapng; the
        GETs are mandatory (PROTOCOL.md §4, MINIMAL negative test). An
        extra all-zero report before the commit is tolerated by the
        firmware but is NOT part of the wire sequence.
        """
        dev = self.kb.dev
        try:
            dev.send_feature_report(self._cached_header)
            time.sleep(self.get_delay)
            self.kb.raw_get()
            view = memoryview(self.buffer)
            for i in range(self.CHUNKS):
                dev.send_feature_report(bytes(view[i * 65:(i + 1) * 65]))
                time.sleep(self.chunk_delay)
            dev.send_feature_report(self._cached_commit)
            time.sleep(self.get_delay)
            self.kb.raw_get()
        except IOError as e:
            raise StreamFault(f"frame delivery failed ({e})") from e
