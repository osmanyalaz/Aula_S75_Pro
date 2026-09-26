# stream_test.py — WASD blink; MINIMAL=1 disables the GETs/zero-report
import os, time, hid
from aula_s75pro import AulaS75Pro, load_keymap, VID, PID_USB
from aula_streamer import AulaStreamer

keymap = load_keymap("rgb-keyboard.xml")
cands = [d for d in hid.enumerate(VID, PID_USB) if d.get("interface_number") == 3]
kb = AulaS75Pro(mode="usb", path=cands[0]["path"]).open()
st = AulaStreamer(kb, keymap, get_delay=0.010, chunk_delay=0.002)

W, A, S, D = (keymap[k].light_index for k in ("W", "A", "S", "D"))
print("Blinking WASD… Ctrl+C to stop")
t = False
try:
    while True:
        st.set_all(0, 0, 0)
        if t:
            for i, k in enumerate(keymap.values()):
                st.set_color(k.light_index, (i * 3) % 256, (255 - i * 2) % 256, (i * 7) % 256)
        st.update()
        t = not t
        time.sleep(0.25)
except KeyboardInterrupt:
    pass
