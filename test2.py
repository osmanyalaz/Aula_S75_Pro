# stream_test.py — WASD blink; MINIMAL=1 disables the GETs/zero-report
import os, time, hid
from aula_s75pro import AulaS75Pro, load_keymap, VID, PID_USB
from aula_streamer import AulaStreamer

MINIMAL = os.environ.get("MINIMAL", "0") == "1"
keymap = load_keymap("rgb-keyboard.xml")
cands = [d for d in hid.enumerate(VID, PID_USB) if d.get("interface_number") == 3]
kb = AulaS75Pro(mode="usb", path=cands[0]["path"]).open()
st = AulaStreamer(kb, keymap)

def update_frame():
    dev = kb.dev
    dev.send_feature_report(st._cached_header)
    if not MINIMAL:
        time.sleep(0.036); kb.raw_get()
    view = memoryview(st.buffer)
    for i in range(8):
        dev.send_feature_report(bytes(view[i*65:(i+1)*65]))
        if not MINIMAL: time.sleep(0.0033)
    if not MINIMAL:
        dev.send_feature_report(bytes(65))
    dev.send_feature_report(st._cached_commit)
    if not MINIMAL:
        time.sleep(0.036); kb.raw_get()

W, A, S, D = (keymap[k].light_index for k in ("W", "A", "S", "D"))
print(f"mode = {'MINIMAL (no GETs/zero)' if MINIMAL else 'FULL (capture-literal)'}")
print("Blinking WASD… Ctrl+C to stop")
t = False
try:
    while True:
        st.set_all(0, 0, 0)
        if t:
            st.set_color(W, 255, 0, 0); st.set_color(A, 0, 255, 0)
            st.set_color(S, 0, 0, 255); st.set_color(D, 255, 255, 0)
        update_frame()
        t = not t
        time.sleep(0.25)
except KeyboardInterrupt:
    pass
