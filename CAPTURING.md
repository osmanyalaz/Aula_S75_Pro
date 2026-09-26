# Capturing more traffic to extend the protocol

The two logs you provided (`KeyResponseTimeLogs.txt`, `TimeToSleepLogs.txt`) were
tshark dumps filtered to the keyboard's USB device. Here's how to make more of
these for other features (lighting, macros, firmware version, etc.) so the
EXPERIMENTAL parts of `PROTOCOL.md` can be nailed down the same way.

## 1. Find the device

**Windows** (using Wireshark + USBPcap):
1. Install [Wireshark](https://www.wireshark.org/) with the USBPcap component.
2. Plug in the keyboard, open Device Manager, and find it to confirm VID `0C45`.
3. Start capturing on the USBPcap interface that shows keyboard traffic.

**Linux**:
```bash
sudo modprobe usbmon
lsusb | grep 0c45          # find bus/device numbers
sudo tshark -i usbmonX -w capture.pcapng
```

## 2. Isolate the keyboard's traffic

```bash
tshark -r capture.pcapng -Y "usb.bus_id == <bus> && usb.device_address == <dev>" \
    -T fields -e frame.time_relative -e _ws.col.info -e usb.data_len
```

Then get the actual bytes:
```bash
tshark -r capture.pcapng -Y "usb.bus_id == <bus> && usb.device_address == <dev>" -x
```

## 3. Change ONE thing at a time in the official driver

- Capture, open the AULA driver, change a single setting (e.g. pick one RGB
  effect), stop capturing.
- Repeat for a different value of that same setting.
- Diff the two captures' SET_REPORT payloads — the differing byte(s) are your
  answer, exactly like we did for key-response-time/sleep-time.

## 4. Feed it back into this tool

Use `cli.py raw-send` / `cli.py raw-get` to replay and test hypotheses live:

```bash
python cli.py raw-send 04 23 09 ...
python cli.py raw-get
```

Once you've confirmed a command, add a proper method to `aula_s75pro.py`
(follow the pattern of `write_general_settings`) and move it out of the
"EXPERIMENTAL" bucket in `PROTOCOL.md`.
