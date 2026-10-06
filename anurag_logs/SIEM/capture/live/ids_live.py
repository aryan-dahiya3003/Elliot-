"""
capture/live/ids_live.py
=========================
Captures IDS/IPS events (log type #10) by watching Suricata EVE JSON log.

If Suricata is not installed -> silently waits (no crash).
Suricata can be installed free from: https://suricata.io/

Also receives IDS alerts via syslog (if syslog server is enabled).
"""
import os, time
from capture.ids_capture import IDSCapture

PARSER = IDSCapture()

EVE_PATHS = [
    r"C:\Suricata\log\eve.json",
    r"C:\Program Files\Suricata\log\eve.json",
    r"C:\Program Files (x86)\Suricata\log\eve.json",
    "/var/log/suricata/eve.json",
    "/var/log/snort/alert.json",
]


def capture(out_queue, interval=2, stop_event=None):
    eve_path = next((p for p in EVE_PATHS if os.path.exists(p)), None)

    if not eve_path:
        # IDS not installed - wait silently
        while not (stop_event and stop_event.is_set()):
            time.sleep(interval)
        return

    with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)  # jump to end - only new alerts
        while not (stop_event and stop_event.is_set()):
            line = f.readline()
            if line and line.strip():
                parsed = PARSER.parse(line.strip())
                if parsed:
                    out_queue.put(("ids_ips", parsed))
            else:
                time.sleep(0.5)
