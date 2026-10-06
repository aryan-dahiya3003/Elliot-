"""
capture/live/firewall_live.py
==============================
Captures Firewall events (log type #1) by tailing Windows Firewall log file.

To enable firewall logging (run as Administrator):
    netsh advfirewall set allprofiles logging droppedconnections enable
    netsh advfirewall set allprofiles logging allowedconnections enable

Without admin / logging disabled -> silently waits, no crash.
"""
import os, time, datetime
from capture.firewall_capture import FirewallCapture

PARSER  = FirewallCapture()
FW_LOG  = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"


def _w3c_to_ufw(line):
    """Convert W3C firewall log line to UFW format our parser understands."""
    parts = line.split()
    if len(parts) < 8:
        return None
    date, tm, action, proto, src, dst, sport, dport = parts[:8]
    try:
        dt = datetime.datetime.strptime(date + " " + tm, "%Y-%m-%d %H:%M:%S")
        ts = dt.strftime("%b %d %H:%M:%S")
    except Exception:
        ts = tm
    word = "BLOCK" if action.upper() == "DROP" else "ALLOW"
    return ("{} FIREWALL kernel: [UFW {}] IN=eth0 OUT= "
            "SRC={} DST={} PROTO={} SPT={} DPT={}".format(
                ts, word, src, dst, proto.upper(), sport, dport))


def capture(out_queue, interval=2, stop_event=None):
    if not os.path.exists(FW_LOG):
        # Firewall logging not enabled - wait silently
        while not (stop_event and stop_event.is_set()):
            time.sleep(interval)
        return

    with open(FW_LOG, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)  # jump to end - only capture new lines
        while not (stop_event and stop_event.is_set()):
            line = f.readline()
            if line:
                line = line.strip()
                if line and not line.startswith("#"):
                    ufw_line = _w3c_to_ufw(line)
                    if ufw_line:
                        parsed = PARSER.parse(ufw_line)
                        if parsed:
                            out_queue.put(("firewall", parsed))
            else:
                time.sleep(0.5)
