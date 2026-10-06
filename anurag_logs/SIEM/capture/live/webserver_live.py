"""
capture/live/webserver_live.py
================================
Captures Web Server logs (log type #7) by tailing access log files.

Works for: IIS, Apache, Nginx, XAMPP, WAMP - any Combined Log Format file.
If no web server is running, waits silently (no crash).

To use: just have a web server running. Logs auto-detected from common paths.
"""
import os, time, threading
from capture.webserver_capture import WebServerCapture

PARSER = WebServerCapture()

DEFAULT_PATHS = [
    r"C:\inetpub\logs\LogFiles",           # IIS
    r"C:\Apache24\logs\access.log",         # Apache
    r"C:\Apache\logs\access.log",
    r"C:\nginx\logs\access.log",            # Nginx
    r"C:\xampp\apache\logs\access.log",     # XAMPP
    r"C:\wamp64\logs\access.log",           # WAMP
    r"C:\wamp\logs\access.log",
]


def _find_log_files():
    found = []
    for p in DEFAULT_PATHS:
        if os.path.isfile(p):
            found.append(p)
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                for fn in files:
                    if fn.lower().endswith(".log"):
                        found.append(os.path.join(root, fn))
    return found


def _tail_file(path, out_queue, stop_event):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            while not (stop_event and stop_event.is_set()):
                line = f.readline()
                if line:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parsed = PARSER.parse(line)
                        if parsed:
                            parsed.setdefault("extra", {})["source_file"] = os.path.basename(path)
                            out_queue.put(("webserver", parsed))
                else:
                    time.sleep(0.3)
    except Exception:
        pass


def capture(out_queue, interval=5, stop_event=None):
    log_files = _find_log_files()
    if log_files:
        for path in log_files:
            t = threading.Thread(target=_tail_file, args=(path, out_queue, stop_event), daemon=True)
            t.start()
    # Keep alive regardless
    while not (stop_event and stop_event.is_set()):
        time.sleep(interval)
