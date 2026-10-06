"""
capture/live/auth_live.py
=========================
Captures Authentication events (log type #6) from Windows Security log.
Events: 4624 (success logon), 4625 (failed logon), 4648 (explicit creds), 4672 (special privileges).

Requires: Run terminal/VS Code as Administrator for Security log access.
Without admin -> will silently do nothing (no crash).
"""
import subprocess, re, time, queue
from capture.windows_capture import WindowsCapture

PARSER = WindowsCapture()
AUTH_IDS = {"4624", "4625", "4648", "4672", "4720", "4723", "4740"}


def _get_last_rid():
    ids_filter = " or ".join("EventID={}".format(i) for i in AUTH_IDS)
    cmd = ('wevtutil qe Security /c:1 /f:xml /rd:true'
           ' /q:"*[System[({})]]]" 2>$null'.format(ids_filter))
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True, timeout=10
    )
    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", r.stdout or "")
    return int(m.group(1)) if m else 0


def _get_events(last_rid):
    ids_filter = " or ".join("EventID={}".format(i) for i in AUTH_IDS)
    cmd = ('wevtutil qe Security /c:20 /f:xml /rd:false'
           ' /q:"*[System[EventRecordID > {} and ({})]]" 2>$null'.format(last_rid, ids_filter))
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True, timeout=15
    )
    return re.findall(r"<Event[^>]*>.*?</Event>", r.stdout or "", re.DOTALL)


def capture(out_queue, interval=10, stop_event=None):
    try:
        last_rid = _get_last_rid()
    except Exception:
        last_rid = 0

    while not (stop_event and stop_event.is_set()):
        try:
            xmls = _get_events(last_rid)
            for xml in xmls:
                m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", xml)
                if m:
                    rid = int(m.group(1))
                    if rid > last_rid:
                        last_rid = rid
                parsed = PARSER.parse(xml)
                if parsed:
                    eid = parsed.get("event_id", "")
                    if eid in ("4625", "4648", "4740"):
                        parsed["severity"] = "high"
                    out_queue.put(("authentication", parsed))
        except Exception:
            pass
        time.sleep(interval)
