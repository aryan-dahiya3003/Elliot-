"""
capture/live/application_live.py
==================================
Captures Application log events (log type #8) from Windows Application Event Log.
Filters for errors and warnings (Level <= 3: Critical/Error/Warning).

No admin required - Application log is readable by normal users.
"""
import subprocess, re, time
from capture.windows_capture import WindowsCapture

PARSER = WindowsCapture()


def _get_last_rid():
    cmd = ('wevtutil qe Application /c:1 /f:xml /rd:true'
           ' /q:"*[System[Level<=3]]" 2>$null')
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True, timeout=10
    )
    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", r.stdout or "")
    return int(m.group(1)) if m else 0


def _get_events(last_rid):
    cmd = ('wevtutil qe Application /c:15 /f:xml /rd:false'
           ' /q:"*[System[Level<=3 and EventRecordID > {}]]" 2>$null'.format(last_rid))
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True, timeout=10
    )
    return re.findall(r"<Event[^>]*>.*?</Event>", r.stdout or "", re.DOTALL)


def capture(out_queue, interval=20, stop_event=None):
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
                    # Extract provider/service name from XML
                    prov = re.search(r"Provider[^>]*Name='([^']+)'", xml)
                    if prov:
                        parsed.setdefault("extra", {})["service"] = prov.group(1)
                    # Map level to severity
                    level = re.search(r"<Level>(\d+)</Level>", xml)
                    if level:
                        lv = int(level.group(1))
                        parsed["severity"] = {1: "critical", 2: "high", 3: "medium"}.get(lv, "info")
                    out_queue.put(("application", parsed))
        except Exception:
            pass
        time.sleep(interval)
