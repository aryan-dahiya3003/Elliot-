"""
windows_live.py - Polls Windows Application and System Event Logs for new events.
"""
import subprocess, re, time, queue, datetime
from capture.windows_capture import WindowsCapture

WIN_PARSER = WindowsCapture()

def _get_events(channel, last_record_id, count=20):
    query = f"*[System[EventRecordID > {last_record_id}]]"
    cmd   = f'wevtutil qe {channel} /c:{count} /f:xml /rd:false /q:"{query}" 2>$null'
    r = subprocess.run(
        ['powershell','-NoProfile','-NonInteractive','-Command', cmd],
        capture_output=True, text=True, timeout=15, errors='ignore'
    )
    return r.stdout or ''

def _split_events(raw):
    return re.findall(r'<Event[^>]*>.*?</Event>', raw, re.DOTALL)

def _get_last_record_id(channel):
    cmd = f'wevtutil qe {channel} /c:1 /f:xml /rd:true 2>$null'
    r = subprocess.run(
        ['powershell','-NoProfile','-NonInteractive','-Command', cmd],
        capture_output=True, text=True, timeout=10, errors='ignore'
    )
    m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', r.stdout or '')
    return int(m.group(1)) if m else 0

def capture(out_queue, interval=10, stop_event=None):
    channels = ['Application', 'System']
    last_ids = {ch: _get_last_record_id(ch) for ch in channels}
    while not (stop_event and stop_event.is_set()):
        for ch in channels:
            try:
                raw   = _get_events(ch, last_ids[ch])
                evts  = _split_events(raw)
                for xml in evts:
                    m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml)
                    if m:
                        rid = int(m.group(1))
                        if rid > last_ids[ch]:
                            last_ids[ch] = rid
                    parsed = WIN_PARSER.parse(xml)
                    if parsed:
                        out_queue.put(('windows', parsed))
            except: pass
        time.sleep(interval)
