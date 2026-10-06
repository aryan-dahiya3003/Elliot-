"""
capture/live/dhcp_live.py
=========================
Captures DHCP events from Windows DHCP Client event log.
Covers log type #3: DHCP - IP to device identification.
"""
import subprocess, re, time, queue, datetime
from capture.dhcp_capture import DHCPCapture

PARSER = DHCPCapture()

DHCP_EVENT_IDS = {
    "50066": "DHCPACK",   # Address matched/plumbed
    "50067": "DHCPACK",
    "50032": "DHCPACK",
    "50036": "DHCPSTART",
    "50037": "DHCPSTOP",
}

def _get_last_rid(channel):
    cmd = 'wevtutil qe "{}" /c:1 /f:xml /rd:true 2>$null'.format(channel)
    r = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",cmd],
                       capture_output=True, text=True, timeout=10)
    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", r.stdout or "")
    return int(m.group(1)) if m else 0

def _get_events(channel, last_rid):
    cmd = 'wevtutil qe "{}" /c:10 /f:xml /rd:false /q:"*[System[EventRecordID > {}]]" 2>$null'.format(channel, last_rid)
    r = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",cmd],
                       capture_output=True, text=True, timeout=10)
    return re.findall(r"<Event[^>]*>.*?</Event>", r.stdout or "", re.DOTALL)

def capture(out_queue, interval=15, stop_event=None):
    channels = [
        "Microsoft-Windows-Dhcp-Client/Admin",
        "Microsoft-Windows-Dhcp-Client/Operational",
    ]
    last_ids = {}
    for ch in channels:
        try:
            last_ids[ch] = _get_last_rid(ch)
        except:
            last_ids[ch] = 0

    while not (stop_event and stop_event.is_set()):
        for ch in channels:
            try:
                xmls = _get_events(ch, last_ids[ch])
                for xml in xmls:
                    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", xml)
                    if m:
                        rid = int(m.group(1))
                        if rid > last_ids[ch]:
                            last_ids[ch] = rid
                    # Extract key info and build synthetic DHCP line
                    eid_m = re.search(r"<EventID>(\d+)</EventID>", xml)
                    ts_m  = re.search(r"SystemTime='([^']+)'", xml)
                    eid   = eid_m.group(1) if eid_m else "?"
                    ts    = ts_m.group(1)[:19] if ts_m else datetime.datetime.utcnow().isoformat()
                    msg_type = DHCP_EVENT_IDS.get(eid, "DHCPEVENT")
                    # Build synthetic ISC DHCP style line
                    date_str = datetime.datetime.fromisoformat(ts.replace("Z","")).strftime("%b %d %H:%M:%S")
                    line = "{} dhcpclient dhcpd: {} on 0.0.0.0 to 00:00:00:00:00:00 (WINDOWS-CLIENT) via eth0".format(
                        date_str, msg_type)
                    parsed = PARSER.parse(line)
                    if parsed:
                        parsed["event_id"] = eid
                        out_queue.put(("dhcp", parsed))
            except:
                pass
        time.sleep(interval)
