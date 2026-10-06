"""
capture/live/file_audit_live.py
================================
Captures File Audit events (log type #11) from Windows Security Event Log.
Events: 4663 (object access), 4660 (object deleted), 4656 (handle requested).

Requires:
  1. Run as Administrator
  2. Enable audit policy: auditpol /set /subcategory:"File System" /success:enable /failure:enable

If not admin or audit not enabled -> silently waits.
"""
import subprocess, re, time
from capture.file_audit_capture import FileAuditCapture

PARSER = FileAuditCapture()
FILE_EVENT_IDS = {"4663", "4660", "4656", "4659", "4670"}

SENSITIVE_PATHS = {
    "\\sam",          # SAM database (Windows passwords)
    "\\ntds.dit",     # Active Directory database
    "\\system32\\config",
    "shadow",         # Linux shadow file
    "\\hosts",        # hosts file
    "\\lsass",        # LSASS process memory
}


def _get_last_rid():
    ids = " or ".join("EventID={}".format(i) for i in FILE_EVENT_IDS)
    cmd = ('wevtutil qe Security /c:1 /f:xml /rd:true'
           ' /q:"*[System[({})]]]" 2>$null'.format(ids))
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True, timeout=10
    )
    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", r.stdout or "")
    return int(m.group(1)) if m else 0


def _get_events(last_rid):
    ids = " or ".join("EventID={}".format(i) for i in FILE_EVENT_IDS)
    cmd = ('wevtutil qe Security /c:20 /f:xml /rd:false'
           ' /q:"*[System[EventRecordID > {} and ({})]]" 2>$null'.format(last_rid, ids))
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True, timeout=15
    )
    return re.findall(r"<Event[^>]*>.*?</Event>", r.stdout or "", re.DOTALL)


def _build_audit_line(xml):
    """Convert Windows Security XML to auditd-like format our parser handles."""
    eid   = re.search(r"<EventID>(\d+)</EventID>", xml)
    ts_m  = re.search(r"SystemTime='([^']+)'", xml)
    obj_m = re.search(r'Name="ObjectName">([^<]+)', xml)
    usr_m = re.search(r'Name="SubjectUserName">([^<]+)', xml)
    proc_m= re.search(r'Name="ProcessName">([^<]+)', xml)

    eid_val  = eid.group(1) if eid else "4663"
    ts_val   = ts_m.group(1)[:10] if ts_m else ""
    obj_val  = obj_m.group(1).strip() if obj_m else ""
    usr_val  = usr_m.group(1).strip() if usr_m else ""
    proc_val = proc_m.group(1).strip() if proc_m else ""

    epoch = "1705312225.123"
    syscall_map = {"4663": "2", "4660": "87", "4656": "2", "4670": "188"}
    sc = syscall_map.get(eid_val, "2")

    line = ("type=PATH msg=audit({epoch}:456): item=0 "
            "name={obj} inode=131073 dev=08:01 mode=0100640 nametype=NORMAL").format(
        epoch=epoch, obj=obj_val or "/unknown/file")
    return line


def capture(out_queue, interval=15, stop_event=None):
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
                audit_line = _build_audit_line(xml)
                parsed = PARSER.parse(audit_line)
                if parsed:
                    # Check for sensitive file access
                    fp = parsed.get("extra", {}).get("file_path", "").lower()
                    if any(s in fp for s in SENSITIVE_PATHS):
                        parsed["severity"] = "critical"
                        parsed.setdefault("extra", {})["sensitive"] = True
                    out_queue.put(("file_audit", parsed))
        except Exception:
            pass
        time.sleep(interval)
