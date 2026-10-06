"""
process_live.py - Polls running processes every N seconds, flags known malicious tools.
"""
import subprocess, json, time, queue, datetime
from capture.edr_capture import EDRCapture

EDR_PARSER = EDRCapture()
SUSPICIOUS = {'mimikatz.exe','psexec.exe','meterpreter.exe','cobaltstrike.exe',
              'procdump.exe','wce.exe','fgdump.exe','pwdump.exe','netcat.exe','nc.exe'}

def _get_processes():
    r = subprocess.run(
        ['powershell','-NoProfile','-NonInteractive','-Command',
         'Get-Process | Select-Object Id,Name,CPU,WorkingSet | ConvertTo-Json -Compress'],
        capture_output=True, text=True, timeout=15, errors='ignore'
    )
    if not r.stdout.strip(): return []
    try:
        data = json.loads(r.stdout)
        return data if isinstance(data, list) else [data]
    except: return []

def capture(out_queue, interval=15, stop_event=None):
    seen_pids = set()
    import os
    hostname = os.environ.get('COMPUTERNAME','unknown')
    user     = os.environ.get('USERNAME','unknown')
    while not (stop_event and stop_event.is_set()):
        try:
            procs = _get_processes()
            now   = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            for p in procs:
                pid  = p.get('Id', 0)
                name = (p.get('Name','') or '') + '.exe'
                if pid in seen_pids: continue
                seen_pids.add(pid)
                event = {"timestamp":now,"event_type":"ProcessCreate","hostname":hostname,"user":user,
                         "process":{"pid":pid,"name":name,"cmdline":name,"parent_name":"unknown"}}
                line = json.dumps(event)
                parsed = EDR_PARSER.parse(line)
                if parsed:
                    out_queue.put(('edr', parsed))
        except: pass
        time.sleep(interval)
