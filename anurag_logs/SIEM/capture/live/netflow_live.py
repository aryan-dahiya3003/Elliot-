"""
netflow_live.py - Polls active TCP connections every N seconds.
"""
import subprocess, json, time, queue, datetime
from capture.netflow_capture import NetflowCapture

NF_PARSER = NetflowCapture()
C2_PORTS  = {4444,1337,31337,5555,6666,9999,8888,1234,65535}

def _get_connections():
    r = subprocess.run(
        ['powershell','-NoProfile','-NonInteractive','-Command',
         'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress'],
        capture_output=True, text=True, timeout=10, errors='ignore'
    )
    if not r.stdout.strip(): return []
    try:
        data = json.loads(r.stdout)
        return data if isinstance(data, list) else [data]
    except: return []

def capture(out_queue, interval=5, stop_event=None):
    seen = set()
    while not (stop_event and stop_event.is_set()):
        try:
            conns = _get_connections()
            now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            for c in conns:
                src = c.get('LocalAddress','')
                sp  = c.get('LocalPort',0)
                dst = c.get('RemoteAddress','')
                dp  = c.get('RemotePort',0)
                if not dst or dst in ('0.0.0.0','::','127.0.0.1','::1'): continue
                key = (src, sp, dst, dp)
                if key in seen: continue
                seen.add(key)
                event = {"start":now,"src_ip":src,"src_port":sp,"dst_ip":dst,"dst_port":dp,"proto":"TCP","bytes":0,"packets":0,"duration":0.0}
                line  = json.dumps(event)
                parsed = NF_PARSER.parse(line)
                if parsed:
                    if dp in C2_PORTS:
                        parsed['severity'] = 'critical'
                        parsed['message'] += f' [C2-PORT:{dp}]'
                    out_queue.put(('netflow', parsed))
        except: pass
        time.sleep(interval)
