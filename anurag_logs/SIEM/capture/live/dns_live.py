"""
dns_live.py - Polls Windows DNS cache every N seconds, detects new queries.
"""
import subprocess, json, time, math, re, queue, threading, datetime
from capture.dns_capture import DNSCapture

DNS_PARSER = DNSCapture()

def _entropy(s):
    if not s: return 0
    from collections import Counter
    c = Counter(s)
    l = len(s)
    return -sum((v/l)*math.log2(v/l) for v in c.values())

def _is_dga(domain):
    parts = domain.split('.')
    label = parts[0] if parts else domain
    return len(label) > 15 and _entropy(label) > 3.5

def _get_dns_cache():
    r = subprocess.run(
        ['powershell','-NoProfile','-NonInteractive','-Command',
         'Get-DnsClientCache | Select-Object Entry,RecordType,Data | ConvertTo-Json -Compress'],
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
            entries = _get_dns_cache()
            now = datetime.datetime.utcnow().strftime('%d-%b-%Y %H:%M:%S.000')
            for e in entries:
                domain = e.get('Entry','') or ''
                rtype  = e.get('RecordType','A') or 'A'
                key    = domain.lower()
                if key and key not in seen:
                    seen.add(key)
                    # build synthetic BIND line
                    line = f"{now} queries: info: client @0x7f 127.0.0.1#53 ({domain}): query: {domain} IN {rtype} + (127.0.0.1)"
                    parsed = DNS_PARSER.parse(line)
                    if parsed:
                        if _is_dga(domain):
                            parsed['severity'] = 'high'
                            parsed['message'] += ' [DGA-SUSPECTED]'
                        out_queue.put(('dns', parsed))
        except Exception as ex:
            pass
        time.sleep(interval)
