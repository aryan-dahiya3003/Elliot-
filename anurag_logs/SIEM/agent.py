"""
agent.py - Deploy this on OTHER Windows PCs to send their logs to your central SIEM.

Usage:
  python agent.py --server 192.168.1.X --interval 30
  python agent.py --server 192.168.1.X --port 9999 --interval 15
"""
import argparse, subprocess, json, time, datetime, os
try:
    import urllib.request as ureq
except ImportError:
    import urllib2 as ureq

def run_ps(cmd):
    r = subprocess.run(
        ['powershell','-NoProfile','-NonInteractive','-Command', cmd],
        capture_output=True, text=True, timeout=20, errors='ignore'
    )
    return r.stdout.strip()

def collect_events():
    events = []
    hostname = os.environ.get('COMPUTERNAME','unknown')
    user     = os.environ.get('USERNAME','unknown')
    now      = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # Windows Application events (no admin)
    try:
        xml_out = run_ps('wevtutil qe Application /c:5 /f:xml /rd:true 2>$null')
        if xml_out:
            import re
            for xml in re.findall(r'<Event[^>]*>.*?</Event>', xml_out, re.DOTALL):
                events.append({'_log_type':'windows','raw':xml,'hostname':hostname})
    except: pass

    # Running processes
    try:
        out = run_ps('Get-Process | Select-Object Id,Name | ConvertTo-Json -Compress')
        if out:
            procs = json.loads(out)
            if not isinstance(procs, list): procs = [procs]
            for p in procs[:20]:
                ev = {"timestamp":now,"event_type":"ProcessCreate","hostname":hostname,
                      "user":user,"process":{"pid":p.get('Id',0),"name":(p.get('Name','')+'.exe'),
                      "cmdline":p.get('Name',''),"parent_name":"unknown"}}
                events.append({'_log_type':'edr','raw':json.dumps(ev),'hostname':hostname})
    except: pass

    # Active TCP connections
    try:
        out = run_ps('Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json -Compress')
        if out:
            conns = json.loads(out)
            if not isinstance(conns, list): conns = [conns]
            for c in conns:
                dst = c.get('RemoteAddress','')
                if dst in ('0.0.0.0','::','127.0.0.1','::1',''): continue
                ev = {"start":now,"src_ip":c.get('LocalAddress',''),"src_port":c.get('LocalPort',0),
                      "dst_ip":dst,"dst_port":c.get('RemotePort',0),"proto":"TCP",
                      "bytes":0,"packets":0,"duration":0.0}
                events.append({'_log_type':'netflow','raw':json.dumps(ev),'hostname':hostname})
    except: pass

    # DNS cache
    try:
        out = run_ps('Get-DnsClientCache | Select-Object Entry,RecordType | ConvertTo-Json -Compress')
        if out:
            dns_entries = json.loads(out)
            if not isinstance(dns_entries, list): dns_entries = [dns_entries]
            for d in dns_entries[:20]:
                name  = d.get('Entry','')
                rtype = d.get('RecordType','A') or 'A'
                ts_str = datetime.datetime.now().strftime('%d-%b-%Y %H:%M:%S.000')
                line = '{} queries: info: client @0x7f 127.0.0.1#53 ({}): query: {} IN {} + (127.0.0.1)'.format(ts_str, name, name, rtype)
                events.append({'_log_type':'dns','raw':line,'hostname':hostname})
    except: pass

    return events

def send_events(events, server, port):
    if not events: return True
    url  = 'http://{}:{}/events'.format(server, port)
    body = json.dumps(events).encode('utf-8')
    req  = ureq.Request(url, data=body, headers={'Content-Type':'application/json'})
    try:
        with ureq.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        print('  Send error: {}'.format(e))
        return False

def main():
    p = argparse.ArgumentParser(description='SIEM Agent - sends local logs to central collector')
    p.add_argument('--server',   required=True, help='IP of central SIEM machine')
    p.add_argument('--port',     type=int, default=9999, help='Port (default 9999)')
    p.add_argument('--interval', type=int, default=30,   help='Interval seconds (default 30)')
    args = p.parse_args()

    hostname = os.environ.get('COMPUTERNAME','?')
    print('SIEM Agent started on {}'.format(hostname))
    print('Sending to {}:{} every {}s'.format(args.server, args.port, args.interval))
    print('Press Ctrl+C to stop')
    print()

    while True:
        try:
            print('  [{}] Collecting events...'.format(datetime.datetime.now().strftime('%H:%M:%S')))
            events = collect_events()
            print('  [{}] Collected {} events, sending...'.format(
                datetime.datetime.now().strftime('%H:%M:%S'), len(events)))
            ok = send_events(events, args.server, args.port)
            status = 'OK' if ok else 'FAILED'
            print('  [{}] Send {} -> sleeping {}s'.format(
                datetime.datetime.now().strftime('%H:%M:%S'), status, args.interval))
        except KeyboardInterrupt:
            print('\nAgent stopped.')
            break
        except Exception as e:
            print('  Error: {}'.format(e))
        time.sleep(args.interval)

if __name__ == '__main__':
    main()
