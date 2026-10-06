"""
live_capture.py
===============
Real-time SIEM log capture from your machine and the network.
Like Wireshark - press Ctrl+C to stop.

Usage:
  python live_capture.py                    # capture local machine only
  python live_capture.py --syslog           # + receive syslog UDP:514 from Linux/routers
  python live_capture.py --agent            # + receive from remote agents on HTTP:9999
  python live_capture.py --all              # all sources enabled
  python live_capture.py --output myfile.jsonl
  python live_capture.py --interval 3      # poll every 3 seconds (default 5)
  python live_capture.py --no-color        # disable color output
"""
import argparse, threading, queue, json, time, datetime, sys, os, signal
from pathlib import Path

# ── capture modules (all 12 log types)
from capture.live import dns_live, netflow_live, windows_live, process_live
from capture.live import firewall_live, auth_live, application_live
from capture.live import webserver_live, ids_live, file_audit_live
from capture.live import dhcp_live
from normalize.normalizer import normalize
from threat_detector import ThreatDetector

# ── ANSI colors
if sys.platform == 'win32':
    os.system('color')  # enable ANSI on Windows

RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
DIM    = '\033[2m'
RESET  = '\033[0m'
BLINK  = '\033[5m'

def color_sev(sev, text, use_color=True):
    if not use_color: return text
    c = {'critical': RED+BOLD, 'high': RED, 'medium': YELLOW, 'info': DIM, 'low': CYAN}.get(sev, '')
    return c + text + RESET


def main():
    parser = argparse.ArgumentParser(description='SIEM Live Capture')
    parser.add_argument('--syslog',   action='store_true', help='Enable syslog UDP receiver')
    parser.add_argument('--agent',    action='store_true', help='Enable agent HTTP receiver')
    parser.add_argument('--all',      action='store_true', help='Enable all sources')
    parser.add_argument('--output',   default='', help='Output JSONL file (default: timestamped)')
    parser.add_argument('--interval', type=int, default=5, help='Poll interval seconds (default: 5)')
    parser.add_argument('--no-color', action='store_true', dest='no_color', help='Disable colors')
    args = parser.parse_args()

    use_color  = not args.no_color
    use_syslog = args.syslog or args.all
    use_agent  = args.agent  or args.all
    iv         = args.interval

    # Output file
    ts_str   = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_file = args.output or f'live_capture_{ts_str}.jsonl'

    event_queue = queue.Queue()
    stop_event  = threading.Event()
    detector    = ThreatDetector()

    # ── Start all 12 capture threads
    threads = []
    def start_thread(fn, *a, **kw):
        t = threading.Thread(target=fn, args=a, kwargs=kw, daemon=True)
        t.start()
        threads.append(t)

    # Always-on (no special requirements)
    start_thread(dns_live.capture,         event_queue, iv,    stop_event)   # #2 DNS
    start_thread(netflow_live.capture,     event_queue, iv,    stop_event)   # #9 Netflow
    start_thread(process_live.capture,     event_queue, iv*3,  stop_event)   # #12 EDR
    start_thread(application_live.capture, event_queue, iv*4,  stop_event)   # #8 Application
    start_thread(dhcp_live.capture,        event_queue, iv*3,  stop_event)   # #3 DHCP

    # Needs admin for Security log (4624/4625 etc) - works silently if no access
    start_thread(windows_live.capture,    event_queue, iv*2,  stop_event)   # #5 Windows
    start_thread(auth_live.capture,       event_queue, iv*2,  stop_event)   # #6 Authentication
    start_thread(file_audit_live.capture, event_queue, iv*3,  stop_event)   # #11 File Audit

    # Needs firewall log enabled (admin netsh command) - waits silently if not
    start_thread(firewall_live.capture,   event_queue, 2,     stop_event)   # #1 Firewall

    # Needs IDS installed (Suricata) - waits silently if not
    start_thread(ids_live.capture,        event_queue, 2,     stop_event)   # #10 IDS/IPS

    # Needs web server running - tails log file, waits silently if no server
    start_thread(webserver_live.capture,  event_queue, iv,    stop_event)   # #7 Web Server

    # Linux logs come via syslog (--syslog flag)                             # #4 Linux

    # ── Optional servers
    syslog_srv    = None
    agent_srv     = None
    syslog_status = ''
    agent_status  = ''

    if use_syslog:
        from capture.live.syslog_server import SyslogServer
        syslog_srv = SyslogServer()
        ok, syslog_status = syslog_srv.start()

    if use_agent:
        from capture.live.agent_receiver import AgentReceiver
        agent_srv = AgentReceiver()
        ok, agent_status = agent_srv.start()

    # ── Banner
    import ctypes
    is_admin = False
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass

    my_ip = ''
    try:
        import socket
        my_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass

    import os as _os
    fw_log_exists = _os.path.exists(r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")

    print()
    if use_color: print(BOLD + CYAN, end='')
    print('=' * 65)
    print('  SIEM LIVE CAPTURE  -  Press Ctrl+C to stop')
    print('  Machine: {}  IP: {}'.format(os.environ.get('COMPUTERNAME','?'), my_ip))
    print('  Output:  {}'.format(out_file))
    print('=' * 65)
    if use_color: print(RESET, end='')
    print()
    print('  LOG TYPE STATUS (12 types):')
    print('  ' + '-' * 55)

    OK  = '[OK] ' if not use_color else (GREEN + '[OK] ' + RESET)
    ADM = '[NEED ADMIN]' if not use_color else (YELLOW + '[NEED ADMIN]' + RESET)
    NA  = '[NOT INSTALLED]' if not use_color else (DIM + '[NOT AVAIL]' + RESET)
    SYS = '[USE --syslog]' if not use_color else (CYAN + '[USE --syslog]' + RESET)
    AGT = '[USE --agent]' if not use_color else (CYAN + '[USE --agent]' + RESET)

    status_table = [
        ('#1  Firewall',      OK if fw_log_exists else ADM + ' (run as admin + enable fw logging)'),
        ('#2  DNS',           OK + ' (polling DNS cache every {}s)'.format(iv)),
        ('#3  DHCP',          OK + ' (Windows DHCP event log)'),
        ('#4  Linux',         (OK + ' Syslog UDP listening') if use_syslog else SYS + ' (receives Linux/router syslog)'),
        ('#5  Windows',       OK if is_admin else ADM + ' (Security log: run as admin)'),
        ('#6  Authentication',OK if is_admin else ADM + ' (Security log: run as admin)'),
        ('#7  Web Server',    OK + ' (tailing log file)' if any(_os.path.exists(p) for p in [r'C:\inetpub\logs',r'C:\nginx\logs',r'C:\Apache\logs']) else NA + ' (no web server found)'),
        ('#8  Application',   OK + ' (Windows Application event log)'),
        ('#9  Network Flow',  OK + ' (polling TCP connections every {}s)'.format(iv)),
        ('#10 IDS/IPS',       OK + ' (tailing Suricata EVE)' if _os.path.exists(r'C:\Suricata\log\eve.json') else NA + ' (install Suricata or use --syslog)'),
        ('#11 File/Audit',    OK if is_admin else ADM + ' (Security events 4663: run as admin)'),
        ('#12 Endpoint/EDR',  OK + ' (polling processes every {}s)'.format(iv*3)),
    ]
    for name, stat in status_table:
        print('  {:<22} {}'.format(name, stat))
    print('  ' + '-' * 55)
    if not is_admin:
        if use_color: print(YELLOW, end='')
        print('  TIP: Run as Administrator to unlock #1 #5 #6 #11')
        if use_color: print(RESET, end='')
    if not use_syslog:
        if use_color: print(DIM, end='')
        print('  TIP: Add --syslog to receive Linux/router logs on UDP:514')
        if use_color: print(RESET, end='')
    if use_syslog and syslog_status: print('  Syslog:  {}'.format(syslog_status))
    if agent_status:  print('  Agents:  {}'.format(agent_status))
    print()


    # Header columns
    print('  {:<10} {:<8} {:<14} {:<10} MESSAGE'.format('TIME', 'SEV', 'TYPE', 'ACTION'))
    print('  ' + '-'*63)

    total_events  = 0
    total_threats = 0
    machines_seen = set()
    machines_seen.add(os.environ.get('COMPUTERNAME','local'))

    def drain_server(srv):
        if srv is None: return
        for log_type, parsed in srv.get_events():
            event_queue.put((log_type, parsed))

    try:
        with open(out_file, 'w', encoding='utf-8') as f_out:
            while True:
                # Drain server queues
                drain_server(syslog_srv)
                drain_server(agent_srv)

                # Process all queued events
                while not event_queue.empty():
                    try:
                        log_type, parsed = event_queue.get_nowait()
                    except queue.Empty:
                        break

                    # Track machines
                    sm = parsed.get('source_machine')
                    if sm: machines_seen.add(sm)

                    # Normalize
                    normalized = normalize(parsed, log_type)
                    if not normalized:
                        continue

                    total_events += 1

                    # Write to file
                    f_out.write(json.dumps(normalized) + '\n')
                    f_out.flush()

                    # Threat detection
                    threat = detector.analyze(normalized)
                    if threat:
                        total_threats += 1
                        if use_color:
                            threat_line = '  ' + BOLD + RED + '  !!! THREAT: {} - {}'.format(
                                threat['threat_type'], threat['message']) + RESET
                        else:
                            threat_line = '  !!! THREAT: {} - {}'.format(
                                threat['threat_type'], threat['message'])
                        print(threat_line)
                        # Write threat to file too
                        threat['log_type'] = 'threat'
                        f_out.write(json.dumps(threat) + '\n')
                        f_out.flush()

                    # Print event line
                    sev  = normalized.get('severity', 'info')
                    act  = normalized.get('action', '?')
                    msg  = normalized.get('message', '')[:50]
                    now_s = datetime.datetime.now().strftime('%H:%M:%S')
                    sev_label  = '[{:<8}]'.format(sev.upper())
                    type_label = '[{:<12}]'.format(log_type)
                    line = '  {} {} {} {:<10} {}'.format(now_s, sev_label, type_label, act, msg)
                    print(color_sev(sev, line, use_color))

                # Update stats line
                runtime = int(time.time() - start_time)
                h, rem  = divmod(runtime, 3600)
                m2, s2  = divmod(rem, 60)
                rt_str  = '{:02d}:{:02d}:{:02d}'.format(h, m2, s2)
                status  = '\r  [Runtime: {}] [Events: {}] [Threats: {}] [Machines: {}]'.format(
                    rt_str, total_events, total_threats, len(machines_seen))
                print(status, end='', flush=True)

                time.sleep(0.5)

    except KeyboardInterrupt:
        stop_event.set()
        print()
        print()
        print('=' * 65)
        print('  CAPTURE STOPPED')
        print('  Total events   : {}'.format(total_events))
        print('  Threats found  : {}'.format(total_threats))
        print('  Machines seen  : {} - {}'.format(len(machines_seen), list(machines_seen)))
        print('  Output file    : {}'.format(out_file))
        print('=' * 65)


if __name__ == '__main__':
    start_time = time.time()
    main()
