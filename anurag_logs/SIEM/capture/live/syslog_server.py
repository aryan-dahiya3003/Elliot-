"""
syslog_server.py - UDP syslog receiver on port 514.
Receives syslog messages from Linux machines, network devices, routers.
"""
import socketserver, threading, queue, re, datetime
from capture.linux_capture   import LinuxCapture
from capture.firewall_capture import FirewallCapture
from capture.dns_capture     import DNSCapture
from capture.application_capture import ApplicationCapture

PARSERS = [
    LinuxCapture(),
    FirewallCapture(),
    DNSCapture(),
    ApplicationCapture(),
]

class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request[0].decode('utf-8', errors='ignore').strip()
            # Strip syslog priority <NNN>
            data = re.sub(r'^<\d+>', '', data).strip()
            for parser in PARSERS:
                result = parser.parse(data)
                if result:
                    result['source_machine'] = self.client_address[0]
                    log_type = parser.__class__.__name__.replace('Capture','').lower()
                    self.server.out_queue.put((log_type, result))
                    break
            else:
                # Unknown format - store as application log
                ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                self.server.out_queue.put(('application', {
                    'raw': data, 'timestamp': ts,
                    'message': data[:120], 'severity': 'info', 'action': 'event',
                    'source_machine': self.client_address[0]
                }))
        except: pass

class SyslogServer:
    def __init__(self, host='0.0.0.0', port=514):
        self.host = host
        self.port = port
        self.out_queue = queue.Queue()
        self._server  = None

    def start(self):
        try:
            self._server = socketserver.UDPServer((self.host, self.port), SyslogHandler)
            self._server.out_queue = self.out_queue
            t = threading.Thread(target=self._server.serve_forever, daemon=True)
            t.start()
            return True, f'Syslog UDP:{self.port} listening'
        except PermissionError:
            # Try port 5140 (no admin needed)
            try:
                self._server = socketserver.UDPServer((self.host, 5140), SyslogHandler)
                self._server.out_queue = self.out_queue
                t = threading.Thread(target=self._server.serve_forever, daemon=True)
                t.start()
                return True, 'Syslog UDP:5140 listening (use port 5140 on senders)'
            except Exception as e:
                return False, f'Syslog server failed: {e}'
        except Exception as e:
            return False, f'Syslog server failed: {e}'

    def get_events(self):
        events = []
        while not self.out_queue.empty():
            try: events.append(self.out_queue.get_nowait())
            except: break
        return events
