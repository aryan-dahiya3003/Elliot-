"""
agent_receiver.py - HTTP server that receives logs from remote agents.
Agents POST JSON to http://THIS_IP:9999/events
"""
import http.server, threading, queue, json

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = self.rfile.read(length).decode('utf-8', errors='ignore')
            data   = json.loads(body)
            agent_ip = self.client_address[0]
            self.server.connected_agents.add(agent_ip)
            events = data if isinstance(data, list) else [data]
            for ev in events:
                log_type = ev.pop('_log_type', 'application')
                ev['source_machine'] = agent_ip
                self.server.out_queue.put((log_type, ev))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        except Exception as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, *args): pass  # silence default HTTP logging

class AgentReceiver:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.out_queue        = queue.Queue()
        self.connected_agents = set()
        self._server          = None

    def start(self):
        try:
            self._server = http.server.HTTPServer((self.host, self.port), _Handler)
            self._server.out_queue        = self.out_queue
            self._server.connected_agents = self.connected_agents
            t = threading.Thread(target=self._server.serve_forever, daemon=True)
            t.start()
            return True, f'Agent receiver HTTP:{self.port} listening'
        except Exception as e:
            return False, f'Agent receiver failed: {e}'

    def get_events(self):
        events = []
        while not self.out_queue.empty():
            try: events.append(self.out_queue.get_nowait())
            except: break
        return events
