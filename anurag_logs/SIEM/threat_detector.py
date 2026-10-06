"""
threat_detector.py - Real-time threat detection engine.
Runs on every normalized event and fires alerts for known attack patterns.
"""
import time, math
from collections import defaultdict
from typing import Optional

class ThreatDetector:
    BRUTE_WINDOW    = 60   # seconds
    BRUTE_THRESHOLD = 5    # failures in window
    SCAN_WINDOW     = 30   # seconds
    SCAN_THRESHOLD  = 10   # unique ports in window
    C2_PORTS        = {4444, 1337, 31337, 5555, 6666, 8888, 1234, 65535}
    EXFIL_BYTES     = 50 * 1024 * 1024  # 50 MB
    DGA_ENTROPY     = 3.5
    DGA_MIN_LEN     = 15

    def __init__(self):
        # ip -> list of failure timestamps
        self._failures = defaultdict(list)
        # ip -> list of (timestamp, port)
        self._ports    = defaultdict(list)

    def analyze(self, event: dict) -> Optional[dict]:
        lt  = event.get('log_type', '')
        act = event.get('action', '')
        src = event.get('source_ip', '')
        dp  = event.get('destination_port', 0)
        now = time.time()

        # 1. Brute force detection
        if lt in ('linux', 'windows', 'authentication') and act == 'block' and src:
            self._failures[src].append(now)
            # prune old
            self._failures[src] = [t for t in self._failures[src] if now - t < self.BRUTE_WINDOW]
            if len(self._failures[src]) >= self.BRUTE_THRESHOLD:
                return self._alert('BRUTE_FORCE', 'critical', src,
                    f'BRUTE FORCE: {len(self._failures[src])} failures from {src} in {self.BRUTE_WINDOW}s',
                    event)

        # 2. Port scan detection
        if lt == 'netflow' and src and dp:
            self._ports[src].append((now, dp))
            self._ports[src] = [(t,p) for t,p in self._ports[src] if now - t < self.SCAN_WINDOW]
            unique_ports = len({p for _,p in self._ports[src]})
            if unique_ports >= self.SCAN_THRESHOLD:
                return self._alert('PORT_SCAN', 'high', src,
                    f'PORT SCAN: {src} contacted {unique_ports} different ports in {self.SCAN_WINDOW}s',
                    event)

        # 3. C2 beacon detection
        if lt == 'netflow' and dp in self.C2_PORTS:
            return self._alert('C2_BEACON', 'critical', src,
                f'C2 BEACON: Connection to known C2 port {dp} from {src}', event)

        # 4. Known malware tool
        if lt == 'edr':
            indicator = event.get('extra', {}).get('attack_indicator')
            if indicator:
                return self._alert('KNOWN_MALWARE', 'critical', src or event.get('hostname','?'),
                    f'MALWARE TOOL DETECTED: {indicator} on {event.get("hostname","?")}', event)

        # 5. Sensitive file access
        if lt == 'file_audit' and event.get('extra', {}).get('sensitive'):
            fp = event.get('extra', {}).get('file_path', '?')
            return self._alert('SENSITIVE_FILE', 'high', src or event.get('hostname','?'),
                f'SENSITIVE FILE ACCESS: {fp}', event)

        # 6. Large data transfer (exfiltration)
        if lt == 'netflow':
            b = event.get('extra', {}).get('bytes', 0)
            if b and b > self.EXFIL_BYTES:
                mb = b / (1024*1024)
                return self._alert('EXFILTRATION', 'high', src,
                    f'LARGE TRANSFER: {mb:.1f} MB from {src} to {event.get("destination_ip","?")}', event)

        # 7. DGA domain
        if lt == 'dns':
            domain = event.get('extra', {}).get('query_name', '')
            if domain and self._entropy(domain.split('.')[0]) > self.DGA_ENTROPY and len(domain.split('.')[0]) > self.DGA_MIN_LEN:
                return self._alert('DGA_DOMAIN', 'high', src,
                    f'POSSIBLE DGA DOMAIN: {domain} queried by {src}', event)

        return None

    def _alert(self, threat_type, severity, source, message, related):
        return {
            'THREAT':           True,
            'threat_type':      threat_type,
            'severity':         severity,
            'source':           source,
            'message':          message,
            'timestamp':        related.get('timestamp', ''),
            'related_log_type': related.get('log_type', ''),
        }

    @staticmethod
    def _entropy(s):
        if not s: return 0
        from collections import Counter
        c = Counter(s)
        l = len(s)
        return -sum((v/l)*math.log2(v/l) for v in c.values())
