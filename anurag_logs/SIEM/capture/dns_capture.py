"""
capture/dns_capture.py
======================
Parser for DNS logs.

WHAT IS A DNS LOG?
------------------
DNS (Domain Name System) translates domain names like "google.com" into IP
addresses. Every time a device looks up a domain, the DNS server logs it.

WHY IT MATTERS FOR SECURITY (SIEM):
- Detect C2 (Command & Control): malware beacons to attacker-controlled domains
- Detect DGA (Domain Generation Algorithm): malware generates random domains
- Detect DNS tunneling: data exfiltrated inside DNS queries
- Detect typosquatting: users visiting lookalike phishing domains

RAW FORMAT (BIND9 query log):
  15-Jan-2024 10:23:45.123 queries: info: client @0x7f 192.168.1.5#53412 (evil.ru): query: evil.ru IN A + (192.168.1.1)

FIELDS WE EXTRACT:
  timestamp, client_ip, client_port, queried_domain, query_type, server_ip
"""

import re
from typing import Optional
from capture.base_capture import BaseCapture


class DNSCapture(BaseCapture):
    LOG_TYPE = "dns"

    # BIND9 query log format
    BIND_PATTERN = re.compile(
        r'(?P<timestamp>[\d\w\-]+\s+[\d:.]+)\s+queries:\s+\w+:\s+'
        r'client\s+(?:@\S+\s+)?(?P<src_ip>[\d.]+)#(?P<src_port>\d+)'
        r'\s+\((?P<domain>[^)]+)\):\s+query:\s+(?P<qname>\S+)\s+IN\s+(?P<qtype>\w+)'
    )

    # Windows DNS debug log format
    # 1/15/2024 10:23:45 AM 0B20 PACKET ...  192.168.1.5 Rcv ... evil.ru
    WIN_DNS_PATTERN = re.compile(
        r'(?P<timestamp>[\d/]+ [\d:]+ [AP]M)\s+\w+\s+PACKET.*?'
        r'(?P<src_ip>[\d.]+)\s+(?:Snd|Rcv).*?(?P<domain>[\w.\-]+\.(?:com|net|org|ru|cn|io|xyz|top|tk))'
    )

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # Try BIND9
        m = self.BIND_PATTERN.search(raw_line)
        if m:
            g = m.groupdict()
            domain = g["qname"]
            return {
                "raw":       raw_line,
                "timestamp": g["timestamp"],
                "source_ip": g["src_ip"],
                "source_port": int(g["src_port"]),
                "protocol":  "UDP",
                "action":    "query",
                "message":   f"DNS query from {g['src_ip']}: {domain} ({g['qtype']})",
                "severity":  "info",
                "extra": {
                    "query_name": domain,
                    "query_type": g["qtype"],
                    "domain": g["domain"],
                },
            }

        # Try Windows DNS debug
        m = self.WIN_DNS_PATTERN.search(raw_line)
        if m:
            g = m.groupdict()
            domain = g["domain"]
            return {
                "raw":       raw_line,
                "timestamp": g["timestamp"],
                "source_ip": g["src_ip"],
                "protocol":  "UDP",
                "action":    "query",
                "message":   f"DNS query from {g['src_ip']}: {domain}",
                "severity":  "info",
                "extra":     {"query_name": domain, "domain": domain},
            }

        return None
