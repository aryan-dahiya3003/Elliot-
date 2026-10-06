"""
capture/firewall_capture.py
===========================
Parser for Firewall logs.

WHAT IS A FIREWALL LOG?
-----------------------
A firewall sits at the network boundary and decides which traffic to ALLOW
or BLOCK based on rules. Every time it makes a decision, it writes a log.

WHY IT MATTERS FOR SECURITY (SIEM):
- Detect port scans (many blocked connections to different ports)
- Detect brute force over network (repeated blocks from same IP)
- Detect C2 communication (outbound to suspicious IPs/ports)
- See which internal hosts are trying to reach the internet

RAW FORMAT (iptables/UFW):
  Jan 15 10:23:45 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.5 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=443

FIELDS WE EXTRACT:
  timestamp, hostname, action (ALLOW/BLOCK), source_ip, destination_ip,
  source_port, destination_port, protocol, interface
"""

import re
from typing import Optional
from capture.base_capture import BaseCapture


class FirewallCapture(BaseCapture):
    LOG_TYPE = "firewall"

    # Regex for iptables/UFW format
    # Example: Jan 15 10:23:45 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1234 DPT=443
    UFW_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+'
        r'(?P<hostname>\S+)\s+kernel:.*?\[UFW\s+(?P<action>\w+)\]'
        r'.*?SRC=(?P<src_ip>[\d.]+)'
        r'.*?DST=(?P<dst_ip>[\d.]+)'
        r'(?:.*?PROTO=(?P<proto>\w+))?'
        r'(?:.*?SPT=(?P<spt>\d+))?'
        r'(?:.*?DPT=(?P<dpt>\d+))?'
    )

    # Regex for Cisco ASA format
    # Example: Jan 15 2024 10:23:45 ASA-4-106023: Deny tcp src outside:1.2.3.4/1234 dst inside:5.6.7.8/443
    ASA_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{4}\s+[\d:]+)\s+'
        r'(?P<hostname>\S+)\s+%ASA-\d-(?P<event_id>\d+):\s+'
        r'(?P<action>\w+)\s+(?P<proto>\w+)\s+'
        r'src\s+\S+:(?P<src_ip>[\d.]+)/(?P<spt>\d+)\s+'
        r'dst\s+\S+:(?P<dst_ip>[\d.]+)/(?P<dpt>\d+)'
    )

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # Try UFW format
        m = self.UFW_PATTERN.search(raw_line)
        if m:
            g = m.groupdict()
            action = g["action"].lower()   # "block" or "allow"
            dst_port = int(g["dpt"]) if g.get("dpt") else None
            result = {
                "raw":       raw_line,
                "timestamp": g["timestamp"],
                "hostname":  g["hostname"],
                "action":    action,
                "source_ip": g["src_ip"],
                "dest_ip":   g["dst_ip"],
                "protocol":  g.get("proto", "").upper() or None,
                "source_port": int(g["spt"]) if g.get("spt") else None,
                "dest_port":   dst_port,
                "message":  f"Firewall {action}ed {g.get('proto','?')} "
                            f"{g['src_ip']} -> {g['dst_ip']}:{dst_port or '?'}",
                "severity": "medium" if action == "block" else "info",
                "extra":    {"interface": "unknown"},
            }
            return {k: v for k, v in result.items() if v is not None}

        # Try Cisco ASA format
        m = self.ASA_PATTERN.search(raw_line)
        if m:
            g = m.groupdict()
            action = "block" if g["action"].lower() == "deny" else "allow"
            dst_port = int(g["dpt"]) if g.get("dpt") else None
            result = {
                "raw":       raw_line,
                "timestamp": g["timestamp"],
                "hostname":  g["hostname"],
                "action":    action,
                "source_ip": g["src_ip"],
                "dest_ip":   g["dst_ip"],
                "protocol":  g.get("proto", "").upper() or None,
                "source_port": int(g["spt"]) if g.get("spt") else None,
                "dest_port":   dst_port,
                "event_id": g.get("event_id"),
                "message":  f"Firewall {action}ed {g.get('proto','?')} "
                            f"{g['src_ip']} -> {g['dst_ip']}:{dst_port or '?'}",
                "severity": "medium" if action == "block" else "info",
            }
            return {k: v for k, v in result.items() if v is not None}

        return None  # unrecognised format
