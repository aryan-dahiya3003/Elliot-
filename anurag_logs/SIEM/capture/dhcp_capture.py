"""
capture/dhcp_capture.py
=======================
Parser for DHCP logs.

WHAT IS A DHCP LOG?
-------------------
DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses
to devices when they join the network. The DHCP server logs every assignment.

WHY IT MATTERS FOR SECURITY (SIEM):
- IP-to-Device mapping: when an alert says "1.2.3.4 did something bad",
  DHCP logs tell you WHICH device had that IP at that time
- Detect rogue DHCP servers (attacker impersonating DHCP to redirect traffic)
- Detect new/unknown devices joining the network (by MAC address)
- Track asset movement across network segments

RAW FORMAT (ISC DHCP):
  Jan 15 10:23:45 dhcp01 dhcpd: DHCPACK on 192.168.1.50 to aa:bb:cc:dd:ee:ff (LAPTOP-USER01) via eth0

FIELDS WE EXTRACT:
  timestamp, hostname, message_type (DHCPACK/DHCPREQUEST/etc.), assigned_ip,
  mac_address, client_hostname, interface
"""

import re
from typing import Optional
from capture.base_capture import BaseCapture


class DHCPCapture(BaseCapture):
    LOG_TYPE = "dhcp"

    # ISC DHCP format
    # Jan 15 10:23:45 dhcp01 dhcpd: DHCPACK on 192.168.1.50 to aa:bb:cc:dd:ee:ff (LAPTOP-USER01) via eth0
    ISC_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+'
        r'(?P<hostname>\S+)\s+dhcpd:\s+'
        r'(?P<msg_type>DHCP\w+)\s+on\s+(?P<ip>[\d.]+)\s+to\s+'
        r'(?P<mac>[\da-f:]+)(?:\s+\((?P<client_host>[^)]+)\))?'
        r'(?:\s+via\s+(?P<interface>\S+))?',
        re.IGNORECASE
    )

    # Windows DHCP Server log format (CSV)
    # 10,01/15/24,10:23:45,Assign,192.168.1.50,LAPTOP-USER01,aa-bb-cc-dd-ee-ff,...
    WIN_PATTERN = re.compile(
        r'(?P<event_id>\d+),(?P<date>[\d/]+),(?P<time>[\d:]+),'
        r'(?P<msg_type>\w+),(?P<ip>[\d.]+),(?P<client_host>[^,]*),(?P<mac>[a-f0-9-]+)',
        re.IGNORECASE
    )

    MSG_TYPE_ACTION = {
        "DHCPACK": "assign",
        "DHCPREQUEST": "request",
        "DHCPDISCOVER": "discover",
        "DHCPRELEASE": "release",
        "DHCPNAK": "deny",
        "Assign": "assign",
        "Release": "release",
        "Expired": "expire",
    }

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # Try ISC DHCP format
        m = self.ISC_PATTERN.search(raw_line)
        if m:
            g = m.groupdict()
            msg = g["msg_type"].upper()
            action = self.MSG_TYPE_ACTION.get(msg, "unknown")
            client = g.get("client_host") or "unknown"
            return {
                "raw":       raw_line,
                "timestamp": g["timestamp"],
                "hostname":  g["hostname"],
                "action":    action,
                "message":   f"DHCP {msg}: IP {g['ip']} assigned to {client} ({g['mac']})",
                "severity":  "info",
                "extra": {
                    "dhcp_message_type": msg,
                    "assigned_ip":       g["ip"],
                    "mac_address":       g["mac"].upper(),
                    "client_hostname":   client,
                    "interface":         g.get("interface"),
                },
            }

        # Try Windows DHCP CSV format
        m = self.WIN_PATTERN.search(raw_line)
        if m:
            g = m.groupdict()
            msg = g["msg_type"]
            action = self.MSG_TYPE_ACTION.get(msg, "unknown")
            return {
                "raw":       raw_line,
                "timestamp": f"{g['date']} {g['time']}",
                "action":    action,
                "event_id":  g["event_id"],
                "message":   f"DHCP {msg}: IP {g['ip']} to {g['client_host']} ({g['mac']})",
                "severity":  "info",
                "extra": {
                    "dhcp_message_type": msg,
                    "assigned_ip":       g["ip"],
                    "mac_address":       g["mac"].upper().replace("-", ":"),
                    "client_hostname":   g["client_host"],
                },
            }

        return None
