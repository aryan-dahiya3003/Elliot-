"""
capture/ids_capture.py
======================
Parser for IDS/IPS logs (Suricata EVE JSON / Snort unified2).

WHAT IS AN IDS/IPS LOG?
------------------------
An IDS (Intrusion Detection System) inspects network traffic against a database
of known attack signatures. An IPS (Intrusion Prevention System) also blocks.

  IDS: watches and alerts       (passive)
  IPS: watches, alerts, blocks  (inline/active)

Popular tools: Suricata (modern, multi-threaded), Snort (classic)

WHY IT MATTERS FOR SECURITY (SIEM):
- Correlate with firewall logs (was the attack blocked or did it get through?)
- Get immediate alert names mapped to CVEs and MITRE ATT&CK techniques
- Detect known malware, exploits, C2 frameworks (CobaltStrike, Metasploit)
- Detect network scanning, protocol anomalies

RAW FORMAT (Suricata EVE JSON - the industry standard):
  {"timestamp":"2024-01-15T10:23:45.123Z","event_type":"alert",
   "src_ip":"192.168.1.5","dest_ip":"198.51.100.1","dest_port":80,"proto":"TCP",
   "alert":{"signature":"ET MALWARE CobaltStrike Beacon","severity":1,
             "category":"Malware C2","signature_id":2019401}}

FIELDS WE EXTRACT:
  timestamp, source_ip, dest_ip, dest_port, protocol, alert signature,
  severity, category, signature_id (rule ID)
"""

import json
import re
from typing import Optional
from capture.base_capture import BaseCapture


class IDSCapture(BaseCapture):
    LOG_TYPE = "ids_ips"

    # Suricata severity: 1=critical, 2=high, 3=medium, 4=low (reversed from ours)
    SURICATA_SEVERITY = {1: "critical", 2: "high", 3: "medium", 4: "low"}

    # Snort fast-log format:
    # 01/15-10:23:45.123456  [**] [1:2019401:5] ET MALWARE CobaltStrike [**] [Classification: ...] [Priority: 1] {TCP} 1.2.3.4:1234 -> 5.6.7.8:80
    SNORT_PATTERN = re.compile(
        r'(?P<timestamp>[\d/\-:.]+)\s+\[\*\*\]\s+\[\d+:(?P<sig_id>\d+):\d+\]\s+'
        r'(?P<signature>[^\[]+?)\s*\[\*\*\].*?\[Priority:\s*(?P<priority>\d)\]'
        r'\s+\{(?P<proto>\w+)\}\s+(?P<src_ip>[\d.]+):(?P<src_port>\d+)'
        r'\s+->\s+(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)'
    )

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        if raw_line.startswith("{"):
            return self._parse_suricata_eve(raw_line)

        # Try Snort fast-log
        m = self.SNORT_PATTERN.search(raw_line)
        if m:
            return self._parse_snort(raw_line, m)

        return None

    def _parse_suricata_eve(self, raw_line: str) -> Optional[dict]:
        try:
            d = json.loads(raw_line)
        except json.JSONDecodeError:
            return None

        event_type = d.get("event_type", "")
        if event_type not in ("alert", "drop"):
            # Only care about alert/drop events; dns/http/flow handled by other parsers
            if event_type not in ("alert",):
                return {  # Still capture non-alert events at info level
                    "raw":       raw_line,
                    "timestamp": d.get("timestamp", ""),
                    "source_ip": d.get("src_ip"),
                    "destination_ip": d.get("dest_ip"),
                    "action":    "event",
                    "message":   f"Suricata {event_type} event",
                    "severity":  "info",
                    "extra":     {"event_type": event_type},
                }

        alert = d.get("alert", {})
        sig   = alert.get("signature", "Unknown signature")
        sev_n = alert.get("severity", 3)
        sev   = self.SURICATA_SEVERITY.get(sev_n, "medium")
        cat   = alert.get("category", "")
        sig_id = str(alert.get("signature_id", ""))
        action = "block" if event_type == "drop" else "detect"

        return {k: v for k, v in {
            "raw":              raw_line,
            "timestamp":        d.get("timestamp", ""),
            "source_ip":        d.get("src_ip"),
            "destination_ip":   d.get("dest_ip"),
            "source_port":      d.get("src_port"),
            "destination_port": d.get("dest_port"),
            "protocol":         d.get("proto", "").upper() or None,
            "action":           action,
            "event_id":         sig_id or None,
            "message":          f"IDS {action.upper()}: {sig}" + (f" [{cat}]" if cat else ""),
            "severity":         sev,
            "extra": {k: v for k, v in {
                "signature":   sig,
                "category":    cat or None,
                "sig_id":      sig_id or None,
                "in_iface":    d.get("in_iface"),
                "flow_id":     str(d.get("flow_id", "")) or None,
            }.items() if v},
        }.items() if v is not None}

    def _parse_snort(self, raw_line: str, m) -> dict:
        g = m.groupdict()
        prio = int(g["priority"])
        sev  = {1: "critical", 2: "high", 3: "medium", 4: "low"}.get(prio, "medium")
        return {
            "raw":              raw_line,
            "timestamp":        g["timestamp"],
            "source_ip":        g["src_ip"],
            "destination_ip":   g["dst_ip"],
            "source_port":      int(g["src_port"]),
            "destination_port": int(g["dst_port"]),
            "protocol":         g["proto"].upper(),
            "action":           "detect",
            "event_id":         g["sig_id"],
            "message":          f"IDS DETECT: {g['signature'].strip()}",
            "severity":         sev,
            "extra":            {"signature": g["signature"].strip(), "sig_id": g["sig_id"]},
        }
