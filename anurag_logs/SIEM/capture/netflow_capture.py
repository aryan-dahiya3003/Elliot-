"""
capture/netflow_capture.py
==========================
Parser for Network Flow logs (NetFlow/IPFIX/sFlow JSON).

WHAT IS NETWORK FLOW DATA?
---------------------------
Unlike packet capture (which captures every byte), flow data captures
METADATA about network connections:
  - Which IP talked to which IP
  - On which port and protocol
  - How many bytes/packets were transferred
  - For how long

Think of it as a phone bill: you do not see the conversation content,
but you see who called whom, for how long, and how much data.

WHY IT MATTERS FOR SECURITY (SIEM):
- Detect port scanning (one IP contacting many ports/IPs quickly)
- Detect C2 beaconing (regular small flows to external IP every N minutes)
- Detect data exfiltration (very large outbound flows to unknown IP)
- Detect lateral movement (internal host connecting to many others)
- Detect DDoS (massive inbound flows from many sources)

RAW FORMAT (NetFlow JSON from nfdump/ntopng):
  {"start":"2024-01-15T10:23:45Z","src_ip":"192.168.1.5","dst_ip":"198.51.100.1",
   "src_port":54321,"dst_port":4444,"proto":"TCP","bytes":15234,"packets":23,"duration":120}

FIELDS WE EXTRACT:
  timestamp, source_ip, destination_ip, source_port, destination_port,
  protocol, bytes transferred, packet count, flow duration
"""

import json
import re
from typing import Optional
from capture.base_capture import BaseCapture


class NetflowCapture(BaseCapture):
    LOG_TYPE = "netflow"

    # CSV-style NetFlow (nfdump -o csv output)
    # ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,ra,eng,bps,pps,bpp,exp
    CSV_PATTERN = re.compile(
        r'(?P<ts>[\d\-T:.Z]+),(?P<te>[\d\-T:.Z]+),(?P<td>[\d.]+),'
        r'(?P<src_ip>[\d.]+),(?P<dst_ip>[\d.]+),'
        r'(?P<src_port>\d+),(?P<dst_port>\d+),'
        r'(?P<proto>\w+).*?,(?P<pkts>\d+),(?P<bytes>\d+)'
    )

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # JSON format
        if raw_line.startswith("{"):
            return self._parse_json(raw_line)

        # CSV format
        m = self.CSV_PATTERN.search(raw_line)
        if m:
            g = m.groupdict()
            return self._build_result(
                raw_line,
                ts=g["ts"], src_ip=g["src_ip"], dst_ip=g["dst_ip"],
                src_port=int(g["src_port"]), dst_port=int(g["dst_port"]),
                proto=g["proto"], bytes_=int(g["bytes"]), pkts=int(g["pkts"]),
                duration=float(g["td"])
            )
        return None

    def _parse_json(self, raw_line: str) -> Optional[dict]:
        try:
            d = json.loads(raw_line)
        except json.JSONDecodeError:
            return None

        ts       = d.get("start", d.get("timestamp", d.get("ts", "")))
        src_ip   = d.get("src_ip", d.get("source_ip", d.get("src", "")))
        dst_ip   = d.get("dst_ip", d.get("dest_ip", d.get("dst", "")))
        src_port = int(d.get("src_port", d.get("source_port", d.get("sport", 0))))
        dst_port = int(d.get("dst_port", d.get("dest_port", d.get("dport", 0))))
        proto    = d.get("proto", d.get("protocol", "TCP")).upper()
        bytes_   = int(d.get("bytes", d.get("byte_count", 0)))
        pkts     = int(d.get("packets", d.get("packet_count", d.get("pkts", 0))))
        duration = float(d.get("duration", d.get("flow_duration", 0)))

        return self._build_result(raw_line, ts, src_ip, dst_ip, src_port, dst_port, proto, bytes_, pkts, duration)

    def _build_result(self, raw, ts, src_ip, dst_ip, src_port, dst_port, proto, bytes_, pkts, duration):
        severity = "info"
        action   = "connect"
        # Heuristics for suspicious flows
        if dst_port in (4444, 4445, 5555, 6666, 8888, 1337, 31337):
            severity, action = "high", "detect"  # Common C2/backdoor ports
        elif bytes_ > 100_000_000:
            severity, action = "high", "detect"  # >100MB transfer - possible exfil
        elif bytes_ > 10_000_000:
            severity = "medium"                   # >10MB - worth watching

        return {k: v for k, v in {
            "raw":              raw,
            "timestamp":        ts or None,
            "source_ip":        src_ip or None,
            "destination_ip":   dst_ip or None,
            "source_port":      src_port or None,
            "destination_port": dst_port or None,
            "protocol":         proto or None,
            "action":           action,
            "message":          f"NetFlow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{proto}] {bytes_} bytes {pkts} pkts {duration:.1f}s",
            "severity":         severity,
            "extra": {
                "bytes":    bytes_,
                "packets":  pkts,
                "duration_sec": duration,
            },
        }.items() if v is not None}
