"""
capture/windows_capture.py
==========================
Parser for Windows Security Event Logs (XML format).

WHAT ARE WINDOWS EVENT LOGS?
-----------------------------
Windows logs every security event in the Security Event Log channel.
They are stored in .evtx format but can be exported/forwarded as XML.
Each event has a numeric EventID that identifies what happened.

KEY EVENT IDs TO KNOW:
  4624 - Successful logon
  4625 - Failed logon          <- brute force indicator
  4634 - Logoff
  4648 - Logon with explicit credentials (pass-the-hash indicator)
  4672 - Special privileges assigned to new logon (admin logon)
  4688 - New process created   <- malware execution indicator
  4698 - Scheduled task created <- persistence indicator
  4720 - User account created
  4728/4732/4756 - Member added to security group <- privilege escalation
  7045 - New service installed <- malware persistence

WHY IT MATTERS:
- Detect brute force (many 4625s from same IP)
- Detect lateral movement (4624 Logon Type 3 = network logon)
- Detect malware (4688 with suspicious parent/child process)
- Detect persistence (4698 scheduled task, 7045 new service)

RAW FORMAT (Windows XML):
  <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System><EventID>4625</EventID><TimeCreated SystemTime='2024-01-15T10:23:45.000Z'/><Computer>DESKTOP-ABC</Computer></System>
    <EventData><Data Name='TargetUserName'>john</Data><Data Name='IpAddress'>192.168.1.5</Data></EventData>
  </Event>
"""

import re
import xml.etree.ElementTree as ET
from typing import Optional
from capture.base_capture import BaseCapture


class WindowsCapture(BaseCapture):
    LOG_TYPE = "windows"

    # Severity mapping by EventID
    EVENT_SEVERITY = {
        "4625": "high",    # Failed logon
        "4648": "high",    # Explicit credentials
        "4688": "medium",  # Process created
        "4698": "high",    # Scheduled task created
        "4720": "high",    # User created
        "4728": "high",    # Member added to global group
        "4732": "high",    # Member added to local group
        "7045": "critical",# New service installed
        "4624": "info",    # Successful logon
        "4634": "info",    # Logoff
        "4672": "medium",  # Special privileges
    }

    EVENT_MESSAGES = {
        "4624": "Windows: Successful logon",
        "4625": "Windows: FAILED logon attempt",
        "4634": "Windows: Logoff",
        "4648": "Windows: Logon with explicit credentials (possible pass-the-hash)",
        "4672": "Windows: Special privileges assigned to new logon",
        "4688": "Windows: New process created",
        "4698": "Windows: Scheduled task created (persistence risk)",
        "4720": "Windows: User account created",
        "4728": "Windows: User added to global security group",
        "4732": "Windows: User added to local security group",
        "7045": "Windows: New service installed (malware persistence risk)",
    }

    # Regex for key-value pairs in EventData (simpler logs)
    KV_PATTERN = re.compile(r'(?P<key>\w+)=(?P<value>[^\s,]+)')

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # If the line looks like XML, parse it as XML
        if raw_line.startswith("<Event"):
            return self._parse_xml(raw_line)

        # Otherwise try key=value format (some forwarders produce this)
        return self._parse_kv(raw_line)

    def _parse_xml(self, raw_line: str) -> Optional[dict]:
        try:
            ns_uri = "http://schemas.microsoft.com/win/2004/08/events/event"
            ns = {"e": ns_uri}
            # Strip namespace from raw XML so plain find() works reliably
            clean_xml = re.sub(r'\s+xmlns\s*=\s*"[^"]*"', "", raw_line)
            root = ET.fromstring(clean_xml)
            system = root.find("System")
            event_data = root.find("EventData")

            def find_text(parent, tag):
                if parent is None:
                    return None
                el = parent.find(tag)
                return el.text if el is not None else None

            def get_data(name):
                if event_data is None:
                    return None
                for data in (event_data if event_data is not None else []):
                    if data.get("Name") == name:
                        return data.text
                return None

            event_id   = find_text(system, "EventID") or ""
            timestamp  = ""
            tc = system.find("TimeCreated") if system is not None else None
            if tc is not None:
                timestamp = tc.get("SystemTime", "")
            computer   = find_text(system, "Computer") or ""
            user       = get_data("TargetUserName") or get_data("SubjectUserName") or ""
            src_ip     = get_data("IpAddress") or ""
            src_port   = get_data("IpPort") or ""
            process    = get_data("NewProcessName") or get_data("ProcessName") or ""
            cmd_line   = get_data("CommandLine") or ""
            task_name  = get_data("TaskName") or ""
            svc_name   = get_data("ServiceName") or ""
            logon_type = get_data("LogonType") or ""

            result = {
                "raw":      raw_line,
                "timestamp": timestamp,
                "hostname":  computer,
                "event_id":  event_id,
                "user":      user or None,
                "source_ip": src_ip if src_ip and src_ip != "-" else None,
                "source_port": int(src_port) if src_port and src_port.isdigit() else None,
                "action":    self._event_to_action(event_id),
                "message":   self._build_message(event_id, user, src_ip, process, task_name, svc_name),
                "severity":  self.EVENT_SEVERITY.get(event_id, "info"),
                "extra": {k: v for k, v in {
                    "process":    process or None,
                    "cmdline":    cmd_line or None,
                    "task_name":  task_name or None,
                    "svc_name":   svc_name or None,
                    "logon_type": logon_type or None,
                }.items() if v},
            }
            return {k: v for k, v in result.items() if v is not None and v != {}}

        except ET.ParseError:
            return None

    def _parse_kv(self, raw_line: str) -> Optional[dict]:
        pairs = dict(self.KV_PATTERN.findall(raw_line))
        event_id = pairs.get("EventID", "")
        if not event_id:
            return None
        user    = pairs.get("TargetUserName", pairs.get("User", ""))
        src_ip  = pairs.get("IpAddress", "")
        ts      = pairs.get("TimeCreated", pairs.get("Timestamp", ""))
        host    = pairs.get("Computer", pairs.get("Hostname", ""))
        result = {
            "raw":       raw_line,
            "timestamp": ts or None,
            "hostname":  host or None,
            "event_id":  event_id,
            "user":      user or None,
            "source_ip": src_ip if src_ip and src_ip != "-" else None,
            "action":    self._event_to_action(event_id),
            "message":   self._build_message(event_id, user, src_ip, "", "", ""),
            "severity":  self.EVENT_SEVERITY.get(event_id, "info"),
        }
        return {k: v for k, v in result.items() if v is not None}

    def _event_to_action(self, event_id: str) -> str:
        mapping = {
            "4624": "allow",  "4625": "block",  "4634": "disconnect",
            "4648": "connect","4688": "process_create", "4698": "task_create",
            "4720": "account_create", "4728": "group_change", "4732": "group_change",
            "7045": "service_install",
        }
        return mapping.get(event_id, "event")

    def _build_message(self, eid, user, src_ip, proc, task, svc):
        base = self.EVENT_MESSAGES.get(eid, f"Windows Event {eid}")
        parts = []
        if user and user != "-":
            parts.append(f"user={user}")
        if src_ip and src_ip != "-":
            parts.append(f"from={src_ip}")
        if proc:
            parts.append(f"process={proc}")
        if task:
            parts.append(f"task={task}")
        if svc:
            parts.append(f"service={svc}")
        return f"{base}" + (f" [{', '.join(parts)}]" if parts else "")
