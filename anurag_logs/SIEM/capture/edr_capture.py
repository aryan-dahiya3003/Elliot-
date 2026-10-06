import json, re
from typing import Optional
from capture.base_capture import BaseCapture

class EDRCapture(BaseCapture):
    LOG_TYPE = "edr"
    SUSPICIOUS_NAMES = {"mimikatz.exe","meterpreter","cobaltstrike","psexec.exe","procdump.exe"}
    LOLBIN_NAMES = {"mshta.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","wmic.exe"}
    SUSPICIOUS_PATTERNS = [
        re.compile(r"-[Ee]nc\w*\s+[A-Za-z0-9+/]{20,}"),
        re.compile(r"IEX\s*\(", re.I),
        re.compile(r"DownloadString|WebClient", re.I),
        re.compile(r"vssadmin\s+delete", re.I),
        re.compile(r"net\s+user\s+.*\s+/add", re.I),
    ]

    def parse(self, raw_line):
        raw_line = raw_line.strip()
        if not raw_line or not raw_line.startswith("{"):
            return None
        try:
            d = json.loads(raw_line)
        except json.JSONDecodeError:
            return None
        ts         = d.get("timestamp", d.get("time", ""))
        hostname   = d.get("hostname", d.get("host", ""))
        user       = d.get("user", d.get("username", ""))
        event_type = d.get("event_type", d.get("eventType", "unknown"))
        proc       = d.get("process", {}) or {}
        proc_name  = proc.get("name", proc.get("exe", ""))
        proc_pid   = proc.get("pid")
        proc_cmd   = proc.get("cmdline", proc.get("command_line", ""))
        parent     = proc.get("parent_name", "")
        file_hash  = proc.get("hash_sha256", proc.get("md5", ""))
        net        = d.get("network", {}) or {}
        dst_ip     = net.get("dst_ip", "")
        dst_port   = net.get("dst_port")
        proto      = net.get("proto", "")
        suspicious = False
        indicator  = None
        if proc_name.lower() in self.SUSPICIOUS_NAMES:
            suspicious, indicator = True, "known_tool:" + proc_name
        elif proc_cmd:
            for p in self.SUSPICIOUS_PATTERNS:
                if p.search(proc_cmd):
                    suspicious, indicator = True, "suspicious_cmdline"
                    break
        if not suspicious and proc_name.lower() in self.LOLBIN_NAMES:
            suspicious, indicator = True, "lolbin:" + proc_name
        sev    = "high" if suspicious else "info"
        action = "detect" if suspicious else event_type.lower().replace(" ", "_")
        extra  = {k:v for k,v in {"process_name": proc_name or None, "process_pid": proc_pid,
                  "cmdline": (proc_cmd[:300] if proc_cmd else None), "parent_process": parent or None,
                  "file_hash": file_hash or None, "attack_indicator": indicator,
                  "event_type": event_type or None}.items() if v is not None}
        result = {"raw": raw_line, "timestamp": ts or None, "hostname": hostname or None,
                  "user": user or None, "destination_ip": dst_ip or None,
                  "destination_port": int(dst_port) if dst_port else None,
                  "protocol": proto.upper() if proto else None,
                  "action": action, "event_id": event_type or None,
                  "message": "EDR " + event_type + " [proc=" + proc_name + ", user=" + user + "]" + (" ALERT:" + indicator if indicator else ""),
                  "severity": sev, "extra": extra if extra else None}
        return {k: v for k, v in result.items() if v is not None}
