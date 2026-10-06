import re
import datetime
from typing import Optional
from capture.base_capture import BaseCapture


class FileAuditCapture(BaseCapture):
    """
    Parser for File Integrity / Audit logs (Linux auditd).

    Two record types:
      type=PATH    - records the file path being accessed
      type=SYSCALL - records which system call was made and by which process

    LEARNING NOTE: These records come in PAIRS. The SYSCALL tells you WHAT
    happened (open, unlink, chmod...) and the PATH tells you to WHICH file.
    In a real SIEM, you correlate them by the audit serial number in msg=audit(ts:serial).
    """
    LOG_TYPE = "file_audit"

    SYSCALL_NAMES = {
        "2": "open", "3": "close", "59": "execve", "82": "rename",
        "83": "mkdir", "84": "rmdir", "87": "unlink", "90": "chmod",
        "92": "chown", "257": "openat", "263": "unlinkat",
    }

    SENSITIVE_PATHS = [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/.ssh/",
        "id_rsa", ".bash_history", "/var/log/auth",
    ]

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        if raw_line.startswith("type=PATH"):
            return self._parse_path(raw_line)

        if raw_line.startswith("type=SYSCALL"):
            return self._parse_syscall(raw_line)

        return None

    def _parse_path(self, raw_line: str) -> Optional[dict]:
        ep_m  = re.search(r"msg=audit\(([\.\d]+):", raw_line)
        # Match name= with quoted OR unquoted value
        nm_m  = re.search(r"name=(?:\"([^\"]+)\"|([^\s]+))", raw_line)
        if not nm_m:
            return None

        path = nm_m.group(1) or nm_m.group(2)
        if not path:
            return None

        ts   = self._e2ts(ep_m.group(1) if ep_m else "0")
        sens = any(s in path for s in self.SENSITIVE_PATHS)

        return {
            "raw":       raw_line,
            "timestamp": ts,
            "action":    "file_access",
            "severity":  "high" if sens else "info",
            "message":   "File access: " + path + (" [SENSITIVE]" if sens else ""),
            "extra":     {"file_path": path, "sensitive": sens},
        }

    def _parse_syscall(self, raw_line: str) -> Optional[dict]:
        ep_m  = re.search(r"msg=audit\(([\.\d]+):", raw_line)
        sc_m  = re.search(r"\bsyscall=(\d+)", raw_line)
        # Match exe= with quoted OR unquoted value
        exe_m = re.search(r"exe=(?:\"([^\"]+)\"|([^\s]+))", raw_line)
        # Match key= with quoted OR unquoted value
        key_m = re.search(r"key=(?:\"([^\"]+)\"|([^\s]+))", raw_line)
        com_m = re.search(r"comm=(?:\"([^\"]+)\"|([^\s]+))", raw_line)

        sc  = self.SYSCALL_NAMES.get(sc_m.group(1) if sc_m else "", "unknown")
        exe = ""
        if exe_m:
            exe = exe_m.group(1) or exe_m.group(2) or ""
        if not exe and com_m:
            exe = com_m.group(1) or com_m.group(2) or ""

        key = ""
        if key_m:
            key = key_m.group(1) or key_m.group(2) or ""

        ts = self._e2ts(ep_m.group(1) if ep_m else "0")

        return {
            "raw":       raw_line,
            "timestamp": ts,
            "action":    "file_" + sc,
            "severity":  "medium" if key else "info",
            "message":   "Audit syscall=" + sc + " exe=" + exe + (" key=" + key if key else ""),
            "extra": {k: v for k, v in {
                "syscall":    sc,
                "exe":        exe or None,
                "audit_key":  key or None,
            }.items() if v is not None},
        }

    def _e2ts(self, epoch_str: str) -> str:
        try:
            ts = datetime.datetime.utcfromtimestamp(float(epoch_str))
            return ts.strftime("%Y-%m-%dT%H:%M:%S.") + str(ts.microsecond // 1000).zfill(3) + "Z"
        except Exception:
            return epoch_str
