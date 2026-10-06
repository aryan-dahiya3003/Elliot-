"""
capture/linux_capture.py
========================
Parser for Linux system and authentication logs.

WHAT IS A LINUX AUTH LOG?
--------------------------
Linux systems write security-relevant events to /var/log/auth.log (Debian/Ubuntu)
or /var/log/secure (RHEL/CentOS). This includes SSH logins, sudo commands,
su attempts, and PAM (Pluggable Authentication Module) events.

WHY IT MATTERS FOR SECURITY (SIEM):
- Detect SSH brute force attacks (many "Failed password" events)
- Detect successful logins from unexpected IPs (lateral movement)
- Detect privilege escalation via sudo
- Detect user account creation/deletion

RAW FORMAT (syslog):
  Jan 15 10:23:45 webserver01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2
  Jan 15 10:23:50 webserver01 sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash

FIELDS WE EXTRACT:
  timestamp, hostname, process, pid, user, source_ip, source_port, action, message
"""

import re
from typing import Optional
from capture.base_capture import BaseCapture


class LinuxCapture(BaseCapture):
    LOG_TYPE = "linux"

    # sshd: Failed password for root from 1.2.3.4 port 22 ssh2
    SSH_FAIL = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+(?P<hostname>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+Failed\s+password\s+for\s+(?:invalid user\s+)?'
        r'(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<src_port>\d+)'
    )

    # sshd: Accepted password/publickey for john from 1.2.3.4 port 22
    SSH_SUCCESS = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+(?P<hostname>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+Accepted\s+(?P<auth_method>\w+)\s+for\s+'
        r'(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<src_port>\d+)'
    )

    # sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash
    SUDO_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+(?P<hostname>\S+)\s+'
        r'sudo:\s+(?P<user>\S+)\s+:.*?USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)'
    )

    # generic syslog fallback
    SYSLOG_GENERIC = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)'
    )

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # SSH Failed login
        m = self.SSH_FAIL.search(raw_line)
        if m:
            g = m.groupdict()
            return {
                "raw":        raw_line,
                "timestamp":  g["timestamp"],
                "hostname":   g["hostname"],
                "user":       g["user"],
                "source_ip":  g["src_ip"],
                "source_port": int(g["src_port"]),
                "action":     "block",
                "protocol":   "SSH",
                "message":    f"SSH login FAILED for '{g['user']}' from {g['src_ip']}",
                "severity":   "medium",
                "extra":      {"process": "sshd", "pid": g["pid"]},
            }

        # SSH Successful login
        m = self.SSH_SUCCESS.search(raw_line)
        if m:
            g = m.groupdict()
            return {
                "raw":        raw_line,
                "timestamp":  g["timestamp"],
                "hostname":   g["hostname"],
                "user":       g["user"],
                "source_ip":  g["src_ip"],
                "source_port": int(g["src_port"]),
                "action":     "allow",
                "protocol":   "SSH",
                "message":    f"SSH login SUCCESS for '{g['user']}' from {g['src_ip']} via {g['auth_method']}",
                "severity":   "info",
                "extra":      {"process": "sshd", "pid": g["pid"], "auth_method": g["auth_method"]},
            }

        # sudo usage
        m = self.SUDO_PATTERN.search(raw_line)
        if m:
            g = m.groupdict()
            return {
                "raw":       raw_line,
                "timestamp": g["timestamp"],
                "hostname":  g["hostname"],
                "user":      g["user"],
                "action":    "privilege_escalation",
                "message":   f"sudo: '{g['user']}' ran as {g['target_user']}: {g['command'].strip()}",
                "severity":  "medium",
                "extra":     {"process": "sudo", "target_user": g["target_user"], "command": g["command"].strip()},
            }

        # Generic syslog fallback
        m = self.SYSLOG_GENERIC.search(raw_line)
        if m:
            g = m.groupdict()
            return {
                "raw":       raw_line,
                "timestamp": g["timestamp"],
                "hostname":  g["hostname"],
                "action":    "event",
                "message":   g["message"][:200],
                "severity":  "info",
                "extra":     {"process": g["process"], "pid": g.get("pid")},
            }

        return None
