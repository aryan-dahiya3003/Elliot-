"""
capture/webserver_capture.py
============================
Parser for Web Server access logs (Apache/Nginx Combined Log Format).

WHAT IS A WEB SERVER LOG?
--------------------------
Web servers log every HTTP request they receive. The most common format is
the "Combined Log Format" used by both Apache and Nginx.

WHY IT MATTERS FOR SECURITY (SIEM):
- Detect web attacks: SQL injection, XSS, path traversal, command injection
- Detect vulnerability scanning (tools like sqlmap, nikto, gobuster)
- Detect brute force on login endpoints (many POST /login with 401 responses)
- Detect data exfiltration (large response sizes from unexpected endpoints)
- Detect bot traffic (suspicious User-Agent strings)

RAW FORMAT (Nginx/Apache Combined Log):
  192.168.1.5 - - [15/Jan/2024:10:23:45 +0000] "GET /admin/../etc/passwd HTTP/1.1" 404 512 "-" "sqlmap/1.0"

FIELDS:
  client_ip, ident, auth_user, timestamp, method, path, http_version,
  status_code, response_bytes, referer, user_agent
"""

import re
from typing import Optional
from capture.base_capture import BaseCapture


class WebServerCapture(BaseCapture):
    LOG_TYPE = "webserver"

    # Combined Log Format:
    # IP - user [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD /path HTTP/x.x" STATUS BYTES "referer" "ua"
    COMBINED_LOG = re.compile(
        r'(?P<src_ip>[\d.]+)\s+-\s+(?P<auth_user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>.+?)\s+HTTP/(?P<http_ver>[\d.]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )

    # Known attack patterns in URL/User-Agent
    ATTACK_PATTERNS = [
        (re.compile(r"(?:union\s+select|union%20select|select\s+.*from|insert\s+into|drop\s+table)", re.I), "sql_injection"),
        (re.compile(r"(?:<script|javascript:|onerror=|onload=)", re.I),                     "xss"),
        (re.compile(r"(?:\.\./|%2e%2e%2f|%252e%252e)", re.I),                              "path_traversal"),
        (re.compile(r"(?:;ls|;id|;cat\s|&&\s*id|`id`|`whoami`)", re.I),                    "command_injection"),
        (re.compile(r"(?:sqlmap|nikto|nmap|masscan|gobuster|dirsearch|burpsuite)", re.I),   "scanner"),
        (re.compile(r"(?:/etc/passwd|/etc/shadow|/proc/self)", re.I),                       "lfi"),
        (re.compile(r"(?:cmd\.exe|powershell|wget\s+http|curl\s+http)", re.I),              "webshell"),
    ]

    STATUS_SEVERITY = {
        "2": "info",     # 2xx success
        "3": "info",     # 3xx redirect
        "4": "low",      # 4xx client error
        "5": "medium",   # 5xx server error
    }

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        m = self.COMBINED_LOG.match(raw_line)
        if not m:
            return None

        g = m.groupdict()
        method   = g["method"]
        path     = g["path"]
        status   = g["status"]
        ua       = g["user_agent"]
        src_ip   = g["src_ip"]
        bytes_   = int(g["bytes"]) if g["bytes"] != "-" else 0

        # Detect attacks
        attack_type = None
        full_url_ua = path + " " + ua
        for pattern, atype in self.ATTACK_PATTERNS:
            if pattern.search(full_url_ua):
                attack_type = atype
                break

        severity = "high" if attack_type else self.STATUS_SEVERITY.get(status[0], "info")
        action   = "detect" if attack_type else ("allow" if status.startswith("2") else "event")

        return {
            "raw":       raw_line,
            "timestamp": g["timestamp"],
            "source_ip": src_ip,
            "action":    action,
            "message":   f"HTTP {method} {path[:80]} -> {status}" +
                         (f" [ATTACK:{attack_type}]" if attack_type else ""),
            "severity":  severity,
            "extra": {k: v for k, v in {
                "http_method":  method,
                "url_path":     path[:200],
                "http_status":  int(status),
                "response_bytes": bytes_,
                "user_agent":   ua[:200],
                "referer":      g["referer"] if g["referer"] != "-" else None,
                "attack_type":  attack_type,
                "http_version": g["http_ver"],
                "auth_user":    g["auth_user"] if g["auth_user"] != "-" else None,
            }.items() if v is not None},
        }
