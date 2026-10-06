"""
capture/application_capture.py
==============================
Parser for Application logs (structured JSON / common log frameworks).

WHAT IS AN APPLICATION LOG?
----------------------------
Applications (APIs, microservices, web apps) generate logs about what they
are doing — errors, transactions, user actions, business events.
Modern apps log in structured JSON (using frameworks like structlog, winston,
log4j, zerolog). Older apps use plaintext with varying formats.

WHY IT MATTERS FOR SECURITY (SIEM):
- Detect application-layer attacks (SQLi in query parameters)
- Detect API abuse (rate-limited endpoints hammered by one user)
- Detect privilege abuse (admin functions called by non-admin)
- Detect data exfiltration (bulk data exports by a user)
- Detect authentication bypass (accessing protected routes without auth)

RAW FORMAT (Structured JSON from a Python/Node app):
  {"time":"2024-01-15T10:23:45Z","level":"ERROR","service":"payment-api",
   "msg":"SQL error","user":"guest","query":"1 OR 1=1"}

FIELDS WE EXTRACT:
  timestamp, level (severity), service, message, user, error details
"""

import json
import re
from typing import Optional
from capture.base_capture import BaseCapture


class ApplicationCapture(BaseCapture):
    LOG_TYPE = "application"

    LEVEL_SEVERITY = {
        "TRACE":    "info",
        "DEBUG":    "info",
        "INFO":     "info",
        "WARNING":  "low",
        "WARN":     "low",
        "ERROR":    "medium",
        "CRITICAL": "high",
        "FATAL":    "critical",
        "EMERGENCY":"critical",
    }

    # Generic text log: [2024-01-15 10:23:45] ERROR service: message
    TEXT_PATTERN = re.compile(
        r'(?:\[(?P<timestamp>[^\]]+)\]|(?P<ts2>[\d\-T:.Z+]+))\s+'
        r'(?P<level>TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|EMERGENCY)\s+'
        r'(?:(?P<service>\S+):\s+)?(?P<message>.+)'
    )

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        if raw_line.startswith("{"):
            return self._parse_json(raw_line)
        return self._parse_text(raw_line)

    def _parse_json(self, raw_line: str) -> Optional[dict]:
        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError:
            return None

        # Normalize common field names across different logging frameworks
        ts      = data.get("time", data.get("timestamp", data.get("@timestamp", data.get("t", ""))))
        level   = str(data.get("level", data.get("severity", data.get("lvl", "INFO")))).upper()
        msg     = data.get("msg", data.get("message", data.get("log", "")))
        service = data.get("service", data.get("app", data.get("logger", "")))
        user    = data.get("user", data.get("username", data.get("user_id", "")))
        src_ip  = data.get("ip", data.get("client_ip", data.get("remote_addr", "")))
        error   = data.get("error", data.get("err", data.get("exception", "")))

        severity = self.LEVEL_SEVERITY.get(level, "info")
        return {k: v for k, v in {
            "raw":       raw_line,
            "timestamp": ts or None,
            "user":      str(user) if user else None,
            "source_ip": src_ip or None,
            "action":    "error" if level in ("ERROR", "CRITICAL", "FATAL") else "event",
            "message":   f"[{service or 'app'}] {level}: {str(msg)[:200]}",
            "severity":  severity,
            "extra": {k: v for k, v in {
                "log_level": level,
                "service":   service or None,
                "error":     str(error)[:300] if error else None,
            }.items() if v},
        }.items() if v is not None and v != {}}

    def _parse_text(self, raw_line: str) -> Optional[dict]:
        m = self.TEXT_PATTERN.search(raw_line)
        if not m:
            return None
        g = m.groupdict()
        ts      = g.get("timestamp") or g.get("ts2") or ""
        level   = g.get("level", "INFO").upper()
        service = g.get("service", "")
        msg     = g.get("message", "")[:200]
        severity = self.LEVEL_SEVERITY.get(level, "info")
        return {
            "raw":       raw_line,
            "timestamp": ts or None,
            "action":    "error" if level in ("ERROR", "CRITICAL", "FATAL") else "event",
            "message":   f"[{service or 'app'}] {level}: {msg}",
            "severity":  severity,
            "extra":     {"log_level": level, "service": service or None},
        }
