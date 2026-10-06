"""
capture/auth_capture.py
=======================
Parser for Authentication logs (Okta/JSON style + generic auth).

WHAT ARE AUTHENTICATION LOGS?
------------------------------
Authentication logs come from identity providers (IdPs) like Okta, Azure AD,
or any SSO system. They record every login attempt: success, failure, MFA, etc.

WHY IT MATTERS FOR SECURITY (SIEM):
- Detect credential stuffing attacks (many failures from different IPs)
- Detect account takeover (successful login from new country/device)
- Detect MFA bypass attempts
- Detect impossible travel (login from NY then Tokyo 10 min later)

RAW FORMAT (Okta-style JSON):
  {"timestamp":"2024-01-15T10:23:45Z","eventType":"user.session.start",
   "outcome":{"result":"FAILURE","reason":"INVALID_CREDENTIALS"},
   "actor":{"login":"john@corp.com"},"client":{"ipAddress":"192.168.1.5"}}

FIELDS WE EXTRACT:
  timestamp, user (email/username), source_ip, action (success/failure),
  event_type, reason, user_agent
"""

import json
import re
from typing import Optional
from capture.base_capture import BaseCapture


class AuthCapture(BaseCapture):
    LOG_TYPE = "authentication"

    # Generic auth.log pattern (Linux PAM / non-SSH)
    # Jan 15 10:23:45 server01 login[1234]: FAILED LOGIN (1) on 'tty1' FOR 'root'
    GENERIC_AUTH = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<message>.+)'
    )

    OUTCOME_ACTION = {
        "SUCCESS": "allow",
        "FAILURE": "block",
        "SKIPPED": "skip",
        "ALLOW":   "allow",
        "DENY":    "block",
    }

    def parse(self, raw_line: str) -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # Try JSON first (Okta, Azure AD, custom app)
        if raw_line.startswith("{"):
            return self._parse_json(raw_line)

        # Fallback: generic auth syslog
        return self._parse_generic(raw_line)

    def _parse_json(self, raw_line: str) -> Optional[dict]:
        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError:
            return None

        # Okta-style
        ts         = data.get("timestamp", data.get("time", data.get("created", "")))
        event_type = data.get("eventType", data.get("event_type", data.get("type", "")))
        actor      = data.get("actor", {})
        user       = actor.get("login", actor.get("email", actor.get("id", "")))
        client     = data.get("client", {})
        src_ip     = client.get("ipAddress", client.get("ip", data.get("ip", "")))
        outcome    = data.get("outcome", {})
        if isinstance(outcome, dict):
            result = outcome.get("result", "UNKNOWN").upper()
            reason = outcome.get("reason", "")
        else:
            result = str(outcome).upper()
            reason = ""
        action   = self.OUTCOME_ACTION.get(result, "event")
        severity = "high" if action == "block" else "info"

        return {k: v for k, v in {
            "raw":       raw_line,
            "timestamp": ts,
            "user":      user or None,
            "source_ip": src_ip or None,
            "action":    action,
            "event_id":  event_type or None,
            "message":   f"Auth {result} for {user or 'unknown'} from {src_ip or 'unknown'}" +
                         (f" ({reason})" if reason else ""),
            "severity":  severity,
            "extra": {k: v for k, v in {
                "event_type":    event_type or None,
                "outcome":       result,
                "reason":        reason or None,
                "user_agent":    client.get("userAgent", {}).get("rawUserAgent") if isinstance(client.get("userAgent"), dict) else None,
                "geo_country":   client.get("geographicalContext", {}).get("country") if isinstance(client.get("geographicalContext"), dict) else None,
            }.items() if v},
        }.items() if v is not None and v != {}}

    def _parse_generic(self, raw_line: str) -> Optional[dict]:
        m = self.GENERIC_AUTH.search(raw_line)
        if not m:
            return None
        g = m.groupdict()
        msg = g["message"]
        # Determine success/failure from message text
        if any(w in msg.upper() for w in ["FAIL", "INVALID", "DENIED", "WRONG"]):
            action, severity = "block", "medium"
        elif any(w in msg.upper() for w in ["SUCCESS", "ACCEPTED", "OPENED SESSION"]):
            action, severity = "allow", "info"
        else:
            action, severity = "event", "info"
        return {
            "raw":       raw_line,
            "timestamp": g["timestamp"],
            "hostname":  g["hostname"],
            "action":    action,
            "message":   f"Auth event [{g['process']}]: {msg[:150]}",
            "severity":  severity,
            "extra":     {"process": g["process"]},
        }
