"""
normalize/schema.py
===================
The unified JSON schema that ALL 12 log types normalize to.

LEARNING NOTE:
--------------
Normalization = making unlike things look alike.

A firewall log:   "SRC=1.2.3.4 DST=8.8.8.8 PROTO=TCP DPT=443 ACTION=BLOCK"
A Windows Event:  "<EventID>4625</EventID> <IpAddress>1.2.3.4</IpAddress>"

After normalization, both become:
  {"source_ip": "1.2.3.4", "log_type": "firewall", "action": "block", ...}
  {"source_ip": "1.2.3.4", "log_type": "windows", "event_id": "4625", ...}

This unified shape lets detection engineers write ONE rule that works
across all log sources.
"""

# Valid log type identifiers
VALID_LOG_TYPES = {
    "firewall", "dns", "dhcp", "linux", "windows",
    "authentication", "webserver", "application",
    "netflow", "ids_ips", "file_audit", "edr",
}

# Valid severity levels
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}

# JSON Schema for validation
NORMALIZED_LOG_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "NormalizedSIEMLog",
    "type": "object",
    "required": ["timestamp", "log_type", "message", "raw"],
    "additionalProperties": False,
    "properties": {
        "timestamp":        {"type": "string"},
        "log_type":         {"type": "string", "enum": list(VALID_LOG_TYPES)},
        "message":          {"type": "string"},
        "raw":              {"type": "string"},
        "source_ip":        {"type": "string"},
        "destination_ip":   {"type": "string"},
        "source_port":      {"type": "integer", "minimum": 0, "maximum": 65535},
        "destination_port": {"type": "integer", "minimum": 0, "maximum": 65535},
        "protocol":         {"type": "string"},
        "action":           {"type": "string"},
        "event_id":         {"type": "string"},
        "severity":         {"type": "string", "enum": list(VALID_SEVERITIES)},
        "user":             {"type": "string"},
        "hostname":         {"type": "string"},
        "extra":            {"type": "object", "additionalProperties": True},
    }
}


def validate_normalized_log(log: dict) -> tuple:
    """
    Validate a normalized log dict against the schema.
    Returns (is_valid: bool, errors: list[str])
    """
    try:
        import jsonschema
        validator = jsonschema.Draft7Validator(NORMALIZED_LOG_SCHEMA)
        errors = [e.message for e in validator.iter_errors(log)]
        return (len(errors) == 0), errors
    except ImportError:
        required = ["timestamp", "log_type", "message", "raw"]
        missing = [f for f in required if f not in log]
        if missing:
            return False, [f"Missing required fields: {missing}"]
        if log.get("log_type") not in VALID_LOG_TYPES:
            return False, [f"Invalid log_type: {log.get('log_type')}"]
        return True, []
