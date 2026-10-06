"""
normalize/normalizer.py
=======================
The Normalizer - the heart of Task 2.

LEARNING NOTE - What normalization does:
-----------------------------------------
Every capture parser returns a dict with DIFFERENT field names because
every log type uses different terminology. The normalizer maps ALL of them
to our COMMON schema defined in schema.py.

Example:
  Firewall parser returns:  {"dest_ip": "8.8.8.8", "dest_port": 443, ...}
  Common schema field name: "destination_ip", "destination_port"

The normalizer handles:
  1. Field renaming   - dest_ip -> destination_ip
  2. Type coercion    - "443" (str) -> 443 (int)
  3. Timestamp normalization - any format -> ISO 8601 UTC
  4. Adding the "raw" field (always kept from parser)
  5. Stripping None/empty fields (clean output)
  6. Validation against the schema
"""

import json
import re
from datetime import datetime, timezone
from typing import Optional
from normalize.schema import validate_normalized_log, VALID_LOG_TYPES, VALID_SEVERITIES


# Maps parser output field names -> normalized schema field names
FIELD_MAP = {
    "dest_ip":     "destination_ip",
    "dst_ip":      "destination_ip",
    "destination": "destination_ip",
    "dest_port":   "destination_port",
    "dst_port":    "destination_port",
    "src_ip":      "source_ip",
    "src_port":    "source_port",
    "proto":       "protocol",
}

# Fields that belong in the normalized schema (kept at top level)
SCHEMA_FIELDS = {
    "timestamp", "log_type", "message", "raw",
    "source_ip", "destination_ip", "source_port", "destination_port",
    "protocol", "action", "event_id", "severity", "user", "hostname", "extra",
}


def normalize(parsed: dict, log_type: str) -> Optional[dict]:
    """
    Convert a parser output dict into a normalized schema-compliant dict.

    Args:
        parsed:   The dict returned by any capture parser.
        log_type: The log type identifier string (e.g. "firewall", "dns").

    Returns:
        A normalized dict matching the schema, or None if input is invalid.
    """
    if parsed is None or not isinstance(parsed, dict):
        return None

    result = {}

    # 1. Always set log_type from the parser class, not from the parsed data
    result["log_type"] = log_type

    # 2. Copy and rename fields
    for key, value in parsed.items():
        if value is None:
            continue
        # Rename known aliases
        normalized_key = FIELD_MAP.get(key, key)
        if normalized_key in SCHEMA_FIELDS:
            result[normalized_key] = value
        else:
            # Unknown field goes into "extra"
            if "extra" not in result:
                result["extra"] = {}
            if key not in ("extra",):  # dont double-nest
                result["extra"][key] = value

    # Merge any "extra" dict from the parser with our accumulated extra
    if "extra" in parsed and isinstance(parsed["extra"], dict):
        if "extra" not in result:
            result["extra"] = {}
        result["extra"].update(parsed["extra"])

    # 3. Normalize timestamp to ISO 8601 UTC
    if "timestamp" in result:
        result["timestamp"] = _normalize_timestamp(str(result["timestamp"]))

    # 4. Validate and coerce types
    if "source_port" in result:
        result["source_port"] = _to_int(result["source_port"])
    if "destination_port" in result:
        result["destination_port"] = _to_int(result["destination_port"])
    if "protocol" in result and isinstance(result["protocol"], str):
        result["protocol"] = result["protocol"].upper()
    if "severity" in result and result["severity"] not in VALID_SEVERITIES:
        result["severity"] = "unknown"
    if "action" in result and isinstance(result["action"], str):
        result["action"] = result["action"].lower()

    # 5. Ensure required fields exist
    if "raw" not in result:
        result["raw"] = json.dumps(parsed)
    if "message" not in result:
        result["message"] = f"[{log_type}] event"
    if "timestamp" not in result:
        result["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # 6. Remove None values and empty extras
    result = {k: v for k, v in result.items() if v is not None}
    if "extra" in result and not result["extra"]:
        del result["extra"]
    # Remove None values inside extra
    if "extra" in result:
        result["extra"] = {k: v for k, v in result["extra"].items() if v is not None}
        if not result["extra"]:
            del result["extra"]

    # 7. Validate
    is_valid, errors = validate_normalized_log(result)
    if not is_valid:
        # Add a warning but still return the result - dont discard data
        if "extra" not in result:
            result["extra"] = {}
        result["extra"]["_validation_errors"] = errors

    return result


def _normalize_timestamp(ts: str) -> str:
    """
    Convert any timestamp string to ISO 8601 UTC format.
    Handles: syslog format, Windows format, epoch, ISO 8601 variants.
    """
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Already ISO 8601
    if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts):
        if not ts.endswith("Z") and "+" not in ts[-6:]:
            ts = ts + "Z"
        return ts

    # Syslog format: "Jan 15 10:23:45" (no year - use current year)
    try:
        year = datetime.now().year
        dt = datetime.strptime(f"{year} {ts.strip()}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        pass

    # Syslog with padding: "Jan  5 10:23:45"
    try:
        year = datetime.now().year
        dt = datetime.strptime(f"{year} {ts.strip()}", "%Y %b  %d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        pass

    # Windows DNS / other: "1/15/2024 10:23:45 AM"
    for fmt in ["%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S %z", "%b %d %Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%Y%m%d%H%M%S"]:
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except ValueError:
            continue

    # Nginx log format: "15/Jan/2024:10:23:45 +0000"
    try:
        m = re.match(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})", ts)
        if m:
            dt = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S")
            return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        pass

    # Unix epoch
    try:
        dt = datetime.utcfromtimestamp(float(ts))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (ValueError, OSError):
        pass

    # Return as-is if nothing worked
    return ts


def _to_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
