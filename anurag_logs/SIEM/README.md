# SIEM Log Capture & Normalization

A Python pipeline that parses 12 types of raw security logs and normalizes them into a unified JSON schema.

## Project Structure
```
SIEM/
├── capture/          # 12 log parsers (one per log type)
├── normalize/        # Normalization layer → unified JSON
├── samples/          # Raw log files for testing
├── tests/            # Unit tests
└── main.py           # Entry point
```

## Quick Start
```bash
pip install -r requirements.txt
python main.py
```
Output: `normalized_logs.jsonl` — one JSON object per line, ready for the next pipeline stage.

## Log Types Supported
| # | Type | Parser File |
|---|------|-------------|
| 1 | Firewall | capture/firewall_capture.py |
| 2 | DNS | capture/dns_capture.py |
| 3 | DHCP | capture/dhcp_capture.py |
| 4 | Linux/SSH | capture/linux_capture.py |
| 5 | Windows Events | capture/windows_capture.py |
| 6 | Authentication | capture/auth_capture.py |
| 7 | Web Server | capture/webserver_capture.py |
| 8 | Application | capture/application_capture.py |
| 9 | Network Flow | capture/netflow_capture.py |
| 10 | IDS/IPS | capture/ids_capture.py |
| 11 | File/Audit | capture/file_audit_capture.py |
| 12 | Endpoint/EDR | capture/edr_capture.py |

## Output Schema
Every normalized event has these fields:
- `timestamp` — ISO 8601 UTC
- `log_type` — one of the 12 type identifiers
- `message` — human-readable description
- `raw` — original log line unchanged
- Optional: `source_ip`, `destination_ip`, `source_port`, `destination_port`,
  `protocol`, `action`, `user`, `hostname`, `event_id`, `severity`, `extra`
