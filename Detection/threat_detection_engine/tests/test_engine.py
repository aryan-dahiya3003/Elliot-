"""Run: python -m unittest discover -s tests -v"""
import os, sys, json, tempfile, threading, time, unittest
import yaml
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.rules import load_rules, match_conditions, RuleError
from engine.loader import normalize_event, canon_log_type, parse_ts, read_events, follow_events
from engine.alerts import AlertManager
from engine.detector import Detector

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")
CONFIG = os.path.join(os.path.dirname(__file__), "..", "config.yml")


def load_all():
    """Rules + the environment lists from config.yml (exactly what main.py does)."""
    with open(CONFIG, encoding="utf-8") as fh:
        return load_rules(RULES_DIR, (yaml.safe_load(fh) or {}).get("lists"))


class Collect:
    def __init__(self): self.items = []
    def handle(self, a): self.items.append(a)


def run(events, dedupe=0):
    sink = Collect()
    det = Detector(load_all(), AlertManager({"dedupe_seconds": dedupe}, [sink]))
    for e in events:
        det.process(normalize_event(e, {}))
    return [a["rule_id"] for a in sink.items]


def ev(t, lt, **f):
    return {"timestamp": 1_700_000_000 + t, "log_type": lt, **f}


class Tests(unittest.TestCase):
    def test_rules_load(self):
        self.assertGreater(len(load_all()), 30)

    def test_operators(self):
        self.assertTrue(match_conditions({"a": "Hello"}, {"a|contains": "ell"}))
        self.assertTrue(match_conditions({"p": 80}, {"p": [80, 443]}))
        self.assertFalse(match_conditions({"n": 5}, {"n|gt": 9}))
        self.assertTrue(match_conditions({}, {"x|exists": False}))

    def test_log_type_normalization(self):
        self.assertEqual(canon_log_type("IDS/IPS"), "ids_ips")
        self.assertEqual(canon_log_type("Network Flow"), "network_flow")

    def test_threshold_fires(self):
        evs = [ev(i, "linux", src_ip="1.1.1.1", message="Failed password") for i in range(6)]
        self.assertIn("LNX-001", run(evs))

    def test_threshold_not_fired_outside_window(self):
        evs = [ev(i * 30, "linux", src_ip="1.1.1.1", message="Failed password") for i in range(6)]
        self.assertNotIn("LNX-001", run(evs))

    def test_distinct_count(self):
        evs = [ev(i, "firewall", src_ip="2.2.2.2", dst_port=i, action="deny") for i in range(16)]
        self.assertIn("FW-001", run(evs))

    def test_sequence(self):
        evs = [ev(i, "authentication", src_ip="3.3.3.3", user="u", status="failure") for i in range(5)]
        evs.append(ev(10, "authentication", src_ip="3.3.3.3", user="u", status="success"))
        self.assertIn("AUTH-003", run(evs))

    def test_benign_no_alert(self):
        self.assertEqual(run([ev(0, "dns", src_ip="1.1.1.1", query="www.google.com", record_type="A")]), [])

    def test_dedupe(self):
        evs = [ev(i, "web_server", src_ip="9.9.9.9", url="/x", user_agent="sqlmap") for i in range(3)]
        self.assertEqual(run(evs, dedupe=120).count("WEB-003"), 1)

    def test_bad_rule_rejected(self):
        import tempfile
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "bad.yml"), "w") as fh:
            fh.write("rules:\n  - {id: X, name: x, severity: nope, type: match}\n")
        with self.assertRaises(RuleError):
            load_rules(d)


    # ------------------------------------------------ timestamp handling
    def test_timestamp_formats(self):
        base = parse_ts("2026-10-04T09:01:40Z")
        self.assertEqual(parse_ts(base), base)                           # epoch seconds
        self.assertEqual(parse_ts(int(base * 1000)), int(base * 1000) / 1000)   # epoch ms
        self.assertEqual(parse_ts(str(int(base))), int(base))            # numeric string
        self.assertEqual(parse_ts(int(base * 1e9)), int(base * 1e9) / 1e9)      # epoch ns
        self.assertEqual(parse_ts("2026-10-04 09:01:40"), base)          # no timezone = UTC
        self.assertEqual(parse_ts("2026-10-04T14:31:40+0530"), base)     # +0530 offset
        self.assertAlmostEqual(parse_ts("2026-10-04T09:01:40.1234567Z"), base + 0.123456, 5)
        self.assertEqual(parse_ts("04/Oct/2026:09:01:40 +0000"), base)   # Apache/Nginx
        self.assertIsNotNone(parse_ts("Oct  4 09:01:40"))                # syslog
        for bad in (None, "", "garbage", True, float("nan"), "2026-13-45T00:00:00Z"):
            self.assertIsNone(parse_ts(bad))

    def test_ms_epoch_event_does_not_crash(self):
        t = 1_759_568_500_000                                            # milliseconds
        evs = [{"timestamp": t + i * 1000, "log_type": "linux", "src_ip": "1.1.1.1",
                "message": "Failed password"} for i in range(6)]
        self.assertIn("LNX-001", run(evs))                               # 60 s window still means 60 s

    # ------------------------------------------------ bad input
    def test_bad_lines_are_skipped_not_fatal(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "mix.jsonl")
        with open(p, "w") as fh:
            fh.write('{"timestamp":"2026-10-04T09:00:00Z","log_type":"dns"}\n')
            for junk in ('GARBAGE', '"just a string"', '123', 'null', '[1,2]', '["ab"]',
                         '{"no_timestamp": 1}', '{"timestamp":"not a time"}', ''):
                fh.write(junk + "\n")
        events, bad = read_events(p, {})
        self.assertEqual(len(events), 1)
        self.assertEqual(bad, 8)

    def test_missing_log_path(self):
        with self.assertRaises(FileNotFoundError):
            read_events("/definitely/not/here.jsonl", {})

    # ------------------------------------------------ grouping
    def test_unhashable_group_value_does_not_crash(self):
        evs = [ev(0, "windows", event_id=1102, host={"name": "h1"}, user="u")]
        self.assertIn("WIN-001", run(evs))

    def test_match_rule_fires_when_group_field_missing(self):
        sink = Collect()
        det = Detector(load_all(), AlertManager({"dedupe_seconds": 0}, [sink]))
        det.process(normalize_event(ev(0, "windows", event_id=1102, host="h"), {}))   # no user
        self.assertEqual([a["rule_id"] for a in sink.items], ["WIN-001"])
        self.assertEqual(sink.items[0]["group"]["user"], "unknown")

    def test_windowed_rule_skips_but_reports_missing_group_field(self):
        sink = Collect()
        det = Detector(load_all(), AlertManager({"dedupe_seconds": 0}, [sink]))
        for i in range(10):                                              # no src_ip at all
            det.process(normalize_event(ev(i, "linux", message="Failed password"), {}))
        self.assertEqual(sink.items, [])
        self.assertEqual(det.skipped["LNX-001"]["src_ip"], 10)
        self.assertIn("LNX-001", det.skipped_report())
        self.assertIn("src_ip", det.skipped_report())

    def test_no_report_when_nothing_skipped(self):
        det = Detector(load_all(), AlertManager({}, []))
        det.process(normalize_event(ev(0, "dns", src_ip="1.1.1.1", query="www.google.com"), {}))
        self.assertEqual(det.skipped_report(), "")

    # ------------------------------------------------ editable lists (config.yml)
    def test_lists_are_applied_to_rules(self):
        lists = {"approved_dhcp_servers": ["10.9.9.9"], "allowed_countries": ["IN"],
                 "bad_domains": ["bad.test"]}
        sink = Collect()
        det = Detector(load_rules(RULES_DIR, lists), AlertManager({"dedupe_seconds": 0}, [sink]))
        for e in (ev(0, "dhcp", action="offer", server_ip="10.9.9.9"),        # approved
                  ev(1, "dhcp", action="offer", server_ip="10.0.0.1"),        # now rogue
                  ev(2, "dns", src_ip="1.1.1.1", query="x.bad.test"),
                  ev(3, "authentication", user="u", status="success", geo_country="US")):
            det.process(normalize_event(e, {}))
        self.assertEqual(sorted(a["rule_id"] for a in sink.items), ["AUTH-004", "DHCP-001", "DNS-003"])
        self.assertEqual(sum(a["rule_id"] == "DHCP-001" for a in sink.items), 1)

    def test_unknown_list_reference_rejected(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "r.yml"), "w") as fh:
            fh.write("rules:\n  - id: X\n    name: x\n    severity: low\n    type: match\n"
                     "    conditions: {user|in: $lists.nope}\n")
        with self.assertRaises(RuleError):
            load_rules(d, {})

    # ------------------------------------------------ memory (live mode)
    def test_idle_state_is_pruned(self):
        det = Detector(load_all(), AlertManager({"dedupe_seconds": 10}, []))
        det.PRUNE_EVERY = 50
        for i in range(49):                                              # 49 different attackers
            det.process(normalize_event(ev(i, "firewall", src_ip=f"9.9.9.{i}", dst_port=i,
                                           action="deny"), {}))
        self.assertGreater(len(det.windows), 40)
        det.process(normalize_event(ev(10_000, "dns", src_ip="1.1.1.1", query="a.com"), {}))   # 50th event
        self.assertEqual(len(det.windows), 0)

    # ------------------------------------------------ live (tail) mode
    def test_follow_handles_partial_lines_bad_lines_and_rotation(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "live.jsonl")
        open(p, "w").close()
        got, stats, stop = [], {}, threading.Event()

        def reader():
            for e in follow_events(p, {}, poll=0.02, should_stop=stop.is_set, stats=stats):
                got.append(e["message"])
        th = threading.Thread(target=reader)
        th.start()

        def line(m):
            return json.dumps({"timestamp": 1_700_000_000, "log_type": "linux", "message": m})

        def wait_for(n):
            for _ in range(200):
                if len(got) >= n:
                    return
                time.sleep(0.02)
        time.sleep(0.15)
        with open(p, "a") as fh:
            fh.write(line("one") + "\n")
            fh.write("NOT JSON\n")
            half = line("two")
            fh.write(half[:20]); fh.flush()                              # half-written line
            time.sleep(0.15)
            fh.write(half[20:] + "\n")
        wait_for(2)
        with open(p, "w") as fh:                                         # rotation: file truncated
            fh.write(line("three") + "\n")
        wait_for(3)
        stop.set(); th.join(5)
        self.assertEqual(got, ["one", "two", "three"])
        self.assertEqual(stats.get("bad"), 1)


if __name__ == "__main__":
    unittest.main()
