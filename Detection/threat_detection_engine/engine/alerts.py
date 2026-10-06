"""Alert system: builds alerts, de-duplicates, filters by severity, sends to handlers."""
import json, os, uuid
from datetime import datetime, timezone
from engine.rules import SEVERITIES

COLORS = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[91m", "critical": "\033[95;1m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def build_alert(rule, group, ts, evidence, evidence_limit=5):
    clean = [{k: v for k, v in e.items() if not k.startswith("_")}
             for e in evidence[-evidence_limit:]]
    return {
        "alert_id": uuid.uuid4().hex[:8],
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "description": rule.get("description", "").strip(),
        "mitre": rule.get("mitre", []),
        "recommendation": rule.get("recommendation", "").strip(),
        "group": group,
        "event_time": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
        "evidence_count": len(evidence),
        "evidence": clean,
    }


class ConsoleHandler:
    def __init__(self, color=True):
        self.color = color

    def handle(self, a):
        c = COLORS[a["severity"]] if self.color else ""
        r = RESET if self.color else ""
        b = BOLD if self.color else ""
        d = DIM if self.color else ""
        grp = ", ".join(f"{k}={v}" for k, v in a["group"].items()) or "global"
        print(f"{c}[{a['severity'].upper():8}]{r} {b}{a['rule_id']}{r} {a['rule_name']}")
        print(f"   time: {a['event_time']}   id: {a['alert_id']}   who/what: {grp}")
        if a["description"]:
            print(f"   {d}{a['description']}{r}")
        if a["mitre"]:
            print(f"   MITRE: {', '.join(a['mitre'])}   events: {a['evidence_count']}")
        if a["recommendation"]:
            print(f"   -> {a['recommendation']}")
        print()


class JsonFileHandler:
    def __init__(self, path, append=False):
        """append=True is used in live mode so a restart does not erase old alerts."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.fh = open(path, "a" if append else "w", encoding="utf-8")

    def handle(self, a):
        self.fh.write(json.dumps(a, default=str) + "\n")
        self.fh.flush()

    def close(self):
        self.fh.close()


class AlertManager:
    def __init__(self, cfg, handlers):
        ms = cfg.get("min_severity", "low")
        if ms not in SEVERITIES:
            raise ValueError(f"alerts.min_severity must be one of {SEVERITIES}, got '{ms}'")
        self.min_idx = SEVERITIES.index(ms)
        self.dedupe = cfg.get("dedupe_seconds", 120)
        self.limit = cfg.get("evidence_limit", 5)
        self.handlers = handlers
        self.last = {}
        self.count = {s: 0 for s in SEVERITIES}
        self.by_rule = {}
        self.suppressed = 0
        self.alerts = []

    def raise_alert(self, rule, group, ts, evidence):
        if SEVERITIES.index(rule["severity"]) < self.min_idx:
            return None
        key = (rule["id"], tuple(sorted(group.items())))
        if key in self.last and ts - self.last[key] < self.dedupe:
            self.suppressed += 1
            return None
        self.last[key] = ts
        alert = build_alert(rule, group, ts, evidence, self.limit)
        self.alerts.append(alert)
        self.count[rule["severity"]] += 1
        self.by_rule[rule["id"]] = self.by_rule.get(rule["id"], 0) + 1
        for h in self.handlers:
            h.handle(alert)
        return alert

    def prune(self, ts):
        """Drop dedupe memory that has already expired."""
        for k in [k for k, v in self.last.items() if ts - v >= self.dedupe]:
            del self.last[k]

    def summary(self):
        total = sum(self.count.values())
        lines = ["=" * 60, f"ALERT SUMMARY: {total} alert(s), {self.suppressed} duplicate(s) suppressed"]
        for s in reversed(SEVERITIES):
            lines.append(f"  {s:9}: {self.count[s]}")
        for rid, n in sorted(self.by_rule.items(), key=lambda x: -x[1]):
            lines.append(f"  {rid:10} x{n}")
        lines.append("=" * 60)
        return "\n".join(lines)

    def close(self):
        for h in self.handlers:
            if hasattr(h, "close"):
                h.close()
