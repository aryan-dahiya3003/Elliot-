"""Core detection logic. Streaming: feed events one by one via process()."""
import json
from collections import deque, defaultdict
from engine.rules import rule_matches, match_conditions, get_field

UNKNOWN = "unknown"


class Detector:
    PRUNE_EVERY = 2000          # events between memory clean-ups (important in live mode)

    def __init__(self, rules, alert_manager):
        self.rules = rules
        self.alerts = alert_manager
        self.windows = defaultdict(deque)   # (rule_id, group) -> deque[(ts, value, event)]
        self.seq = {}                       # (rule_id, group) -> progress dict
        self.events_seen = 0
        # rule_id -> {missing field -> count}: events a rule could not group (shown in summary)
        self.skipped = defaultdict(lambda: defaultdict(int))
        self._win = {r["id"]: r["window"] for r in rules if "window" in r}

    # ---------------------------------------------------------------- grouping
    @staticmethod
    def _hashable(v):
        """Dict/list field values cannot be dict keys; turn them into stable text."""
        if isinstance(v, (dict, list, set)):
            return json.dumps(v, sort_keys=True, default=str)
        return v

    def _group(self, event, rule, fill_missing):
        """Return (group_dict_or_None, missing_fields).
        fill_missing=True : missing fields become 'unknown' (used by match rules).
        fill_missing=False: any missing field -> group None (counting would be wrong)."""
        out, missing = {}, []
        for f in rule.get("group_by") or []:
            v = get_field(event, f)
            if v is None:
                missing.append(f)
                out[f] = UNKNOWN
            else:
                out[f] = self._hashable(v)
        if missing and not fill_missing:
            return None, missing
        return out, missing

    def _note_skip(self, rule, missing):
        for f in missing:
            self.skipped[rule["id"]][f] += 1

    def skipped_report(self):
        """Text for the end-of-run summary; empty string if nothing was skipped."""
        if not self.skipped:
            return ""
        lines = ["NOTE: some events matched a rule but could not be counted because a",
                 "      'group_by' field was missing (check your log field names):"]
        for rid, fields in sorted(self.skipped.items()):
            detail = ", ".join(f"{f} x{n}" for f, n in sorted(fields.items()))
            lines.append(f"  {rid:10} missing {detail}")
        return "\n".join(lines)

    # -------------------------------------------------------------- processing
    def process(self, event):
        self.events_seen += 1
        ts = event["_ts"]
        for rule in self.rules:
            t = rule["type"]
            if t == "sequence":
                self._sequence(rule, event, ts)
                continue
            if not rule_matches(event, rule):
                continue
            group, missing = self._group(event, rule, fill_missing=(t == "match"))
            if group is None:
                self._note_skip(rule, missing)
                continue
            if t == "match":
                self.alerts.raise_alert(rule, group, ts, [event])
            else:
                self._windowed(rule, event, ts, group)
        if self.events_seen % self.PRUNE_EVERY == 0:
            self._prune(ts)

    def _windowed(self, rule, event, ts, group):
        key = (rule["id"], tuple(group.items()))
        dq = self.windows[key]
        value = get_field(event, rule["field"]) if rule["type"] == "distinct_count" else None
        dq.append((ts, self._hashable(value), event))
        while dq and ts - dq[0][0] > rule["window"]:
            dq.popleft()
        if rule["type"] == "threshold":
            hit = len(dq) >= rule["threshold"]
        else:
            hit = len({v for _, v, _ in dq if v is not None}) >= rule["threshold"]
        if hit:
            fired = self.alerts.raise_alert(rule, group, ts, [e for _, _, e in dq])
            if fired is not None:
                dq.clear()   # start fresh after an alert

    def _sequence(self, rule, event, ts):
        lt = rule.get("log_type")
        if lt and event.get("log_type") not in (lt if isinstance(lt, list) else [lt]):
            return
        group, missing = self._group(event, rule, fill_missing=False)
        if group is None:
            if any(match_conditions(event, s.get("conditions")) for s in rule["steps"]):
                self._note_skip(rule, missing)
            return
        key = (rule["id"], tuple(group.items()))
        st = self.seq.setdefault(key, {"idx": 0, "count": 0, "start": None, "ev": []})
        if st["start"] is not None and ts - st["start"] > rule["window"]:
            st.update(idx=0, count=0, start=None, ev=[])
        step = rule["steps"][st["idx"]]
        if not match_conditions(event, step.get("conditions")):
            return
        if st["start"] is None:
            st["start"] = ts
        st["count"] += 1
        st["ev"].append(event)
        if st["count"] >= step.get("count", 1):
            st["idx"] += 1
            st["count"] = 0
            if st["idx"] == len(rule["steps"]):
                self.alerts.raise_alert(rule, group, ts, st["ev"])
                st.update(idx=0, count=0, start=None, ev=[])

    def _prune(self, ts):
        """Forget idle groups so a long-running live process does not grow forever."""
        for key in [k for k, dq in self.windows.items()
                    if not dq or ts - dq[-1][0] > self._win.get(k[0], 0)]:
            del self.windows[key]
        for key in [k for k, st in self.seq.items()
                    if st["start"] is None or ts - st["start"] > self._win.get(k[0], 0)]:
            del self.seq[key]
        self.alerts.prune(ts)
