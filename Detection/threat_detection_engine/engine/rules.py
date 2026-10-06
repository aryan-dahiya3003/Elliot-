"""Loads and validates YAML rule files, and evaluates rule conditions."""
import os, re, glob
from functools import lru_cache
import yaml

RULE_TYPES = {"match", "threshold", "distinct_count", "sequence"}
SEVERITIES = ["low", "medium", "high", "critical"]


class RuleError(Exception):
    pass


@lru_cache(maxsize=512)
def _rx(pattern):
    return re.compile(pattern, re.IGNORECASE)


def _s(x):
    return "" if x is None else str(x).lower()


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _cmp(a, b, fn):
    a, b = _num(a), _num(b)
    return a is not None and b is not None and fn(a, b)


OPS = {
    "eq": lambda a, b: _s(a) == _s(b),
    "ne": lambda a, b: _s(a) != _s(b),
    "in": lambda a, b: _s(a) in [_s(i) for i in b],
    "nin": lambda a, b: _s(a) not in [_s(i) for i in b],
    "contains": lambda a, b: _s(b) in _s(a),
    "contains_any": lambda a, b: any(_s(i) in _s(a) for i in b),
    "startswith": lambda a, b: _s(a).startswith(_s(b)),
    "endswith": lambda a, b: _s(a).endswith(_s(b)),
    "regex": lambda a, b: a is not None and _rx(b).search(str(a)) is not None,
    "gt": lambda a, b: _cmp(a, b, lambda x, y: x > y),
    "gte": lambda a, b: _cmp(a, b, lambda x, y: x >= y),
    "lt": lambda a, b: _cmp(a, b, lambda x, y: x < y),
    "lte": lambda a, b: _cmp(a, b, lambda x, y: x <= y),
    "exists": lambda a, b: (a is not None) == bool(b),
}


def get_field(event, name):
    """Supports dotted names for nested JSON ('process.name')."""
    if name in event:
        return event[name]
    cur = event
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def match_conditions(event, conditions):
    """All conditions must hold (AND). Key format: 'field' or 'field|operator'."""
    for key, expected in (conditions or {}).items():
        field, _, op = key.partition("|")
        if not op:
            op = "in" if isinstance(expected, list) else "eq"
        actual = get_field(event, field)
        if not OPS[op](actual, expected):
            return False
    return True


def rule_matches(event, rule):
    """log_type filter + 'conditions' (AND) + optional 'any_of' (OR of AND-groups)."""
    lt = rule.get("log_type")
    if lt:
        allowed = lt if isinstance(lt, list) else [lt]
        if event.get("log_type") not in allowed:
            return False
    if not match_conditions(event, rule.get("conditions")):
        return False
    any_of = rule.get("any_of")
    if any_of and not any(match_conditions(event, grp) for grp in any_of):
        return False
    return True


def _validate(rule, src):
    where = f"{src}: rule '{rule.get('id', '?')}'"
    for k in ("id", "name", "severity", "type"):
        if k not in rule:
            raise RuleError(f"{where} missing '{k}'")
    if rule["type"] not in RULE_TYPES:
        raise RuleError(f"{where} bad type '{rule['type']}'")
    if rule["severity"] not in SEVERITIES:
        raise RuleError(f"{where} bad severity '{rule['severity']}'")
    t = rule["type"]
    if t == "threshold" and not {"threshold", "window"} <= rule.keys():
        raise RuleError(f"{where} threshold rules need 'threshold' and 'window'")
    if t == "distinct_count" and not {"field", "threshold", "window"} <= rule.keys():
        raise RuleError(f"{where} distinct_count rules need 'field','threshold','window'")
    if t == "sequence" and not {"steps", "window"} <= rule.keys():
        raise RuleError(f"{where} sequence rules need 'steps' and 'window'")
    for conds in [rule.get("conditions")] + (rule.get("any_of") or []) + \
                 [s.get("conditions") for s in rule.get("steps", [])]:
        for key in (conds or {}):
            op = key.partition("|")[2]
            if op and op not in OPS:
                raise RuleError(f"{where} unknown operator '{op}'")


_LIST_REF = re.compile(r"\$lists\.([A-Za-z0-9_]+)$")


def _resolve(value, lists, where):
    """Replace '$lists.name' with the list defined under 'lists:' in config.yml."""
    if isinstance(value, str):
        m = _LIST_REF.match(value)
        if m:
            if m.group(1) not in lists:
                raise RuleError(f"{where} uses unknown list '$lists.{m.group(1)}' "
                                f"(define it under 'lists:' in config.yml)")
            return list(lists[m.group(1)])
    return value


def _resolve_rule(rule, lists, src):
    where = f"{src}: rule '{rule.get('id', '?')}'"
    groups = [rule.get("conditions")] + list(rule.get("any_of") or []) + \
             [s.get("conditions") for s in rule.get("steps") or []]
    for conds in groups:
        for key in list(conds or {}):
            conds[key] = _resolve(conds[key], lists, where)
    if isinstance(rule.get("group_by"), str):
        rule["group_by"] = [rule["group_by"]]


def load_rules(rules_dir, lists=None):
    """Load + validate every rule. 'lists' = the 'lists:' section of config.yml."""
    lists = lists or {}
    rules, seen = [], set()
    files = sorted(glob.glob(os.path.join(rules_dir, "*.yml")) +
                   glob.glob(os.path.join(rules_dir, "*.yaml")))
    if not files:
        raise RuleError(f"No rule files found in {rules_dir}")
    for fp in files:
        with open(fp, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        for rule in doc.get("rules", []):
            _validate(rule, os.path.basename(fp))
            _resolve_rule(rule, lists, os.path.basename(fp))
            if rule["id"] in seen:
                raise RuleError(f"Duplicate rule id {rule['id']}")
            seen.add(rule["id"])
            if rule.get("enabled", True):
                rule["_file"] = os.path.basename(fp)
                rules.append(rule)
    return rules
