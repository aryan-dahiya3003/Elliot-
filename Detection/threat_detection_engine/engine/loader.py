"""Reads normalized logs (JSON Lines) and makes them uniform for the rules."""
import json, math, re, os, time
from datetime import datetime, timezone


def canon_log_type(value):
    """'IDS/IPS' -> 'ids_ips', 'Network Flow' -> 'network_flow'."""
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


# ---------------------------------------------------------------- timestamps
_NUMBER = re.compile(r"[+-]?\d+(\.\d+)?")
_ISO = re.compile(
    r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}(?::?\d{2})?)?$",
    re.IGNORECASE)
# other layouts seen in real logs (Apache/Nginx, RFC-2822, slashes)
_FORMATS = ["%d/%b/%Y:%H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %z",
            "%Y/%m/%d %H:%M:%S", "%d %b %Y %H:%M:%S"]


def _epoch(x):
    """Epoch number -> seconds. Detects seconds / milliseconds / microseconds / nanoseconds."""
    if not math.isfinite(x):
        return None
    a = abs(x)
    if a >= 1e17:
        return x / 1e9
    if a >= 1e14:
        return x / 1e6
    if a >= 1e11:
        return x / 1e3
    return x


def _as_utc(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _fix_tz(tz):
    if not tz or tz.upper() == "Z":
        return "+00:00"
    digits = tz[1:].replace(":", "")
    if len(digits) == 2:
        digits += "00"
    return f"{tz[0]}{digits[:2]}:{digits[2:]}"


def parse_ts(value):
    """Return epoch seconds (float) or None if the value cannot be understood.

    Accepts: epoch seconds/ms/us/ns (number or numeric string), ISO-8601 (any
    fraction length, Z / +05:30 / +0530), Apache '04/Oct/2026:09:01:40 +0000',
    RFC-2822, and syslog 'Oct  4 09:01:40' (year assumed = current year, UTC).
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _epoch(float(value))
    s = str(value).strip()
    if not s:
        return None
    if _NUMBER.fullmatch(s):
        return _epoch(float(s))
    m = _ISO.match(s)
    if m:
        d, t, frac, tz = m.groups()
        frac = (frac or "")[:6].ljust(6, "0")
        try:
            return datetime.fromisoformat(f"{d}T{t}.{frac}{_fix_tz(tz)}").timestamp()
        except ValueError:
            return None
    for fmt in _FORMATS:
        try:
            return _as_utc(datetime.strptime(s, fmt))
        except ValueError:
            pass
    # syslog style has no year
    try:
        flat = re.sub(r"\s+", " ", s)
        now = time.time()
        year = datetime.fromtimestamp(now, timezone.utc).year
        dt = datetime.strptime(f"{year} {flat}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        if dt.timestamp() > now + 86400:          # e.g. a December log read in January
            dt = dt.replace(year=year - 1)
        return dt.timestamp()
    except ValueError:
        return None


# -------------------------------------------------------------------- events
def normalize_event(raw, aliases):
    """Map alias field names to canonical ones and add internal '_ts'.
    Raises TypeError if the JSON line is not an object (so callers can skip it)."""
    if not isinstance(raw, dict):
        raise TypeError("log line is not a JSON object")
    ev = dict(raw)
    for canon, alts in (aliases or {}).items():
        if canon not in ev:
            for a in alts:
                if a in ev:
                    ev[canon] = ev[a]
                    break
    if "log_type" in ev:
        ev["log_type"] = canon_log_type(ev["log_type"])
    ev["_ts"] = parse_ts(ev.get("timestamp"))
    return ev


def _parse_line(line, aliases):
    """One text line -> event dict, or None if it is unusable."""
    line = line.strip()
    if not line:
        return None
    try:
        ev = normalize_event(json.loads(line), aliases)
    except (ValueError, TypeError, RecursionError):   # JSONDecodeError is a ValueError
        return False
    return ev if ev["_ts"] is not None else False


def _files(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Log path not found: {path}")
    if os.path.isdir(path):
        return sorted(os.path.join(path, f) for f in os.listdir(path)
                      if f.endswith((".jsonl", ".json", ".log")))
    return [path]


def read_events(path, aliases):
    """Batch mode: load everything, sort by time. Returns (events, bad_line_count)."""
    events, bad = [], 0
    for fp in _files(path):
        with open(fp, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                ev = _parse_line(line, aliases)
                if ev is None:
                    continue
                if ev is False:
                    bad += 1
                else:
                    events.append(ev)
    events.sort(key=lambda e: e["_ts"])
    return events, bad


def follow_events(path, aliases, poll=0.5, should_stop=None, stats=None):
    """Live mode: tail a single file like 'tail -F' and yield events as they arrive.

    * waits for the file to appear if it does not exist yet
    * only complete lines are processed (a half-written line waits for its end)
    * detects log rotation / truncation and continues with the new file
    * stats (optional dict) gets stats['bad'] = number of unreadable lines
    * should_stop (optional callable) lets a caller end the loop cleanly
    """
    stop = should_stop or (lambda: False)
    fh = None
    try:
        while fh is None and not stop():
            try:
                fh = open(path, encoding="utf-8", errors="replace")
            except FileNotFoundError:
                time.sleep(poll)
        if fh is None:
            return
        fh.seek(0, os.SEEK_END)                      # only new lines, like tail
        inode, buf = os.fstat(fh.fileno()).st_ino, ""
        while not stop():
            chunk = fh.readline()
            if chunk:
                buf += chunk
                if not buf.endswith("\n"):
                    continue                          # partial line, wait for the rest
                line, buf = buf, ""
                ev = _parse_line(line, aliases)
                if ev is False and stats is not None:
                    stats["bad"] = stats.get("bad", 0) + 1
                if ev:
                    yield ev
                continue
            try:                                      # no new data: was the file rotated?
                st = os.stat(path)
                if st.st_ino != inode or st.st_size < fh.tell():
                    fh.close()
                    fh = open(path, encoding="utf-8", errors="replace")
                    inode, buf = os.fstat(fh.fileno()).st_ino, ""
                    continue                          # read the new file from its start
            except FileNotFoundError:
                pass                                  # rotation in progress
            time.sleep(poll)
    finally:
        if fh is not None:
            fh.close()
