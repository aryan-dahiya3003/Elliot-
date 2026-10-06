#!/usr/bin/env python3
"""Threat Detection Engine - command line entry point.

Examples:
  python main.py                                   # run on sample data
  python main.py --logs /path/to/logs.jsonl        # your own normalized logs
  python main.py --logs live.jsonl --follow        # real-time (tail) mode
  python main.py --validate-rules                  # only check the YAML rules
"""
import argparse, os, sys, yaml
from engine.loader import read_events, follow_events
from engine.rules import load_rules, RuleError
from engine.alerts import AlertManager, ConsoleHandler, JsonFileHandler
from engine.detector import Detector

BASE = os.path.dirname(os.path.abspath(__file__))


def build(cfg, rules, color_override=None, append=False):
    ac = cfg.get("alerts", {})
    handlers = []
    if ac.get("console", True):
        color = ac.get("color", True) if color_override is None else color_override
        handlers.append(ConsoleHandler(color))
    if ac.get("json_file"):
        p = ac["json_file"]
        handlers.append(JsonFileHandler(p if os.path.isabs(p) else os.path.join(BASE, p), append))
    manager = AlertManager(ac, handlers)
    return Detector(rules, manager), manager


def main():
    ap = argparse.ArgumentParser(description="YAML-rule based threat detection engine")
    ap.add_argument("--logs", default=os.path.join(BASE, "sample_data", "normalized_logs.jsonl"))
    ap.add_argument("--rules", default=os.path.join(BASE, "rules"))
    ap.add_argument("--config", default=os.path.join(BASE, "config.yml"))
    ap.add_argument("--follow", action="store_true", help="live mode: keep reading new lines")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--validate-rules", action="store_true")
    args = ap.parse_args()

    try:
        with open(args.config, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        rules = load_rules(args.rules, cfg.get("lists"))
    except OSError as e:
        sys.exit(f"Cannot read file: {e}")
    except yaml.YAMLError as e:
        sys.exit(f"YAML syntax error: {e}")
    except RuleError as e:
        sys.exit(f"Rule error: {e}")
    print(f"Loaded {len(rules)} rules from {args.rules}")
    if args.validate_rules:
        print("All rules are valid.")
        return

    try:
        detector, manager = build(cfg, rules, False if args.no_color else None, append=args.follow)
    except ValueError as e:
        sys.exit(f"Config error: {e}")
    aliases = cfg.get("field_aliases", {})
    stats = {"bad": 0}

    if args.follow:
        if os.path.isdir(args.logs):
            sys.exit("--follow needs a single log file, not a folder")
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(line_buffering=True)   # show alerts instantly, even when piped
        print(f"Watching {args.logs} for NEW lines (Ctrl+C to stop)...\n")
        try:
            for ev in follow_events(args.logs, aliases, stats=stats):
                detector.process(ev)
        except KeyboardInterrupt:
            print("\nStopped.")
        finally:
            print(f"{detector.events_seen} event(s) processed, {stats['bad']} unreadable line(s) skipped")
    else:
        try:
            events, bad = read_events(args.logs, aliases)
        except OSError as e:
            manager.close()
            sys.exit(f"Cannot read logs: {e}")
        print(f"Read {len(events)} events ({bad} unreadable lines skipped)\n")
        try:
            for ev in events:
                detector.process(ev)
        except KeyboardInterrupt:
            print("\nStopped.")

    print(manager.summary())
    note = detector.skipped_report()
    if note:
        print(note)
    manager.close()


if __name__ == "__main__":
    main()
