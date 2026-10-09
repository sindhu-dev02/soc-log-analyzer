import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict

from socanalyzer.config import ConfigError, load_config
from socanalyzer.detector import (
    find_distributed_attack,
    find_many_usernames,
    find_success_after_failures,
)
from socanalyzer.follow import follow_file
from socanalyzer.registry import PARSE_LINES, PARSERS


def positive_int(text):
    """argparse type: accept only whole numbers greater than 0."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number")
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def count_failures(events, allowlist):
    """Failed logins per IP, ignoring trusted (allowlisted) IPs."""
    return Counter(
        e.ip for e in events
        if e.kind == "failed" and e.ip not in allowlist
    )


def build_parser():
    p = argparse.ArgumentParser(
        description="Analyze SSH auth logs for suspicious login activity."
    )
    p.add_argument("logfile", nargs="?",
                   help="log file to analyze (overrides log_file in the config)")
    p.add_argument("--config", default="config.yaml",
                   help="path to the YAML config (default: config.yaml)")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    p.add_argument("--type", choices=sorted(PARSERS), default="auth",
                   help="log format to parse (default: auth)")
    p.add_argument("--threshold", type=positive_int,
                   help="override brute_force.threshold from the config for this run")
    p.add_argument("--follow", action="store_true",
                   help="keep watching the log and print new alerts as they appear")
    return p


def print_text(failures, alerts, event_count, bad_lines):
    print("Total failed logins per IP:")
    for ip, count in failures.most_common():
        print(f"  {ip:<18} {count}")

    print("\nAlerts:")
    if alerts:
        for a in alerts:
            print(f"  Line {a.line_no}: {a.severity} - {a.message}")
            print(f"      rule: {a.rule} | ATT&CK: {a.technique}")
            print(f"      evidence: {a.evidence}")
    else:
        print("  None")

    print(f"\nParsed {event_count} events, skipped {bad_lines} unreadable line(s).")


def print_json(log_file, failures, alerts, event_count, bad_lines):
    report = {
        "log_file": log_file,
        "events_parsed": event_count,
        "unreadable_lines": bad_lines,
        "failures_per_ip": dict(failures),
        "alerts": [asdict(a) for a in alerts],
    }
    print(json.dumps(report, indent=2))


def run_detectors(events, config, threshold):
    alerts = find_success_after_failures(
        events, threshold=threshold, window=config.window,
        allowlist=config.allowlist_ips,
    )
    alerts += find_many_usernames(
        events, threshold=config.spray_threshold, window=config.spray_window,
        allowlist=config.allowlist_ips,
    )
    alerts += find_distributed_attack(
        events, threshold=config.dist_threshold, window=config.dist_window,
        allowlist=config.allowlist_ips,
    )
    alerts.sort(key=lambda a: a.line_no)
    return alerts


def follow_mode(log_file, args, config, threshold):
    printed = set()   # alerts we already showed, so we never repeat one

    def report(events):
        for a in run_detectors(events, config, threshold):
            key = (a.rule, a.line_no)
            if key not in printed:
                printed.add(key)
                print(f"[{a.severity}] {a.message}  (line {a.line_no}, {a.technique})",
                      flush=True)

    print(f"Watching {log_file} (Ctrl+C to stop)...", file=sys.stderr)
    try:
        follow_file(log_file, PARSE_LINES[args.type], config.year, report)
    except FileNotFoundError:
        print(f"Error: log file not found: {log_file}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    log_file = args.logfile or config.log_file
    threshold = args.threshold if args.threshold is not None else config.threshold

    if args.follow:
        return follow_mode(log_file, args, config, threshold)

    try:
        events, bad_lines = PARSERS[args.type](log_file, config.year)
    except FileNotFoundError:
        print(f"Error: log file not found: {log_file}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"Error: cannot read {log_file}: {e}", file=sys.stderr)
        return 2

    failures = count_failures(events, config.allowlist_ips)
    alerts = run_detectors(events, config, threshold)

    if args.format == "json":
        print_json(log_file, failures, alerts, len(events), bad_lines)
    else:
        print_text(failures, alerts, len(events), bad_lines)

    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())