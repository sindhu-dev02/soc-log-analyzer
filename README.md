# SOC Log Analyzer

A command-line tool that reads Linux SSH authentication logs and web server
access logs and flags suspicious login activity. Detections are tagged with
MITRE ATT&CK techniques. Built as a learning project with sample data.

## What it detects

| Rule | Severity | ATT&CK | Trigger |
|---|---|---|---|
| success_after_failures | CRITICAL | T1110 | An IP logs in successfully after N failures inside a time window |
| many_usernames | HIGH | T1110.003 | One IP fails logins against N different usernames inside a time window |
| distributed_attack | HIGH | T1110.004 | N different IPs fail against one username inside a time window |

## Install

```
pip install -r requirements.txt
```

## Usage

```
python analyze.py                                   # uses config.yaml
python analyze.py path/to/auth.log                  # analyze a specific file
python analyze.py sample_logs/access.log --type web # web server access log
python analyze.py --format json > report.json       # machine-readable output
python analyze.py --threshold 10                    # override brute-force threshold
python analyze.py live.log --follow                 # watch a growing log
python -m pytest                                    # run the tests
```

Exit codes: `0` no alerts, `1` alerts found, `2` error (bad config, missing file).

## Example output

```
Alerts:
  Line 11: CRITICAL - 203.0.113.5 logged in as 'root' after 5 failures in the last 60s
      rule: success_after_failures | ATT&CK: T1110 Brute Force
      evidence: Oct  8 03:14:40 web01 sshd[1500]: Accepted password for root from 203.0.113.5 port 52200 ssh2
```

## Configuration

All thresholds, windows and the IP allowlist live in `config.yaml`.
Invalid values are rejected with a clear error before any analysis runs.

## Design

- `parser.py` and `webparser.py` turn log lines into `LogEvent` objects. They know nothing about attacks.
- `detector.py` turns events into `Alert` objects. It knows nothing about files or log formats.
- Each detection rule is one function, so adding a rule never touches the others.
- Unreadable lines are counted and reported, never fatal.

## Known limitations

- Only sshd password events are parsed (no key-based logins, sudo, etc.).
- Syslog timestamps have no year; it is set in the config. Logs spanning New Year are not handled.
- Whole file is read into memory before detection.
- Web logs: a login is detected only by POST to a known login path (see `LOGIN_PATHS`).
  Sites that return `200` even for a failed login are not detected.
- Web logs: usernames appear only with HTTP basic auth. Form-based logins show `-`,
  so the username rules cannot work on them without the application's own logs.
- Follow mode re-runs all detectors on every event seen so far and prints only
  new alerts. It is simple and reuses the tested rules, but its cost grows as the
  log grows. A streaming detector that keeps state would be more efficient.