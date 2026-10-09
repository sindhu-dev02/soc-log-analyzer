import re
from datetime import datetime

from socanalyzer.models import LogEvent
from socanalyzer.reader import read_events

# '203.0.113.5 - admin [08/Oct/2026:03:14:07 +0000] "POST /login HTTP/1.1" 401 512'
LINE_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
)

# Pages that count as "a login attempt". Adjust for the site you monitor.
LOGIN_PATHS = {"/login", "/wp-login.php", "/admin", "/signin"}
FAILED_STATUSES = {401, 403}
SUCCESS_STATUSES = {302, 303}   # a redirect after POST usually means "logged in"


def parse_line(line, line_no, year=None):
    """Turn one access-log line into a LogEvent.

    Returns None for valid lines that aren't login attempts.
    Raises ValueError if the line doesn't look like an access log at all.
    """
    m = LINE_PATTERN.match(line)
    if not m:
        raise ValueError(f"not an access log line: {line_no}")

    timestamp = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")

    path = m["path"].split("?")[0]          # drop ?query=strings
    if m["method"] != "POST" or path not in LOGIN_PATHS:
        return None

    status = int(m["status"])
    if status in FAILED_STATUSES:
        kind = "failed"
    elif status in SUCCESS_STATUSES:
        kind = "success"
    else:
        return None

    return LogEvent(
        timestamp=timestamp,
        kind=kind,
        user=m["user"],
        ip=m["ip"],
        line_no=line_no,
        raw=line.rstrip("\n"),
    )


def parse_file(path, year=None):
    """Read an access log. Returns (list_of_events, number_of_bad_lines)."""
    return read_events(path, parse_line, year)