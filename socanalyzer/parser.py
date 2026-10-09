import re
from datetime import datetime

from socanalyzer.models import LogEvent
from socanalyzer.reader import read_events

TIME_PATTERN = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})")
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


def parse_line(line, line_no, year):
    """Turn one line into a LogEvent.

    Returns None if the line is valid but not interesting (like a CRON line).
    Raises ValueError if the line has no readable timestamp.
    """
    time_match = TIME_PATTERN.match(line)
    if not time_match:
        raise ValueError(f"no timestamp on line {line_no}")

    timestamp = datetime.strptime(f"{year} {time_match['ts']}", "%Y %b %d %H:%M:%S")

    if m := FAILED_PATTERN.search(line):
        kind = "failed"
    elif m := ACCEPTED_PATTERN.search(line):
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


def parse_file(path, year):
    """Read an auth log. Returns (list_of_events, number_of_bad_lines)."""
    return read_events(path, parse_line, year)