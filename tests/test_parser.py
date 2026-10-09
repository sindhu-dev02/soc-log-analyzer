import pytest

from socanalyzer.parser import parse_line
from socanalyzer.parser import parse_file

YEAR = 2026


def test_failed_login_is_parsed():
    line = "Oct  8 03:14:07 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2"
    event = parse_line(line, 1, YEAR)

    assert event.kind == "failed"
    assert event.user == "admin"
    assert event.ip == "203.0.113.5"


def test_successful_login_is_parsed():
    line = "Oct  8 03:14:30 web01 sshd[1301]: Accepted password for deploy from 198.51.100.7 port 40022 ssh2"
    event = parse_line(line, 6, YEAR)

    assert event.kind == "success"
    assert event.user == "deploy"


def test_uninteresting_line_returns_none():
    line = "Oct  8 03:15:01 web01 CRON[1400]: pam_unix(cron:session): session opened for user root"
    assert parse_line(line, 7, YEAR) is None


def test_line_without_timestamp_raises():
    with pytest.raises(ValueError):
        parse_line("this is not a log line", 10, YEAR)

def test_blank_lines_are_not_counted_as_bad(tmp_path):
    log = tmp_path / "a.log"
    log.write_text(
        "\n"
        "Oct  8 03:14:07 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n"
        "\n"
    )

    events, bad_lines = parse_file(log, 2026)

    assert len(events) == 1
    assert bad_lines == 0