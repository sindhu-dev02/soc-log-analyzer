import json
import pytest

from analyze import main

FAILED = "".join(
    f"Oct  8 03:14:0{i} web01 sshd[1]: Failed password for root "
    f"from 203.0.113.5 port 5000{i} ssh2\n"
    for i in range(5)
)
ACCEPTED = (
    "Oct  8 03:14:40 web01 sshd[2]: Accepted password for root "
    "from 203.0.113.5 port 9 ssh2\n"
)


def test_json_output_and_exit_code_when_alerting(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text(FAILED + ACCEPTED)
    cfg = tmp_path / "c.yaml"
    cfg.write_text("year: 2026\n")

    code = main([str(log), "--config", str(cfg), "--format", "json"])
    report = json.loads(capsys.readouterr().out)

    assert code == 1
    assert len(report["alerts"]) == 1
    assert report["failures_per_ip"] == {"203.0.113.5": 5}


def test_missing_log_returns_error_code(tmp_path, capsys):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("year: 2026\n")

    code = main([str(tmp_path / "nope.log"), "--config", str(cfg)])

    assert code == 2
    assert "not found" in capsys.readouterr().err

def test_threshold_option_overrides_config(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text(FAILED + ACCEPTED)       # 5 failures, then a success
    cfg = tmp_path / "c.yaml"
    cfg.write_text("year: 2026\n")          # config threshold defaults to 5

    code = main([str(log), "--config", str(cfg), "--format", "json", "--threshold", "6"])
    report = json.loads(capsys.readouterr().out)

    assert code == 0
    assert report["alerts"] == []


def test_invalid_threshold_is_rejected(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main([str(tmp_path / "a.log"), "--threshold", "0"])

    assert exc.value.code == 2

def test_text_output_has_no_none_when_alerts_exist(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text(FAILED + ACCEPTED)
    cfg = tmp_path / "c.yaml"
    cfg.write_text("year: 2026\n")

    main([str(log), "--config", str(cfg)])

    out = capsys.readouterr().out
    assert "CRITICAL" in out
    assert "  None" not in out


def test_text_output_says_none_when_clean(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text(FAILED)                  # failures only, no success
    cfg = tmp_path / "c.yaml"
    cfg.write_text("year: 2026\n")

    code = main([str(log), "--config", str(cfg)])

    assert code == 0
    assert "  None" in capsys.readouterr().out

def test_alerts_section_printed_exactly_once(tmp_path, capsys):
    log = tmp_path / "a.log"
    # two different IPs fail, so a misplaced block would repeat
    log.write_text(
        FAILED
        + "Oct  8 03:14:50 web01 sshd[3]: Failed password for bob "
          "from 192.0.2.44 port 7 ssh2\n"
        + ACCEPTED
    )
    cfg = tmp_path / "c.yaml"
    cfg.write_text("year: 2026\n")

    main([str(log), "--config", str(cfg)])

    assert capsys.readouterr().out.count("Alerts:") == 1

from analyze import count_failures
from socanalyzer.models import LogEvent
from datetime import datetime


def _event(kind, ip):
    return LogEvent(datetime(2026, 10, 8, 3, 0, 0), kind, "root", ip, 0, "")


def test_count_failures_skips_allowlisted_ips():
    events = [_event("failed", "10.0.0.99")] * 3 + [_event("failed", "203.0.113.5")]

    result = count_failures(events, frozenset({"10.0.0.99"}))

    assert result == {"203.0.113.5": 1}


def test_count_failures_ignores_successes():
    events = [_event("success", "203.0.113.5")]

    assert count_failures(events, frozenset()) == {}


def test_allowlisted_ip_absent_from_report(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text(FAILED + ACCEPTED)
    cfg = tmp_path / "c.yaml"
    cfg.write_text("year: 2026\nallowlist_ips:\n  - 203.0.113.5\n")

    code = main([str(log), "--config", str(cfg), "--format", "json"])
    report = json.loads(capsys.readouterr().out)

    assert code == 0
    assert report["failures_per_ip"] == {}
    assert report["alerts"] == []

def test_web_log_type_uses_the_same_detectors(tmp_path, capsys):
    log = tmp_path / "access.log"
    log.write_text(
        "".join(
            f'203.0.113.5 - admin [08/Oct/2026:03:14:0{i} +0000] '
            f'"POST /login HTTP/1.1" 401 512\n'
            for i in range(5)
        )
        + '203.0.113.5 - admin [08/Oct/2026:03:14:40 +0000] "POST /login HTTP/1.1" 302 0\n'
    )
    cfg = tmp_path / "c.yaml"
    cfg.write_text("year: 2026\n")

    code = main([str(log), "--config", str(cfg), "--type", "web", "--format", "json"])
    report = json.loads(capsys.readouterr().out)

    assert code == 1
    assert report["alerts"][0]["rule"] == "success_after_failures"