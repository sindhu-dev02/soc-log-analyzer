from datetime import datetime, timedelta

from socanalyzer.models import LogEvent
from socanalyzer.detector import find_success_after_failures
from socanalyzer.detector import find_many_usernames
from socanalyzer.detector import find_distributed_attack

START = datetime(2026, 10, 8, 3, 0, 0)


def make_event(kind, seconds, ip="203.0.113.5", user="root"):
    """Build a fake event 'seconds' after START. Saves repeating this in every test."""
    return LogEvent(
        timestamp=START + timedelta(seconds=seconds),
        kind=kind,
        user=user,
        ip=ip,
        line_no=0,
        raw="",
    )


def test_alerts_on_success_after_enough_failures():
    events = [make_event("failed", i) for i in range(5)]
    events.append(make_event("success", 10))

    alerts = find_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"


def test_no_alert_if_too_few_failures():
    events = [make_event("failed", i) for i in range(4)]   # only 4
    events.append(make_event("success", 10))

    assert find_success_after_failures(events) == []


def test_no_alert_if_success_comes_first():
    events = [make_event("success", 0)]
    events += [make_event("failed", i) for i in range(1, 6)]

    assert find_success_after_failures(events) == []


def test_no_alert_if_failures_are_too_old():
    events = [make_event("failed", i) for i in range(5)]
    events.append(make_event("success", 300))   # 5 minutes later

    assert find_success_after_failures(events) == []


def test_failures_from_one_ip_do_not_count_for_another():
    events = [make_event("failed", i, ip="203.0.113.5") for i in range(5)]
    events.append(make_event("success", 10, ip="198.51.100.7"))

    assert find_success_after_failures(events) == []

def test_allowlisted_ip_is_ignored():
    events = [make_event("failed", i) for i in range(5)]
    events.append(make_event("success", 10))

    alerts = find_success_after_failures(events, allowlist=frozenset({"203.0.113.5"}))

    assert alerts == []

def test_alerts_on_many_usernames_from_one_ip():
    events = [make_event("failed", i, user=f"user{i}") for i in range(5)]

    alerts = find_many_usernames(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"


def test_same_username_repeated_is_not_spraying():
    events = [make_event("failed", i, user="root") for i in range(10)]

    assert find_many_usernames(events) == []


def test_usernames_spread_outside_window_do_not_count():
    # one new username every 100s: at most 4 fall inside any 300s window
    events = [make_event("failed", i * 100, user=f"user{i}") for i in range(5)]

    assert find_many_usernames(events) == []


def test_only_one_alert_per_ip():
    events = [make_event("failed", i, user=f"user{i}") for i in range(10)]

    assert len(find_many_usernames(events)) == 1

def test_alert_carries_evidence_and_technique():
    events = [make_event("failed", i, user=f"user{i}") for i in range(5)]

    alert = find_many_usernames(events)[0]

    assert alert.technique.startswith("T1110")
    assert alert.rule == "many_usernames"

def test_allowlisted_ip_is_ignored_for_many_usernames():
    events = [make_event("failed", i, user=f"user{i}") for i in range(5)]

    alerts = find_many_usernames(events, allowlist=frozenset({"203.0.113.5"}))

    assert alerts == []

def test_alerts_when_many_ips_hit_one_username():
    events = [make_event("failed", i, ip=f"192.0.2.{i}") for i in range(5)]

    alerts = find_distributed_attack(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "distributed_attack"


def test_one_ip_repeating_is_not_distributed():
    events = [make_event("failed", i) for i in range(10)]   # same IP every time

    assert find_distributed_attack(events) == []


def test_different_usernames_do_not_combine():
    events = [make_event("failed", i, ip=f"192.0.2.{i}", user=f"user{i}") for i in range(5)]

    assert find_distributed_attack(events) == []


def test_distributed_attack_respects_allowlist():
    events = [make_event("failed", i, ip=f"192.0.2.{i}") for i in range(5)]

    allow = frozenset(f"192.0.2.{i}" for i in range(5))
    assert find_distributed_attack(events, allowlist=allow) == []