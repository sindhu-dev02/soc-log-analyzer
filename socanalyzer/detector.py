from collections import defaultdict, deque
from datetime import timedelta

from socanalyzer.models import Alert


def find_success_after_failures(
    events, threshold=5, window=timedelta(seconds=60), allowlist=frozenset()
):
    """Alert when an IP logs in successfully right after many failures."""
    recent_failures = defaultdict(deque)   # ip -> times of recent failures
    alerts = []

    for event in events:
        if event.ip in allowlist:
            continue   # trusted IP, don't track or alert

        times = recent_failures[event.ip]

        # forget failures that are too old to matter
        while times and event.timestamp - times[0] > window:
            times.popleft()

        if event.kind == "failed":
            times.append(event.timestamp)
        elif event.kind == "success" and len(times) >= threshold:
            alerts.append(Alert(
                line_no=event.line_no,
                severity="CRITICAL",
                message=(
                    f"{event.ip} logged in as '{event.user}' after "
                    f"{len(times)} failures in the last {int(window.total_seconds())}s"
                ),
                rule="success_after_failures",
                technique="T1110 Brute Force",
                evidence=event.raw,
            ))
    return alerts

def find_many_usernames(
    events, threshold=5, window=timedelta(seconds=300), allowlist=frozenset()
):
    """Alert when one IP fails logins against many different usernames."""
    recent = defaultdict(deque)   # ip -> (timestamp, username) of recent failures
    already_alerted = set()
    alerts = []

    for event in events:
        if event.kind != "failed" or event.ip in allowlist:
            continue

        attempts = recent[event.ip]
        attempts.append((event.timestamp, event.user))

        # forget attempts that fell out of the window
        while attempts and event.timestamp - attempts[0][0] > window:
            attempts.popleft()

        users = {user for _, user in attempts}
        if len(users) >= threshold and event.ip not in already_alerted:
            already_alerted.add(event.ip)
            alerts.append(Alert(
                line_no=event.line_no,
                severity="HIGH",
                message=(
                    f"{event.ip} tried {len(users)} different usernames within "
                    f"{int(window.total_seconds())}s ({', '.join(sorted(users))})"
                ),
                rule="many_usernames",
                technique="T1110.003 Password Spraying",
                evidence=event.raw,
            ))

    return alerts

def find_distributed_attack(
    events, threshold=5, window=timedelta(seconds=300), allowlist=frozenset()
):
    """Alert when many different IPs fail logins against the same username."""
    recent = defaultdict(deque)   # username -> (timestamp, ip) of recent failures
    already_alerted = set()
    alerts = []

    for event in events:
        if event.kind != "failed" or event.ip in allowlist:
            continue

        attempts = recent[event.user]
        attempts.append((event.timestamp, event.ip))

        while attempts and event.timestamp - attempts[0][0] > window:
            attempts.popleft()

        ips = {ip for _, ip in attempts}
        if len(ips) >= threshold and event.user not in already_alerted:
            already_alerted.add(event.user)
            alerts.append(Alert(
                line_no=event.line_no,
                severity="HIGH",
                message=(
                    f"account '{event.user}' failed logins from {len(ips)} "
                    f"different IPs within {int(window.total_seconds())}s"
                ),
                rule="distributed_attack",
                technique="T1110.004 Credential Stuffing",
                evidence=event.raw,
            ))

    return alerts