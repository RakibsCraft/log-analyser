from datetime import datetime, timedelta

import pytest

from log_analyser.detectors import (
    detect_brute_force,
    detect_compromise,
    detect_password_spraying,
    run_all_detectors,
)
from log_analyser.models import Alert, LogEvent

# Change to True when you start Milestone 3.
STARTED = False
pytestmark = pytest.mark.skipif(not STARTED, reason="Not started")

T0 = datetime(2026, 11, 7, 9, 0, 0)


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def fail(seconds, ip="203.0.113.5", user="root"):
    return LogEvent(at(seconds), "web01", "failed_login", user, ip, 22, "password")


def invalid(seconds, ip="198.51.100.7", user="test"):
    return LogEvent(at(seconds), "web01", "invalid_user", user, ip, 22, None)


def success(seconds, ip="203.0.113.5", user="root"):
    return LogEvent(at(seconds), "web01", "successful_login", user, ip, 22, "password")


# ---------- brute force ----------

def test_brute_force_raises_alert_for_fast_failures():
    events = [fail(i * 30, user=u) for i, u in enumerate(["root", "admin", "root", "pi", "root"])]
    assert detect_brute_force(events) == [Alert(
        rule="brute_force", severity="high", ip="203.0.113.5", count=5,
        first_seen=at(0), last_seen=at(120), usernames=("admin", "pi", "root"),
    )]


def test_brute_force_needs_threshold_failures():
    assert detect_brute_force([fail(i * 10) for i in range(4)]) == []


def test_brute_force_failures_must_fall_inside_window():
    # 5 failures, 150 seconds apart: first to last is 10 minutes.
    events = [fail(i * 150) for i in range(5)]
    assert detect_brute_force(events, window=timedelta(minutes=5)) == []
    # A window of exactly 10 minutes includes them.
    assert len(detect_brute_force(events, window=timedelta(minutes=10))) == 1


def test_brute_force_count_covers_the_whole_log():
    events = [fail(i * 10) for i in range(5)] + [fail(3600), fail(7200)]
    [alert] = detect_brute_force(events)
    assert alert.count == 7
    assert alert.last_seen == at(7200)


def test_brute_force_window_can_be_anywhere_in_the_log():
    slow = [fail(i * 600) for i in range(3)]
    burst = [fail(5000 + i * 5) for i in range(5)]
    [alert] = detect_brute_force(slow + burst)
    assert alert.first_seen == at(0)
    assert alert.count == 8


def test_brute_force_handles_unsorted_events():
    events = [fail(40), fail(0), fail(30), fail(10), fail(20)]
    [alert] = detect_brute_force(events)
    assert (alert.first_seen, alert.last_seen) == (at(0), at(40))


def test_brute_force_only_counts_failed_logins():
    events = [invalid(i, ip="203.0.113.5") for i in range(10)] + [success(i, ip="203.0.113.5") for i in range(10)]
    assert detect_brute_force(events) == []


def test_brute_force_tracks_each_ip_separately_and_sorts_alerts():
    events = (
        [fail(100 + i, ip="203.0.113.9") for i in range(5)]
        + [fail(i, ip="203.0.113.7") for i in range(5)]
        + [fail(100 + i, ip="203.0.113.1") for i in range(5)]
        + [fail(i * 1000, ip="198.51.100.1") for i in range(5)]
    )
    assert [a.ip for a in detect_brute_force(events)] == ["203.0.113.7", "203.0.113.1", "203.0.113.9"]


def test_brute_force_custom_threshold():
    events = [fail(i) for i in range(3)]
    assert len(detect_brute_force(events, threshold=3)) == 1


# ---------- password spraying ----------

def test_spraying_counts_distinct_usernames_across_both_event_types():
    events = [
        invalid(0, user="admin"), fail(2, ip="198.51.100.7", user="admin"),
        invalid(180, user="oracle"),
        fail(360, ip="198.51.100.7", user="guest"),
        invalid(540, user="test"), fail(542, ip="198.51.100.7", user="test"),
    ]
    assert detect_password_spraying(events) == [Alert(
        rule="password_spraying", severity="medium", ip="198.51.100.7", count=6,
        first_seen=at(0), last_seen=at(542), usernames=("admin", "guest", "oracle", "test"),
    )]


def test_spraying_needs_enough_distinct_users():
    events = [invalid(i * 60, user=u) for i, u in enumerate(["a", "b", "c", "a", "b", "c"])]
    assert detect_password_spraying(events) == []
    assert len(detect_password_spraying(events, min_users=3)) == 1


def test_spraying_ignores_many_attempts_on_one_user():
    assert detect_password_spraying([fail(i) for i in range(50)]) == []


def test_spraying_ignores_successful_logins():
    events = [success(i, ip="192.168.1.5", user=u) for i, u in enumerate("abcdef")]
    assert detect_password_spraying(events) == []


# ---------- compromise ----------

def test_compromise_after_many_failures():
    events = [fail(i * 15, user="deploy") for i in range(5)] + [success(90, user="deploy")]
    assert detect_compromise(events) == [Alert(
        rule="compromised_account", severity="critical", ip="203.0.113.5", count=5,
        first_seen=at(0), last_seen=at(90), usernames=("deploy",),
    )]


def test_no_compromise_with_too_few_failures():
    events = [fail(i) for i in range(4)] + [success(10)]
    assert detect_compromise(events) == []


def test_no_compromise_when_success_comes_first():
    events = [success(0)] + [fail(10 + i) for i in range(10)]
    assert detect_compromise(events) == []


def test_compromise_only_counts_failures_from_the_same_ip():
    events = [fail(i, ip="198.51.100.1") for i in range(10)] + [success(20, ip="203.0.113.5")]
    assert detect_compromise(events) == []


def test_compromise_uses_first_success_after_reaching_threshold():
    events = (
        [fail(i) for i in range(3)]
        + [success(10, user="first")]
        + [fail(20 + i) for i in range(2)]
        + [success(30, user="second")]
        + [fail(40)]
        + [success(50, user="third")]
    )
    [alert] = detect_compromise(events)
    assert (alert.count, alert.last_seen, alert.usernames) == (5, at(30), ("second",))


def test_compromise_handles_unsorted_events():
    events = [success(100, user="deploy")] + [fail(i) for i in range(5)]
    assert len(detect_compromise(events)) == 1


# ---------- all detectors ----------

def test_run_all_sorts_by_severity_then_time():
    events = (
        [invalid(0, ip="198.51.100.7", user=u) for u in "abcd"]           # spraying (medium)
        + [fail(100 + i, ip="203.0.113.5") for i in range(5)]             # brute force (high)
        + [fail(50 + i, ip="203.0.113.6") for i in range(5)]              # brute force (high), earlier
        + [success(200, ip="203.0.113.5")]                                # compromise (critical)
    )
    alerts = run_all_detectors(events)
    assert [(a.severity, a.ip) for a in alerts] == [
        ("critical", "203.0.113.5"),
        ("high", "203.0.113.6"),
        ("high", "203.0.113.5"),
        ("medium", "198.51.100.7"),
    ]


def test_run_all_passes_options_through():
    events = [fail(i * 60, user=u) for i, u in enumerate("abc")] + [success(500)]
    rules = sorted(a.rule for a in run_all_detectors(events, threshold=3, window=timedelta(minutes=3), spray_users=3))
    assert rules == ["brute_force", "compromised_account", "password_spraying"]


def test_run_all_with_no_events():
    assert run_all_detectors([]) == []
