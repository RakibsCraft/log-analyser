import json
from datetime import datetime

import pytest

from log_analyser.models import Alert, LogEvent
from log_analyser.report import build_summary, format_json, format_text

# Change to True when you start Milestone 4.
STARTED = False
pytestmark = pytest.mark.skipif(not STARTED, reason="Not started")


def ev(minute, event_type, ip="203.0.113.5", user="root"):
    return LogEvent(datetime(2026, 11, 7, 9, minute), "web01", event_type, user,
                    None if event_type == "sudo" else ip, None if event_type == "sudo" else 22)


ALERT = Alert("brute_force", "high", "203.0.113.5", 3,
              datetime(2026, 11, 7, 9, 1), datetime(2026, 11, 7, 9, 3), ("root",))


def sample_events():
    return [
        ev(5, "successful_login", ip="192.168.1.20", user="alice"),
        ev(1, "failed_login"),
        ev(2, "failed_login"),
        ev(3, "failed_login"),
        ev(4, "failed_login", ip="10.0.0.15", user="backup"),
        ev(6, "sudo", user="alice"),
        ev(7, "invalid_user", ip="198.51.100.7", user="test"),
    ]


def test_build_summary():
    assert build_summary(sample_events(), [ALERT]) == {
        "total_events": 7,
        "events_by_type": {"failed_login": 4, "successful_login": 1, "invalid_user": 1, "sudo": 1},
        "time_range": {"start": "2026-11-07T09:01:00", "end": "2026-11-07T09:07:00"},
        "top_attacking_ips": [
            {"ip": "203.0.113.5", "failed_logins": 3, "type": "public"},
            {"ip": "10.0.0.15", "failed_logins": 1, "type": "private"},
        ],
        "alerts_by_severity": {"critical": 0, "high": 1, "medium": 0},
    }


def test_build_summary_with_no_events():
    assert build_summary([], []) == {
        "total_events": 0,
        "events_by_type": {"failed_login": 0, "successful_login": 0, "invalid_user": 0, "sudo": 0},
        "time_range": {"start": None, "end": None},
        "top_attacking_ips": [],
        "alerts_by_severity": {"critical": 0, "high": 0, "medium": 0},
    }


def test_top_attacking_ips_keeps_five_and_breaks_ties_by_ip():
    events = []
    for ip, n in [("203.0.113.9", 2), ("203.0.113.1", 2), ("8.8.8.8", 5), ("1.1.1.1", 1),
                  ("9.9.9.9", 3), ("4.4.4.4", 2), ("5.5.5.5", 1)]:
        events += [ev(i, "failed_login", ip=ip) for i in range(n)]
    top = build_summary(events, [])["top_attacking_ips"]
    assert [(t["ip"], t["failed_logins"]) for t in top] == [
        ("8.8.8.8", 5), ("9.9.9.9", 3), ("203.0.113.1", 2), ("203.0.113.9", 2), ("4.4.4.4", 2),
    ]


def test_format_json_round_trips():
    summary = build_summary(sample_events(), [ALERT])
    data = json.loads(format_json(summary, [ALERT]))
    assert data["summary"] == summary
    assert data["alerts"] == [ALERT.to_dict()]


def test_format_json_is_indented():
    text = format_json(build_summary([], []), [])
    assert '\n  "summary"' in text


def test_format_text_lists_totals_and_alerts():
    text = format_text(build_summary(sample_events(), [ALERT]), [ALERT])
    assert "7" in text
    assert "high" in text.lower()
    assert "brute_force" in text
    assert "203.0.113.5" in text


def test_format_text_says_when_there_are_no_alerts():
    text = format_text(build_summary(sample_events(), []), [])
    assert "No alerts" in text
