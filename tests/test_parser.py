from datetime import datetime
from pathlib import Path

import pytest

from log_analyser.models import LogEvent
from log_analyser.parser import parse_file, parse_line, parse_lines

# Change to True when you start Milestone 1.
STARTED = False
pytestmark = pytest.mark.skipif(not STARTED, reason="Not started")

YEAR = 2026
SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"


def test_failed_password():
    line = "Nov  7 09:15:02 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2"
    assert parse_line(line, YEAR) == LogEvent(
        timestamp=datetime(2026, 11, 7, 9, 15, 2),
        host="web01",
        event_type="failed_login",
        user="root",
        ip="203.0.113.5",
        port=52211,
        method="password",
    )


def test_failed_password_for_invalid_user():
    line = "Nov  7 09:15:02 web01 sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 4444 ssh2"
    event = parse_line(line, YEAR)
    assert event.event_type == "failed_login"
    assert event.user == "admin"
    assert event.ip == "198.51.100.7"


def test_failed_publickey():
    line = ("Nov  7 09:15:02 web01 sshd[1234]: Failed publickey for deploy from 192.0.2.50 port 6000 ssh2: "
            "RSA SHA256:abcDEF123")
    event = parse_line(line, YEAR)
    assert (event.event_type, event.user, event.method, event.port) == ("failed_login", "deploy", "publickey", 6000)


def test_accepted_password():
    line = "Nov  7 10:00:00 web01 sshd[99]: Accepted password for alice from 192.168.1.20 port 50000 ssh2"
    assert parse_line(line, YEAR) == LogEvent(
        timestamp=datetime(2026, 11, 7, 10, 0, 0),
        host="web01",
        event_type="successful_login",
        user="alice",
        ip="192.168.1.20",
        port=50000,
        method="password",
    )


def test_accepted_publickey_with_key_details():
    line = ("Nov  7 10:00:00 web01 sshd[99]: Accepted publickey for bob from 192.168.1.21 port 50001 ssh2: "
            "ED25519 SHA256:4mZ1bq9Xr2kQ7pVt0s8yLwHn3dJcF6uE5aRgTiOxKfM")
    event = parse_line(line, YEAR)
    assert (event.event_type, event.user, event.method) == ("successful_login", "bob", "publickey")


def test_invalid_user():
    line = "Nov  7 10:00:00 web01 sshd[99]: Invalid user test from 198.51.100.7 port 4445"
    assert parse_line(line, YEAR) == LogEvent(
        timestamp=datetime(2026, 11, 7, 10, 0, 0),
        host="web01",
        event_type="invalid_user",
        user="test",
        ip="198.51.100.7",
        port=4445,
        method=None,
    )


def test_sudo_command():
    line = "Nov  7 11:30:45 db02 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
    assert parse_line(line, YEAR) == LogEvent(
        timestamp=datetime(2026, 11, 7, 11, 30, 45),
        host="db02",
        event_type="sudo",
        user="alice",
        command="/usr/bin/apt update",
    )


def test_two_digit_day_and_given_year():
    line = "Dec 17 23:59:59 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
    assert parse_line(line, 2025).timestamp == datetime(2025, 12, 17, 23, 59, 59)


def test_trailing_newline_is_ignored():
    line = "Nov  7 09:15:02 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2\n"
    assert parse_line(line, YEAR).port == 52211


@pytest.mark.parametrize("line", [
    "Nov  7 09:15:03 web01 sshd[1234]: pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)",
    "Nov  7 09:15:03 web01 sshd[1234]: Connection closed by authenticating user root 203.0.113.5 port 52211 [preauth]",
    "Nov  7 09:15:03 web01 sshd[1234]: Received disconnect from 192.168.1.20 port 50000:11: disconnected by user",
    "Nov  7 09:15:03 web01 CRON[555]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
    "Nov  7 09:15:03 web01 sudo:    bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; "
    "USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
])
def test_lines_we_do_not_track_return_none(line):
    assert parse_line(line, YEAR) is None


@pytest.mark.parametrize("line", [
    "",
    "   ",
    "this is not a log line",
    "Nov  7 09:15:02 web01",
    "Feb 30 09:15:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
    "Nov  7 25:15:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
    "Foo  7 09:15:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
])
def test_malformed_lines_return_none_without_crashing(line):
    assert parse_line(line, YEAR) is None


def test_parse_lines_skips_untracked_lines_and_keeps_order():
    lines = [
        "Nov  7 09:00:00 web01 sshd[1]: Invalid user test from 198.51.100.7 port 1",
        "garbage",
        "Nov  7 09:00:02 web01 sshd[1]: Failed password for invalid user test from 198.51.100.7 port 1 ssh2",
        "Nov  7 09:00:05 web01 sshd[2]: Accepted password for alice from 192.168.1.20 port 2 ssh2",
    ]
    events = parse_lines(lines, YEAR)
    assert [e.event_type for e in events] == ["invalid_user", "failed_login", "successful_login"]


def test_parse_file_reads_the_sample_log():
    events = parse_file(str(SAMPLE), YEAR)
    counts = {}
    for e in events:
        counts[e.event_type] = counts.get(e.event_type, 0) + 1
    assert counts == {"failed_login": 49, "successful_login": 7, "invalid_user": 8, "sudo": 5}
