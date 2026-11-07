"""MILESTONE 1: Parse auth log lines into LogEvent objects.

Linux servers write login activity to /var/log/auth.log (Debian, Ubuntu) or
/var/log/secure (Red Hat). Each line looks like:

    Nov  7 09:15:02 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2
    <mon> <d> <time>  <host> <process>[<pid>]: <message>

Notes on the format:
    - The day is padded with a space when it's one digit: "Nov  7", but "Nov 17".
    - The year is missing, so it's passed in as a parameter.
    - Some processes have no [pid], for example "sudo:".

Messages to recognise (everything else returns None):

    Failed password for root from 203.0.113.5 port 52211 ssh2
        -> event_type 'failed_login', user 'root', method 'password'
    Failed password for invalid user admin from 198.51.100.7 port 4444 ssh2
        -> event_type 'failed_login', user 'admin', method 'password'
    Failed publickey for deploy from 192.0.2.50 port 6000 ssh2: RSA SHA256:abc...
        -> event_type 'failed_login', user 'deploy', method 'publickey'
    Accepted password for alice from 192.168.1.20 port 50000 ssh2
        -> event_type 'successful_login', user 'alice', method 'password'
    Accepted publickey for bob from 192.168.1.21 port 50001 ssh2: ED25519 SHA256:xyz...
        -> event_type 'successful_login', user 'bob', method 'publickey'
    Invalid user test from 198.51.100.7 port 4445
        -> event_type 'invalid_user', user 'test', method None
    (process "sudo") alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
        -> event_type 'sudo', user 'alice', command '/usr/bin/apt update', ip/port/method None

The `re` module (regular expressions) is the natural tool here. Write one
pattern for the line prefix and one per message type.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import LogEvent


def parse_line(line: str, year: int) -> LogEvent | None:
    """Parse one log line. Return a LogEvent, or None if the line isn't one we track.

    Never raise an exception for a badly formed line: return None instead.
    That includes impossible dates such as "Feb 30".
    """
    raise NotImplementedError("parse_line")


def parse_lines(lines: Iterable[str], year: int) -> list[LogEvent]:
    """Parse many lines, keeping the events in their original order and skipping
    lines that parse_line returns None for."""
    raise NotImplementedError("parse_lines")


def parse_file(path: str, year: int) -> list[LogEvent]:
    """Read and parse a whole log file. (Provided.)"""
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse_lines(f, year)
