"""MILESTONE 3: Detect attacks.

Each detector takes a list of LogEvents (which may NOT be in time order, so
sort them first) and returns a list of Alerts. Return alerts sorted by
first_seen, then by ip.
"""

from __future__ import annotations

from datetime import timedelta

from .models import Alert, LogEvent


def detect_brute_force(
    events: list[LogEvent],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> list[Alert]:
    """One IP guessing passwords quickly.

    Raise one alert per IP that has at least `threshold` failed_login events
    within any period of `window` length (a gap of exactly `window` between
    the first and last counts as within it).

    Alert fields:
        rule='brute_force', severity='high'
        count       total failed logins from that IP across the whole log
        first_seen  time of its first failed login
        last_seen   time of its last failed login
        usernames   the distinct usernames it tried, sorted alphabetically
    """
    raise NotImplementedError("detect_brute_force")


def detect_password_spraying(events: list[LogEvent], min_users: int = 4) -> list[Alert]:
    """One IP trying many different usernames, often slowly to avoid lockouts.

    Look at failed_login AND invalid_user events. Raise one alert per IP that
    targeted at least `min_users` distinct usernames, at any speed.

    Alert fields:
        rule='password_spraying', severity='medium'
        count       number of failed_login plus invalid_user events from that IP
        first_seen  time of the first of those events
        last_seen   time of the last of those events
        usernames   the distinct usernames targeted, sorted alphabetically
    """
    raise NotImplementedError("detect_password_spraying")


def detect_compromise(events: list[LogEvent], threshold: int = 5) -> list[Alert]:
    """An attacker who got in: many failures, then a successful login.

    Raise one alert per IP that had at least `threshold` failed_login events
    BEFORE a successful_login from the same IP. Only the first such successful
    login matters.

    Alert fields:
        rule='compromised_account', severity='critical'
        count       failed logins from that IP before that successful login
        first_seen  time of its first failed login
        last_seen   time of that successful login
        usernames   a one-item tuple: the user who logged in successfully
    """
    raise NotImplementedError("detect_compromise")


def run_all_detectors(
    events: list[LogEvent],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
    spray_users: int = 4,
) -> list[Alert]:
    """Run all three detectors and combine their alerts.

    Sort the result by severity (critical, then high, then medium), then by
    first_seen, then by ip.
    """
    raise NotImplementedError("run_all_detectors")
