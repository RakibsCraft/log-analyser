"""Data types shared across the project. You shouldn't need to change these."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

EVENT_TYPES = ("failed_login", "successful_login", "invalid_user", "sudo")
SEVERITIES = ("critical", "high", "medium")


@dataclass(frozen=True)
class LogEvent:
    """One security-relevant line from an auth log."""

    timestamp: datetime
    host: str
    event_type: str  # one of EVENT_TYPES
    user: str
    ip: str | None = None  # None for sudo events
    port: int | None = None  # None for sudo events
    method: str | None = None  # 'password' or 'publickey' for logins, otherwise None
    command: str | None = None  # the command run, for sudo events only


@dataclass(frozen=True)
class Alert:
    """Something suspicious that a detector found."""

    rule: str  # 'brute_force', 'password_spraying' or 'compromised_account'
    severity: str  # one of SEVERITIES
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    usernames: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "usernames": list(self.usernames),
        }
