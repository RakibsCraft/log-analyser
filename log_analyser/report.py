"""MILESTONE 4: Summarise events and alerts for people and for other tools."""

from __future__ import annotations

from .ip_utils import classify_ip
from .models import EVENT_TYPES, SEVERITIES, Alert, LogEvent


def build_summary(events: list[LogEvent], alerts: list[Alert]) -> dict:
    """Return a dictionary like this:

    {
        "total_events": 120,
        "events_by_type": {"failed_login": 80, "successful_login": 20, "invalid_user": 15, "sudo": 5},
        "time_range": {"start": "2026-11-07T08:00:00", "end": "2026-11-07T18:30:00"},
        "top_attacking_ips": [
            {"ip": "203.0.113.45", "failed_logins": 40, "type": "public"},
            ...
        ],
        "alerts_by_severity": {"critical": 1, "high": 2, "medium": 1},
    }

    Rules:
        - events_by_type and alerts_by_severity include every key (see
          EVENT_TYPES and SEVERITIES), even when the count is 0.
        - time_range uses the earliest and latest event timestamps as ISO
          strings (datetime.isoformat()). Both are None when there are no events.
        - top_attacking_ips: the 5 IPs with the most failed_login events, most
          first. Break ties by ip string, alphabetically. "type" comes from
          classify_ip. IPs with no failed logins are left out.
    """
    raise NotImplementedError("build_summary")


def format_json(summary: dict, alerts: list[Alert]) -> str:
    """Return JSON text: {"summary": <summary>, "alerts": [<alert.to_dict()>, ...]},
    indented by 2 spaces. Use the json module."""
    raise NotImplementedError("format_json")


def format_text(summary: dict, alerts: list[Alert]) -> str:
    """Return a report a person can read in a terminal. Design the layout
    yourself. It must include:
        - the total number of events
        - each alert's severity, rule and ip
        - the text "No alerts" when there are none
    """
    raise NotImplementedError("format_text")
