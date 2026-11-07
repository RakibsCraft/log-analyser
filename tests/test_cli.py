import json
from pathlib import Path

import pytest

from log_analyser.cli import main

# Change to True when you start Milestone 5.
STARTED = False
pytestmark = pytest.mark.skipif(not STARTED, reason="Not started")

SAMPLE = str(Path(__file__).parent.parent / "samples" / "auth.log")


def run_json(capsys, *args):
    code = main([SAMPLE, "--year", "2026", "--format", "json", *args])
    return code, json.loads(capsys.readouterr().out)


def test_sample_log_finds_every_attack(capsys):
    code, data = run_json(capsys)
    assert code == 1
    assert [(a["severity"], a["rule"], a["ip"]) for a in data["alerts"]] == [
        ("critical", "compromised_account", "185.220.101.7"),
        ("high", "brute_force", "203.0.113.45"),
        ("high", "brute_force", "185.220.101.7"),
        ("medium", "password_spraying", "198.51.100.23"),
    ]


def test_json_summary_for_sample_log(capsys):
    _, data = run_json(capsys)
    summary = data["summary"]
    assert summary["total_events"] == 69
    assert summary["top_attacking_ips"][0] == {"ip": "203.0.113.45", "failed_logins": 30, "type": "public"}
    assert summary["time_range"]["start"].startswith("2026-11-06")


def test_year_option_is_used(capsys):
    _, data = run_json(capsys, "--year", "2024")
    assert data["summary"]["time_range"]["start"].startswith("2024-11-06")


def test_text_format_is_the_default(capsys):
    code = main([SAMPLE, "--year", "2026"])
    out = capsys.readouterr().out
    assert code == 1
    assert "compromised_account" in out
    assert "185.220.101.7" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_high_threshold_leaves_only_medium_alerts(capsys):
    code, data = run_json(capsys, "--threshold", "50")
    assert code == 0
    assert [a["rule"] for a in data["alerts"]] == ["password_spraying"]


def test_spray_users_option(capsys):
    _, data = run_json(capsys, "--spray-users", "20")
    assert "password_spraying" not in [a["rule"] for a in data["alerts"]]


def test_window_option(capsys):
    # The compromise attempts are 12 to 18 seconds apart, so 5 of them never fit in 30 seconds.
    _, data = run_json(capsys, "--window", "0.5")
    brute_ips = [a["ip"] for a in data["alerts"] if a["rule"] == "brute_force"]
    assert brute_ips == ["203.0.113.45"]


def test_clean_log_exits_zero(tmp_path, capsys):
    log = tmp_path / "clean.log"
    log.write_text(
        "Nov  7 09:00:00 web01 sshd[1]: Accepted publickey for alice from 192.168.1.20 port 1 ssh2\n"
        "Nov  7 09:05:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/ls\n"
    )
    assert main([str(log), "--year", "2026"]) == 0
    assert "No alerts" in capsys.readouterr().out


def test_missing_file_exits_two_with_error_on_stderr(capsys):
    code = main(["does-not-exist.log"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert captured.err.strip() != ""
