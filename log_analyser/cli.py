"""MILESTONE 5: The command-line interface.

Usage:
    python -m log_analyser LOGFILE [--year YEAR] [--threshold N] [--window MINUTES]
                                   [--spray-users N] [--format {text,json}]

Options:
    LOGFILE         path to the auth log (required)
    --year          year the log is from. Default: the current year.
    --threshold     failed logins that count as brute force. Default: 5
    --window        brute-force time window in minutes; decimals allowed, e.g. 0.5. Default: 5
    --spray-users   distinct usernames that count as password spraying. Default: 4
    --format        'text' (default) or 'json'

Behaviour:
    - Parse the file, run all detectors, build the summary, then print the
      report in the chosen format to stdout.
    - Return (don't call sys.exit) an exit code:
        0  no high or critical alerts
        1  at least one high or critical alert
        2  the log file doesn't exist or can't be read. Print a short error
           message to stderr in this case, and nothing to stdout.

Exit codes let other scripts act on the result, for example a scheduled job
that emails the security team when the code is 1.

Use the argparse module. argparse already exits with code 2 for bad options.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    """argv is the list of arguments without the program name, e.g.
    ['auth.log', '--format', 'json']. When it's None, argparse reads sys.argv."""
    raise NotImplementedError("main")
