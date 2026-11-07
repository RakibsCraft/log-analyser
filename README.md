# Log analyser

![Tests](https://github.com/RakibsCraft/log-analyser/actions/workflows/tests.yml/badge.svg)

A Python command-line tool, which I'm building milestone by milestone, that reads Linux SSH authentication logs and flags attacks:

- **Brute force:** one IP making many failed logins in a short time
- **Password spraying:** one IP trying many different usernames, often slowly to avoid lockouts
- **Compromised accounts:** an IP that fails repeatedly and then logs in successfully

It prints a readable report or JSON for other tools, and its exit code tells scripts whether anything serious was found.

**Stack:** Python 3.10+, standard library only (re, argparse, datetime, json), pytest, GitHub Actions

## Example

```
$ python -m log_analyser samples/auth.log --year 2026
```

The sample log in `samples/auth.log` is a day on a web server containing:

| Time | What happens | Expected alert |
|---|---|---|
| 02:14 | 203.0.113.45 tries `root` 30 times in 4 minutes | Brute force (high) |
| 10:30 | 198.51.100.23 tries 8 usernames, one every 3 minutes | Password spraying (medium) |
| 13:05 | 185.220.101.7 fails 7 times on `deploy`, gets in, then uses sudo to download and run a script | Compromised account (critical) and brute force (high) |

It also contains normal staff logins, a mistyped password, a few failures from an internal backup server, and routine system noise, none of which should raise an alert.

## Usage

```
python -m log_analyser LOGFILE [--year YEAR] [--threshold N] [--window MINUTES]
                               [--spray-users N] [--format {text,json}]
```

| Option | Default | Meaning |
|---|---|---|
| `--year` | current year | Auth logs don't record the year |
| `--threshold` | 5 | Failed logins that count as brute force or come before a compromise |
| `--window` | 5 | Brute-force time window in minutes |
| `--spray-users` | 4 | Distinct usernames that count as password spraying |
| `--format` | text | `text` for people, `json` for other tools |

| Exit code | Meaning |
|---|---|
| 0 | No high or critical alerts |
| 1 | At least one high or critical alert |
| 2 | The log file couldn't be read |

The exit codes make the tool easy to schedule. For example, a cron job can run it every hour and email the security team when it returns 1.

## How it works

```
auth.log -> parser -> LogEvents -> detectors -> Alerts -> report -> text or JSON
```

1. **Parser** (`parser.py`) turns each relevant line into a `LogEvent` using regular expressions and skips everything else, including malformed lines.
2. **Detectors** (`detectors.py`) group events by IP and apply each rule. Brute force uses a sliding time window over sorted failures.
3. **Report** (`report.py`) counts events by type, ranks the IPs with the most failed logins, labels each IP as public or private, and formats the output.
4. **CLI** (`cli.py`) handles options, errors and exit codes.

## Running it

```bash
pip install -e ".[dev]"     # installs pytest and the log-analyser command
pytest                       # run the tests
python -m log_analyser samples/auth.log --year 2026
log-analyser samples/auth.log --year 2026 --format json
```

On a real Linux server, the log is at `/var/log/auth.log` (Debian, Ubuntu) or `/var/log/secure` (Red Hat, Fedora). Reading it needs `sudo`.

## Testing

Each test file has a `STARTED` switch at the top; tests for parts not yet built are skipped. GitHub Actions runs the tests on Python 3.10 and 3.13 on every push.
