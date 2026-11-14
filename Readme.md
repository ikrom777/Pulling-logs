# Pulling Logs: SSH Auth Log Analyser

A small Python command-line tool that reads a Linux auth log and flags suspicious SSH activity.

## What it detects

- **Compromised logins:** an IP with failed logins followed by a successful login
- **Brute force:** a burst of failed logins from one IP within a time window
- **Top offenders:** the IPs with the most failed logins

Lines with an invalid IP address (for example `999.999.999.999`) are skipped with a logged warning.

## Requirements

- Python 3.10+
- `pytest` and `pytest-cov` (only for running the tests)

## Usage

```
python pullinglogs.py LOGFILE [-t THRESHOLD] [-w WINDOW] [-y YEAR] [-n TOP]
```

| Option | Meaning | Default |
|---|---|---|
| `LOGFILE` | Path to the log file | required |
| `-t`, `--threshold` | Minimum failed logins before an IP is flagged | 2 |
| `-w`, `--window` | Time window in minutes for detecting bursts | 5 |
| `-y`, `--year` | Year to use, since syslog timestamps have no year | 2026 |
| `-n`, `--top` | Number of top offenders to show | 3 |

Example:

```
python pullinglogs.py sample_auth.log --threshold 3 --window 10 --top 5
```

Show all options with:

```
python pullinglogs.py -h
```

## Example output

```
COMPROMISED (failures followed by a successful login)
203.0.113.5     root      2    2026-10-25 03:12:30

BRUTE FORCE (burst of failed logins)
203.0.113.5     (also compromised)

TOP OFFENDERS (total failed logins)
203.0.113.5     2
198.51.100.7    1
```

A sample log file, `sample_auth.log`, is included in the repository.

## Running the tests

```
pytest
pytest --cov=pullinglogs --cov-report=term-missing
```

Current coverage is 98%. The only uncovered lines are the `__main__` entry point.

## Project notes

- The command-line interface is built with `argparse`. `main(argv=None)` returns the report as text, so tests call it directly without needing a terminal.
- Code was scanned with Bandit.