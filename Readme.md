# SSH Log Analyser

A small Python tool that reads SSH authentication log lines (syslog format), detects suspicious activity, and prints a plain-text report. It works as a command-line tool and as a Python module.

It looks for three things:

- **Compromised logins**: an IP that failed to log in several times within a short window and was then followed by a successful login.
- **Brute-force bursts**: an IP with many failed logins inside a short time window, whether or not it eventually got in.
- **Top offenders**: the IPs with the most failed logins overall.

## Requirements

- Python 3.9 or newer (standard library only)
- `pytest` and `pytest-cov` for the tests

## Quick start

### Command line

```
python pullinglogs.py sample_auth.log
python pullinglogs.py sample_auth.log --threshold 3 --window 10 --top 5
```

A sample log file, `sample_auth.log`, is included in the repository.

| Option | Meaning | Default |
|--------|---------|---------|
| `logfile` | Path to the log file | required |
| `-t`, `--threshold` | Failed logins needed to flag a compromise or a brute-force burst | `2` |
| `-w`, `--window` | Time window in minutes in which the failures must happen | `5` |
| `-y`, `--year` | Year added to timestamps | `2026` |
| `-n`, `--top` | Number of top offenders to list | `3` |

Show all options with:

```
python pullinglogs.py -h
```

### As a module

```python
from pullinglogs import parse_log, build_report

with open("auth.log") as f:
    entries = parse_log(f)

print(build_report(entries, threshold=5, n=3))
```

Note that the module function `build_report` defaults to a threshold of `5`, while the command line defaults to `2`.

## Input format

The parser expects `sshd` lines like these:

```
Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2
Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2
Oct 25 03:15:44 server sshd[1301]: Accepted password for alice from 192.0.2.10 port 50500 ssh2
```

- Lines that don't match (for example `sudo` lines) are skipped.
- Lines with an invalid IP address (for example `999.999.999.999`) are skipped, and a warning is logged.
- Syslog timestamps have no year, so the `year` setting supplies one (default `2026`).

## Main functions

| Function | What it does |
|----------|--------------|
| `main(argv=None)` | Command-line entry point. Parses the arguments, reads the file and returns the report as text. Pass a list as `argv` to call it without a terminal. |
| `parse_log(lines)` | Turns raw lines into a list of dicts with `timestamp`, `event`, `user` and `ip`. |
| `detect_compromised(entries, threshold, window, year)` | Returns logins that came after at least `threshold` failures from the same IP inside `window`. |
| `detect_brute_force(entries, threshold, window, year)` | Returns IPs with at least `threshold` failed logins inside `window`, using a sliding window. |
| `top_offenders(entries, n)` | Returns the `n` IPs with the most failed logins. |
| `build_report(entries, threshold, window, year, n)` | Runs all detectors and returns the full report as one string. |

## Report settings

`build_report` accepts these parameters:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `threshold` | `5` | Failed logins needed to flag a compromise or a brute-force burst |
| `window` | `timedelta(minutes=5)` | Time span in which the failures must happen |
| `year` | `2026` | Year added to timestamps |
| `n` | `3` | Number of top offenders to list |

## Example output

Running `python pullinglogs.py sample_auth.log`:

```
COMPROMISED (failures followed by a successful login)
203.0.113.5     root      2    2026-10-25 03:12:30

BRUTE FORCE (burst of failed logins)
203.0.113.5     (also compromised)

TOP OFFENDERS (total failed logins)
203.0.113.5     2
198.51.100.7    1
```

When nothing is detected, each section says so, for example `No compromised logins detected.`

An IP flagged as both a burst and a compromise is marked `(also compromised)` in the brute-force section.

## Tests

```
pytest --cov=pullinglogs --cov-report=term-missing
```

Current coverage is 98%. Only the `__main__` entry point is uncovered.

The report tests check:

- the three sections appear in the right order,
- key details (user, IP, the `(also compromised)` marker) are present,
- blank lines separate the sections and the report doesn't end with a blank line,
- the quiet case, where a very high threshold produces the "No ... detected" messages.

The command-line tests check:

- a normal run on a log file finds the compromised IP,
- a missing log file raises `FileNotFoundError`,
- an invalid option value (for example `-t abc`) exits with code 2.