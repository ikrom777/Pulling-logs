# SSH Log Analyser

A small Python tool that parses SSH authentication logs (`sshd` lines) and flags suspicious activity: heavy failed-login sources, brute-force bursts, and logins that succeeded right after repeated failures.

Built as a learning project in security and Python, with a focus on clean, testable functions.

## Features

- **Log parsing:** extracts timestamp, event (failed/accepted), user and IP from `sshd` lines using a regular expression. Lines that don't match are ignored.
- **IP validation:** every IP is checked with the standard `ipaddress` module. Invalid addresses (for example `999.999.999.999`) are skipped and a warning is logged.
- **Failed logins per IP:** `count_failed_by_ip` returns a `Counter`, and `top_offenders` returns the worst `n` IPs.
- **Brute-force detection:** `detect_brute_force` flags IPs with at least `threshold` failed logins inside a sliding time window.
- **Compromise detection:** `detect_compromised` flags successful logins that were preceded by at least `threshold` failures from the same IP within the window.
- **Report sections:** `compromised_section`, `brute_force_section` and `top_offenders_section` turn detection results into lists of formatted lines. They return data and never print, which keeps them easy to test.

## Requirements

- Python 3.10 or newer
- `pytest` and `pytest-cov` for the tests

The analyser itself only uses the standard library.

## Usage

The file `pullinglogs.py` contains the functions and a demo in its `__main__` block, which runs on a hardcoded sample log:

```bash
python pullinglogs.py
```

Using the functions in your own code:

```python
from datetime import timedelta
from pullinglogs import (
    parse_log, count_failed_by_ip, top_offenders,
    detect_brute_force, detect_compromised,
)

with open("auth.log") as f:
    entries = parse_log(f)

print(top_offenders(entries, n=3))
print(detect_brute_force(entries, threshold=5, window=timedelta(minutes=5)))
print(detect_compromised(entries, threshold=5, window=timedelta(minutes=5)))
```

### Example

Input lines:

```
Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2
Oct 25 03:12:09 server sshd[1234]: Failed password for root from 203.0.113.5 port 52342 ssh2
Oct 25 03:12:30 server sshd[1400]: Accepted password for root from 203.0.113.5 port 52350 ssh2
Oct 25 03:15:44 server sshd[1301]: Accepted password for alice from 192.0.2.10 port 50500 ssh2
```

With `threshold=2`:

```python
detect_brute_force(entries, threshold=2)
# ['203.0.113.5']

detect_compromised(entries, threshold=2)
# [{'ip': '203.0.113.5', 'user': 'root',
#   'timestamp': datetime(2026, 10, 25, 3, 12, 30), 'failures': 2}]
```

`alice` is not flagged, because she had no failed logins before her successful one.

## How detection works

- **Brute force** groups failed logins by IP, sorts each IP's timestamps, and uses a sliding window (two pointers) to check whether `threshold` failures fall inside one window.
- **Compromise** collects failures per IP and all successful logins, then for each success counts that IP's failures in the half-open interval `[login time - window, login time)`.

## Tests

```bash
pytest
pytest --cov=pullinglogs --cov-report=term-missing
```

The suite covers parsing, IP validation (including logging checks with `caplog`), counting, both detectors with threshold and boundary cases (parametrized), and the report section helpers.

Current coverage is 87%. The uncovered lines are the `if __name__ == "__main__":` demo block.

## Limitations

- Only the `sshd` password format (`Failed password` / `Accepted password`) is parsed. Other methods, such as public key authentication, are not matched.
- Only IPv4 addresses are matched by the regular expression.
- Syslog timestamps have no year, so the year is a parameter (default `2026`).
- The demo uses a hardcoded sample, and there is no command-line interface yet.

## Possible next steps

- Combine the report sections into one `build_report` function.
- Add a command-line interface with `argparse` that reads a log file path.
- Support more `sshd` message formats and IPv6.
- Add anomaly detection for unusual login times and usernames.