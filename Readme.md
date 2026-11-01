# SSH Log Analyser

A small Python tool that parses SSH authentication logs, counts failed logins per IP address, and flags likely brute-force attacks.

## Features

- **Log parsing**: extracts timestamp, event (`failed` / `accepted`), user and IP from `sshd` password-login lines using a regex. Lines that don't match are ignored.
- **IP validation**: every IP is checked with Python's `ipaddress` module. Lines with invalid IPs such as `999.999.999.999` are skipped and a warning is logged.
- **Failed-login counting**: `count_failed_by_ip` returns a `Counter` of failed logins per IP, and `top_offenders` returns the most active ones.
- **Brute-force detection**: `detect_brute_force` flags any IP with at least `threshold` failed logins inside a sliding time `window`. The defaults are 5 failures within 5 minutes.

## How detection works

1. Keep only `failed` entries and group them by IP.
2. Parse each timestamp into a `datetime` (the log has no year, so a `year` parameter is added) and sort each IP's times.
3. `has_burst` slides a window over the sorted times. If `threshold` failures fall inside the window, the IP is flagged.

A span of exactly `window` between the first and last failure does **not** count as inside the window.

## Usage

```python
from pullinglogs import parse_log, detect_brute_force, top_offenders

entries = parse_log(lines)                 # list of dicts: timestamp, event, user, ip
top_offenders(entries, n=3)                # [("203.0.113.5", 12), ...]
detect_brute_force(entries)                # ["203.0.113.5"]
detect_brute_force(entries, threshold=3)   # custom threshold
```

Running the file directly executes a small demo:

```
python pullinglogs.py
```

Demo output:

```
Counter({'203.0.113.5': 2, '198.51.100.7': 1})
[('203.0.113.5', 2), ('198.51.100.7', 1)]
['203.0.113.5']
```

## Tests

Tests use `pytest`, with `pytest-cov` for coverage.

```
pip install pytest pytest-cov
pytest -v
pytest --cov=pullinglogs --cov-report=term-missing
```

The tests cover:

- parsing, including invalid IPs (with `caplog`) and non-matching lines
- counting and top offenders, including edge cases
- `has_burst`: clear burst, spread-out failures, one below the threshold, exactly at the threshold, window edges, a burst in the middle, and an empty list
- `detect_brute_force`: grouping by IP, ignoring accepted logins, unsorted input, spread-out failures, an empty list and custom parameters
- an integration test from raw log lines to flagged IPs

Coverage is 90% of the module. The only uncovered lines are the `if __name__ == "__main__":` demo block.

## Limitations

- Only matches `sshd` password logins in this specific log format.
- Only IPv4 addresses are matched by the regex.
- Timestamps carry no year, so the year is supplied as a parameter and defaults to 2026.

## Possible next steps

- Support more event types (invalid user, publickey) and IPv6
- Read logs from a file or stdin
- Add anomaly detection and an evaluation of it