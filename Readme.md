# SSH Log Parser

A small Python tool that reads SSH authentication log lines (as found in `/var/log/auth.log`) and turns them into structured data. It is the first building block of a log analyser for spotting suspicious login activity, such as brute-force attempts.

## What it does

- Extracts login events from `sshd` log lines using a regular expression.
- Records the timestamp, event type (`failed` or `accepted`), username and source IP address.
- Handles failed logins for users that do not exist ("invalid user").
- Validates every IP address with Python's `ipaddress` module, so values like `999.999.999.999` are rejected even though they match the regex.
- Skips lines that are not SSH login events (for example `sudo` entries) and logs a warning when a line contains an invalid IP, instead of crashing.

## Example

Input:

```
Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2
```

Output:

```python
{
    "timestamp": "Oct 25 03:12:01",
    "event": "failed",
    "user": "root",
    "ip": "203.0.113.5",
}
```

## Usage

```bash
python pullinglogs.py
```

To use it in your own code:

```python
from pullinglogs import parse_line, parse_log

entry = parse_line(line)   # a dict, or None if the line is not usable
entries = parse_log(lines) # a list of dicts, unusable lines are dropped
```

## Running the tests

```bash
pip install pytest pytest-cov
pytest -v
pytest --cov=pullinglogs --cov-report=term-missing
```

The tests cover accepted and failed logins, invalid users, irregular spacing in timestamps, unrelated lines, empty input, invalid IP handling, and the warning log message (using pytest's `caplog` fixture).

## Known limitations

- Only IPv4 addresses are matched. Log lines with IPv6 addresses are ignored.
- The log format is fixed: the hostname in the pattern is `server`, and only password-based `Failed` and `Accepted` events are recognised.
- Timestamps do not include a year, because the syslog format does not store one.

## Planned

- Count failed logins per IP address to flag possible brute-force attempts.
- Read log lines from a file instead of a hard-coded list.