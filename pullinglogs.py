import re
import ipaddress
import logging
from collections import Counter

log = logging.getLogger(__name__)

PATTERN = re.compile(
    r"(?P<timestamp>[A-Za-z]+ +\d+ \d+:\d+:\d+) server sshd\[\d+\]: "
    r"(?P<event>Failed|Accepted) password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def count_failed_by_ip(entries):
    failed_ips = [entry["ip"] for entry in entries if entry["event"] == "failed"]
    return Counter(failed_ips)
    

def top_offenders(entries, n=3):
    counts = count_failed_by_ip(entries)
    return counts.most_common(n)

def parse_line(line):
    match = PATTERN.search(line)
    if not match:
        return None
    
    ip = match.group("ip")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        log.warning("Skipping line with invalid IP %r: %s", ip, line)
        return None
    
    return {
        "timestamp": match.group("timestamp"),
        "event": match.group("event").lower(),
        "user": match.group("user"),
        "ip": ip,
    }


def parse_log(lines):
    results = []
    for line in lines:
        result = parse_line(line)
        if result is not None:
            results.append(result)
    return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    lines = [
        "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2",
        "Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2",
        "Oct 25 03:15:44 server sshd[1301]: Accepted password for alice from 192.0.2.10 port 50500 ssh2",
        "Oct 25 03:16:00 server sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls",
        "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 999.999.999.999 port 52341 ssh2",
        "Oct 25 03:12:09 server sshd[1234]: Failed password for root from 203.0.113.5 port 52342 ssh2",
    ]
    entries = parse_log(lines)
    print(count_failed_by_ip(entries))
    print(top_offenders(entries, n = 2))