import re
import ipaddress
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

PATTERN = re.compile(
    r"(?P<timestamp>[A-Za-z]+ +\d+ \d+:\d+:\d+) server sshd\[\d+\]: "
    r"(?P<event>Failed|Accepted) password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def detect_compromised(entries, threshold=5, window=timedelta(minutes=5), year=2026):
    failures_by_ip = defaultdict(list)
    successes = []
    flagged = []
    for entry in entries:
        when = datetime.strptime(f"{year} {entry['timestamp']}", "%Y %b %d %H:%M:%S")
        if entry["event"] == "failed":
            failures_by_ip[entry["ip"]].append(when)
        elif entry["event"] == "accepted":
            successes.append((entry["user"], entry["ip"], when))
    for user, ip, when in successes:
        cutoff = when - window
        times = failures_by_ip[ip]      
        count = 0
        for t in times:
            if cutoff <= t < when:
                count += 1
        if count >= threshold:
            flagged.append({"ip": ip, "user": user, "timestamp": when, "failures": count})
    return flagged

def has_burst(timestamps, threshold, window):
    left = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] >= window:
            left = left + 1
        count = right - left + 1
        if count >= threshold:
            return True
    return False

def detect_brute_force(entries, threshold=5, window=timedelta(minutes=5), year=2026):
    groups = defaultdict(list)
    for entry in entries:
        if entry["event"] == "failed":
            when = datetime.strptime(f"{year} {entry['timestamp']}", "%Y %b %d %H:%M:%S")
            groups[entry["ip"]].append(when)

    flagged = []
    for ip, times in groups.items():
        times.sort()
        if has_burst(times, threshold, window):
            flagged.append(ip)
    return flagged

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
        "Oct 25 03:12:30 server sshd[1400]: Accepted password for root from 203.0.113.5 port 52350 ssh2",
    ]
    entries = parse_log(lines)
    print(count_failed_by_ip(entries))
    print(top_offenders(entries, n = 2))
    print(detect_brute_force(entries, threshold=2))
    print(detect_compromised(entries, threshold=2))
