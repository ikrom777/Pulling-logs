from pullinglogs import parse_line, parse_log, count_failed_by_ip, top_offenders
import logging
import pytest

FAILED = "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2"
INVALID = "Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2"
ACCEPTED = "Oct 25 03:15:44 server sshd[1301]: Accepted password for alice from 192.0.2.10 port 50500 ssh2"
SUDO = "Oct 25 03:16:00 server sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls"
BOBB = "Nov 18 09:12:13 server sshd[3213]: Accepted password for bob from 10.0.0.1 port 50500 ssh2"
SPACEE = "Nov      1 09:12:13 server sshd[3213]: Accepted password for bob from 10.0.0.1 port 50500 ssh2"
BAD_IPP = "Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 999.999.999.999 port 22 ssh2"
FAILED2 = "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2"

@pytest.fixture
def sample_entries():
    return [
        make_entry("1.1.1.1"),
        make_entry("1.1.1.1"),
        make_entry("2.2.2.2"),
        make_entry("3.3.3.3", event="accepted"),
    ]

def make_entry(ip, event="failed", user="root"):
    return {"timestamp": "Oct 25 03:12:01", "event": event, "user": user, "ip": ip}

@pytest.mark.parametrize("entries, expected", [
    ([], {}),
    ([make_entry("1.1.1.1", event="accepted")], {}),
    ([make_entry("1.1.1.1")], {"1.1.1.1": 1})
])

def test_count_failed_by_ip_cases(entries, expected):
    assert count_failed_by_ip(entries) == expected

def test_counts_only_failed(sample_entries):
    result = count_failed_by_ip(sample_entries)
    assert result == {"1.1.1.1": 2, "2.2.2.2": 1}

def test_tops(sample_entries):
    result = top_offenders(sample_entries, n=1)
    assert result == [("1.1.1.1", 2)]

def test_tops_with_a_lot_of_n(sample_entries):
    result = top_offenders(sample_entries, n=10)
    assert result == [("1.1.1.1", 2), ("2.2.2.2", 1)]

def test_tops_with_a_default_n():
    entries = [
        make_entry("1.1.1.1"),
        make_entry("4.4.4.4"),
        make_entry("2.2.2.2"),
        make_entry("3.3.3.3"),
    ]
    result = top_offenders(entries)
    assert result == [("1.1.1.1", 1), ("4.4.4.4", 1), ("2.2.2.2", 1)]

def test_pipeline_counts_failures_from_raw_lines():
    lines = [FAILED, FAILED2, ACCEPTED, SUDO, BAD_IPP]
    result = count_failed_by_ip(parse_log(lines))
    assert result == {"203.0.113.5": 2}
    
def test_parse_log_skipping():
    result  = parse_log([FAILED, BAD_IPP, ACCEPTED])
    assert len(result) == 2

def test_acceptedlogin():
    result = parse_line(ACCEPTED)
    assert result["event"] == "accepted"
    assert result["user"] == "alice"

def test_unrelatedline():
    assert parse_line(SUDO) is None

def test_parselog():
    assert len(parse_log([FAILED, INVALID, ACCEPTED, SUDO])) == 3

def test_invaliduser():
    result = parse_line(INVALID)
    assert result["user"] == "admin"

def test_bad_ip(caplog):
    with caplog.at_level(logging.WARNING):
        result = parse_line(BAD_IPP)
    assert result is None
    assert BAD_IPP in caplog.text
    
def test_failed_login():
    result = parse_line(FAILED)
    assert result == {
        "timestamp": "Oct 25 03:12:01",
        "event": "failed",
        "user": "root",
        "ip": "203.0.113.5",
    }

def test_bob():
    result = parse_line(BOBB)
    assert result == {
        "timestamp": "Nov 18 09:12:13",
        "event": "accepted",
        "user": "bob",
        "ip": "10.0.0.1",
    }

def test_casespace():
    result = parse_line(SPACEE)
    assert result == {
        "timestamp": "Nov      1 09:12:13",
        "event": "accepted",
        "user": "bob",
        "ip": "10.0.0.1",
    }

def test_emptyinput():
    result = parse_line("")
    result2 = parse_log([])
    assert result is None
    assert result2 == []