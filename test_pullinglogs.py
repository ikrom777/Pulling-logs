from pullinglogs import parse_line, parse_log
import logging

FAILED = "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2"
INVALID = "Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2"
ACCEPTED = "Oct 25 03:15:44 server sshd[1301]: Accepted password for alice from 192.0.2.10 port 50500 ssh2"
SUDO = "Oct 25 03:16:00 server sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls"
BOBB = "Nov 18 09:12:13 server sshd[3213]: Accepted password for bob from 10.0.0.1 port 50500 ssh2"
SPACEE = "Nov      1 09:12:13 server sshd[3213]: Accepted password for bob from 10.0.0.1 port 50500 ssh2"
BAD_IPP = "Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 999.999.999.999 port 22 ssh2"

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
