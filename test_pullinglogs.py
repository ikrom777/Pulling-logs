from pullinglogs import parse_line, parse_log, count_failed_by_ip, top_offenders, has_burst, detect_brute_force, detect_compromised, top_offenders_section, brute_force_section, compromised_section, build_report, main
import logging
import pytest
from datetime import datetime, timedelta

FAILED = "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2"
INVALID = "Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2"
ACCEPTED = "Oct 25 03:15:44 server sshd[1301]: Accepted password for alice from 192.0.2.10 port 50500 ssh2"
SUDO = "Oct 25 03:16:00 server sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls"
BOBB = "Nov 18 09:12:13 server sshd[3213]: Accepted password for bob from 10.0.0.1 port 50500 ssh2"
SPACEE = "Nov      1 09:12:13 server sshd[3213]: Accepted password for bob from 10.0.0.1 port 50500 ssh2"
BAD_IPP = "Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 999.999.999.999 port 22 ssh2"
FAILED2 = "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2"

@pytest.fixture
def sample_entries1():
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
    return entries

@pytest.fixture
def sample_report(sample_entries1):
    return build_report(sample_entries1, threshold=2, n=2)

def test_report_quiet_case(sample_entries1):
    report = build_report(sample_entries1, threshold=100, n=2)
    assert "No compromised logins detected." in report
    assert "No brute-force activity detected." in report
    assert "203.0.113.5" in report
    assert "root" not in report
    assert "(also compromised)" not in report

def test_report_section_order(sample_report):
    lines = sample_report.split("\n")
    compromised_pos = lines.index("COMPROMISED (failures followed by a successful login)")
    brute_force_pos = lines.index("BRUTE FORCE (burst of failed logins)")
    top_offenders_pos = lines.index("TOP OFFENDERS (total failed logins)")

    assert compromised_pos < brute_force_pos < top_offenders_pos

def test_contains_key_details(sample_report):
    assert "root" in sample_report
    assert "203.0.113.5" in sample_report
    assert "(also compromised)" in sample_report

def test_report_spacing(sample_report):
    lines = sample_report.split("\n")
    brute_force_pos = lines.index("BRUTE FORCE (burst of failed logins)")
    top_offenders_pos = lines.index("TOP OFFENDERS (total failed logins)")
    assert lines[-1] != ""
    assert lines[brute_force_pos - 1] == ""
    assert lines[top_offenders_pos - 1] == ""

def make_entry2(ip, event="failed", user="root", timestamp="Oct 25 03:12:01"):
    return {"timestamp": timestamp, "event": event, "user": user, "ip": ip}

@pytest.mark.parametrize(
    "rows, expected_count",
    [
        pytest.param(
            [("failed", "Oct 25 03:12:01", "1.1.1.1"),
             ("failed", "Oct 25 03:12:05", "1.1.1.1"),
             ("failed", "Oct 25 03:12:09", "1.1.1.1"),
             ("accepted", "Oct 25 03:12:30", "1.1.1.1")],
            1, id="exactly_threshold_flagged"),
        pytest.param(
            [("failed", "Oct 25 03:12:01", "1.1.1.1"),
             ("failed", "Oct 25 03:12:05", "1.1.1.1"),
             ("accepted", "Oct 25 03:12:30", "1.1.1.1")],
            0, id="below_threshold"),
        pytest.param(
            [("accepted", "Oct 25 03:12:01", "1.1.1.1"),
             ("failed", "Oct 25 03:12:05", "1.1.1.1"),
             ("failed", "Oct 25 03:12:09", "1.1.1.1"),
             ("failed", "Oct 25 03:12:12", "1.1.1.1")],
            0, id="failures_after_login"),
        pytest.param(
            [("failed", "Oct 25 03:12:01", "1.1.1.1"),
             ("failed", "Oct 25 03:12:05", "1.1.1.1"),
             ("failed", "Oct 25 03:12:09", "1.1.1.1"),
             ("accepted", "Oct 25 03:12:30", "2.2.2.2")],
            0, id="different_ip"),
        pytest.param(
            [("failed", "Oct 25 03:00:01", "1.1.1.1"),
             ("failed", "Oct 25 03:00:05", "1.1.1.1"),
             ("failed", "Oct 25 03:00:09", "1.1.1.1"),
             ("accepted", "Oct 25 03:20:00", "1.1.1.1")],
            0, id="failures_too_old"),
        pytest.param(
            [("failed", "Oct 25 03:07:30", "1.1.1.1"),
             ("failed", "Oct 25 03:12:05", "1.1.1.1"),
             ("failed", "Oct 25 03:12:09", "1.1.1.1"),
             ("accepted", "Oct 25 03:12:30", "1.1.1.1")],
            1, id="failure_exactly_at_cutoff_counts"),
        pytest.param([], 0, id="empty"),
    ],
)

def test_detect_compromised(rows, expected_count):
    entries = [make_entry2(ip=ip, event=event, timestamp=ts) for event, ts, ip in rows]
    result = detect_compromised(entries, threshold=3)
    assert len(result) == expected_count

def t(h, m, s=0):
    return datetime(2026, 10, 26, h, m, s)

@pytest.mark.parametrize(
    "timestamps, expected",
    [
        ([t(10,0,0), t(10,1), t(10,2), t(10,3), t(10,4,59)], True),
        ([t(10,0), t(10,10), t(10,20), t(10,30), t(10,40)], False),
        ([t(10,0,0), t(10,0,10), t(10,0,20), t(10,0,30)], False),
        ([], False),
        ([t(10,0,0), t(10,1), t(10,2), t(10,3), t(10,5,1)], False),
        ([t(8,0), t(8,30), t(9,0), t(9,30), t(10,0,0), t(10,0,10), t(10,0,20), t(10,0,30), t(10,0,40), t(11,0), t(11,30)], True),
    ],
    ids=["clear_burst", "spread_out", "4entries", "empty", "just_outside_window", "burst_in_middle"],
)
def test_has_burst(timestamps, expected):
    WINDOW = timedelta(minutes=5)
    assert has_burst(timestamps, threshold=5, window=WINDOW) is expected

A = "203.0.113.5"
B = "198.51.100.7"
C = "192.0.2.10"

def e(event, ip, ts):
    return {"timestamp": ts, "event": event, "user": "root", "ip": ip}

@pytest.mark.parametrize(
    "entries, expected",
    [
        # 1 one_attacker: 5 failures, 10 s apart
        ([e("failed", A, "Oct 25 03:12:01"), e("failed", A, "Oct 25 03:12:11"),
          e("failed", A, "Oct 25 03:12:21"), e("failed", A, "Oct 25 03:12:31"),
          e("failed", A, "Oct 25 03:12:41")], ["203.0.113.5"]),

        # 2 grouping: A and B interleaved, 3 failures each
        ([e("failed", A, "Oct 25 03:12:01"), e("failed", B, "Oct 25 03:12:11"),
          e("failed", A, "Oct 25 03:12:21"), e("failed", B, "Oct 25 03:12:31"),
          e("failed", A, "Oct 25 03:12:41"), e("failed", B, "Oct 25 03:12:51")],[]),

        # 3 filtering: 4 failures plus 1 accepted from the same IP
        ([e("failed", A, "Oct 25 03:12:01"), e("failed", A, "Oct 25 03:12:11"),
          e("failed", A, "Oct 25 03:12:21"), e("failed", A, "Oct 25 03:12:31"),
          e("accepted", A, "Oct 25 03:12:41")], []),

        # 4 sorting: 5 close failures, given in reverse time order
        ([e("failed", A, "Oct 25 03:12:41"), e("failed", A, "Oct 25 03:12:31"),
          e("failed", A, "Oct 25 03:12:21"), e("failed", A, "Oct 25 03:12:11"),
          e("failed", A, "Oct 25 03:12:01")], ["203.0.113.5"]),

        # 5 spread_out: 5 failures, 10 minutes apart
        ([e("failed", A, "Oct 25 03:00:00"), e("failed", A, "Oct 25 03:10:00"),
          e("failed", A, "Oct 25 03:20:00"), e("failed", A, "Oct 25 03:30:00"),
          e("failed", A, "Oct 25 03:40:00")], []),

        # 6 empty
        ([], []),

        # 7 attacker_and_innocent: A has 5 close failures, B has 2, C only logs in
        ([e("failed", A, "Oct 25 03:12:01"), e("failed", B, "Oct 25 03:12:05"),
          e("failed", A, "Oct 25 03:12:11"), e("failed", A, "Oct 25 03:12:21"),
          e("accepted", C, "Oct 25 03:12:25"), e("failed", B, "Oct 25 03:12:29"),
          e("failed", A, "Oct 25 03:12:31"), e("failed", A, "Oct 25 03:12:41")], ["203.0.113.5"]),

        # 8 two_attackers: both A and B have 5 close failures
        ([e("failed", A, "Oct 25 03:12:01"), e("failed", B, "Oct 25 03:12:02"),
          e("failed", A, "Oct 25 03:12:11"), e("failed", B, "Oct 25 03:12:12"),
          e("failed", A, "Oct 25 03:12:21"), e("failed", B, "Oct 25 03:12:22"),
          e("failed", A, "Oct 25 03:12:31"), e("failed", B, "Oct 25 03:12:32"),
          e("failed", A, "Oct 25 03:12:41"), e("failed", B, "Oct 25 03:12:42")], ["203.0.113.5", "198.51.100.7"]),

        # 9 window_edge: first and last failure exactly 5 minutes apart
        ([e("failed", A, "Oct 25 03:00:00"), e("failed", A, "Oct 25 03:01:00"),
          e("failed", A, "Oct 25 03:02:00"), e("failed", A, "Oct 25 03:03:00"),
          e("failed", A, "Oct 25 03:05:00")], []),
    ],
    ids=["one_attacker", "grouping", "filtering", "sorting", "spread_out",
         "empty", "attacker_and_innocent", "two_attackers", "window_edge"],
)
def test_detect_brute_force(entries, expected):
    assert detect_brute_force(entries) == expected

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

def test_top_offenders_rows():
    lines = top_offenders_section([("203.0.113.5", 2), ("198.51.100.7", 1)])
    assert lines[0] == "TOP OFFENDERS (total failed logins)"
    assert len(lines) == 3
    assert lines[1].startswith("203.0.113.5")
    assert lines[1].split()[-1] == "2"
    assert lines[2].startswith("198.51.100.7")


def test_top_offenders_empty():
    lines = top_offenders_section([])
    assert lines == [
        "TOP OFFENDERS (total failed logins)",
        "No failed logins recorded.",
    ]

def test_compromised_section_sorted():
    data = [
        {"ip": "198.51.100.7", "user": "admin",
         "timestamp": datetime(2026, 10, 25, 3, 20, 0), "failures": 2},
        {"ip": "203.0.113.5", "user": "root",
         "timestamp": datetime(2026, 10, 25, 3, 12, 30), "failures": 7},
    ]
    lines = compromised_section(data)
    assert lines[0] == "COMPROMISED (failures followed by a successful login)"
    assert len(lines) == 3
    assert lines[1].startswith("203.0.113.5")
    assert lines[1].split()[-3] == "7"
    assert lines[1].split()[-1] == "03:12:30"


def test_compromised_section_empty():
    lines = compromised_section([])
    assert lines == [
        "COMPROMISED (failures followed by a successful login)",
        'No compromised logins detected.',
    ]

def test_brute_force_section_mixed():
    flagged = ["203.0.113.5", "198.51.100.7"]
    compromised = [
        {"ip": "203.0.113.5", "user": "root",
         "timestamp": datetime(2026, 10, 25, 3, 12, 30), "failures": 2},
    ]
    lines = brute_force_section(flagged, compromised)
    assert lines[0] == "BRUTE FORCE (burst of failed logins)"
    assert lines[1].startswith("203.0.113.5")
    assert "(also compromised)" in lines[1]
    assert lines[2].startswith("198.51.100.7")
    assert "(also compromised)" not in lines[2]

def test_brute_force_section_empty():
    lines = brute_force_section([], [])
    assert lines == [
        "BRUTE FORCE (burst of failed logins)",
        "No brute-force activity detected.",
    ]

def test_brute_force_section_no_compromised():
    lines = brute_force_section(["198.51.100.7"], [])
    assert lines[-1] == ("198.51.100.7    ")

LINES = [
    "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2",
    "Oct 25 03:12:05 server sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2",
    "Oct 25 03:15:44 server sshd[1301]: Accepted password for alice from 192.0.2.10 port 50500 ssh2",
    "Oct 25 03:16:00 server sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls",
    "Oct 25 03:12:01 server sshd[1234]: Failed password for root from 999.999.999.999 port 52341 ssh2",
    "Oct 25 03:12:09 server sshd[1234]: Failed password for root from 203.0.113.5 port 52342 ssh2",
    "Oct 25 03:12:30 server sshd[1400]: Accepted password for root from 203.0.113.5 port 52350 ssh2",
]


def test_happy_path(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    result = main([str(log)])
    assert "COMPROMISED" in result
    assert "203.0.113.5" in result
    assert "No compromised logins detected" not in result