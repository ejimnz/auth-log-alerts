from datetime import datetime

from authlog.parser import parse_line, parse_lines

YEAR = 2026


def test_accepted_password():
    e = parse_line(
        "Oct 15 14:03:02 web01 sshd[2240]: Accepted password for alice from 198.51.100.7 port 50022 ssh2",
        YEAR,
    )
    assert e is not None
    assert e.timestamp == datetime(2026, 10, 15, 14, 3, 2)
    assert e.host == "web01"
    assert e.user == "alice"
    assert e.ip == "198.51.100.7"
    assert e.port == 50022
    assert e.success is True
    assert e.method == "password"
    assert e.invalid_user is False


def test_accepted_publickey_with_key_suffix():
    e = parse_line(
        "Oct 15 14:03:02 web01 sshd[2240]: Accepted publickey for bob from 198.51.100.8 port 50023 ssh2: RSA SHA256:abc",
        YEAR,
    )
    assert e.method == "publickey"
    assert e.success is True


def test_failed_password_for_invalid_user():
    e = parse_line(
        "Oct 15 14:02:11 web01 sshd[2231]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2",
        YEAR,
    )
    assert e.success is False
    assert e.invalid_user is True
    assert e.user == "admin"


def test_single_digit_day_is_space_padded():
    e = parse_line(
        "Oct  5 09:00:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2",
        YEAR,
    )
    assert e.timestamp == datetime(2026, 10, 5, 9, 0, 0)


def test_non_login_lines_are_skipped():
    assert parse_line("Oct 15 14:00:01 web01 CRON[100]: pam_unix(cron:session): session opened", YEAR) is None
    assert parse_line("Oct 15 14:00:02 web01 sshd[2231]: Connection closed by 203.0.113.5 port 52144", YEAR) is None
    assert parse_line("", YEAR) is None
    assert parse_line("garbage", YEAR) is None


def test_parse_lines_keeps_only_logins():
    lines = [
        "Oct 15 14:00:01 web01 CRON[100]: pam_unix(cron:session): session opened",
        "Oct 15 14:02:11 web01 sshd[2231]: Failed password for root from 203.0.113.5 port 52144 ssh2",
        "Oct 15 14:03:02 web01 sshd[2240]: Accepted password for alice from 198.51.100.7 port 50022 ssh2",
    ]
    events = list(parse_lines(lines, YEAR))
    assert [e.success for e in events] == [False, True]
