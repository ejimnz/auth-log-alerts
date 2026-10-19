"""Turn sshd lines from a syslog-style auth.log into LoginEvent objects.

Example lines this understands:
  Oct 15 14:02:11 web01 sshd[2231]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2
  Oct 15 14:03:02 web01 sshd[2240]: Accepted publickey for alice from 198.51.100.7 port 50022 ssh2: RSA SHA256:abc

Lines that aren't SSH login attempts (cron, sudo, other sshd messages) are skipped.
"""

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from authlog.events import LoginEvent

# Syslog prefix: "Oct 15 14:02:11 web01 sshd[2231]: <message>"
# The day is space-padded for single digits ("Oct  5"), hence \s+.
_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[\d+\]: (?P<message>.*)$"
)

# The message part of an accepted or failed login.
_LOGIN = re.compile(
    r"^(?P<result>Accepted|Failed) (?P<method>password|publickey) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


def parse_line(line: str, year: int) -> LoginEvent | None:
    """Parse one log line. Returns None if it isn't an SSH login attempt.

    Syslog timestamps have no year, so the caller supplies it.
    """
    prefix = _PREFIX.match(line.strip())
    if prefix is None:
        return None
    login = _LOGIN.match(prefix["message"])
    if login is None:
        return None

    timestamp = datetime.strptime(
        f"{year} {prefix['month']} {prefix['day']} {prefix['time']}", "%Y %b %d %H:%M:%S"
    )
    return LoginEvent(
        timestamp=timestamp,
        host=prefix["host"],
        user=login["user"],
        ip=login["ip"],
        port=int(login["port"]),
        success=login["result"] == "Accepted",
        method=login["method"],
        invalid_user=login["invalid"] is not None,
    )


def parse_lines(lines: Iterable[str], year: int) -> Iterator[LoginEvent]:
    """Yield a LoginEvent for every login line, skipping everything else."""
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event
