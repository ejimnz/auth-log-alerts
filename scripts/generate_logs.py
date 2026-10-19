"""Write a fake but realistic auth.log with planted attacks.

Normal traffic: a few users logging in from their usual IPs, plus cron noise.
Planted attacks (so tests and demos know what should be caught):
  1. Brute force: 203.0.113.5 fails 30 passwords in about 2 minutes, mostly invalid users.
  2. Brute force that succeeds: 203.0.113.77 fails 8 times on "alice", then gets in.
  3. New-IP login: "bob" logs in once from 192.0.2.200, an IP he has never used.

All IPs are from the documentation ranges (RFC 5737), so nothing points at a real host.
Usage: python scripts/generate_logs.py > samples/auth.log
"""

import random
from datetime import datetime, timedelta

random.seed(388)  # fixed seed: same file every run

HOST = "web01"
USERS = {"alice": "198.51.100.7", "bob": "198.51.100.8", "carol": "198.51.100.9"}
GUESSES = ["root", "admin", "test", "oracle", "ubuntu", "guest", "postgres", "pi"]

lines: list[tuple[datetime, str]] = []
pid = 1000


def add(ts: datetime, program: str, message: str) -> None:
    global pid
    pid += 1
    lines.append((ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {program}[{pid}]: {message}"))


start = datetime(2026, 10, 15, 8, 0, 0)

# Normal day: each user logs in a few times from their own IP; cron runs hourly.
for hour in range(12):
    add(start + timedelta(hours=hour), "CRON", "pam_unix(cron:session): session opened for user root by (uid=0)")
for user, ip in USERS.items():
    for _ in range(4):
        ts = start + timedelta(minutes=random.randint(0, 11 * 60))
        if random.random() < 0.15:  # the occasional typo
            add(ts, "sshd", f"Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")
            ts += timedelta(seconds=5)
        method = random.choice(["password", "publickey"])
        suffix = ": RSA SHA256:" + "".join(random.choices("abcdef0123456789", k=12)) if method == "publickey" else ""
        add(ts, "sshd", f"Accepted {method} for {user} from {ip} port {random.randint(40000, 60000)} ssh2{suffix}")

# Attack 1: fast brute force from one IP.
ts = start + timedelta(hours=3, minutes=10)
for _ in range(30):
    user = random.choice(GUESSES)
    invalid = "" if user == "root" else "invalid user "
    add(ts, "sshd", f"Failed password for {invalid}{user} from 203.0.113.5 port {random.randint(40000, 60000)} ssh2")
    ts += timedelta(seconds=random.randint(2, 6))

# Attack 2: password guessing on a real account that eventually works.
ts = start + timedelta(hours=6, minutes=40)
for _ in range(8):
    add(ts, "sshd", f"Failed password for alice from 203.0.113.77 port {random.randint(40000, 60000)} ssh2")
    ts += timedelta(seconds=random.randint(3, 10))
add(ts, "sshd", f"Accepted password for alice from 203.0.113.77 port {random.randint(40000, 60000)} ssh2")

# Attack 3: a valid login from an IP the user has never used.
add(start + timedelta(hours=9, minutes=5), "sshd", f"Accepted password for bob from 192.0.2.200 port 51515 ssh2")

for _, line in sorted(lines):
    print(line)
