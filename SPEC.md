# auth-log-alerts: SSH Login Detection Service

**Project spec, v1.0, 2026-10-19**

| Milestone | Focus | Checkpoint (end of week) |
|---|---|---|
| 1 | Parser + CLI | Wed 2026-10-21 |
| **2** | **Detection engine (hand-written)** | **Wed 2026-10-28** |
| 3 | SQLite storage, FastAPI REST API, GitHub Actions CI | Wed 2026-11-04 |
| 4 | Docker image, React alerts page | Wed 2026-11-11 |
| 5 | AWS deploy, PostgreSQL | Wed 2026-11-18 |
| 6 | Polish, stretch rules, demo | Wed 2026-11-25 |

Each checkpoint has to be something you can demo. If a week slips, push the dates back and say so in `DEVLOG.md`. Don't cut a milestone's tests to make a date.

---

## Table of contents

1. [Introduction](#introduction)
2. [Learning goals](#learning-goals)
3. [Where to start](#where-to-start)
4. [System overview](#system-overview)
5. [Milestone 1: Parser](#milestone-1-parser)
6. [Milestone 2: Detection engine](#milestone-2-detection-engine)
7. [Milestone 3: Storage, REST API, CI](#milestone-3-storage-rest-api-ci)
8. [Milestone 4: Docker and React](#milestone-4-docker-and-react)
9. [Milestone 5: AWS and PostgreSQL](#milestone-5-aws-and-postgresql)
10. [Milestone 6: Polish and stretch goals](#milestone-6-polish-and-stretch-goals)
11. [Testing](#testing)
12. [Code quality](#code-quality)
13. [Dev log](#dev-log)
14. [Definition of done (the "autograder")](#definition-of-done-the-autograder)
15. [FAQ](#faq)
16. [Appendix A: auth.log format](#appendix-a-authlog-format)
17. [Appendix B: MITRE ATT&CK mapping](#appendix-b-mitre-attck-mapping)

---

## Introduction

Every Linux server that runs SSH gets probed all day. Bots try `root`/`admin`/`pi` with common passwords, and now and then a real account is logged into from somewhere it has never been. `sshd` writes each attempt to `/var/log/auth.log`. Nobody reads that file by hand, and that gap is what security tools like SIEMs and EDRs exist to fill.

In this project you build a small version of that pipeline:

1. **Parse** raw `auth.log` lines into structured login events.
2. **Detect** suspicious patterns with rules you write, and tag each alert with its MITRE ATT&CK technique.
3. **Store** alerts and **serve** them over a REST API.
4. **Show** them on a small web page.
5. **Ship** it: tests in CI, a Docker image, and a deployment on AWS.

When you're done you'll have a public, deployed, tested backend service. You'll be able to explain every design decision in it and tell the story of at least one real bug.

## Learning goals

By the end of this project you should be able to:

- Design a streaming, stateful detection engine and explain its time and space complexity (sliding windows, per-key state).
- Map a detection to a MITRE ATT&CK technique and describe how an attacker would get around it.
- Design and document a REST API with filtering, pagination and correct status codes, built with FastAPI.
- Write a pytest suite with fixtures and parametrized cases, and run it in GitHub Actions on every push.
- Package a Python service in Docker and deploy it on AWS with a managed PostgreSQL database.
- Keep a dev log that records why you made each decision, not only what you did.

---

## Where to start

You're at the end of Milestone 1. Here's what to do next, in order:

1. **Make the first commit.** The repo has no commits yet. Run `pytest` and read the diff, then commit Milestone 1 as `Parse SSH login events from auth.log`. From here on, commit small and often.
2. **Read [Milestone 2](#milestone-2-detection-engine) end to end** before writing any code, the same way you would read a 281 spec before touching `main.cpp`.
3. **Work the sample by hand.** Open `samples/auth.log` and the generator's docstring (`scripts/generate_logs.py`). Using the rules in this spec, find each alert yourself and check your list against [the expected output](#expected-output-on-the-sample-log). If you disagree with it, figure out why. That's your first DEVLOG entry for the week.
4. **Make the open design decisions** (marked **🧭 Your call**) and write each one in `DEVLOG.md` before you code it.
5. **Write the tests first** for the brute-force rule, using the tiny hand-made logs described in [Testing](#testing). Then implement it.
6. Then do `new_ip`, then `brute_force_success`, then the CLI `--alerts` output, and finally `diff` against the expected output.

> **Pro-tip:** Brute force is the right rule to start with. Its sliding window is the most interesting data structure in the project and the most likely place for an off-by-one. You want to hit that bug early, while the codebase is still small.

---

## System overview

```
                      ┌──────────────── authlog package ────────────────┐
 auth.log ──lines──▶  │ parser.py ──LoginEvent──▶ engine.py ──Alert──▶  │
 (file or POST body)  │              (M1)          rules/*.py   (M2)    │
                      └───────────────────────────────┬─────────────────┘
                                                      │
                          ┌───────────────────────────┼──────────────────┐
                          ▼                           ▼                  ▼
                   CLI (cli.py)               store.py (M3)        FastAPI app (M3)
                   prints alerts          SQLite → PostgreSQL (M5)  /api/v1/...
                                                                         │
                                                              React page (M4)
```

The core rule of the architecture: **parser, engine and rules know nothing about the database or HTTP.** The engine takes `LoginEvent`s and returns `Alert`s. The CLI, the API and the tests are all just callers. That keeps the engine unit-testable in milliseconds and lets you swap SQLite for PostgreSQL without touching detection code.

### Target layout (by end of M4)

```
src/authlog/
  events.py        LoginEvent (M1)
  parser.py        auth.log → LoginEvent (M1)
  alerts.py        Alert, Severity (M2)
  engine.py        runs rules over an event stream (M2)
  rules/           one module per rule (M2, M6)
  cli.py           command line (M1, M2)
  store.py         database access (M3)
  api.py           FastAPI app (M3)
tests/
  test_parser.py
  test_rules_*.py
  test_engine.py
  test_api.py
samples/
  auth.log
  expected-alerts.txt
web/               React page (M4)
Dockerfile         (M4)
.github/workflows/ci.yml   (M3)
```

---

## Milestone 1: Parser

**Status: done** (`src/authlog/parser.py`, `tests/test_parser.py`).

What it does: turns `Accepted`/`Failed` `password`/`publickey` lines into frozen `LoginEvent` dataclasses and skips every other line. The year comes in as a parameter because syslog timestamps don't include one.

Before you close M1, check off the following:

- [ ] `pytest` passes.
- [ ] `authlog samples/auth.log` prints `53 login attempts, 39 failed`.
- [ ] First commit made.
- [ ] DEVLOG mentions known limitations you chose not to handle: logs that cross New Year, IPv6 addresses (does `\S+` already cover them? Write a test to find out), and `Invalid user X from IP` lines, which are a different message from `Failed password for invalid user`.

---

## Milestone 2: Detection engine

> **This milestone is yours to write by hand.** Claude may write tests, fixtures and scaffolding around it if you ask. For the engine and the rules, the help ladder is: questions → a hint → pointing at the bug → an analogous example → writing it only if you explicitly ask.

### 2.1 Alerts

Each alert has at least the following fields. The names are fixed because the API and the database use them later.

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | `datetime` | Time of the event that **triggered** the alert |
| `rule` | `str` | Rule ID: `brute_force`, `brute_force_success`, `new_ip` |
| `technique` | `str` | ATT&CK ID, e.g. `T1110.001` |
| `severity` | `low` \| `medium` \| `high` | See each rule |
| `ip` | `str` | Source IP |
| `user` | `str \| None` | Account involved, if the rule is about one account |
| `details` | `dict[str, int \| str]` | Rule-specific facts, e.g. `{"failures": 5}` |

Like `LoginEvent`, `Alert` should be immutable.

### 2.2 Engine contract

- The engine takes `LoginEvent`s **one at a time, in timestamp order**, and returns the alerts (zero or more) that each event triggers. It must not need the whole log in advance. In M3 the same engine processes lines that arrive over HTTP, a few at a time.
- Rules are **stateful** (they remember recent failures and known IPs). State persists across calls.
- When one event triggers several alerts, they come out in **rule order**: `brute_force`, then `brute_force_success`, then `new_ip`.
- **Complexity requirement:** processing *n* events takes **O(n)** time overall (amortized O(1) per event) and memory proportional to the number of distinct IPs and users plus the events inside the current window. A solution that rescans the event history on every event doesn't meet the spec, even if its output is correct.

> 🧭 **Your call: how rules plug in.** The options: a `Rule` base class with `def process(self, event) -> list[Alert]`, a `typing.Protocol`, or plain classes the engine calls in a fixed order. Think about how you'll add a fourth rule in M6, and how the rule configuration (thresholds) gets in. Record the choice and the alternative you rejected.

### 2.3 Rules

Default parameters: `N = 5` failures, window `W = 5 minutes`. They have to be configurable (as constructor arguments at minimum). Tests use other values.

#### Rule `brute_force`: T1110.001 Password Guessing, severity `medium`

- On each **failed** event from IP `x` at time `t`, count the failures from `x` with timestamps in the closed interval `[t − W, t]`.
- If the count is **≥ N**, emit an alert with `ip = x`, `user = None`, `details = {"failures": count}`.
- **Cooldown:** after alerting on `x` at time `t₀`, don't alert on `x` again for failures before `t₀ + W`. A 30-attempt burst produces **one** alert, not 26.
- Failures for valid and invalid users both count.

#### Rule `brute_force_success`: T1110.001 Password Guessing, severity `high`

- On each **successful** event from IP `x` for user `u` at time `t`: if `x` has **≥ N** failures in `[t − W, t]`, emit an alert with `ip = x`, `user = u`, `details = {"failures": count}`.
- This is the alert a human should see first, because the guessing worked.

> 🧭 **Your call:** should this rule share failure history with `brute_force` (one structure, two readers) or keep its own? Sharing is less memory and code, but it couples the two. Pick one and defend it.

#### Rule `new_ip`: T1078 Valid Accounts, severity `low`

- Track, per user, the set of IPs with at least one **successful** login.
- On a successful login by `u` from `x`:
  - If `u` has no known IPs, this is the **baseline**: record `x` and **don't** alert.
  - Otherwise, if `x` isn't in `u`'s set, emit an alert with `ip = x`, `user = u`, `details = {}`, then add `x` to the set. Each new (user, IP) pair alerts once.
- Failed logins never add an IP.

> 🧭 **Your call: the baseline.** "The first login is trusted" is the simplest rule that gives the expected output, but it has a real hole: an attacker whose first-ever login is the malicious one never gets flagged. Alternatives are a learning period (no alerts for the first X hours) or a `known_ips` file loaded at startup. Whatever you choose, write the weakness in DEVLOG. This is a great interview question, and you want to have answered it already.

### 2.4 Command line

Add an `--alerts` flag. Without it, `authlog` behaves exactly as it does now. With it, `authlog` prints **only** the alerts, one per line, then a blank line and a summary:

```
f"{a.timestamp:%Y-%m-%d %H:%M:%S}  {SEVERITY:<6}  {a.rule:<19}  {a.technique:<9}  ip={a.ip}[ user={a.user}][ failures={n}]"
```

- `SEVERITY` is uppercase.
- ` user=…` appears only when `user` is not `None`. ` failures=…` appears only when `details` has it.
- The summary line: `{k} alerts ({h} high, {m} medium, {l} low)`.
- Also add `--window SECONDS` and `--threshold N`, which override the defaults.

#### Expected output on the sample log

`authlog --year 2026 --alerts samples/auth.log` must print exactly:

```
2026-10-15 11:10:15  MEDIUM  brute_force          T1110.001  ip=203.0.113.5 failures=5
2026-10-15 14:40:30  MEDIUM  brute_force          T1110.001  ip=203.0.113.77 failures=5
2026-10-15 14:41:02  HIGH    brute_force_success  T1110.001  ip=203.0.113.77 user=alice failures=8
2026-10-15 14:41:02  LOW     new_ip               T1078      ip=203.0.113.77 user=alice
2026-10-15 17:05:00  LOW     new_ip               T1078      ip=192.0.2.200 user=bob

5 alerts (1 high, 2 medium, 2 low)
```

Save this as `samples/expected-alerts.txt` and test it 281-style:

```bash
authlog --year 2026 --alerts samples/auth.log | diff - samples/expected-alerts.txt && echo PASS
```

Things to notice in the expected output (and test separately):

- Bob's single typo at 10:06 followed by a success is **not** an alert. Normal users mistype.
- The 30-failure burst from `203.0.113.5` gives **one** `brute_force` alert (cooldown).
- Alice at 14:41:02 triggers **two** alerts from **one** event, in rule order.
- Each user's first login (alice 08:11, bob 10:06, carol 09:36) is a baseline, not an alert.

If you change a 🧭 decision in a way that changes this output, update `expected-alerts.txt` in the **same commit** and explain the change in DEVLOG.

### 2.5 M2 checkpoint demo

`authlog --alerts samples/auth.log` prints the five alerts above. `pytest` passes with rule unit tests (see [Testing](#testing)). DEVLOG has entries for every 🧭 decision and at least one bug you hit.

---

## Milestone 3: Storage, REST API, CI

### 3.1 Database (SQLite)

At minimum:

```sql
CREATE TABLE alerts (
  alertid    INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp  TEXT NOT NULL,          -- ISO 8601, event time
  created    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- when stored
  rule       TEXT NOT NULL,
  technique  TEXT NOT NULL,
  severity   TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
  ip         TEXT NOT NULL,
  user       TEXT,
  details    TEXT NOT NULL DEFAULT '{}',   -- JSON
  status     TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged'))
);

CREATE TABLE known_ips (
  user        TEXT NOT NULL,
  ip          TEXT NOT NULL,
  first_seen  TEXT NOT NULL,
  PRIMARY KEY (user, ip)
);
```

`known_ips` exists because the `new_ip` rule's state has to **survive restarts**. Otherwise every restart would re-baseline every user and miss the next new-IP login.

> 🧭 **Your call:** do you also persist the brute-force window state, or accept that a restart forgets the last 5 minutes? (Either answer is fine if you can say why.) Also: raw `sqlite3` with SQL you write (like 485), or SQLAlchemy? Raw SQL is simpler now. SQLAlchemy makes M5's switch to PostgreSQL cheaper.

All database access lives in `store.py`. Nothing else imports `sqlite3`.

### 3.2 REST API (FastAPI)

All routes are under `/api/v1/`. Responses are JSON. Errors return `{"detail": "<message>"}` with the right status code. Write endpoints require the header `X-API-Key: <key>`, with the key read from the `AUTHLOG_API_KEY` environment variable. Read endpoints are public in M3. Revisit that before deploying in M5.

| Method | Route | Description | Success | Errors |
|---|---|---|---|---|
| GET | `/api/v1/` | List of resource URLs | 200 | none |
| GET | `/api/v1/alerts/` | Newest first, filterable, paginated (below) | 200 | 400 bad filter |
| GET | `/api/v1/alerts/{alertid}/` | One alert | 200 | 404 |
| PATCH | `/api/v1/alerts/{alertid}/` | Body `{"status": "acknowledged"}` | 200 | 400, 401/403, 404 |
| POST | `/api/v1/ingest/?year=2026` | Body: raw auth.log text (`text/plain`). Parses, runs the engine, stores and returns new alerts | 201 | 400, 401/403 |
| GET | `/api/v1/stats/` | Counts by severity, rule, and top 5 source IPs | 200 | none |

**`GET /api/v1/alerts/` query parameters**, all optional:

- `severity`, `rule`, `ip`, `user`, `status`: exact-match filters
- `since`: ISO 8601 timestamp, lower bound on `timestamp`
- `size` (default 10, must be ≥ 1) and `page` (default 0, must be ≥ 0)
- `alertid_lte`: only alerts with `alertid <= alertid_lte`. This keeps pages stable while new alerts arrive, the same trick as insta485's `postid_lte`. Default: the newest `alertid`.

Response:

```json
{
  "results": [
    {"alertid": 3, "timestamp": "2026-10-15T14:41:02", "rule": "brute_force_success",
     "technique": "T1110.001", "severity": "high", "ip": "203.0.113.77", "user": "alice",
     "details": {"failures": 8}, "status": "open", "url": "/api/v1/alerts/3/"}
  ],
  "next": "/api/v1/alerts/?size=10&page=1&alertid_lte=5",
  "url": "/api/v1/alerts/?size=10&page=0"
}
```

`next` is `""` on the last page.

Ingesting the same file twice must not create duplicate alerts.

> 🧭 **Your call:** how do you make ingest idempotent? You could hash lines, use a unique constraint on `(timestamp, rule, ip, user)`, or track the last ingested timestamp. Each one has a failure mode. Write down which one you picked.

FastAPI generates OpenAPI docs at `/docs` for free. Make sure they're accurate: request and response models, examples. Reviewers will open that page.

### 3.3 Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

1. Set up Python 3.12.
2. `pip install -e ".[dev]"`
3. `ruff check .` (lint)
4. `pytest`
5. The sample diff: `authlog --year 2026 --alerts samples/auth.log | diff - samples/expected-alerts.txt`

Add the CI status badge to the README. From now on `main` must always be green.

### 3.4 M3 checkpoint demo

Start the server, `curl` the sample log into `/ingest/`, list alerts with filters, acknowledge one, show `/docs`, and show a green CI run on GitHub.

---

## Milestone 4: Docker and React

### 4.1 Docker

- A `Dockerfile` for the API: slim Python base image, runs as a non-root user, dependencies installed in their own cached layer, and the server listening on `0.0.0.0:8000`.
- A `docker-compose.yml` that runs the API with a volume for the SQLite file.
- `docker compose up`, then `curl localhost:8000/api/v1/` works on a clean machine.
- CI also runs `docker build`.

### 4.2 React page

One page, kept small. Its job is to show the API works, not to be a design portfolio.

- A table of alerts (time, severity, rule, technique, IP, user, status), newest first.
- A severity filter and an "Acknowledge" button that calls `PATCH`.
- "Load more" pagination using `next`.
- Severity in color, with text as well, so color isn't the only signal.
- Each technique ID links to `https://attack.mitre.org/techniques/<ID with . replaced by />/`.

> 🧭 **Your call:** serve the built React files from FastAPI (one container) or separately (two containers / S3 in M5)? One container is simpler to deploy.

### 4.3 M4 checkpoint demo

`docker compose up` on a fresh clone, open the browser, ingest the sample, and acknowledge an alert.

---

## Milestone 5: AWS and PostgreSQL

- **Day one: set an AWS budget alarm** (e.g. $10/month). Do this before creating anything else.
- Replace SQLite with PostgreSQL (Amazon RDS, smallest free-tier-eligible instance) for the deployed version. Local dev and tests can stay on SQLite or use a Postgres container. Pick one and say why in DEVLOG.
- Deploy the container. Options, simplest first: EC2 with Docker, App Runner, ECS Fargate.
- Secrets (DB password, API key) live in environment variables or AWS Secrets Manager, **never** in the repo.
- Least privilege: the database accepts connections only from the app, through security groups.
- The README has the live URL and a short "how it's deployed" section with a diagram.

> 🧭 **Your call:** which compute option. Write down the cost, how deploys work, and what you'd change at 100× the traffic.

**M5 checkpoint demo:** the public URL shows the React page with alerts from an ingest you ran against the live API.

---

## Milestone 6: Polish and stretch goals

Required:

- [ ] README: what it is (2 sentences), screenshot or GIF, live URL, architecture diagram, how to run locally, design decisions (link to DEVLOG), and limitations.
- [ ] Every 🧭 decision is in DEVLOG.
- [ ] `ruff` clean, type hints on all public functions, no dead code.
- [ ] You can explain any line in the repo. Do a mock interview: open a random file and explain it out loud.

Stretch (pick one or two):

| Rule | ATT&CK | Idea |
|---|---|---|
| `sudo_failures` | T1548.003 Sudo and Sudo Caching | Burst of `sudo: ... authentication failure` / `incorrect password attempts` lines from one user. Needs a parser extension. |
| `password_spray` | T1110.003 Password Spraying | One IP, **many distinct users**, few attempts each. Compare with `brute_force` and decide whether `203.0.113.5` is really guessing or spraying. |
| `off_hours` | T1078 | Successful login outside a user's usual hours. Needs a baseline, like `new_ip`. |
| `root_login` | T1078.003 Local Accounts | Any successful login as `root`. |
| Correlation | n/a | Bump `new_ip` to `high` when the same IP has a `brute_force` alert. Your first multi-rule correlation. |
| Live tail | n/a | `authlog --follow /var/log/auth.log` that streams lines into the API as they're written (the engine is already streaming, see 2.2). |

---

## Testing

Use the same approach as 281's `spec-*` files and 370's `.correct` diffs: small inputs whose correct output you know.

**Required tests by end of M2:**

- **Unit tests per rule** (`tests/test_rules_brute_force.py`, and so on), built from **hand-made event lists**, not the sample file. Use pytest fixtures for a helper like `fail(ip, t)` / `ok(user, ip, t)` that builds `LoginEvent`s, and `@pytest.mark.parametrize` for boundary cases.
- **Boundary cases you must cover:**
  - exactly `N − 1` failures → no alert; exactly `N` → alert
  - a failure at exactly `t − W` counts; one second earlier doesn't
  - cooldown: a second burst *after* `t₀ + W` alerts again; one inside the cooldown doesn't
  - failures from two different IPs don't add together
  - `new_ip`: the baseline doesn't alert, a repeat of a known IP doesn't alert, a new IP alerts exactly once
  - a failed login from a new IP doesn't add it to the known set
  - one event triggering two alerts → rule order
- **End-to-end test:** run the engine over `samples/auth.log` and compare against `samples/expected-alerts.txt`.

**By end of M3:** API tests with FastAPI's `TestClient` and a temporary database fixture. Cover every status code in the API table at least once, including pagination with `alertid_lte` after new alerts arrive.

> **Pro-tip:** When a test fails, check whether the **test** is wrong before you touch the code. Most of the best DEVLOG bug stories are a wrong assumption written down in a test.

## Code quality

- `ruff check .` passes (add `ruff` to the `dev` extras).
- Type hints on public functions. `LoginEvent` and `Alert` stay frozen dataclasses.
- Module docstrings say what the module is **for**. Comments explain **why**, not what.
- No `print` outside `cli.py`. No `sqlite3` import outside `store.py`.
- Small commits with imperative messages (`Add brute-force cooldown`).

## Dev log

`DEVLOG.md` is a required deliverable, not a nice extra. Newest entries first. Each week needs at least:

- **Decisions:** what you chose, the alternative you rejected, and why. One entry per 🧭 at minimum.
- **Bugs:** symptom → how you found it → root cause → fix → the test that now guards it.
- **Next:** what the next session starts with.

In an interview, "tell me about a bug you fixed" is answered straight from this file.

---

## Definition of done (the "autograder")

A milestone is done when **all** its boxes are true. There's no partial credit.

| | M1 | M2 | M3 | M4 | M5 | M6 |
|---|---|---|---|---|---|---|
| `pytest` green | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Sample `diff` passes | | ✅ | ✅ (in CI) | ✅ | ✅ | ✅ |
| Boundary tests from [Testing](#testing) | | ✅ | ✅ | ✅ | ✅ | ✅ |
| O(n) engine (2.2) | | ✅ | ✅ | ✅ | ✅ | ✅ |
| API table fully implemented and tested | | | ✅ | ✅ | ✅ | ✅ |
| CI green on `main` | | | ✅ | ✅ | ✅ | ✅ |
| `docker compose up` works from a fresh clone | | | | ✅ | ✅ | ✅ |
| Live public URL | | | | | ✅ | ✅ |
| README complete, DEVLOG covers every 🧭 | | | | | | ✅ |
| Demo recorded / rehearsed | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## FAQ

**Q: Can I change the default thresholds or the rule definitions?**
Yes. That's a design decision, so record it. Update `expected-alerts.txt` in the same commit and make sure the boundary tests still describe the new behavior.

**Q: The log isn't sorted. What do I do?**
Real syslog is append-only, so assume it's sorted. If you want to handle out-of-order lines, that's a stretch goal, and it's harder than it looks with a sliding window.

**Q: Why the closed interval `[t − W, t]`?**
It has to be one or the other so the tests can be exact, and closed is the easier one to say out loud. If you'd rather use half-open, change it, update the boundary test, and note it.

**Q: Should the engine read the file itself?**
No. The engine takes events. The CLI opens files, and the API reads request bodies. That split is what lets M3 reuse M2 unchanged.

**Q: Are these real attacker IPs?**
No. Every IP is from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Keep it that way. Never commit a real auth.log.

**Q: How much can Claude write?**
Tests, fixtures, scaffolding, CI, Docker, the React page and docs: yes, and you review every change before committing. The detection engine and rules: no, unless you explicitly ask, and then only after the help ladder in M2.

---

## Appendix A: auth.log format

```
Oct 15 14:02:11 web01 sshd[2231]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2
└─month day time─┘ └host┘ └prog[pid]┘ └──────────────────────── message ────────────────────────────┘
```

| Message | Parsed? | Meaning |
|---|---|---|
| `Accepted password for U from IP port P ssh2` | ✅ | Success, password |
| `Accepted publickey for U from IP port P ssh2: RSA SHA256:…` | ✅ | Success, key |
| `Failed password for U from IP port P ssh2` | ✅ | Wrong password, real account |
| `Failed password for invalid user U from IP port P ssh2` | ✅ | Account doesn't exist |
| `Invalid user U from IP port P` | ❌ (M6?) | Logged before the auth attempt |
| `Connection closed by IP port P [preauth]` | ❌ | Noise |
| `sudo: U : TTY=… ; COMMAND=…` / `pam_unix(sudo:auth): authentication failure` | ❌ (M6 stretch) | Privilege escalation |

## Appendix B: MITRE ATT&CK mapping

| Technique | Name | Tactic | Used by |
|---|---|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Credential Access | `brute_force`, `brute_force_success` |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying | Credential Access | `password_spray` (stretch) |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Initial Access, Persistence, Defense Evasion, Privilege Escalation | `new_ip`, `off_hours` |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Valid Accounts: Local Accounts | same | `root_login` (stretch) |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control: Sudo and Sudo Caching | Privilege Escalation, Defense Evasion | `sudo_failures` (stretch) |

For each rule you ship, be ready to answer: *what does the attacker see, and how would they get around this rule?* (For example, slow brute force under `N` per `W`, or rotating through many IPs.) Put the answers in the README's limitations section.
