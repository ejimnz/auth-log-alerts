# Dev log

Short entries: what I decided and why, what broke and how I found it. Newest first.

## 2026-10-19 — M2: Alert type and engine

Decisions:
- `Alert` has a typed `failures: int | None` field instead of a `details: dict`. Rejected: the dict. `Alert` is a frozen dataclass, but frozen only stops you reassigning fields; the dict inside could still be changed (`alert.details["failures"] = 0`), so the alert wasn't really immutable. `failures` is also the only extra fact any rule records, so a typed field is simpler and mypy checks it. The API still returns it as `details: {"failures": N}`.
- Rules plug in through a `typing.Protocol` (`Rule`, with `process(event) -> list[Alert]`); the `Engine` holds a list of rules and calls them in order, which also gives the required rule order for free. Rejected: an ABC base class. My rules don't share any code, only the `process` method, so inheritance didn't buy me anything, and test fakes can be plain classes. Trade-off: Python doesn't check a rule at runtime, so a wrong `process` is caught by mypy, not when the code runs.
- Added ruff and mypy to the dev extras. mypy matters because of how rules plug in (see below): nothing else checks a rule's `process` signature.

## 2026-10-15 — Week 1 kickoff

Decisions:
- FastAPI for the API (week 3): new to me, common in current Python backend jobs.
- SQLite first, PostgreSQL when deploying to AWS (week 5).
- Generated sample logs with planted attacks, so tests know exactly what should be caught and nothing real gets published.
- Detection engine (week 2) is the part I write by hand.

Notes:
- Syslog lines have no year, so the parser takes the year as an argument.
- Single-digit days are space-padded ("Oct  5"), which the first regex has to allow for.

<!-- Add your own notes below as you review and run things. -->
