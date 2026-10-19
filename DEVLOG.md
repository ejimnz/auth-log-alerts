# Dev log

Short entries: what I decided and why, what broke and how I found it. Newest first.

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
