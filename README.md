# auth-log-alerts

Reads Linux SSH auth logs and flags suspicious logins (brute force, logins from new IPs), with each alert tagged by its MITRE ATT&CK technique.

Status: week 1 of 6. Parsing works; detection comes next.

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts/generate_logs.py > samples/auth.log   # fake log with planted attacks
authlog samples/auth.log
pytest
```

## Roadmap

1. Parse SSH logins from auth.log (done)
2. Detection rules: brute force (T1110), new-IP login (T1078)
3. Store alerts in SQLite, serve them over a FastAPI REST API; tests run in GitHub Actions
4. Docker image and a small React page
5. Deploy to AWS with PostgreSQL
6. Polish

Sample logs are generated and use documentation-only IP ranges (RFC 5737).
