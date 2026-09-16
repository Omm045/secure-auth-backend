# Secure FastAPI Authentication Backend

Features include Argon2id password hashing, an 8–128 character policy with local common-password blocking, HIBP k-anonymity breach checking, secure HttpOnly sessions, CSRF protection, rate limiting, password reset/change flows, audit logs, admin statistics, security headers, and explicit CORS.

## Run
`python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt`
`uvicorn app.main:app --reload`

Copy `.env.example` to `.env`; SQLite is the default. Clients may query HIBP using only the first five SHA-1 characters; the backend checker does the same and never sends a password. Production deployments must use PostgreSQL (SQLite is development/test only) and set a random `SECRET_KEY`, `ENVIRONMENT=production`,
`SESSION_COOKIE_SECURE=true`, restrictive HTTPS CORS, `REDIS_URL`, and a
production database. SMTP settings (`EMAIL_PROVIDER`, `SMTP_HOST`,
`SMTP_USERNAME`, `SMTP_PASSWORD`, and `EMAIL_FROM`) are also required.
Production rate limiting fails closed if Redis is unavailable; development/test
uses an in-process fallback. SMTP delivery is used for reset and verification
messages. Newly registered users have reduced access until they verify their
email; existing authentication remains available so clients can complete
verification. Apply schema changes with `alembic upgrade head`.

The `/health` endpoint is liveness; `/ready` checks database readiness. Sessions
and reset values are opaque, hashed before persistence, and never logged.
The admin-only `/admin/breach-report` endpoint evaluates only the clearly fake
accounts in `tests/fixtures/sample_accounts.csv`; it returns addresses and
breached/not-breached flags, never passwords. A minimal advisory zxcvbn meter
is provided in `frontend/index.html`; server-side policy and breach checks
remain authoritative.
CI runs the complete test suite against both SQLite and the Docker Compose
PostgreSQL/Redis services.

## Test
`python -m pytest -q`
