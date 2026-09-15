# Secure FastAPI Authentication Backend

Features include Argon2id password hashing, an 8–128 character policy with local common-password blocking, HIBP k-anonymity breach checking, secure HttpOnly sessions, CSRF protection, rate limiting, password reset/change flows, audit logs, admin statistics, security headers, and explicit CORS.

## Run
`python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt`
`uvicorn app.main:app --reload`

Copy `.env.example` to `.env`; SQLite is the default. Clients may query HIBP using only the first five SHA-1 characters; the backend checker does the same and never sends a password. Production deployments must set a random `SECRET_KEY`, HTTPS cookies, restrictive CORS, and a production database.

## Test
`python -m pytest -q`
