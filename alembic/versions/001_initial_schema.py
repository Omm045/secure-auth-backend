"""Create the authentication schema."""
from alembic import op
import sqlalchemy as sa

revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        statements = [
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, created_at TEXT NOT NULL,
                last_login TEXT, disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')))""",
            """CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1)))""",
            """CREATE TABLE IF NOT EXISTS password_resets (
                id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0,1)), created_at TEXT NOT NULL)""",
            """CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                event TEXT NOT NULL, ip TEXT, metadata TEXT, created_at TEXT NOT NULL)""",
        ]
    else:
        statements = [
            "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL, last_login TEXT, disabled BOOLEAN NOT NULL DEFAULT FALSE, role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')))",
            "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)",
            "CREATE TABLE IF NOT EXISTS password_resets (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL, used BOOLEAN NOT NULL DEFAULT FALSE, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS audit_logs (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, event TEXT NOT NULL, ip TEXT, metadata TEXT, created_at TEXT NOT NULL)",
        ]
    for statement in statements:
        op.execute(sa.text(statement))
    for index in ("idx_sessions_token_active", "idx_sessions_user", "idx_resets_token_active", "idx_resets_user", "idx_audit_event_time"):
        op.execute(sa.text(f"CREATE INDEX IF NOT EXISTS {index} ON " + {
            "idx_sessions_token_active": "sessions(token_hash, revoked, expires_at)",
            "idx_sessions_user": "sessions(user_id)",
            "idx_resets_token_active": "password_resets(token_hash, used, expires_at)",
            "idx_resets_user": "password_resets(user_id)",
            "idx_audit_event_time": "audit_logs(event, created_at)",
        }[index]))

def downgrade():
    for table in ("audit_logs", "password_resets", "sessions", "users"):
        op.drop_table(table)
