"""Add email verification state and single-use tokens."""
from alembic import op
import sqlalchemy as sa

revision = "002_email_verification"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("users")}
    if "email_verified" not in columns:
        op.add_column("users", sa.Column("email_verified", sa.Boolean(), nullable=False,
                                          server_default=sa.text("FALSE")))
    if "email_verification_tokens" not in inspector.get_table_names():
        op.create_table(
            "email_verification_tokens",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("token_hash", sa.String(), unique=True, nullable=False),
            sa.Column("expires_at", sa.String(), nullable=False),
            sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
            sa.Column("created_at", sa.String(), nullable=False),
        )
        op.create_index("idx_verification_token_active", "email_verification_tokens",
                        ["token_hash", "used", "expires_at"])

def downgrade():
    op.drop_table("email_verification_tokens")
    op.drop_column("users", "email_verified")
