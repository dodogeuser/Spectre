"""Accounts, case membership, audit trail and opaque sessions."""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("users", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("username", sa.String(100), nullable=False, unique=True),
                    sa.Column("password_hash", sa.String(255), nullable=False),
                    sa.Column("role", sa.String(20), nullable=False),
                    sa.Column("created_at", sa.DateTime, nullable=False),
                    sa.CheckConstraint("role IN ('admin','investigator','viewer')", name="ck_user_role"))
    op.create_table("cases", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("title", sa.String(200), nullable=False),
                    sa.Column("description", sa.Text, nullable=False),
                    sa.Column("status", sa.String(20), nullable=False),
                    sa.Column("owner_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("created_at", sa.DateTime, nullable=False))
    op.create_table("case_members",
                    sa.Column("case_id", sa.Integer, sa.ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True),
                    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True))
    op.create_table("audit_logs", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
                    sa.Column("action", sa.String(100), nullable=False),
                    sa.Column("object_type", sa.String(50), nullable=False),
                    sa.Column("object_id", sa.Integer, nullable=True),
                    sa.Column("timestamp", sa.DateTime, nullable=False),
                    sa.Column("metadata_json", sa.JSON, nullable=False))
    op.create_table("login_sessions", sa.Column("token_hash", sa.String(64), primary_key=True),
                    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
                    sa.Column("csrf_token", sa.String(64), nullable=False),
                    sa.Column("expires_at", sa.DateTime, nullable=False))


def downgrade():
    for table in ("login_sessions", "audit_logs", "case_members", "cases", "users"):
        op.drop_table(table)
