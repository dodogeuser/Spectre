"""Typed case targets without collection."""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("targets",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("case_id", sa.Integer, sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("normalized_value", sa.Text, nullable=False),
        sa.Column("canonical_hash", sa.String(64), nullable=False),
        sa.Column("scope_status", sa.String(30), nullable=False),
        sa.Column("archived", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.UniqueConstraint("case_id", "type", "canonical_hash", name="uq_target_canonical"),
        sa.CheckConstraint("type IN ('domain','ipv4','ipv6','url','organization','username','email')", name="ck_target_type"),
        sa.CheckConstraint("scope_status IN ('passive_allowed','active_authorized','excluded')", name="ck_target_scope"))
    op.create_index("ix_targets_case_id", "targets", ["case_id"])


def downgrade():
    op.drop_table("targets")
