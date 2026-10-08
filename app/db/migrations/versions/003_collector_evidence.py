"""Collector execution provenance and evidence repository."""
from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("collector_runs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("collector", sa.String(50), nullable=False),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("ended_at", sa.DateTime, nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error_code", sa.String(50), nullable=True),
        sa.Column("target_snapshot", sa.JSON, nullable=False),
        sa.Column("warnings_json", sa.JSON, nullable=False),
        sa.CheckConstraint("status IN ('running','completed','failed')", name="ck_run_status"))
    op.create_index("ix_collector_runs_target_id", "collector_runs", ["target_id"])
    op.create_table("evidence",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("run_id", sa.Integer, sa.ForeignKey("collector_runs.id"), nullable=False),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("source_ref", sa.Text, nullable=False),
        sa.Column("captured_at", sa.DateTime, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("raw_json", sa.JSON, nullable=False),
        sa.Column("parsed_json", sa.JSON, nullable=False))
    op.create_index("ix_evidence_run_id", "evidence", ["run_id"])


def downgrade():
    op.drop_table("evidence")
    op.drop_table("collector_runs")
