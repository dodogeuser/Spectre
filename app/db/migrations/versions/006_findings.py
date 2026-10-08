"""Evidence-linked deterministic findings and append-only revision history."""
from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("case_id", sa.Integer, sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("entity_id", sa.Integer, sa.ForeignKey("entities.id"), nullable=True),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("rule_version", sa.String(30), nullable=False),
        sa.Column("finding_type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(250), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("generated_json", sa.JSON, nullable=False),
        sa.Column("original_json", sa.JSON, nullable=False),
        sa.Column("notes", sa.Text, nullable=False),
        sa.Column("severity_override", sa.String(20), nullable=True),
        sa.Column("override_reason", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.UniqueConstraint("case_id","target_id","rule_id",name="uq_finding_rule_target"),
        sa.CheckConstraint("status IN ('open','accepted','false_positive','informational','resolved')",name="ck_finding_status"),
        sa.CheckConstraint("severity_override IS NULL OR severity_override IN ('informational','low','medium','high','critical')",name="ck_finding_override"), mysql_engine="InnoDB")
    op.create_index("ix_findings_case_id","findings",["case_id"])
    op.create_table("finding_evidence",
        sa.Column("finding_id",sa.Integer,sa.ForeignKey("findings.id"),primary_key=True),
        sa.Column("evidence_id",sa.Integer,sa.ForeignKey("evidence.id"),primary_key=True),mysql_engine="InnoDB")
    op.create_table("finding_relationships",
        sa.Column("finding_id",sa.Integer,sa.ForeignKey("findings.id"),primary_key=True),
        sa.Column("relationship_id",sa.Integer,sa.ForeignKey("relationships.id"),primary_key=True),mysql_engine="InnoDB")
    op.create_table("finding_revisions",
        sa.Column("id",sa.Integer,primary_key=True),
        sa.Column("finding_id",sa.Integer,sa.ForeignKey("findings.id"),nullable=False),
        sa.Column("actor_id",sa.Integer,sa.ForeignKey("users.id"),nullable=False),
        sa.Column("change_type",sa.String(30),nullable=False),
        sa.Column("snapshot_json",sa.JSON,nullable=False),
        sa.Column("created_at",sa.DateTime,nullable=False),mysql_engine="InnoDB")
    op.create_index("ix_finding_revisions_finding_id","finding_revisions",["finding_id"])


def downgrade():
    # Only safe on disposable databases: deletes Phase 09 findings/revisions, never evidence.
    for table in ("finding_revisions","finding_relationships","finding_evidence","findings"):
        op.drop_table(table)
