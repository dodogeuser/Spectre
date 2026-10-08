"""Minimal Phase 04 domain entities and evidence-backed relationships."""
from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("entities",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("case_id", sa.Integer, sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("entity_type", sa.String(30), nullable=False),
        sa.Column("canonical_value", sa.Text, nullable=False),
        sa.Column("canonical_hash", sa.String(64), nullable=False),
        sa.Column("attributes_json", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.UniqueConstraint("case_id", "entity_type", "canonical_hash", name="uq_entity_canonical"),
        mysql_engine="InnoDB")
    op.create_index("ix_entities_case_id", "entities", ["case_id"])
    op.create_table("relationships",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("case_id", sa.Integer, sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("from_entity_id", sa.Integer, sa.ForeignKey("entities.id"), nullable=False),
        sa.Column("to_entity_id", sa.Integer, sa.ForeignKey("entities.id"), nullable=False),
        sa.Column("relation_type", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("evidence_id", sa.Integer, sa.ForeignKey("evidence.id"), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.UniqueConstraint("from_entity_id", "to_entity_id", "relation_type", "evidence_id", name="uq_relationship_evidence"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_relationship_confidence"),
        mysql_engine="InnoDB")
    op.create_index("ix_relationships_case_id", "relationships", ["case_id"])
    op.create_index("ix_relationships_evidence_id", "relationships", ["evidence_id"])


def downgrade():
    op.drop_table("relationships")
    op.drop_table("entities")
