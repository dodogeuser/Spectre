"""Add explicit active authorization and separate active run/verification history."""
from alembic import op
import sqlalchemy as sa

revision="007"
down_revision="006"
branch_labels=None
depends_on=None


def upgrade():
    op.create_table("active_authorizations",
        sa.Column("id",sa.Integer,primary_key=True),sa.Column("case_id",sa.Integer,sa.ForeignKey("cases.id"),nullable=False),
        sa.Column("target_id",sa.Integer,sa.ForeignKey("targets.id"),nullable=False),sa.Column("granted_by",sa.Integer,sa.ForeignKey("users.id"),nullable=False),
        sa.Column("granted_at",sa.DateTime,nullable=False),sa.Column("scope_json",sa.JSON,nullable=False),sa.Column("note",sa.Text,nullable=False),
        sa.Column("revoked_at",sa.DateTime),sa.Column("revoked_by",sa.Integer,sa.ForeignKey("users.id")),mysql_engine="InnoDB")
    op.create_index("ix_active_authorizations_case_id","active_authorizations",["case_id"])
    op.create_index("ix_active_authorizations_target_id","active_authorizations",["target_id"])
    op.create_table("active_case_controls",sa.Column("case_id",sa.Integer,sa.ForeignKey("cases.id"),primary_key=True),
        sa.Column("stopped",sa.Boolean,nullable=False),sa.Column("updated_by",sa.Integer,sa.ForeignKey("users.id"),nullable=False),sa.Column("updated_at",sa.DateTime,nullable=False),mysql_engine="InnoDB")
    op.create_table("active_runs",sa.Column("id",sa.Integer,primary_key=True),sa.Column("case_id",sa.Integer,sa.ForeignKey("cases.id"),nullable=False),
        sa.Column("target_id",sa.Integer,sa.ForeignKey("targets.id"),nullable=False),sa.Column("authorization_id",sa.Integer,sa.ForeignKey("active_authorizations.id"),nullable=False),
        sa.Column("actor_id",sa.Integer,sa.ForeignKey("users.id"),nullable=False),sa.Column("module",sa.String(30),nullable=False),sa.Column("version",sa.String(30),nullable=False),
        sa.Column("action_json",sa.JSON,nullable=False),sa.Column("requested_at",sa.DateTime,nullable=False),sa.Column("started_at",sa.DateTime),sa.Column("ended_at",sa.DateTime),
        sa.Column("status",sa.String(20),nullable=False),sa.Column("collector_run_id",sa.Integer,sa.ForeignKey("collector_runs.id"),unique=True),
        sa.Column("result_json",sa.JSON,nullable=False),sa.Column("error_code",sa.String(40)),sa.Column("cancel_requested",sa.Boolean,nullable=False),
        sa.CheckConstraint("status IN ('queued','running','completed','failed','cancelled')",name="ck_active_run_status"),mysql_engine="InnoDB")
    op.create_index("ix_active_runs_case_id","active_runs",["case_id"])
    op.create_table("finding_verifications",sa.Column("id",sa.Integer,primary_key=True),sa.Column("finding_id",sa.Integer,sa.ForeignKey("findings.id"),nullable=False),
        sa.Column("active_run_id",sa.Integer,sa.ForeignKey("active_runs.id"),nullable=False,unique=True),sa.Column("state",sa.String(30),nullable=False),
        sa.Column("reason",sa.Text,nullable=False),sa.Column("evidence_id",sa.Integer,sa.ForeignKey("evidence.id")),sa.Column("created_at",sa.DateTime,nullable=False),
        sa.CheckConstraint("state IN ('observed','verified','not_confirmed','failed_to_verify')",name="ck_finding_verification_state"),mysql_engine="InnoDB")
    op.create_index("ix_finding_verifications_finding_id","finding_verifications",["finding_id"])


def downgrade():
    for name in ("finding_verifications","active_runs","active_case_controls","active_authorizations"):
        op.drop_table(name)
