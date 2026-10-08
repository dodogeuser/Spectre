"""Require transactional MySQL storage and restore previously ignored FKs."""
from alembic import context, op
from sqlalchemy import inspect, text

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None

TABLES = ("users", "cases", "case_members", "audit_logs", "login_sessions", "targets", "collector_runs", "evidence", "alembic_version")
LINKS = (
    ("cases", "owner_id", "users", None),
    ("case_members", "case_id", "cases", "CASCADE"),
    ("case_members", "user_id", "users", "CASCADE"),
    ("audit_logs", "actor_id", "users", None),
    ("login_sessions", "user_id", "users", "CASCADE"),
    ("targets", "case_id", "cases", "CASCADE"),
    ("collector_runs", "target_id", "targets", None),
    ("collector_runs", "actor_id", "users", None),
    ("evidence", "run_id", "collector_runs", None),
)


def upgrade():
    connection = op.get_bind()
    if connection.dialect.name != "mysql":
        return  # SQLite already enforces FKs when enabled and is transactional.
    if context.is_offline_mode():
        raise RuntimeError("Migration 004 requires online orphan and foreign-key checks; use alembic upgrade head")
    # Verify referential integrity before making any engine changes.
    for table, column, parent, _ in LINKS:
        count = connection.scalar(text(
            f"SELECT COUNT(*) FROM `{table}` c LEFT JOIN `{parent}` p ON c.`{column}`=p.id "
            f"WHERE c.`{column}` IS NOT NULL AND p.id IS NULL"))
        if count:
            raise RuntimeError(f"Orphan records in {table}.{column}; migration stopped without deleting data")
    for table in TABLES:
        connection.execute(text(f"ALTER TABLE `{table}` ENGINE=InnoDB"))
    inspector = inspect(connection)
    for table, column, parent, ondelete in LINKS:
        existing = inspector.get_foreign_keys(table)
        if not any(item["constrained_columns"] == [column] and item["referred_table"] == parent for item in existing):
            op.create_foreign_key(f"fk_{table}_{column}", table, parent, [column], ["id"], ondelete=ondelete)


def downgrade():
    if op.get_bind().dialect.name == "mysql":
        raise RuntimeError("Transactional storage hardening is forward-only on MySQL; do not revert to MyISAM")
