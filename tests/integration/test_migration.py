from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from io import StringIO
from sqlalchemy import text
import pytest


def test_initial_migration_round_trip():
    engine = create_engine("sqlite://")
    config = Config("alembic.ini")
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        assert {"users", "cases", "case_members", "audit_logs", "login_sessions"} <= set(inspect(connection).get_table_names())
        command.downgrade(config, "base")
        assert set(inspect(connection).get_table_names()) == {"alembic_version"}
    engine.dispose()


def test_mysql_migration_sql():
    output = StringIO()
    config = Config("alembic.ini", output_buffer=output)
    command.upgrade(config, "003", sql=True)
    sql = output.getvalue()
    for table in ("users", "cases", "case_members", "audit_logs", "login_sessions"):
        assert f"CREATE TABLE {table}" in sql
    assert "AUTO_INCREMENT" in sql
    assert "FOREIGN KEY" in sql


def test_storage_hardening_requires_online_mysql_checks():
    config = Config("alembic.ini", output_buffer=StringIO())
    with pytest.raises(RuntimeError, match="requires online"):
        command.upgrade(config, "003:004", sql=True)


def test_target_migration_preserves_phase_one_data():
    engine = create_engine("sqlite://")
    config = Config("alembic.ini")
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "001")
        connection.execute(text("INSERT INTO users (id,username,password_hash,role,created_at) VALUES (1,'fixture','fixture-hash','investigator','2026-10-05')"))
        connection.execute(text("INSERT INTO cases (id,title,description,status,owner_id,created_at) VALUES (1,'Existing case','','open',1,'2026-10-05')"))
        command.upgrade(config, "002")
        assert "targets" in inspect(connection).get_table_names()
        assert connection.scalar(text("SELECT title FROM cases WHERE id=1")) == "Existing case"
        command.downgrade(config, "001")
        assert "targets" not in inspect(connection).get_table_names()
        assert connection.scalar(text("SELECT username FROM users WHERE id=1")) == "fixture"
    engine.dispose()


def test_findings_only_upgrade_and_safe_disposable_rollback():
    engine=create_engine("sqlite://")
    config=Config("alembic.ini")
    with engine.begin() as connection:
        config.attributes["connection"]=connection
        command.upgrade(config,"005")
        connection.execute(text("INSERT INTO users (id,username,password_hash,role,created_at) VALUES (1,'fixture','hash','investigator','2026-10-06')"))
        connection.execute(text("INSERT INTO cases (id,title,description,status,owner_id,created_at) VALUES (1,'Preserved','','open',1,'2026-10-06')"))
        command.upgrade(config,"006")
        assert {"findings","finding_evidence","finding_relationships","finding_revisions"} <= set(inspect(connection).get_table_names())
        assert connection.scalar(text("SELECT title FROM cases WHERE id=1"))=="Preserved"
        command.downgrade(config,"005")
        assert "findings" not in inspect(connection).get_table_names()
        assert connection.scalar(text("SELECT title FROM cases WHERE id=1"))=="Preserved"
        command.upgrade(config,"006")
    engine.dispose()
