"""Real Alembic upgrade/rollback on a disposable database only."""
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine,text,inspect


def test_additive_active_migration_upgrade_rollback(tmp_path):
    engine=create_engine('sqlite:///'+str(tmp_path/'migration.sqlite'))
    config=Config('alembic.ini')
    with engine.begin() as connection:
        config.attributes['connection']=connection
        command.upgrade(config,'006')
        connection.execute(text("INSERT INTO users (id,username,password_hash,role,created_at) VALUES (1,'preserved','fixture','investigator','2026-01-01')"))
        before=list(connection.execute(text('SELECT * FROM users')))
        command.upgrade(config,'007')
        assert {'active_authorizations','active_runs','active_case_controls','finding_verifications'}<=set(inspect(connection).get_table_names())
        assert len(inspect(connection).get_foreign_keys('active_runs'))==5
        assert list(connection.execute(text('SELECT * FROM users')))==before
        command.downgrade(config,'006')
        assert 'active_runs' not in inspect(connection).get_table_names()
        assert list(connection.execute(text('SELECT * FROM users')))==before
        command.upgrade(config,'007')
    engine.dispose()
