"""Apply only additive 007 to existing MySQL; verify every pre-existing row digest."""
import hashlib
import json
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect,text
from app.config import get_settings
from app.db.session import make_session_factory


def digest(rows):return hashlib.sha256(json.dumps([list(r) for r in rows],default=str,sort_keys=True).encode()).hexdigest()


def main():
    factory=make_session_factory(get_settings());engine=factory.kw['bind']
    with engine.connect() as connection:
        revision=connection.scalar(text('SELECT version_num FROM alembic_version'))
        assert revision=='006',f'Expected reviewed revision 006, got {revision}; no migration attempted'
        tables=[t for t in inspect(connection).get_table_names() if t!='alembic_version']
        before={t:{'count':connection.scalar(text(f'SELECT COUNT(*) FROM `{t}`')),'digest':digest(connection.execute(text(f'SELECT * FROM `{t}` ORDER BY 1,2')))} for t in tables}
    out=Path('.local/phase12-migration-verification.json');out.write_text(json.dumps({'before':before,'from':'006','to':'007','status':'before_upgrade'},indent=2))
    command.upgrade(Config('alembic.ini'),'007')
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT version_num FROM alembic_version'))=='007'
        for t,data in before.items():
            assert digest(connection.execute(text(f'SELECT * FROM `{t}` ORDER BY 1,2')))==data['digest'],f'Existing records changed: {t}'
        new=['active_authorizations','active_case_controls','active_runs','finding_verifications']
        constraints={t:len(inspect(connection).get_foreign_keys(t)) for t in new}
        assert constraints=={'active_authorizations':4,'active_case_controls':2,'active_runs':5,'finding_verifications':3}
    result={'from':'006','to':'007','existing_tables_verified':before,'foreign_keys':constraints,'preserved':True}
    out.write_text(json.dumps(result,indent=2));print(json.dumps({'migration':'006 -> 007','existing_tables':len(before),'all_existing_rows_preserved':True,'foreign_keys':constraints}))


if __name__=='__main__':main()
