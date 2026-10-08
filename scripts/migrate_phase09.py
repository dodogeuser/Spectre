"""Apply pending 006 only and verify preservation of all existing application rows."""
import json
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect,text
from app.config import get_settings
from app.db.session import make_session_factory


def main():
    factory=make_session_factory(get_settings())
    with factory() as db:
        head=db.scalar(text("SELECT version_num FROM alembic_version"))
        assert head in {"005","006"},"Unexpected schema; no migration applied"
        tables=[name for name in inspect(db.get_bind()).get_table_names() if name!="alembic_version"]
        before={name:[tuple(row) for row in db.execute(text(f"SELECT * FROM `{name}`"))] for name in tables}
    if head=="005":command.upgrade(Config("alembic.ini"),"006")
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version"))=="006"
        for table,rows in before.items():
            after={tuple(row) for row in db.execute(text(f"SELECT * FROM `{table}`"))}
            assert all(row in after for row in rows),f"Existing {table} rows changed"
        schema=inspect(db.get_bind())
        new_tables=["findings","finding_evidence","finding_relationships","finding_revisions"]
        fk={name:len(schema.get_foreign_keys(name)) for name in new_tables}
        assert fk=={"findings":3,"finding_evidence":2,"finding_relationships":2,"finding_revisions":2}
        engines=dict(db.execute(text("SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")).all())
        assert all(engines[name]=="InnoDB" for name in new_tables)
    report={"before_revision":head,"after_revision":"006","existing_rows_preserved":True,"tables":new_tables,"foreign_keys":fk}
    Path(".local/phase09-migration.json").write_text(json.dumps(report,indent=2),encoding="utf-8");print(json.dumps(report))


if __name__=="__main__":main()
