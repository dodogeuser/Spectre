"""Read-only installation diagnostics; never imports collectors or invokes AI."""
import os
import sys
from pathlib import Path
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext
from pydantic import ValidationError
from sqlalchemy import create_engine,inspect,text
from app.config import Settings
from app.db.models import Base
from app.db.session import database_url
from app.version import VERSION,RELEASE_STATUS

ROOT=Path(__file__).resolve().parents[1]


def checks(settings,engine=None):
    results=[]
    def add(status,message):results.append((status,message))
    add("PASS" if sys.version_info>=(3,12) else "FAIL","Python 3.12+ required")
    add("PASS",f"SPECTRE {VERSION} ({RELEASE_STATUS})")
    password=settings.mysql_password.get_secret_value()
    add("FAIL" if not password or password=="CHANGE_ME" else "PASS","Database credential configured (value withheld)")
    add("WARNING" if settings.mysql_user.lower()=="root" else "PASS","Use a dedicated least-privilege database account")
    add("WARNING" if settings.bind_host not in {"127.0.0.1","localhost","::1"} else "PASS","Bind address: loopback recommended")
    add("WARNING" if settings.active_assessment_enabled else "PASS","Active feature enabled; per-target authority still required" if settings.active_assessment_enabled else "Active feature disabled")
    add("WARNING" if settings.ai_enabled else "PASS","AI configured locally; no provider contacted" if settings.ai_enabled and settings.ai_model else "AI disabled or model not configured; no provider contacted")
    output=settings.output_dir.resolve()
    add("PASS" if output.is_dir() and os.access(output,os.W_OK) else "FAIL","Configured output directory exists and is writable")
    owned=engine is None
    if owned:engine=create_engine(database_url(settings),hide_parameters=True,connect_args={"connect_timeout":5})
    try:
        with engine.connect() as connection:
            heads=MigrationContext.configure(connection).get_current_heads()
            script=ScriptDirectory(str(ROOT/"app/db/migrations"))
            add("PASS" if set(heads)==set(script.get_heads()) else "FAIL","Database migration revision matches application head")
            inspector=inspect(connection)
            tables=set(inspector.get_table_names())
            add("PASS" if set(Base.metadata.tables)<=tables else "FAIL","Required schema tables present")
            columns_ok=all(table.name in tables and set(table.columns.keys())<=set(column['name'] for column in inspector.get_columns(table.name)) for table in Base.metadata.sorted_tables)
            add("PASS" if columns_ok else "FAIL","Required schema columns present")
            fk_ok=True
            for table in Base.metadata.sorted_tables:
                if table.name not in tables:fk_ok=False;continue
                actual={(tuple(fk['constrained_columns']),fk['referred_table'],tuple(fk['referred_columns'])) for fk in inspector.get_foreign_keys(table.name)}
                for fk in table.foreign_key_constraints:
                    expected=(tuple(e.parent.name for e in fk.elements),next(iter(fk.elements)).column.table.name,tuple(e.column.name for e in fk.elements))
                    if expected not in actual:fk_ok=False
            add("PASS" if fk_ok else "FAIL","Required foreign-key relationships present")
            if connection.dialect.name=='mysql':
                engines=connection.execute(text('SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()')).all()
                add("PASS" if all(engine=='InnoDB' for name,engine in engines if name in Base.metadata.tables) else "FAIL","Required MySQL tables use InnoDB")
    except Exception:add("FAIL","Database unavailable or schema unreadable; check credentials, service and migrations (details withheld)")
    finally:
        if owned:engine.dispose()
    return results


def main():
    try:settings=Settings()
    except ValidationError:
        print("FAIL Configuration missing/invalid; check .env.example (values withheld)")
        return 1
    results=checks(settings)
    for status,message in results:print(f"{status} {message}")
    return int(any(status=="FAIL" for status,_ in results))


if __name__=="__main__":raise SystemExit(main())
