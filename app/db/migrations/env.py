from alembic import context
from sqlalchemy import create_engine, pool

from app.config import get_settings
from app.db.models import Base
from app.db.session import database_url

if context.is_offline_mode():
    context.configure(url=database_url(get_settings()), target_metadata=Base.metadata,
                      literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()
elif context.config.attributes.get("connection") is not None:
    context.configure(connection=context.config.attributes["connection"], target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_engine(database_url(get_settings()), poolclass=pool.NullPool, hide_parameters=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
