from collections.abc import Generator

from fastapi import Request
from sqlalchemy import URL, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings


def database_url(settings: Settings) -> URL:
    return URL.create("mysql+pymysql", username=settings.mysql_user,
                      password=settings.mysql_password.get_secret_value(),
                      host=settings.mysql_host, port=settings.mysql_port,
                      database=settings.mysql_database, query={"charset": "utf8mb4"})


def make_session_factory(settings: Settings) -> sessionmaker:
    engine = create_engine(database_url(settings), pool_pre_ping=True, hide_parameters=True)
    return sessionmaker(engine, expire_on_commit=False)


def get_db(request: Request) -> Generator[Session, None, None]:
    with request.app.state.session_factory() as session:
        yield session
