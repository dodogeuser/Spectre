"""Prompted schema-only migration credentials; never saved to configuration."""
import argparse
from getpass import getpass
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from app.config import Settings
from app.db.session import database_url


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--user',required=True);args=parser.parse_args()
    password=getpass('Migration database password: ')
    if not password:parser.error('A migration password is required')
    settings=Settings(mysql_user=args.user,mysql_password=password)
    engine=create_engine(database_url(settings),hide_parameters=True)
    try:
        with engine.begin() as connection:
            config=Config('alembic.ini');config.attributes['connection']=connection;command.upgrade(config,'head')
    except Exception:raise SystemExit('Migration failed; preserve backups and inspect schema/configuration. Database error details withheld.')
    finally:engine.dispose()


if __name__=='__main__':main()
