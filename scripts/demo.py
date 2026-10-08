"""Synthetic offline mock case in a NEW disposable SQLite directory, never MySQL."""
import argparse
import secrets
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app.api.auth import hasher
from app.db.models import User


def build(output):
    output=Path(output)
    output.mkdir(exist_ok=False)
    engine=create_engine('sqlite:///'+str((output/'synthetic.sqlite').resolve()),connect_args={'check_same_thread':False})
    try:
        config=Config('alembic.ini')
        with engine.begin() as connection:
            config.attributes['connection']=connection;command.upgrade(config,'head')
        factory=sessionmaker(engine,expire_on_commit=False)
        password=secrets.token_urlsafe(32)
        with factory() as db:
            db.add(User(username='synthetic_demo',role='investigator',password_hash=hasher.hash(password)));db.commit()
        settings=Settings(_env_file=None,ai_enabled=False,active_assessment_enabled=False)
        with TestClient(create_app(settings,factory)) as client:
            auth=client.post('/api/auth/login',json={'username':'synthetic_demo','password':password},headers={'X-Spectre-Login':'1'})
            assert auth.status_code==200
            headers={'X-CSRF-Token':auth.json()['csrf_token']}
            case=client.post('/api/cases',json={'title':'SYNTHETIC offline release demo','description':'Mock data only. No real intelligence or target contact.'},headers=headers).json()['id']
            target=client.post(f'/api/cases/{case}/targets',json={'type':'domain','value':'example.com','scope_status':'passive_allowed'},headers=headers).json()['id']
            run=client.post(f'/api/cases/{case}/targets/{target}/collectors/mock/runs',headers=headers)
            assert run.status_code in {200,201} and run.json()['status']=='completed'
            for format in ('html','pdf'):
                report=client.post(f'/api/cases/{case}/reports/export',json={'format':format},headers=headers)
                assert report.status_code==200,report.text[:100]
                (output/f'synthetic.{format}').write_bytes(report.content)
        return {'case_id':case,'target_id':target,'synthetic':True,'no_network':True}
    finally:engine.dispose()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    print(build(args.output))


if __name__=='__main__':main()
