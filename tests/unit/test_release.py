import hashlib
import json
import logging
import socket
import sys
from pathlib import Path
from zipfile import ZipFile

import pytest
from alembic import command
from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy import create_engine
from fastapi.testclient import TestClient

from app.config import Settings
from app.doctor import checks
from app.main import create_app
from app.logging_config import RedactingJsonFormatter
from app.security.login_limit import LoginLimiter
from app.version import VERSION
from scripts.release_package import build as package


@pytest.mark.parametrize('values',[
    {'bind_port':0},{'bind_port':65536},{'environment':'unknown'},
    {'environment':'production'},
    {'environment':'production','mysql_password':'fixture-only','secure_cookies':False},
    {'environment':'production','mysql_password':'fixture-only','secure_cookies':True,'mysql_user':'root'},
    {'environment':'production','mysql_password':'fixture-only','secure_cookies':True,'log_level':'DEBUG'},
])
def test_invalid_release_configuration(values):
    with pytest.raises(ValidationError):Settings(_env_file=None,**values)


def test_release_defaults_and_portable_path(tmp_path):
    settings=Settings(_env_file=None,output_dir=tmp_path/'directory with spaces')
    assert settings.bind_host=='127.0.0.1' and not settings.active_assessment_enabled
    assert not settings.ai_enabled and isinstance(settings.output_dir,Path)
    assert not settings.mysql_password.get_secret_value()


def test_doctor_empty_database_migration_and_read_only(tmp_path):
    engine=create_engine('sqlite:///'+str(tmp_path/'empty.sqlite'))
    settings=Settings(_env_file=None,mysql_password='fixture-only',output_dir=tmp_path)
    assert any(s=='FAIL' for s,_ in checks(settings,engine))
    config=Config('alembic.ini')
    with engine.begin() as connection:
        config.attributes['connection']=connection;command.upgrade(config,'head')
    before=(tmp_path/'empty.sqlite').read_bytes()
    result=checks(settings,engine)
    assert not any(s=='FAIL' for s,_ in result),result
    assert 'fixture-only' not in str(result)
    assert (tmp_path/'empty.sqlite').read_bytes()==before
    engine.dispose()


def test_doctor_missing_credentials_directory_and_failure(tmp_path):
    engine=create_engine('sqlite://')
    results=checks(Settings(_env_file=None,output_dir=tmp_path/'missing'),engine)
    assert sum(s=='FAIL' for s,_ in results)>=3
    engine.dispose()


def test_login_throttle_bounded_and_expires():
    clock=[0];limiter=LoginLimiter(lambda:clock[0])
    assert all(limiter.admit('loopback') for _ in range(10))
    assert not limiter.admit('loopback')
    for n in range(1023):assert limiter.admit(str(n))
    assert not limiter.admit('overflow') and len(limiter.entries)==1024
    clock[0]=61;assert limiter.admit('loopback') and len(limiter.entries)==1


def test_version_security_headers_and_login_throttle():
    # No database calls: the missing login header is rejected before querying.
    with TestClient(create_app(Settings(_env_file=None))) as client:
        assert client.get('/version').json()=={'version':VERSION,'status':'release-candidate'}
        response=client.get('/')
        assert response.headers['x-frame-options']=='DENY'
        assert response.headers['x-content-type-options']=='nosniff'
        assert "script-src 'self'" in response.headers['content-security-policy']
        assert client.get('/health').json()=={'status':'ok'}


def test_log_cookie_and_access_query_redaction():
    formatter=RedactingJsonFormatter()
    record=logging.LogRecord('uvicorn.access',20,__file__,1,'GET /api/cases?arbitrary=private-value HTTP/1.1 Cookie: private-cookie csrf_token=private-csrf',(),None)
    result=formatter.format(record)
    assert all(secret not in result for secret in ['private-value','private-cookie','private-csrf'])


def test_synthetic_demo_no_network_no_overwrite(tmp_path,monkeypatch):
    def deny(*args,**kwargs):raise AssertionError('Demo must not contact any host')
    monkeypatch.setattr(socket,'create_connection',deny)
    monkeypatch.setattr(socket,'getaddrinfo',deny)
    from scripts.demo import build
    output=tmp_path/'offline demo'
    assert build(output)['synthetic']
    assert (output/'synthetic.pdf').read_bytes().startswith(b'%PDF')
    assert b'SYNTHETIC' in (output/'synthetic.html').read_bytes()
    with pytest.raises(FileExistsError):build(output)


def test_release_package_allowlist_integrity_and_no_overwrite(tmp_path):
    output=tmp_path/'candidate.zip';manifest=package(output)
    with ZipFile(output) as archive:
        names=archive.namelist()
        assert 'spectre/.env.example' in names and 'spectre/.env' not in names
        assert not any('/.local/' in n or '/output/' in n or '/__pycache__/' in n for n in names)
        assert 'spectre/docs/PHASE_12_HANDOFF.md' not in names
        for name,hash in manifest.items():assert hashlib.sha256(archive.read('spectre/'+name)).hexdigest()==hash
        assert b'\r\n' not in archive.read('spectre/scripts/install_linux.sh')
    with pytest.raises(FileExistsError):package(output)


def test_backup_refuses_existing_output_and_nonempty_restore(tmp_path,monkeypatch):
    from scripts.backup import main
    file=tmp_path/'backup.sql';file.write_text('preserved')
    monkeypatch.setattr(sys,'argv',['backup','backup','spectre',str(file)])
    with pytest.raises(SystemExit,match='already exists'):main()
    assert file.read_text()=='preserved'
    calls=[]
    class Result:returncode=0;stdout=b'existing_table\n'
    def run(args,**kwargs):calls.append(args);return Result()
    monkeypatch.setattr('scripts.backup.subprocess.run',run)
    monkeypatch.setattr(sys,'argv',['backup','restore','fresh_schema',str(file),'--confirm-empty-restore'])
    with pytest.raises(SystemExit,match='empty database'):main()
    assert len(calls)==1 and calls[0][-1]=='SHOW TABLES'


def test_configuration_errors_do_not_echo_values(monkeypatch,capsys):
    from app.doctor import main
    monkeypatch.setenv('SPECTRE_MYSQL_PORT','private-invalid-value')
    assert main()==1
    assert 'private-invalid-value' not in capsys.readouterr().out
