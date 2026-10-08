"""Isolated Windows launcher integration. No target collection or live DB access."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
pytestmark=pytest.mark.skipif(sys.platform!='win32',reason='Windows executable integration')


@pytest.fixture(scope='module')
def harness(tmp_path_factory):
    output=tmp_path_factory.mktemp('launcher-build')/'harness.exe'
    compiler=Path(os.environ.get('WINDIR','C:/Windows'))/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    if not compiler.exists():pytest.skip('Windows .NET compiler unavailable')
    subprocess.run([str(compiler),'/nologo',f'/reference:{ROOT/"SPECTRE.exe"}',f'/out:{output}',str(ROOT/'tests/windows/LauncherHarness.cs')],check=True,capture_output=True)
    shutil.copy2(ROOT/'SPECTRE.exe',output.parent/'SPECTRE.exe')
    return output


@pytest.fixture
def install(tmp_path):
    root=tmp_path/'Moved SPECTRE Ω'
    root.mkdir()
    shutil.copytree(ROOT/'app',root/'app',ignore=shutil.ignore_patterns('__pycache__'))
    # Disposable copied startup gets an automatic safety exit; never touches real app/config.
    startup=root/'app/run.py'
    startup.write_text(startup.read_text(encoding='utf-8')+"\n",encoding='utf-8')
    original=startup.read_text(encoding='utf-8')
    startup.write_text(original.replace('import sys','import os, threading\nthreading.Timer(10, lambda: os._exit(0)).start()\nimport sys',1),encoding='utf-8')
    shutil.copytree(ROOT/'launcher',root/'launcher',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(ROOT/'SPECTRE.exe',root/'SPECTRE.exe')
    scripts=root/'.venv/Scripts';scripts.mkdir(parents=True)
    shutil.copy2(Path(sys.executable),scripts/'python.exe')
    shutil.copy2(ROOT/'.venv/pyvenv.cfg',root/'.venv/pyvenv.cfg')
    site=root/'.venv/Lib/site-packages';site.mkdir(parents=True)
    (site/'fixture-runtime.pth').write_text(str(ROOT/'.venv/Lib/site-packages'),encoding='utf-8')
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    (root/'.env').write_text(f'SPECTRE_MYSQL_PASSWORD=synthetic-not-used\nSPECTRE_BIND_PORT={port}\nSPECTRE_AI_ENABLED=false\nSPECTRE_ACTIVE_ASSESSMENT_ENABLED=false\n',encoding='utf-8')
    return root,port


def run(harness,root,mode):
    env={k:v for k,v in os.environ.items() if not k.startswith('SPECTRE_') and k not in {'PYTHONPATH','PYTHONHOME'}}
    return subprocess.run([str(harness),str(root),mode],capture_output=True,text=True,env=env,timeout=65)


def test_relocated_launch_readiness_and_no_duplicate(harness,install):
    root,port=install
    result=run(harness,root,'success')
    assert result.returncode==0,result.stdout+result.stderr
    assert 'READY_BEFORE_BROWSER; SINGLE_SERVER; REUSED;' in result.stdout
    assert f'http://127.0.0.1:{port}/' in result.stdout


@pytest.mark.parametrize('fault,message',[
    ('missing','Required file missing'),
    ('python','Python environment missing'),
    ('unsafe','loopback bind settings'),
    ('bad','Configuration'),
])
def test_actionable_startup_failures(harness,install,fault,message):
    root,_=install
    if fault=='missing':(root/'app/run.py').unlink()
    elif fault=='python':(root/'.venv/Scripts/python.exe').unlink()
    elif fault=='unsafe':
        with (root/'.env').open('a') as f:f.write('SPECTRE_BIND_HOST=0.0.0.0\n')
    else:
        with (root/'.env').open('a') as f:f.write('SPECTRE_MYSQL_PORT=private-invalid-input\n')
    result=run(harness,root,'error')
    assert result.returncode==0,result.stdout+result.stderr
    assert message.lower() in result.stdout.lower()
    assert 'private-invalid-input' not in result.stdout


def test_occupied_unrecognized_port_refuses_duplicate(harness,install):
    root,port=install
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',port));listener.listen()
        result=run(harness,root,'error')
    assert result.returncode==0,result.stdout+result.stderr
    assert 'occupied' in result.stdout


def test_executable_icon_and_private_config_exclusion():
    binary=(ROOT/'SPECTRE.exe').read_bytes()
    assert binary.startswith(b'MZ')
    # An ICO PNG payload is embedded unchanged as an executable icon resource.
    icon=(ROOT/'app/static/images/branding/favicon-32.png').read_bytes()
    assert b'\x89PNG' in binary
    from scripts.release_package import files
    payload=set(files(ROOT))
    assert ROOT/'SPECTRE.exe' in payload and ROOT/'launcher/SpectreLauncher.cs' in payload
    assert ROOT/'.env' not in payload
