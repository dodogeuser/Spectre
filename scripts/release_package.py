"""Build an allowlisted source candidate ZIP; never include local investigations."""
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
from app.version import VERSION

ROOT=Path(__file__).resolve().parents[1]
DOCS=['INSTALL_WINDOWS.md','INSTALL_LINUX.md','CONFIGURATION.md','BACKUP_RESTORE.md','TROUBLESHOOTING.md','ARCHITECTURE.md','DATA_MODEL.md','COLLECTOR_GUIDE.md','DEPENDENCY_AUDIT.md','RELEASE_CHECKLIST.md','PHASE_13_HANDOFF.md']
SCRIPTS=['create_user.py','install_windows.ps1','install_linux.sh','backup.py','demo.py','migrate.py','release_package.py','release_audit.py']


def files(root=ROOT):
    selected=[]
    for directory in ('app','tests','launcher'):
        selected.extend(p for p in (root/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix not in {'.pyc','.pyo'})
    names=['README.md','SECURITY.md','RESEARCH_SCOPE.md','INSTALL.md','CONTRIBUTING.md','.env.example','.gitignore','.gitattributes','alembic.ini','pytest.ini','requirements.txt','requirements-dev.txt','requirements-runtime.lock','requirements-dev.lock','requirements-mysql-rsa.txt']
    selected.extend(root/name for name in names)
    # Cross-platform source packaging must not require a Windows compiler/binary.
    if (root/'SPECTRE.exe').is_file():selected.append(root/'SPECTRE.exe')
    selected.extend(root/'docs'/name for name in DOCS)
    selected.extend(root/'scripts'/name for name in SCRIPTS)
    return sorted(set(selected),key=lambda p:p.relative_to(root).as_posix())


def build(destination,root=ROOT):
    destination=Path(destination);manifest={}
    # Fail before creating output when an allowlisted deliverable is absent.
    selected=files(root)
    for file in selected:
        if not file.is_file():raise ValueError('Missing release deliverable: '+file.name)
    with destination.open('xb') as output,ZipFile(output,'w',ZIP_DEFLATED) as archive:
        for file in selected:
            name=file.relative_to(root).as_posix();data=file.read_bytes()
            if name.endswith('.sh'):data=data.replace(b'\r\n',b'\n')
            manifest[name]=hashlib.sha256(data).hexdigest();archive.writestr('spectre/'+name,data)
        archive.writestr('spectre/RELEASE_MANIFEST.json',json.dumps({'version':VERSION,'status':'release-candidate','sha256':manifest},sort_keys=True,indent=2))
    return manifest


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('destination',type=Path);args=parser.parse_args();build(args.destination);print('Release candidate source package created; clean Linux acceptance remains required.')
