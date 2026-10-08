"""Explicit MySQL-client backup/empty-schema restore; no secrets in argv."""
import argparse
import re
import subprocess
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['backup','restore'])
    parser.add_argument('database')
    parser.add_argument('file',type=Path)
    parser.add_argument('--login-path',default='spectre')
    parser.add_argument('--confirm-empty-restore',action='store_true')
    args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_]{1,64}',args.database):parser.error('Invalid database identifier')
    try:
        if args.action=='backup':
            with args.file.open('xb') as destination:
                result=subprocess.run(['mysqldump',f'--login-path={args.login_path}','--single-transaction','--no-tablespaces','--skip-lock-tables',args.database],stdout=destination,stderr=subprocess.PIPE,check=False)
            if result.returncode:
                args.file.unlink()
                raise SystemExit('Backup failed; check MySQL client/login-path permissions (details withheld)')
            print('Database backup created. Protect it as sensitive investigation data.')
        else:
            if not args.confirm_empty_restore:parser.error('Restore requires --confirm-empty-restore and a separately created empty database')
            command=['mysql',f'--login-path={args.login_path}',args.database]
            probe=subprocess.run(command+['-N','-B','-e','SHOW TABLES'],capture_output=True,check=False)
            if probe.returncode or probe.stdout.strip():raise SystemExit('Restore refused: destination must be an accessible empty database')
            with args.file.open('rb') as source:result=subprocess.run(command,stdin=source,stderr=subprocess.PIPE,check=False)
            if result.returncode:raise SystemExit('Restore failed; destination may be partial. Preserve backup and review before retrying.')
            print('Restored into the explicitly selected empty database. Verify schema and evidence hashes before use.')
    except FileNotFoundError:raise SystemExit('MySQL client/input/parent directory unavailable; check installation and paths')
    except FileExistsError:raise SystemExit('Output already exists; nothing overwritten')


if __name__=='__main__':main()
