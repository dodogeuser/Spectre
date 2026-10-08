# Backup and restore

Back up BEFORE migrations or service maintenance. Stop new mutations/collection and let active work finish or explicitly cancel it. Active background runs are not durable across restarts; never assume they will resume. Use a consistent InnoDB transaction dump while no schema DDL runs.

A complete investigation backup includes MySQL (raw/normalized evidence, hashes, targets, findings, relationship support, users, audit and grants) AND separately saved reports/artifacts/logs/private configuration. Raw evidence currently resides in MySQL, but filesystem exports remain independent sensitive copies. Do not back up just PDFs. Encrypt backups, restrict access, retain integrity digests and test recovery on an isolated machine. Never commit backups/.env to source control.

Configure a private MySQL client login path with the client tool's interactive password prompt:

```text
mysql_config_editor set --login-path=spectre-backup --host=127.0.0.1 --user=YOUR_BACKUP_USER --password
python -m scripts.backup backup spectre PRIVATE_DESTINATION.sql --login-path spectre-backup
```

Grant the backup user only required schema SELECT/SHOW VIEW privileges; this schema has no stored routines/triggers to export. Login-path storage is obfuscated, not strong encryption; protect the OS account and client credential file. The wrapper uses no shell, never puts passwords in argv, and creates dump output exclusively without overwriting. mysqldump/mysql must be available on PATH (ordinary MySQL installation, not WAMP-specific).

Copy protected .env/configuration and any necessary output/log directories separately while the app is quiescent; do not copy .venv as a cross-platform environment. Use Windows backup tools or Linux cp/rsync according to your permissions policy. Generate a SHA-256 digest for the dump/artifacts and store it separately. Credentials in the restored DB remain sensitive.

## Restore into a NEW empty database only

Do not point restoration at the live investigation database. Have a DBA create a separate empty schema/account with suitable schema privileges. Review the dump as trusted SQL before use: restoration executes its SQL, and untrusted dumps are not safe inputs. The wrapper refuses an existing/nonempty destination and requires explicit confirmation:

```text
python -m scripts.backup restore spectre_recovery PRIVATE_DESTINATION.sql --login-path spectre-restore --confirm-empty-restore
```

A failed restore may leave a partial new schema; preserve the backup and investigate before retrying. No automatic DROP/recreate/overwrite is supplied. Configure an isolated SPECTRE instance to use the restored DB, run doctor, inspect migration revision, counts, evidence hashes/provenance and reports without collecting. Review all active authorization grants before any future active execution; a restored grant is historical authority, not a reason to automatically contact targets. Verify artifacts against their saved digests. Adopt the recovery database only after explicit review. Backup/restore commands were fixture-tested, not executed against the existing investigation database during Phase 13.
