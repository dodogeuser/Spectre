# Windows 10/11 installation

Status: existing Windows CPython 3.14 environment tested; a clean Windows install has not been performed. Target minimum is CPython 3.12+. Install Python with PATH support and MySQL 8 through their normal installers. WAMP MySQL is compatible but optional. SPECTRE does not install system services.

Extract the candidate into a writable directory, open PowerShell there, review and run:

```powershell
powershell -NoProfile -File scripts/install_windows.ps1
```

It checks Python, creates/reuses a Windows .venv, installs exact baseline packages, prepares output/pdf and logs, and copies .env.example only when .env does not exist. It does not modify an existing database, install a model or silently alter execution policy. Restrict .env access to your Windows user (Properties ? Security); do not place it in a shared directory.

## New database only

Use the MySQL administrator client with a prompted password (`mysql -u root -p`). For a new installation only, choose unused database/account names. Do not run these commands against an existing SPECTRE schema. Replace the illustrative passwords privately with independent random passwords; never use the placeholders. Avoid saving statements containing passwords in terminal transcripts/history.

```sql
CREATE DATABASE spectre CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'spectre'@'localhost' IDENTIFIED BY 'REPLACE_WITH_RANDOM_RUNTIME_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON spectre.* TO 'spectre'@'localhost';
CREATE USER 'spectre_migrate'@'localhost' IDENTIFIED BY 'REPLACE_WITH_DIFFERENT_RANDOM_MIGRATION_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES ON spectre.* TO 'spectre_migrate'@'localhost';
```

Match account host restrictions to the local server connection policy; do not use '%' merely to bypass access-denied errors. Configure .env with runtime account credentials. Keep migration credentials separate; the migration CLI prompts without persisting them. MySQL 8 caching_sha2_password can require RSA support when a secure connection is not already established:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-mysql-rsa.txt
```

That optional cryptography dependency is resolved separately and still needs advisory/platform validation; do not downgrade MySQL authentication to an insecure legacy plugin to avoid it.

```powershell
.\.venv\Scripts\python.exe -m scripts.migrate --user spectre_migrate
.\.venv\Scripts\python.exe -m scripts.create_user administrator --role admin
.\.venv\Scripts\python.exe -m app.doctor
.\.venv\Scripts\python.exe -m app.run
```

Account passwords are entered privately, 12?1024 characters; no production account is seeded. Create investigator/viewer accounts with the same CLI and appropriate --role. Open http://127.0.0.1:8000. For existing installations: back up first, preserve .env and all rows, review pending migrations, and use the migration account; never recreate the database. Version 1.0.0 candidate uses migration head 007 and adds no Phase 13 migration.


### Optional desktop launcher (RC)

After completing setup and checking `python -m app.doctor`, double-click `SPECTRE.exe` beside the `app` directory. It uses the existing `.venv`, `.env` and `python -m app.run`; it does not install/start MySQL or migrate records. It opens the default browser after local readiness and reuses an existing instance on the configured loopback port. If the EXE is missing in a source checkout, build with `python launcher/build_windows.py`; see [launcher documentation](../launcher/README.md). No admin, firewall or Windows policy changes are part of normal use. The EXE is unsigned; owner signing/SmartScreen and clean-machine acceptance remain pending.
