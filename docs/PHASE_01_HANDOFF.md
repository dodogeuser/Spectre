# Phase 01 handoff

## Implemented

MySQL SQLAlchemy persistence and Alembic migration 001 for users, cases, membership, audits, and revocable login sessions. Local CLI account provisioning with privately entered passwords and Argon2id hashing. Login/logout and session identity API. Case dashboard, create/edit/archive, membership controls, and recent case audits.

Authorization is enforced by API dependencies and the case authorization module: viewers read assigned cases only; investigators create cases and access owned/shared cases; only owners/admins manage members; administrators have explicit audited access across cases. Unrelated cases return 404. Mutations require CSRF tokens. Session cookies are HttpOnly/SameSite Strict and Secure under HTTPS. No collectors were added.

## Files created

- `alembic.ini`
- `app/db/models.py`, `app/db/session.py`
- `app/db/migrations/env.py`, `app/db/migrations/versions/001_accounts_cases.py`
- `app/api/auth.py`, `app/api/cases.py`
- `app/security/rbac.py`
- `scripts/create_user.py`
- `tests/integration/test_accounts_cases.py`, `tests/integration/test_migration.py`
- `docs/PHASE_01_HANDOFF.md`

## Files modified

- `requirements.txt`, `.env.example`
- `app/config.py`, `app/main.py`
- `app/static/index.html`, `app/static/css/main.css`, `app/static/js/main.js`
- `README.md`, `SECURITY.md`

The build guide and Phase 00 tests were preserved. All files remain uncommitted because this repository has no initial commit.

## Commands executed

```powershell
Get-Content app/main.py,app/config.py,requirements.txt,tests/unit/test_foundation.py
rg --files -g AGENTS.md
Get-Service *mysql*
Get-ChildItem C:/wamp64/bin/mysql -ErrorAction SilentlyContinue
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q app tests scripts
.\.venv\Scripts\python.exe -m alembic upgrade head --sql
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -c "from app.main import app; print(app.title, len(app.routes))"
git status --short --untracked-files=all
node --check app/static/js/main.js
.\.venv\Scripts\python.exe -m scripts.create_user --help
```

Dependency installation used approved network access. Files were created/updated with the patch tool. The final reviewed suite has 17 passing tests: 14 Phase 01 integration tests and 3 unchanged Phase 00 regression tests. The existing upstream TestClient deprecation warning remains. Import, compilation, dependency consistency, MySQL SQL generation, and CLI help checks passed. The JS syntax command could not run because Node.js is not available on PATH. Migration upgrade/downgrade executed on in-memory SQLite with no persistent database changes.

## Phase 01 verification gates

The Phase 01 requirements and verification gates were re-read before the final review. No Phase 02 or later features were implemented.

| Gate | Evidence and result |
| --- | --- |
| Viewer cannot mutate cases | Assigned viewer reads succeed; create, update, and membership removal return 403. Passed. |
| Investigator cannot access an unrelated case | Unrelated case is absent from list; read, update, and membership mutation return 404. Passed. |
| Admin access is explicit and audited | Admin list, cross-case read, edit, and membership changes are exercised; actor IDs and audit actions are checked. Passed. |
| Passwords never stored/logged in plaintext | Stored hashes use Argon2id; login/logout captured logs and audit metadata exclude the submitted password and session/CSRF secrets. Validation responses omit submitted input. Phase 00 redaction tests still pass. |

Additional checks cover unauthenticated access to every case endpoint, CSRF rejection, session rotation, expiry and revocation, generic failed-login responses, owner protection, membership management by authorized operators, case persistence across app instances, SQLite migration round-trip, and MySQL migration SQL generation.

Final review commands, in addition to those above:

```powershell
# Read the Phase 01 section of SPECTRE_OSINT_Codex_Build_Guide.md and existing implementation/handoff.
Get-Content app/api/auth.py,app/api/cases.py,app/security/rbac.py,docs/PHASE_01_HANDOFF.md
.\.venv\Scripts\python.exe -m pytest tests/integration -q
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m compileall -q app tests scripts
.\.venv\Scripts\python.exe -m pip check
```

The final review expanded `tests/integration/test_accounts_cases.py` and `tests/integration/test_migration.py`, and updated this handoff and README verification documentation. Phase 00 routes, configuration, logging controls, health check, and static assets were preserved.

## Setup and run

WAMP MySQL 8.4.7 is installed but its service was stopped during inspection. No service state, MySQL database, or MySQL account was changed. No application account or `.env` was created. Live database setup requires a dedicated database/account and matching `.env` settings; see README. Then run:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m scripts.create_user administrator --role admin
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. No server is left running.

## Verification limits

Tests use SQLite and local ASGI requests, not a live MySQL instance. MySQL migration SQL generation passed, but live MySQL migration, browser interaction, and JavaScript execution have not been verified. This phase has no login throttling, password recovery, role editing UI, or expired-session cleanup. The app remains intended for loopback development. No target management, collection, graph, AI, or reports exist yet.

## Items requiring review

- Configure dedicated MySQL credentials and execute migration 001 against a live local database before manual account/case acceptance testing. The application does not create schema implicitly.
- Manually verify login/logout, case dashboard, editing, and membership controls in a browser against that database.
- Keep the service local; login throttling and release hardening remain outside this implementation.

STOP: Phase 01 code and automated gates are complete. Wait for explicit approval before Phase 02.
