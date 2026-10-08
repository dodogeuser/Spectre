# Phase 02 handoff

## Live setup and verification update

The user clarified that no SPECTRE database had actually been created and authorized complete local provisioning. Inspection confirmed the MySQL service was running, no `spectre` database existed, and no `.env` existed. The earlier claimed live Phase 01 verification therefore did not represent this workspace's database state; no missing configuration file was found or deleted by setup.

Created a new dedicated `spectre` database and localhost-only database account, with generated credentials saved in ignored `.env`. Other databases were untouched. Because the database was empty, applied migrations 001 and 002; current revision is `002 (head)`. The account has schema-scoped SELECT/INSERT/UPDATE/DELETE/CREATE/ALTER/INDEX/REFERENCES permissions, with no global permissions or DROP permission.

Created administrator, researcher, observer, and unrelated local application accounts with Argon2id passwords. Generated login passwords are saved in ignored `.local/login-credentials.json`, not documentation or tool outputs. A synthetic case named `Phase 02 live verification` remains for review.

Live MySQL checks passed for target schema columns and uniqueness constraint; all seven target types and expected canonical values; duplicates (409); scope updates; editing; archiving; viewer mutation denial (403); unrelated investigator access denial (404); administrator access and mutation audit records. The full 54-test suite passed afterward. Git ignore checks confirm both secret files are ignored.

SPECTRE started on loopback port 8000; live `/health` returned `{"status":"ok"}`. Browser verification remains a user review step. No Phase 03 work was performed.

Additional files: `scripts/setup_local_database.py` (refuses existing database/account/config rather than replacing), `scripts/verify_local_phase02.py` (one-time private account provisioning/live checks), and `.gitignore` (`.local/`). These scripts are not automatic startup actions. Do not rerun provisioning against the now-initialized database.

Additional commands:

```powershell
Get-Service wampmysqld64
Test-Path .env
# Read-only SHOW DATABASES through local PyMySQL root connection.
.\.venv\Scripts\python.exe -m scripts.setup_local_database
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m scripts.verify_local_phase02
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
git check-ignore .env .local/login-credentials.json
.\.venv\Scripts\python.exe -m pytest -q
(Invoke-WebRequest -Uri http://127.0.0.1:8000/health -UseBasicParsing).Content
```

The sections below retain the earlier implementation record; their pending database/server statements are superseded by this update.

## Scope and implementation

Re-read Phase 02 requirements and gates before implementation. Added typed targets for domain, IPv4, IPv6, URL, organization, username, and email, deterministic pure normalization, scope tracking, case-bound CRUD with archival deletion, target controls in the existing case detail view, duplicate prevention, and mutation audits. No Phase 03 framework, collectors, external providers, or active assessment was added.

Preserved Phase 00 health/static/configuration/logging behavior and Phase 01 authentication, CSRF, RBAC, case membership, and audits. Existing MySQL configuration/session factory is reused. Migration 002 descends from 001; the application never implicitly creates schema. Target creation has no network collection. Scope status is metadata only in this phase.

## Files created

- `app/services/normalization.py`
- `app/api/targets.py`
- `app/db/migrations/versions/002_targets.py`
- `tests/unit/test_normalization.py`
- `tests/integration/test_targets.py`
- `docs/PHASE_02_HANDOFF.md`

## Files modified

- `app/db/models.py`: target model, constraints, case index, timestamps, canonical hash.
- `app/main.py`: register case-scoped target router.
- `app/static/index.html`, `app/static/js/main.js`: target create/edit/archive, pagination, safe text rendering, role-aware controls.
- `requirements.txt`: declare IDNA dependency explicitly (already installed).
- `tests/integration/test_migration.py`: verify 001 → 002 preserves existing account/case records and rollback to 001 leaves them intact.
- `README.md`: migration, target API, normalization and archival behavior, tests, and limitations.

No prior migration was rewritten. The guide and prior-phase tests were preserved. No user database, account, credentials, or local service configuration was changed.

## Verification gates

| Gate | Result |
| --- | --- |
| Malformed targets fail safely | Tests reject malformed domains, IP version mismatches, unsafe URL syntax/credentials, bad email structure, invalid scope, whitespace-only values, and invisible/control characters; API returns 422. |
| Normalization deterministic | Repeated normalization and canonical replay tested across all seven types, including IDNA, IPv6, URL default ports/fragments, and case rules. |
| Canonical duplicates predictable | Creation/update return 409 within a case; duplicate updates roll back without mutation audits; different cases can reuse a canonical value; archived targets retain their canonical reservation. Database uniqueness handles races. |
| Zero collection during creation | Tests block DNS resolution and socket connections while creating all seven types using the in-memory test database. No collector/network code is called. Local MySQL transport is separate from target collection. |

Additional tests verify viewer restrictions, investigator isolation, admin audit behavior, CSRF, cross-case target-ID isolation, mutation provenance, and idempotent archival. User-supplied display values use `textContent` in the UI.

Final suite: **54 tests passed**, including all earlier regression tests. Compile checks and dependency consistency passed. MySQL SQL generation for 001 → 002 passed. SQLite migration round-trip and preservation checks passed. The prior upstream Starlette/httpx TestClient deprecation warning remains.

An initial malformed-input test exposed IDNA accepting a remaining trailing root dot; domain validation was corrected and the suite rerun successfully.

## Commands performed

```powershell
# Extracted the Phase 02 section from the build guide with Get-Content and string slicing.
Get-Content app/db/models.py,app/main.py,app/static/js/main.js,app/static/index.html,tests/integration/test_accounts_cases.py,app/db/migrations/env.py
rg --files -g AGENTS.md
git status --short
Test-Path .env
Get-Service wampmysqld64
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q app tests scripts
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m alembic upgrade 001:002 --sql
```

Files were edited with the patch tool. Tests were repeated after the validation correction and expanded coverage.

## Live database and review items

The user approved Phase 01 after live MySQL migration and browser verification. In this session, `.env` is absent and WAMP MySQL is stopped. `alembic current` failed with connection refused against configured defaults. No migration was applied to a guessed or replacement database. Connection configuration was requested; live Phase 02 migration is pending that configuration.

Once the existing connection is available:

```powershell
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Verify the existing database advances from 001 to 002, existing accounts/cases remain present, and manually exercise target create/edit/archive, duplicate errors, scope display, role controls, and audits in the browser. No server is left running. Browser behavior was not exercised in this session.

## Limits and policy choices

No real-world target validity/reachability checks, network controls/collection, active assessment, restore action, or physical target deletion. Archived rows remain visible and cannot be recreated as duplicates. Domains must contain a dot. Username and email local-part case is preserved; organization deduplication is case-insensitive. URL path/query semantics are conservatively preserved; fragments are ignored, but dot segments and equivalent percent encodings are not collapsed. Hash uniqueness uses SHA-256; a theoretical collision fails closed as a duplicate.

STOP after Phase 02. Live database/UI checks require review; do not begin Phase 03 without approval.
