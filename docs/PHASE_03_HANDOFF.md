# Phase 03 handoff

## Completed manual verification

The user completed the browser/API checks after implementation:

- Registry lists only enabled passive `mock` version 1.0.0. An attempt to invoke `dns` returned 404 `Collector unavailable`.
- Researcher explicitly created run 4 for case 5 / target 11. It completed with no error, operator 2, start/end timestamps, passive scope/value snapshot, and synthetic warning.
- Evidence 4 references run 4, source type `synthetic`, source `mock://target/11`, capture timestamp, raw target metadata, parsed synthetic marker/empty observations, and stored SHA-256 `b95748920e520a46c2daf60102442115e4f624791717fd35a1ef6850f7c76136`.
- Case audit contains run 4 started/completed events, actor 2, collector/version/target attribution, and one evidence record.
- Saved failure-fixture run 3 shows failed status, end time, safe `collector_error`, failure audit, and an empty evidence result. This was inspection of the earlier test-created failure; the fixture is not registered in the running app.
- Excluded case 3 / target 9 returned 403 on collection and recorded `collector.denied` with reason `target_scope` and actor 2.
- Observer received 403 `Viewer access is read-only` on collection, while reading synthetic evidence in its assigned case succeeded.
- Unrelated investigator saw no assigned cases and received `Case not found` on direct case evidence access.
- Missing-CSRF POST returned `Invalid CSRF token`. Run 4 remained the newest execution after rejected DNS and CSRF attempts.
- User reran `python -m pytest tests/unit/test_network_policy.py -q`: **31 passed**, with a non-failing pytest cache-path warning. These are simulated guard/transport checks, not a browser proof of arbitrary plugin sandboxing or real-provider traffic.

These results supersede the pending manual browser/API review item below. No Phase 04 implementation or real provider registration occurred. Phase 03 remains stopped for approval.

## Architecture implemented

Read the complete Phase 03 requirements/gates and reviewed target CRUD, scope states, case RBAC, audit helpers, SQLAlchemy models/session configuration, application initialization, existing migrations, and previous tests before implementation. Implemented Phase 03 only. No DNS/RDAP/CT/IP/web provider collectors, scanning, exploitation, active assessment, or AI execution capability were added.

The collection path is authenticated case/target action → central executor → static trusted registry → immutable seed snapshot and controlled HTTP context → validated result → evidence repository → transactional evidence/run/audit commit. Collectors do not receive a database handle. The only default registration is the offline `mock` collector, version 1.0.0, whose evidence explicitly says synthetic and whose observation list is empty. Disabled registrations are unavailable; active registrations are rejected. API clients cannot import/register arbitrary Python code or request arbitrary outbound URLs.

The executor checks case mutation permission, scope, archival status, supported type, enabled registration, passive-only behavior, and process concurrency before execution. `active_authorized` still enables passive behavior only. CSRF remains mandatory on execution. Run/evidence reads inherit case isolation. Started/completed/failed/denied actions retain operator/case attribution. Unsupported/unavailable/capacity/scope denials create no run; authorized executions get durable start records and terminal status. Collector exceptions expose safe codes only. Failed persistence rolls back partial evidence and then marks the run failed with an audit record.

Runs store target/actor IDs, collector/version, times, status/error code, warning list, and target value/scope snapshot. Evidence stores source type/reference, capture time (ingestion time), raw and parsed JSON, and SHA-256 of canonical raw JSON. Canonical serialization is sorted compact UTF-8 JSON, no NaN. `raw_response()` preserves exact HTTP body bytes as base64 alongside selected response metadata. There is no evidence mutation endpoint.

## Files created

- `app/collectors/base.py`, `app/collectors/mock.py`, `app/collectors/registry.py`
- `app/security/url_policy.py`, `app/security/rate_limit.py`
- `app/services/http_client.py`, `app/services/evidence.py`, `app/services/collection.py`
- `app/api/collectors.py`
- `app/db/migrations/versions/003_collector_evidence.py`
- `app/db/migrations/versions/004_transactional_storage.py`
- `tests/unit/test_network_policy.py`, `tests/integration/test_collectors.py`
- `scripts/verify_local_phase03.py`, `scripts/check_live_phase03_failures.py`
- `docs/PHASE_03_HANDOFF.md`

## Files modified

- `app/config.py`, `.env.example`: bounded network settings.
- `app/db/models.py`: collector runs and evidence tables.
- `app/main.py`: framework router, registry, shared limiter, admission semaphore.
- `tests/integration/test_migration.py`: SQL generation through 003 and intentional online-only storage migration check.
- `README.md`, `SECURITY.md`: setup/API/architecture, network/transaction boundaries, limits.

Prior routes and frontend code were preserved. No secrets were printed or added to source/docs. Existing `.env` and local login credentials were reused unchanged. The build guide was not modified.

## Migrations and live database findings

Initial live revision: **002**. Migration 003 adds `collector_runs` and `evidence`, including target/user/run references, timestamps, status checks, snapshots, parsed/raw payloads, hashes, and lookup indexes.

Live schema verification exposed WAMP's server default **MyISAM** on all SPECTRE tables. MyISAM ignored foreign keys and did not support transactional rollback, contradicting the evidence failure-isolation requirement. Added migration 004 within Phase 03 to precheck orphan relationships, convert only this database's tables to InnoDB, and restore all nine declared foreign keys. No server-wide settings or other databases were changed; no existing rows were deleted/recreated. Exact pre/post row snapshots confirmed users, cases, memberships, targets, audits, and sessions were preserved during storage conversion.

Current live revision: **004 (head)**. Live engine inspection confirmed InnoDB; foreign-key inspection passed. The executor refuses MySQL collection if required tables are nontransactional or run/evidence foreign keys are missing. Migration 004 is forward-only on MySQL; it deliberately rejects offline SQL generation because it needs integrity checks and constraint inspection. SQLite migration tests treat engine conversion as a no-op and preserve existing foreign keys/transactions. MySQL DDL commits incrementally; a future large deployment should back up before running storage conversion.

Two verification-script errors were corrected: the initial snapshot incorrectly assumed sessions had an `id` column (fixed before migration), and the first schema inspection exposed the MyISAM issue (resolved via 004). Neither error caused existing-row deletion. An offline migration test caught the need for explicit online-only handling for 004; the final test documents that restriction.

## Security controls

- Credential-free HTTPS on port 443 only. No HTTP/private-network exception.
- Blocks localhost/internal names, non-public/private/link-local/reserved/multicast/unspecified addresses, metadata destinations (including Azure's special address), and IPv6 transition/mapped addresses.
- Validates every DNS answer; mixed public/private answers fail closed. Numeric host spellings are checked after resolution.
- Connects to a validated pinned IP, preserving original hostname for certificate verification and Host. No hostname re-resolution at connection time.
- Revalidates each redirect; bounded hop count; no HTTPS downgrade.
- Fixed identifying User-Agent, identity encoding, no ambient proxy/cookie/auth or arbitrary request headers.
- Default total deadline 10 seconds, one retry, one second between host request starts, three redirects, 1 MiB streamed body limit. Config bounds prevent unlimited settings.
- Rejects compressed responses and oversized declared/streamed bodies; closes transport on failure.
- Four concurrent runs and eight network workers per process. Timed-out worker slots remain occupied until work actually exits; OS DNS work cannot spawn unlimited abandoned threads.
- At most 100 evidence records and total raw+parsed budget twice the response limit per run; bounded warnings.
- No plugin/user/AI execution path bypasses the shipped central API/executor/client flow. Plugins are trusted reviewed in-process Python, not an OS sandbox against malicious developer code.

## Tests and results

**96 automated tests passed**, including all Phase 00–02 regression coverage. One pre-existing Starlette/httpx TestClient deprecation warning remains. Compile/import and dependency checks passed.

Verification gates:

| Gate | Evidence |
| --- | --- |
| Malicious targets cannot cause private/local SSRF | Blocked URL/IP/scheme/credential/metadata matrix; mixed DNS and alternate numeric hostname checks; private redirect rejected before connect; pinned transport preserves TLS hostname; central runner records network-policy failure. |
| Timeouts and response limits enforced | Slow DNS deadline, slow collector timeout, bounded retries, host scheduling, redirect ceiling, oversized Content-Length/chunk stream, compressed-response rejection, oversized evidence rejection. |
| Collector failure does not corrupt case | Exception/timeout/cancellation/policy/size failures preserve case and safe terminal audit; injected partial evidence writes roll back. Live MySQL insert/flush/rollback verified real InnoDB behavior, and failed mock runs leave no evidence. |

Additional tests: synthetic provenance/hash verification with DNS/outbound socket access blocked, supported-type/enabled registry/passive enforcement, excluded/archived targets, CSRF, viewers/unrelated case access, capacity limits, evidence retrieval, audit attribution, and migration round trips. Windows asyncio uses a loopback control socket internally; the no-network mock test blocks outbound connection primitives without disabling that control pipe.

Live MySQL verification (using existing private credentials and ASGI API requests): completed mock run/evidence/hash, retained scope snapshot, exclusion denial, viewer read/write restriction, unrelated investigator denial, admin audit access, schema/foreign keys/engine validation, and sanitized failed-run behavior. Synthetic framework/failure cases and records are retained for inspection. No external target network collection was performed.

Server restarted with final Phase 03 code on http://127.0.0.1:8000. Live `/health` returned `{"status":"ok"}`; OpenAPI exposes the four framework endpoints. A localhost HTTP client also verified health, researcher login, and authorized registry retrieval returning only `mock`. Credentials were read locally, never printed. Previous case UI code remains preserved; this phase does not add a collector UI.

## Commands run

```powershell
# Extracted complete Phase 03 guide section with Get-Content/string slicing.
Get-Content app/api/targets.py,app/security/rbac.py,app/db/models.py,app/config.py,app/db/session.py,app/main.py,requirements.txt
rg --files -g AGENTS.md
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m scripts.verify_local_phase03
# Read-only SHOW CREATE TABLE and information_schema engine inspection via SQLAlchemy.
.\.venv\Scripts\python.exe -m scripts.check_live_phase03_failures
.\.venv\Scripts\python.exe -m compileall -q app tests scripts
.\.venv\Scripts\python.exe -m pip check
Get-CimInstance Win32_Process -Filter 'ProcessId = 4236' | Select-Object ProcessId,ExecutablePath,CommandLine
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
(Invoke-WebRequest -Uri http://127.0.0.1:8000/health -UseBasicParsing).Content
# Read OpenAPI framework endpoint names with Invoke-RestMethod.
# Local Python/httpx smoke check: health, researcher login, case list, mock registry.
git check-ignore .env .local/login-credentials.json
```

Files were edited with the patch tool. Tests repeated after fixes/new controls. Process inspection initially required sandbox escalation, then succeeded; the prior task-owned server was stopped through its existing tool session and restarted. Live setup/failure scripts add synthetic records; do not rerun merely to reconfirm unchanged results. The migration verifier requires 002/003 and stops at other revisions.

## Known limitations and manual review

- Only synthetic mock evidence; real provider compatibility, external TLS/DNS traffic and provider quotas are intentionally untested. No Phase 04 collector exists.
- Central limits are process-local; use one server worker. Synchronous API execution is bounded but there is no background queue, persisted recovery, or kill switch.
- Trusted async plugins must cooperate with cancellation; Python code is not sandboxed. A plugin that blocks the event loop can defeat a cooperative deadline. Review future plugins for raw networking/DB/subprocess access before registration.
- Scope is validated at admission and recorded; later scope/membership edits do not cancel an in-flight operation. Process crash/database outage can leave a `running` record and prevent terminal audit persistence.
- Evidence hash proves deterministic payload identity, not authenticity against privileged database edits. Source content remains untrusted data. API payload budget is enforced on result ingestion, not on arbitrary memory allocation by trusted plugin code.
- Network response headers use standard-library parser limits; explicit application payload limits cover body/evidence. DNS worker deadlines stop the caller but cannot forcibly interrupt the OS resolver.
- Storage hardening is forward-only; downgrading new tables on disposable MySQL databases requires an account with DROP permission, which the normal local account intentionally lacks.
- Browser interaction with new API actions has not been manually verified. Existing frontend was preserved. After signing in as researcher, use API requests with session CSRF to explicitly run `mock` on an allowed unarchived target, inspect status/evidence and case audits, then confirm scope/viewer/unrelated-case denials. `/docs` lists the new endpoints; execute POST via an authenticated client supplying `X-CSRF-Token`.

STOP after Phase 03. Wait for explicit approval before any Phase 04 work.
