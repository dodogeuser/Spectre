# Phase 06 handoff

Implementation completed across 2026-10-05/06. Phase 06 only; Phase 07 has not begun. Automated, existing-MySQL API and live public-page verification passed. **Manual browser review remains pending because the browser automation tool exposes no available browser session.** This document does not claim that pending check passed.

## Functionality and provider

Guide steps 37–42 are implemented: scoped URL collection, one bounded public page, status/final URL/selected headers/title/server hints, inert HTML parsing, no recursive collection, and informational missing-security-header observations. The default `web_metadata` collector version is `1.0.0`; provider attribution is `Direct public HTTPS page / declared response headers`. No third-party API subscription, key or secret is needed. `PageProvider` is a replaceable constructor-injected Protocol; the shipped adapter delegates exclusively to the controlled client.

The UI adds a stored-evidence web overview with an explicit collection control, evidence citations, hashes, warnings and run history. Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy produce only informational observations. No semantic policy validation, vulnerability scoring, exploitation or later-phase correlation is implemented. Equivalent protections and applicability require review.

Manual-review follow-up on 2026-10-06: case list buttons and case headings now display `Case #ID`, and target rows display `Target #ID`. This distinguishes duplicate verification-case titles without changing records or collection behavior. JavaScript syntax validation passed; visual confirmation remains part of the pending owner browser review.

## Architecture and database

POST collection uses the Phase 03 central executor. Case mutation authorization, CSRF, enabled registry entry, URL type, scope and archive state are checked before provider work. The collector additionally validates the HTTPS seed; transport checks every resolved address and redirect destination. GET overview checks case access and reads stored records only.

Endpoints: `POST /api/cases/{case_id}/targets/{target_id}/collectors/web_metadata/runs`, `GET /api/cases/{case_id}/targets/{target_id}/web`, plus existing case-authorized evidence/run/audit endpoints. The overview limits display to 30 web runs/responses. Historical evidence remains retrievable through run endpoints.

**No Phase 06 database migration or DDL is required.** Existing revision **005 (head)** stores runs, raw evidence and normalized web observations. No generic findings table, graph rules or correlation jobs were added. Existing domain/IP projections remain available. The live MySQL fixture verifier checked InnoDB, revision 005 and exact preservation of all pre-existing rows in users, cases, targets, memberships, audits, runs, evidence, entities and relationships. Normal login sessions can rotate; they were not treated as immutable evidence. The database was not recreated, overwritten or deleted.

## Evidence and result states

Received supported responses retain provider, final source URL, HTTP status, selected headers, public resolved IP, bounded redirect metadata and exact body bytes as base64. Evidence includes capture time, raw canonical JSON SHA-256 and normalized observations. Its run retains operator, collector/version, target/scope snapshot and execution timestamps. Hashes use the inherited sorted-key compact UTF-8 canonical JSON format and are reproducibility checks, not administrator-resistant signatures.

Observed HTML success completes with title/header observations. An unclosed/oversized title or unsupported/invalid text encoding is explicitly partial and generates no missing-header findings. HTTP 404/410 completes as a `negative_http_response` observation; it describes that request only. HTTP 429 is `rate_limited`; other non-200 responses are unavailable. These retain supported raw responses with failed runs and `provider_http_error`, rather than becoming negative findings. Timeouts and network-policy violations retain sanitized failed runs/audits. Binary/oversized responses abort and produce no accepted evidence. Partial, unavailable and failed states are never represented as confirmed absence.

Synthetic responses are labeled `synthetic_fixture` and kept in a separate review case. Raw HTML remains case-authorized evidence; UI values use text nodes and never execute raw page content.

## Network and security controls

The inherited client enforces HTTPS/443, public-only DNS/IP destinations, pinned IP transport, verified original-host TLS, redirect revalidation, total deadlines, streamed size limits, bounded retries, per-host pacing and bounded workers/concurrent runs. Defaults: 10 seconds, 1 MiB, three redirects, one retry, one-second host pacing and four concurrent runs per process. HTTP 429/503 shared backoff remains in force. Limits are process-local; use one server worker.

The web adapter uses a fixed HTML/XHTML Accept value. Successful responses require those media types; error responses additionally permit plain text/JSON. Selected response headers have an 8,192-character individual limit. Cookies/authentication/ambient proxies are not forwarded. Redirect bodies are skipped; final compressed or binary/oversized responses are rejected. Binary magic and decoded NUL checks supplement content-type enforcement. HTML text decoding uses a bounded set of common encodings; title capture is limited to 1,000 characters.

No JavaScript execution, form submission, resource loading, crawling, target authentication, scanning, brute force, exploitation or AI collection invocation exists. HTTP-only targets remain recordable but cannot collect; no automatic TLS upgrade or relaxed transport fallback was added. Scope is checked at run admission; inherited in-flight cancellation limitations remain. Trusted adapters are reviewed Python code, not an OS sandbox against malicious plugins. `SPECTRE_WEB_METADATA_ENABLED=false` disables execution after restart.

## Automated tests and existing-MySQL verification

- Full Phase 00–06 suite: **224 passed**, including the complete Phase 00–05 regressions and network-policy tests. One inherited Starlette/httpx deprecation warning.
- HTML title/entity parsing, selected headers and informational observations passed; fixture links, script calls, images and forms generated no additional requests.
- Private-network/metadata redirects, HTTPS downgrade, nonpublic DNS answers, binary media/magic, oversized responses, bounded redirect history and fixed unauthenticated request headers passed.
- Successful, malformed/partial, timeout, network-policy, rate-limit and unavailable paths passed, including evidence hashes/provenance and completed/failed/denied audits.
- API scope/archive/type/disabled-registry/CSRF/viewer/unrelated-case restrictions passed. Fixture integration tests blocked socket/DNS primitives to detect transport bypasses.
- `compileall -q app tests scripts` and `pip check` passed on 2026-10-06.
- JavaScript syntax validation passed using the tool runtime's parser without executing the application script. The local Node CLI is not installed. Final full regression rerun: **224 passed**, one inherited warning, 37.32 seconds. Running application's `/health` returned `{"status":"ok"}`.
- `scripts/verify_local_phase06.py` passed against the existing MySQL database on 2026-10-05. Retained synthetic case **10**, URL target **21**, excluded target **22**, runs **29–33**, four evidence responses: observed 200, HTTP 404, failed HTTP 429 and partial unclosed title. Run 33 rejected PDF content with no evidence. Existing-row preservation, hashes, stored-only reads, scope, CSRF, viewer/unrelated restrictions and audit events were checked. Private report: `.local/phase06-fixture-verification.json`.

The fixture verifier makes no external requests. Re-running it adds a new labeled review case; it is not a provisioning or database-reset tool.

## Live-page results and manual verification still required

On 2026-10-06, `wampmysqld64` was stopped. Both normal and elevated tool service-start attempts failed with Windows access denial. The owner started the existing service from Administrator PowerShell; the database is again available at revision 005. Existing database settings/credentials were preserved. No alternate data directory, server initialization or authentication bypass was attempted.

`scripts/verify_live_phase06.py` performed one real page collection through the central API against the existing MySQL database. Retained case **12**, URL target **24** (`https://example.com/`), completed run **35**, evidence **61**. Observed HTTP **200**, title **Example Domain**, final URL `https://example.com/`, declared server hint `cloudflare`, selected response headers and six explicitly informational missing-header observations. Provider/source attribution, public resolved IP, raw hash, stored overview and started/completed audits passed. All **59 stored evidence hashes** were recomputed and every pre-existing project row was preserved. Private report: `.local/phase06-live-verification.json`. These are historical response observations, not vulnerability claims.

The first restricted-network attempt was retained separately as case **11**, target **23**, failed run **34**, `collector_error`, no evidence. The same verifier succeeded after required network escalation; no application network controls were changed. Re-running this script adds another review case, so do not rerun merely to inspect results.

The browser tool reported no available browsers and could not create the in-app browser. No alternate browser-control technology or security bypass was used. API verification was performed through local ASGI requests backed by actual MySQL; it does not replace visual browser review.

Finish these checks through the running local application:

1. Sign in as researcher, open synthetic case 10 and target 21's Web metadata view; inspect observed/partial/404/rate-limit history and evidence/audits.
2. Open live case 12, URL target 24's Web metadata view. Confirm title, HTTP 200, completed run 35, evidence 61, provider, final URL, selected headers and informational wording. No repeat collection is needed.
3. Inspect evidence 61 and recent audit records in the browser. Hash recomputation and revision checks already passed through the API/database.
4. Inspect viewer-disabled controls and excluded target 22's disabled control; confirm stored evidence remains readable only by authorized case members.
5. Save and inspect a private UI screenshot; update this handoff with actual live/manual results. If a public page fails under existing policy, record the failure without weakening controls.

Browser/API checks must concern the local SPECTRE UI; the collector must never use browser automation against target pages. Live target response data remains historical observations, not confirmed vulnerabilities.

## Files changed

New implementation: `app/collectors/web_metadata.py`, `app/api/web.py`.

Updated implementation: `app/services/http_client.py`, `app/services/collection.py`, `app/collectors/registry.py`, `app/config.py`, `app/main.py`, `app/static/index.html`, `app/static/js/main.js`, `app/static/css/main.css`, `.env.example`. Existing `.env` and credentials were preserved.

New verification: `tests/fixtures/web_page.html`, `tests/web_fixtures.py`, `tests/unit/test_web_parsers.py`, `tests/integration/test_web_metadata.py`, `scripts/verify_local_phase06.py`, `scripts/verify_live_phase06.py`. Updated verification: `tests/unit/test_network_policy.py`. Documentation: `README.md`, `SECURITY.md`, this handoff. Local reports remain ignored; no dependency change or migration is needed.

## Provider limits and known limitations

Direct web access has no configured provider quota beyond inherited host pacing/backoff and transport limits. Site policies may be more restrictive. No sustained collection schedule exists. Dynamic pages, challenges, unsupported encodings, compression or large bodies can prevent collection; limits are not relaxed. A title/server header is unverified response metadata, not proof of product/version or ownership. Security-header observations describe one unauthenticated response, not every route or authenticated application state.

Inherited limits include cooperative deadlines, process-local locking/rates, no persistent queue/recovery and no cancellation when scope changes after admission. Process termination can leave a running record. UI overviews are bounded; older evidence remains stored. Final manual browser review is pending, so Phase 06 should not yet be treated as fully verified. **Stop at Phase 06; Phase 07 requires explicit owner approval.**
