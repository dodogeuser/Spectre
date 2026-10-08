# Phase 09 handoff

Implemented and verified **2026-10-06**, Asia/Beirut. Phase 09 only; Phase 10 has not begun. No LLM, AI configuration, AI dependencies or new collection behavior was added. Phase 08 visual verification was approved by the owner. Phase 09 manual visual verification remains unavailable through automation; exact owner steps are below.

## Architecture and scope

Guide steps 55–60 are implemented: documented rubric, independent severity/confidence, explicit rules, analyst workflow, notes/audited severity overrides and visible reasoning. The guide does not enumerate additional vulnerability rules. The rule catalog therefore promotes only Phase 06's expressly defined informational missing-security-header observations. It does not invent DNS/CT/routing vulnerabilities or speculative ownership findings.

`app/services/findings.py` holds the catalog, scoring and generation. Generation queries stored case URL targets/runs/evidence, validates an eligible response and upserts one finding per case/target/rule. It does not run correlation or collection. The affected URL entity is reused when already present; the target and immutable captured URL remain available when no entity has been correlated. `app/api/findings.py` enforces authorization and manages views, generation and review. The local UI renders persisted API findings, never generates them itself.

Finding fields include case, target, optional URL entity, type/title/description, stable rule ID, rule/scoring versions, current generated assessment, immutable original assessment, effective severity, independent confidence, analyst status/notes/override/reason and creation/update timestamps. Supporting evidence and contextual relationships have normalized FK tables. Append-only revision snapshots preserve changes and actors.

## Rule catalog

Type: `missing_security_header`. Version: **1.0.0**. Stable identifiers:

- `web.missing_header.strict-transport-security`
- `web.missing_header.content-security-policy`
- `web.missing_header.x-content-type-options`
- `web.missing_header.x-frame-options`
- `web.missing_header.referrer-policy`
- `web.missing_header.permissions-policy`

Preconditions: current allowed/unarchived URL target, allowed run snapshot, `web_metadata` source/collector, completed run, observed/ok normalized result, HTTP 200 in raw and normalized metadata, HTML/XHTML media type, reproducible raw SHA-256, matching captured requested/final URL and agreement between raw selected headers and normalized security headers. A missing/empty selected header supports only absence in that captured unauthenticated response. Applicability, route coverage and equivalent protections require human review. This is not proof of vulnerability.

Latest run ordering is stored start time then run ID; latest evidence is capture time then evidence ID. Failures with no response, partial parsing, unavailable/rate-limited responses, HTTP 404/410 response negatives, unsupported or invalid/hash-damaged evidence create no new header finding. No provider absence is converted to a vulnerability or global-negative claim.

## Severity, confidence and rubric

| Input | Explicit rule/rubric behavior |
| --- | --- |
| Evidence type | Complete unauthenticated HTML selected-header observation |
| Security relevance | Header applicability is unassessed; rule severity is **informational** |
| Confidence | Fixed **0.95 high-support band** for the hash-verified captured-header observation, not exploitability, site-wide coverage or ownership |
| Recency | Age in whole days relative to newest stored evidence capture in this case; **<=30 days recent**, otherwise historical |
| Priority | **informational**, independent of confidence/recency; human review required |

There is **no numeric risk-score formula**. Scoring is a categorical result with a visible input/reason breakdown. The 0.95 constant is a documented ordinal high-support convention for a direct recorded observation, retaining uncertainty about capture/source completeness; it is not a calibrated probability. The 30-day threshold is an explicit recency-label convention, not a vulnerability-expiry claim. Recency never changes confidence/severity automatically. Same stored case evidence/rules produce the same scoring data because wall-clock time is not an input.

`generated_json` exposes severity, confidence, priority, evidence type, captured URL, recency/reference/threshold, rule state, assessment state, supporting IDs, rule/scoring versions and human-readable reasons. `original_json` preserves the first generated result and versions permanently. Creation/update timestamps record persistence operations, not scoring inputs.

Manual severity may be informational/low/medium/high/critical and requires a nonblank reason, including reset to rule severity. It changes effective analyst severity only, never original rule severity, confidence or rule priority. Status supports open, accepted, false_positive, informational and resolved; new header findings default to informational. No confidence-edit API exists. Notes are bounded to 10,000 characters and reasons to 2,000.

## Determinism, updates and provenance

Uniqueness is `(case_id, target_id, rule_id)`; rule-version upgrades update that identity and preserve prior revisions. Identical replay creates no findings, revisions or updated timestamps; the generation operation itself is audited. Re-generation with new matching absence evidence updates current support while retaining all previous FK evidence references, original score and analyst decisions.

A later complete response containing the header sets `not_observed_in_latest_response`; prior absence remains historical and the finding is not silently resolved. Partial/unavailable/failed current collection sets `historical_unverified` with an explicit assessment state/reason. Analyst status/notes/override remain unchanged. Historical active-support IDs refer to the observation that caused the finding; separate assessment support identifies why the current interpretation changed. Archived/excluded targets are skipped without erasing history. Case archive blocks generation and review mutations; historical target findings can still be reviewed in an open case.

Redirect relationships, when present, are contextual rather than prerequisites for header absence. They must match the Phase 07 pure deterministic plan for the same evidence, and endpoints/evidence must belong to the case. No relationship is generated or copied from unsupported inference. Evidence hashes/source/capture/run/collector metadata remain reachable through existing APIs; raw evidence is displayed as inert text.

## API and UI

- `GET /api/cases/{case_id}/findings`: 100-row pages, offset, status/effective-severity filters applied server-side.
- `GET .../findings/rules`: rule catalog/version/rubric.
- `POST .../findings/generate?after=0`: explicit synchronous mutation; up to 100 URL targets, with `has_more`/`next_after` continuation.
- `GET .../findings/{id}?offset=0`: finding, evidence history pages of 100, contextual relationships up to 100 and latest 50 revisions.
- `PATCH .../findings/{id}`: analyst status, notes and justified severity override/reset only.

**Open stored findings** and filters perform GETs only. **Generate from stored evidence** is an explicit separate POST, with a continuation message for larger cases. Cards show severity, independent confidence, status and rule state. **Why this finding / evidence** shows description, captured URL, target/entity, timestamps, visible reasoning, original result, recency, current assessment, direct active/assessment evidence buttons, support history and review form. Reasons are not hidden in tooltips. Entity navigation opens the existing stored graph inspection; no collection occurs.

The raw evidence panel uses text nodes and JSON formatting, never HTML injection. Views are reset on case switches and case-generation guards reject stale responses. Viewer/archived-case mutation controls are disabled; backend authorization remains authoritative. No clean/negative conclusion is implied by an empty list.

## Database and migration

Alembic **006_findings.py**, from **005**, adds only `findings`, `finding_evidence`, `finding_relationships`, `finding_revisions`. Tables explicitly use InnoDB on MySQL. Nine FKs: findings -> case/target/entity; evidence links -> finding/evidence; relationship links -> finding/relationship; revisions -> finding/actor. Target/rule uniqueness prevents replay duplicates. Status/override checks constrain workflow values. Referenced evidence cannot be physically deleted.

`scripts/migrate_phase09.py` applied only pending 006 to the existing database. Before/after row snapshots verified all pre-existing application tables unchanged, including sessions during migration. Tables/engines/FKs were inspected; revision is **006 (head)**. No database recreation, existing-table replacement or secret/config overwrite occurred. Report: ignored `.local/phase09-migration.json`.

Upgrade and downgrade/re-upgrade were tested on disposable SQLite, including preservation of prior case rows. No live MySQL downgrade was performed: it would delete new findings/revisions. The downgrade drops only Phase 09 tables in FK-safe order and is appropriate only for disposable databases. Prior-phase verification scripts with fixed revision-005 assertions remain historical tools, not current-head checks.

## RBAC, isolation, audits and network boundary

Generation/review require authenticated investigator/admin case mutation access plus existing CSRF. Viewers read only assigned cases; unrelated users receive 404 on list/detail/rules/generation/updates. Case-bound target joins, entity checks and evidence/run/target/relationship endpoint checks prevent cross-case influence/navigation. The reference clock is case-local. No endpoint accepts arbitrary evidence, relationship or entity IDs for finding creation.

Shared persistence locking covers generation/review plus outcome audits and commit. MySQL case locks and locking finding reads provide additional write serialization; deployment retains the existing single-worker assumption. Unexpected generation failures roll back all new findings/supports/revisions, then record a safe failure audit. No notes, reasons, raw provider payloads or credentials are copied into audit metadata. Reasons/notes are stored locally in authorized finding/revision records.

Audit actions: `finding.generated`, `finding.regenerated`, `findings.generated` (batch summary/replay), `findings.failed`, `finding.updated`, `finding.status_changed`, `finding.severity_overridden`. A combined review emits all relevant distinct events. Original result and every override/reset reason remain in revision history.

No finding action calls network collection, scans, exploits, brute force, arbitrary HTTP or an AI model. Existing collectors/network policy remain unchanged. No AI dependency/configuration/provider was introduced.

## Automated/regression verification

Full Phase 00–09 suite: **263 passed**, one inherited Starlette/httpx deprecation warning; final run **60.34 seconds**. Complete Phase 00–08 regression and all existing network-policy tests passed. Seventeen findings tests plus one migration-preservation/rollback test were added.

Coverage: generation/replay/no duplicate records or revisions, rule explanations/versioning, severity/confidence independence, evidence/entity linkage, valid redirect context, FK deletion protection, all workflow states, notes, override reason/reset/original preservation, server-side severity filtering, new evidence and historical support retention, partial/provider failure/HTTP negatives/hash-damaged/malformed evidence, no-response failures, excluded/archive states, empty cases, RBAC/CSRF/case isolation, atomic rollback/failure audits and deterministic recency. Socket/DNS primitives are blocked during generation tests to detect collection bypass.

Offline findings UI tests exercise actual handlers with an inert mock DOM: visible reasoning/original result, evidence inspection, inert malicious-looking JSON, explicit generation only, analyst review, unchanged confidence/original severity, viewer-disabled controls and reset. Existing real-Cytoscape graph UI tests also passed. JavaScript syntax, Python compilation, dependency checks and Alembic current passed.

## Live MySQL/API verification

`scripts/verify_local_phase09.py` passed against the restarted server at `http://127.0.0.1:8000` and the existing MySQL database. Retained **case 12**, **target 24**, **URL entity 58**, **run 35**, **evidence 61**, and findings **1–6**. The exact verified path is:

Stored complete response titled **Example Domain**, HTTP 200 -> evidence 61 and target/entity -> explicit missing-header rule v1.0.0 -> persisted finding -> informational rule severity / confidence 0.95 -> visible explanation -> authorized evidence inspection and reproducible raw hash.

All six findings reference evidence 61; repeated generation created/updated zero findings. Valid entity detail/evidence navigation was checked. One newly generated finding was temporarily changed to analyst low severity/accepted status with a verification reason and restored to rule severity/informational status; confidence and original score remained unchanged and revision/audit history retained both operations. Re-running the script only re-tests that specifically marked verification finding; it does not overwrite arbitrary analyst reviews.

Live CSRF rejection, observer assigned-case reads/write denial, unrelated-user list/detail/generation/update rejection, original result, support hashes and same-case finding evidence passed. Before/after snapshots preserved all previous users/cases/targets/memberships/runs/evidence/entities/relationships rows and counts. Only Phase 09 findings/supports/revisions and expected audit/session changes were created. No collector run or provider request occurred. Report: ignored `.local/phase09-verification.json`.

The initial live override check found that combined status/severity changes emitted only the status event. The implementation now emits generic update plus distinct status and severity-override events; full regression and live verification were repeated successfully.

## Manual UI verification status and exact steps

Supported browser inventory remains empty. This is an automation limitation, not an application failure. Actual findings UI visual verification was not claimed. API/database and offline UI checks passed.

1. Refresh http://127.0.0.1:8000 with Ctrl+F5 and sign in as researcher.
2. Open **Case #12 · Phase 06 live page verification**; use the visible ID to distinguish duplicate titles.
3. Under **Explainable findings**, click **Open stored findings**. Expect findings **#1–#6**, informational severity/status and confidence **95% recorded-observation support**.
4. Click **Why this finding / evidence** on finding #1. Inspect rule/version, affected captured URL, target #24/entity #58, explanation, original rule result and separate severity/confidence. Check the retained verification override/reset in revision history.
5. Click **Inspect current supporting evidence #61**. Expect run #35, title **Example Domain**, HTTP 200, source metadata and SHA-256. The evidence is JSON text, not a rendered external page.
6. Click **Inspect affected entity #58** to open existing stored graph inspection; no collection should start.
7. Optionally click **Generate from stored evidence** once: expect created 0 / updated 0 / unchanged 6. Reads/filters alone never generate.
8. For analyst workflow review, enter a status/note; a severity change/reset requires a reason. Verify original score/confidence remain unchanged and recent case audit records reflect the review. Assigned viewers can read but cannot generate/edit.

SPECTRE remains running on loopback. No Phase 10 approval is requested as part of these steps.

## Files changed and deferred functionality

New: `app/services/findings.py`, `app/api/findings.py`, `app/db/migrations/versions/006_findings.py`, `app/static/js/findings.js`, `tests/integration/test_findings.py`, `tests/js/test_findings.cjs`, `scripts/migrate_phase09.py`, `scripts/verify_local_phase09.py`, this handoff.

Updated: `app/db/models.py`, `app/main.py`, `app/static/index.html`, `app/static/js/main.js`, `app/static/js/investigation.js` (stored entity navigation helper), `app/static/css/main.css`, `tests/integration/test_migration.py`, `README.md`, `SECURITY.md`. `.env`, credentials, collectors and dependency requirements were preserved.

Only six informational header rules exist. No scoring of exploitation, certificate deployment, ownership or inferred services is provided. The categorical rubric does not rank speculative risk; recency labels use a stored-case reference rather than today's date. Generation is synchronous/bounded, not scheduled. Relationship context and revision responses are bounded; all history remains stored. Normalized observations remain trusted application/database data; raw hashes are reproducibility checks, not administrator-resistant signatures. Archive/exclusion retains historical review data and does not retract it. Browser visual review is still required for owner acceptance.

AI assistant, LLMs, reporting and later-phase functionality are deferred. **Stop after Phase 09; Phase 10 requires explicit owner approval.**
