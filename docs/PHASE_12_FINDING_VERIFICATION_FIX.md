# Phase 12 Finding → prepared verification correction

The Finding action now says **Prepare authorized verification**. Its explanation makes clear that preparation does not contact the target and that fresh authority confirmation and explicit execution are required.

The frontend checks the handler, current case, finding/target IDs, target value, and affected HTTP(S) URL before preparing the form. Invalid data or missing controls produce the existing visible alert. Finding button actions now catch synchronous errors as well as rejected promises. This fixes confirmed error-handling weaknesses; the original browser's unchanged-page failure was not conclusively reproduced.

Preparation selects the target, retains only the finding/target IDs, selects validation and HEAD, takes scheme/path from the stored affected URL, clears query/custom headers, initializes port checkboxes, and unchecks authority confirmation. Prior active state/history is cleared. Preparation uses console navigation without invoking its usual API refresh, so the click issues **zero API requests**. The analyst must use **Refresh stored history** to read the existing local active state before execution can be enabled. This reads SPECTRE records and does not contact the target.

Backend authorization remains authoritative and unchanged: RBAC, CSRF, provider configuration, exact-target authorization, scope, ports, public-address policy, case stop controls, rate limits, and evidence handling. No migration or dependency change is needed.

## Files changed

- `app/static/js/findings.js`: action wording/explanation, required handler check, synchronous error capture.
- `app/static/js/active.js`: validated preparation, explicit state reset, stored-state refresh prerequisite.
- `app/static/js/console.js`: preparation-only navigation without API reads.
- `tests/js/test_console.cjs`: complete shipped-script integration coverage, inert APIs only.
- `tests/js/test_active.cjs`: malformed, cross-case, mismatched target/host, unsupported URL/port rejection.
- `tests/js/test_findings.cjs`: fixture matches the existing detail API's case/target shape.
- This handoff.

## Verification

All eight offline JavaScript suites passed. The console suite now includes `active.js` in the shipped load order alongside main, investigation, findings, AI, reports, and console. It exercises the actual Finding button, real console navigation, prepared fields, visible errors, zero preparation requests, fresh confirmation, stored-state refresh, explicit mock submission with finding ID, and the real API helper's CSRF header.

Complete Python regression: `python -m pytest -q` → **378 passed**, including existing active rejection/security and network-policy tests, in 97.71 seconds. One dependency deprecation warning concerns Starlette TestClient/httpx. Tests use disposable/in-memory fixture databases and injected transports; no live verification or existing MySQL record change is part of this correction.

## Manual retest (pending)

1. Hard-refresh `http://127.0.0.1:8000` with Ctrl+F5. Sign in as the authorized investigator.
2. Open Case #16, **Wooperly Authorized Security Assessment**, then Findings → Finding #7 → **Why this finding / evidence**.
3. Click **Prepare authorized verification**. Expect the Active / Validation view and “Prepared Finding #7.” No run or verification should be created by this click.
4. Check target #27 `getwooperly.com`, validation, HEAD, HTTPS, `/login` (the stored affected path), empty `{}` query/headers, and unchecked authority confirmation. Execution must be disabled.
5. Click **Refresh stored history**. Check provider enabled, case not stopped, current authorization #4 for target #27/443, and the prior run history. This reads local stored data only.
6. Confirm authority afresh and click **Execute one authorized request** only when ready to contact the target. This is the step that can create a new active run and verification. Check its actual result and linked evidence; a successful transport does not guarantee a “verified” finding result.
7. Reopen Finding #7 (or reload its detail) to see the new verification history. The original finding result must remain intact.

Browser workflow status remains **pending manual verification**. No real request against getwooperly.com was executed, Case #16 records were not altered, Case #15 was not recollected, and Phase 13 was not started.

## Evidence-backed resource admission correction

The next manual retest reached submission but revealed a contract mismatch: the frontend prepared the finding's affected `/login` path, while backend admission forced domain targets to `/`. Admission now uses the immutable finding `original_json.affected_url` only when supported by original linked evidence, rather than deriving the resource from the parent target value.

`verification_resource` joins original evidence IDs through FindingEvidence, CollectorRun, and Target, constrained to the finding's case and target. It requires a completed collector run, valid canonical SHA-256, and an applicable complete HTTP observation supporting the missing-header rule. Active HTTP/validation/manual support must contain an observed HTTP 200 GET/HEAD HTML measurement, matching raw target ID and exact affected/source URL, without a scope boundary. Passive web-metadata support uses the existing `assess` gate and GET-only collector provenance, with the stored requested URL matching the affected URL and an authorized final destination. Unsupported, partial, hash-invalid, unlinked or foreign support cannot admit a request.

The affected resource must pass the existing exact-host and authorized-scheme/port destination policy, with no query or fragment. The submitted scheme and literal path must match that evidence-backed resource. GET/HEAD, HTTP/validation module, empty query and empty custom headers are checked independently with distinct error messages. No evidence means rejection before ActiveRun/FindingVerification insertion or transport scheduling. The existing final-response comparison against original hash-valid supporting evidence remains unchanged; admission alone is not a verified finding.

No arbitrary path capability was added. Provider gate, RBAC, CSRF, fresh confirmation, exact-target grants, scope, kill switch, network/SSRF protections, response/redirect limits, concurrency/rate limits, and original evidence remain unchanged. No database migration is needed.

Additional files changed in this contract correction:

- `app/active/service.py`: evidence-backed resource applicability/admission helper.
- `app/api/active.py`: resource-bound admission and distinct validation errors.
- `tests/integration/test_active_finding_resource.py`: 24 fixture cases, including domain `/login` GET/HEAD acceptance and pre-transport/pre-record rejection assertions.
- `tests/integration/test_active.py`: existing final-resource comparison test now requests its evidence-backed `/login` path; changed final responses still fail to verify.
- `tests/js/test_console.cjs`: shipped-script workflow fixture now explicitly uses a domain parent with an affected `/login` resource.
- This document.

Targeted backend verification: **70 passed**. All **8 frontend suites passed**. Complete Python regression: **402 passed** in 108.17 seconds, including existing active security and network-policy tests. The sole warning is the existing Starlette TestClient/httpx deprecation. All transports/databases are fixtures; no live requests or existing MySQL records were touched.

Before the manual steps above, restart the running SPECTRE/Uvicorn process to load the backend change, then hard-refresh the browser. Do not change authorization or target scope as part of restarting. Manual acceptance remains pending.

## Prepared-verification association lifecycle correction

The next manual run (#16 / evidence #88) succeeded as generic validation with `finding_id: null`, so it did not establish finding-specific admission or association. The frontend previously stored only a nullable finding variable; target-change events and case resets could erase it while retaining prepared request fields. This correction changes frontend state handling only. No production backend/schema changes were needed.

The explicit lifecycle is now **standalone → finding → cancelled**, with intentional transitions back to standalone or a newly prepared finding:

- Preparation freezes a snapshot of finding ID, case ID, target ID, module, method, scheme and path. Preparation itself still makes zero API requests.
- Refresh stored history and same-target change events retain the snapshot. Same-case/target authorization replacement also retains it and clears authority confirmation after successful replacement.
- Actual target changes, case reset/reopen/change, invalid preparation, missing/corrupt state, request-field mismatch, or a failed prepared submission cancel preparation. Cancellation clears finding-specific request fields, clears confirmation, replaces the prepared message with an explanation, and disables execution. Refreshing or rechecking confirmation cannot convert cancellation into standalone validation.
- **Start a new standalone request** is the explicit opt-in after cancellation. It clears prepared context and starts with a blank path and unchecked authority confirmation. The analyst must intentionally configure and confirm a standalone action.
- Immediately before a prepared submission, the frontend checks the snapshot against the current case, selected target and form contract. It reads the authorized Finding detail from the local API and checks its ID/case/target again, rechecking the snapshot and confirmation after the asynchronous read. Failure cannot omit `finding_id` and fall back to generic validation. Server-side admission remains authoritative and unchanged.

Additional files changed:

- `app/static/js/active.js`: explicit lifecycle, cancellation, snapshot validation, current-finding check, confirmation reset after authorization replacement.
- `app/static/index.html`: explicit standalone action and accessible verification status.
- `tests/js/test_active.cjs`: DOM fixture includes the new control.
- `tests/js/test_prepared_state.cjs`: nine state-transition scenarios plus explicit standalone recovery. Missing private state is fault-injected in the test VM only; production has no test hook.
- `tests/js/test_prepared_bridge.cjs` and `tests/integration/frontend_active_bridge.py`: actual Finding/Active handler output sent over local subprocess pipes to the real API with fixture storage and injected transport. No HTTP server/socket or existing MySQL database is used. Three scenarios cover refresh, same-target event, and actual fixture authorization replacement. Each verifies stored run association, completed verification, new evidence/link, detail retrieval, and unchanged original support.
- Phase 12 handoff and this fix document.

Targeted backend tests: **70 passed**. All **10 frontend suites passed**, including **9 lifecycle transition scenarios** and **3 frontend-to-real-fixture-API bridge scenarios**. Complete Python regression: **402 passed** in 109.06 seconds, including existing active security/network-policy coverage. The sole warning remains the Starlette TestClient/httpx deprecation. The bridge is exercised from the JavaScript suite; it is not counted as additional pytest cases. Evidence #88 remains immutable and unassociated with Finding #7. No Case #16 records, Finding #7, Authorization #5, or Case #15 records were changed; no live target request was made. Manual acceptance remains pending.

### Final browser retest

1. Hard-refresh with Ctrl+F5 to load the frontend fix; no configuration or authorization change is required.
2. Open Case #16 → Findings → Finding #7 → Why this finding / evidence → **Prepare authorized verification**.
3. Confirm target #27, validation, HEAD, HTTPS, `/login`, query `{}`, headers `{}`, and unchecked authority confirmation. The status must say Prepared Finding #7.
4. Click **Refresh stored history**; verify current Authorization #5 and case/provider state. Do not create a replacement authorization merely for this test. Finding #7 must remain prepared. Re-selecting the same target must also preserve preparation.
5. Confirm authority afresh and explicitly execute when ready for a live request. The frontend will read current Finding detail before submission; this read does not contact the target.
6. Inspect the newly created run: its action must contain **`finding_id: 7`** and the correct current authorization. Record the actual new run/evidence IDs rather than assuming their sequence.
7. Reopen Finding #7 and inspect the new verification's evidence link. Successful capture alone does not guarantee “verified”; the stored applicable response determines verified/not-confirmed/failed-to-verify. Original evidence/history and evidence #88 must remain intact.
8. Optional cancellation check, without executing: prepare again, then reopen/reset the case. Expect a visible cancellation, blank path, unchecked confirmation and disabled execution. Prepare again or explicitly start a standalone request to continue.

Stop after this Phase 12 fix; Phase 13 has not started.
