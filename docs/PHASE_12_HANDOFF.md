# Phase 12 handoff - authorized active verification

Phase 12 provides explicitly authorized, non-destructive active verification and controlled security validation. It is NOT an exploitation framework. Phase 13 has not started.

## Final status: CLOSED

Phase 12 is closed on the owner's instruction after final automated validation and owner-reported manual acceptance. Automated validation passed: **402 complete Python tests** and **10 frontend suites**. The final manual Finding workflow retained `finding_id=7` in **Run #17**, created **Evidence #89**, and exposed **Finding #7 Verification #3 = verified**. Original **Evidence #74** and failed/intermediate historical evidence remained preserved and immutable.

This closure records the owner's supplied acceptance results; no additional live or manual acceptance testing was performed for closure. No investigation records, authorization records, or schema were changed. Phase 12 is ready for Phase 13 planning, but Phase 13 implementation has not been authorized or started.

## Architecture and configuration

`SPECTRE_ACTIVE_ASSESSMENT_ENABLED=false` is the default. The owner enabled the active feature for final manual acceptance; this closure does not change configuration. Earlier implementation checks used a temporary in-process Settings override and ended with the feature disabled; that historical snapshot is not the final manual-acceptance state. Passive collectors, their registry, HTTPS policy, AI provider, scoring rules and graph storage keys remain unchanged.

The separate `app.active` layer owns policy, bounded pinned transports, fresh authorization checks, execution, stored projection and views. HTTP/TLS/TCP transports and resolver functions are replaceable trusted adapters injected through `ActiveClient`; no user-selected provider/client is exposed. Active modules are never registered as passive collectors and AI has no active-tool capability.

Migration **007**, from **006**, adds only `active_authorizations`, `active_case_controls`, `active_runs` and `finding_verifications`, with InnoDB foreign keys and lifecycle checks. It does not recreate the database or alter historical tables. Active runs link an attributable `active_*` CollectorRun to reuse the existing Evidence FK, integrity, inspection, graph and report pipeline. This shadow record is created only by the active lifecycle, never through the passive registry.

## Authorization and RBAC

Every execution requires the global flag, an authenticated current session, case access, investigator/admin execution permission, an unarchived case/target, `active_authorized` target scope, a separately recorded unrevoked grant and explicit confirmed request. Grant scope snapshots target type/value, exact host, allowed methods and selected ports. Editing the canonical target invalidates the grant. No domain/subdomain/IP discovery inherits authority.

| Action | Permission |
| --- | --- |
| View active history/evidence | Existing authorized case readers, including viewers |
| Grant/revoke authorization | Case owner or administrator; never an ordinary member/viewer |
| Execute HTTP/TLS/service/validation/manual request | Authorized investigator or administrator, with all gates above |
| Stop case/cancel run | Authorized investigator or administrator |
| Resume case | Case owner or administrator |

Mutations use existing CSRF checks. Unauthorized cases return 404. Revocation, cancellation and stopping remain usable when the feature is disabled. Fresh database checks occur before resolution, before transport, between bounded reads/redirects, after transport and before committing positive observations. A request already on the wire cannot be recalled; revocation prevents subsequent steps and positive result commit.

## Modules and request limits

- **HTTP / HTTPS:** one explicit GET, HEAD or OPTIONS action, with at most two same-host redirects (three HTTP requests total). Records status, redirect history, final URL, selected headers, pinned public destination, timing and bounded body measurements/hash.
- **TLS:** one verified TLS connection to exact-host port 443. Stores presented leaf SHA-256, subject/issuer, bounded SANs, validity, capture-time expiration state, negotiated protocol/cipher. Invalid certificates fail closed; there is no unverified retry. SANs do not become authorized targets or inferred live hosts.
- **Service:** explicitly selected ports **80 and/or 443 only**, TCP connection acceptance/refusal and timing. No banners, ranges, CIDRs, arbitrary ports or service guesses. A successful first port survives a later unavailable port as partial intelligence.
- **Validation:** deterministic informational header observations, advertised additional methods from OPTIONS, wildcard CORS, server metadata and a bounded root-HTML directory-index signature. Advertised PUT/DELETE/PATCH/TRACE/CONNECT are never executed. No exploitability verdict.
- **Safe endpoints/manual builder:** exactly one entered path, including `/robots.txt` and `/.well-known/security.txt`; validated small query/header objects. Only Accept and Accept-Language custom headers. No destination URL, Host override, cookies, Authorization, credentials, request body, file access, enumeration or payload engine.

Global active concurrency is one per process; excess work fails safely rather than forming an unbounded queue. Starts are at least two seconds apart per host. Limits are 20 seconds total, five seconds per connection/read, 64 KiB uncompressed body, 16 KiB aggregate response headers and 4 KiB per selected header. 429/503 impose a 60-second host defer. All DNS answers must be public; mixed public/private answers fail closed. Validated addresses are pinned, with original-host verified TLS/SNI. HTTP is permitted only in this active-specific client on authorized port 80; the passive HTTPS-only policy is unchanged. Every redirect is checked before resolution/contact; host changes, private addresses and HTTPS downgrades are not followed.

## Evidence, findings, graph and timeline

Active evidence uses distinct `active_http`, `active_tls`, `active_service`, `active_validation` and `active_manual` sources. Canonical raw JSON retains module/version, target, active run, numeric authorization FK, safe action metadata and measured observations. Capture time, SHA-256 and existing CollectorRun provenance remain inspectable. Query values/custom-header values are not persisted; query keys and a canonical query fingerprint attribute the request. Selected response headers are scrubbed. Arbitrary HTML is not retained; body size/hash and a bounded signature are retained. Only plain-text robots/security.txt responses may have a 512-character scrubbed preview.

Failure evidence is explicitly unavailable, not a negative finding. Partial, rate-limited, unavailable and 404/410 response states remain distinct. A refused TCP connection describes only that port at capture time. TLS failure proves no successful certificate inspection. Original evidence is immutable.

New informational findings use existing missing-header rule IDs where applicable, plus `active.http.advertised_methods`, `active.http.cors_wildcard`, `active.http.server_metadata` and `active.http.directory_listing`. They retain rule/scoring version `1.0.0`, original result, supporting evidence and explicit reasoning. Severity is informational; confidence **0.95** follows the existing direct-observation rubric and is not a vulnerability probability. No numeric risk score or recency rating is assigned to the additional active rules. Existing same-target/rule findings are preserved instead of duplicated or overwritten.

Finding -> Verify supports existing missing-header rules only. Separate verification rows distinguish **observed**, **verified**, **not_confirmed** and **failed_to_verify**. Verification requires a complete 200 HTML HEAD/GET response for the same originally evidenced final resource, a verified original evidence hash and case/target-local support. Same-host redirects are allowed only if they reach that original resource. A changed resource, incomplete response or failed request cannot refute the finding. New verification evidence is linked without changing original rule severity/confidence or analyst review. Queries/custom headers are excluded from this compatible workflow.

Stored projection reuses canonical case entities and logical-edge deduplication. New service entities use `tcp://host:80|443`. Observed relationships are `active_connects_to` (exact host to pinned IP), `exposes_service` (accepted connection/response) and `presents_certificate` (verified presented leaf fingerprint). Each support references active evidence; certificate fingerprints can reuse CT entities. No SAN topology or network-neighbor inference is generated. Existing dragging, resizing, layout/collapse controls and browser-local storage namespaces were not changed.

Timeline reads stored grant/revoke, active requested/started/terminal timestamps, evidence captures and finding verification request/result events. Ordering uses existing timestamp/type/key sorting. Viewing graph, timeline, findings, active history or reports never collects.

HTML/PDF reports add **Active Verification** only when active history exists. The section includes scope, grants, actor/times, safe actions, measurements, evidence, failures and verification states. Default analyst-note redaction also covers grant notes. Active and passive sources remain distinguishable. No AI is involved. Passive-only Case 15 exports retain their approved digest and identical bytes.

## UI

Dedicated **Active / Validation** navigation contains target selection, authorization note/ports, case stop/resume, module/method/scheme/path controls, safe endpoint suggestions, bounded JSON query/header inputs and stored run/evidence/cancel controls. A prominent **THIS ACTION DIRECTLY CONTACTS THE TARGET** warning and confirmation checkbox precede authorization/execution. Disabled feature/viewer/archive controls are visible; backend checks are authoritative.

Stored history polls every five seconds only when the workspace/page is visible. Case changes clear state and stale responses are discarded. Finding inspection shows verification history and a separate explicit-authority Verify action. Graph filtering adds the stored `service` type without resetting presentation state. Evidence/provider text uses inert DOM text, not HTML.

## Verification results

- Baseline: **317 passed**, one existing Starlette/httpx deprecation warning.
- Final complete Python suite: **402 passed**, one existing Starlette TestClient/httpx deprecation warning. Includes all Phase 00-11 regressions and **85 Phase 12 tests**.
- Phase 12 tests: **70 integration + 14 transport/policy unit + 1 disposable migration test = 85**. Deterministic mocks only; no public target dependency. The final targeted backend run passed all 70 integration tests.
- Existing network-policy suite: **38 passed**.
- Final frontend: **10 suites passed**: investigation, findings, AI, console, graph presentation, populated graph, reports, active handlers, prepared-state lifecycle and frontend-to-fixture-API bridge. Includes 2,000-node fixtures, persistent layouts, no-collection navigation, disabled/viewer controls, confirmation, polling, stale-case rejection, nine prepared-state scenarios and three actual frontend-payload-to-real-fixture-API association scenarios. Bridge scenarios are not counted as additional pytest cases.
- Migration: disposable SQLite upgrade 006 -> 007 -> 006 -> 007 preserved a sentinel existing record. Existing MySQL upgraded 006 -> 007; digests of every row in **14 existing tables** remained identical. Four new tables have 4/2/5/3 FKs respectively. No populated live downgrade was attempted.
- Mock paths cover disabled/passive/excluded authorization rejection, revocation, owner/member/viewer access, CSRF, case isolation, private/mixed DNS, exact-host redirects, unsafe methods/ports/path/query/headers, timeout/size/TLS/malformed failures, partial services, queued cancellation, mid-operation revoke/kill/cancel/archive/edit/logout, immutable original findings, all verification outcomes, same-resource redirect matching, evidence hashes, graph/timeline and deterministic reports.

Commands: `python -m pytest -q`; `python -m pytest tests/unit/test_network_policy.py -q`; `python -m pytest tests/integration/test_active.py tests/unit/test_active_transport.py tests/unit/test_active_migration.py -q`. Frontend suites are exported async functions under `tests/js`, executed with Node's VM and the locally shipped Cytoscape dependency.

## Owner-authorized live acceptance

### Final owner-reported manual acceptance

The following real-world workflows were manually verified by the owner:

- Active feature enablement and authorization gating.
- Exact Target #27 authorization for `getwooperly.com` in Case #16.
- HTTP/HTTPS active verification, TLS certificate inspection and security validation.
- Active evidence creation and evidence-backed Finding verification.
- Fresh authority confirmation and Finding association preservation.
- **Run #17 retained `finding_id=7`; Evidence #89 was created; Finding #7 Verification #3 = verified.**
- Original **Evidence #74** remained preserved; failed/intermediate historical evidence remained immutable.

**Run #16 / Evidence #88:** a legitimate authorized standalone validation observation under Authorization #5. It remains immutable and intentionally is not retroactively associated with Finding #7. It does not represent a Finding-verification result. Closure does not change or revoke Authorization #5.

### Capabilities not manually exercised in final acceptance

Each remaining capability below has the status **Covered by automated tests; manual acceptance not performed.** Historical engineering API checks, where listed later, do not constitute owner manual acceptance.

| Capability | Acceptance status |
| --- | --- |
| OPTIONS / advertised-method observations | Covered by automated tests; manual acceptance not performed. |
| Selected TCP service ports, refused/unavailable/partial service results | Covered by automated tests; manual acceptance not performed. |
| Safe endpoint requests and standalone manual query/header builder | Covered by automated tests; manual acceptance not performed. |
| Case stop/resume, queued cancellation and mid-operation revocation/cancellation | Covered by automated tests; manual acceptance not performed. |
| Viewer/member/admin restrictions, CSRF rejection and cross-case isolation paths beyond the manually verified authorization workflow | Covered by automated tests; manual acceptance not performed. |
| Private/mixed DNS rejection, forbidden hosts/ports/paths, redirect boundaries and SSRF rejection | Covered by automated tests; manual acceptance not performed. |
| Timeouts, malformed responses, invalid TLS, rate/concurrency limits and response-size bounds | Covered by automated tests; manual acceptance not performed. |
| Other Finding outcomes and malformed/foreign/hash-invalid support rejection | Covered by automated tests; manual acceptance not performed. |
| Invalidating prepared-state transitions, corrupt-state cancellation and explicit standalone recovery beyond the final verified association workflow | Covered by automated tests; manual acceptance not performed. |
| Active graph/timeline projection, report integration and deterministic replay | Covered by automated tests; manual acceptance not performed. |
| Migration preservation/rollback on disposable storage | Covered by automated tests; manual acceptance not performed. |

Any other Phase 12 capability not explicitly listed as owner-manually verified above is **Covered by automated tests; manual acceptance not performed.** No further acceptance testing is requested as a condition of this closure.

### Historical implementation API checks (not owner manual acceptance)

Dedicated **Case #16: Wooperly Authorized Security Assessment**, **Target #27: getwooperly.com**. User stated ownership/control; recorded notes preserve that authorization. Only the exact authorized host was contacted. No iana.org collection, third-party redirect follow, subdomain probes or discovered-IP enumeration occurred.

| Check | Result |
| --- | --- |
| Passive-only / no-current-grant request | 403 before transport |
| HTTP HEAD | Run 2; 301 HTTPS upgrade, then same-host `/login`, final 200 |
| HTTPS HEAD | Run 3, 200 |
| TLS | Run 4; verified TLSv1.3, Sectigo issuer; validity Jan 13 2026-Jan 13 2027; not expired |
| Security validation HEAD | Run 5, 200; informational missing-header observations |
| OPTIONS | Run 6, 200; only safe OPTIONS executed |
| GET robots.txt | Run 7, 200 |
| GET security.txt | Run 8, 404; recorded negative HTTP response, not general absence |
| Ports 80/443 | Run 9; both accepted; no application identity inferred |
| Manual HEAD with neutral query/Accept | Run 10, 200; fixed authorized host |
| Finding #7 verification | Run 12, **verified**, Evidence **#84**, original Evidence #74 retained |
| Active graph | 5 stored entities / 4 logical relationships, all evidence-backed |
| Timeline | 62 stored events at final acceptance, including 42 active lifecycle events |
| HTML/PDF | Active Verification present; replay byte-identical; final PDF 12 pages |
| Revocation | All three grants revoked; subsequent POST returned 403 |

Failure handling encountered: sandboxed Run 1 failed `network_unavailable`, retained Evidence #73 and no inferred finding. It was not deleted. Authorized execution outside the sandbox succeeded without weakening network policy. Initial verification Run 11 conservatively returned failed_to_verify because the root redirected to `/login`. Added same-original-resource tests and fixed comparison against immutable original support; one final HEAD produced verified Run 12. Run 11/Evidence #83 remain intact.

All live evidence #73-84 hashes verified. Historical investigation/audit rows were compared by primary key after acceptance; none was altered. Normal login-session rotation follows existing authentication behavior. Existing active runs/grants were preserved while new histories were appended. The initial HTTP-80 acceptance action retained the unused service-selector default `[443]`; its actual HTTP scheme, redirect history and grant show port 80 correctly. Future action metadata now derives the operation's actual port, with a regression assertion; historical JSON was not rewritten. Windows PowerShell Stop-Process failed during reload; a validated listener-only taskkill/restart succeeded. Final server checks confirmed health, disabled active POST (403), all grants revoked, verified Finding 7/Evidence 84, and the unchanged Case 15 digest. Detailed local results: `.local/phase12-migration-verification.json`, `.local/phase12-live-verification.json`, `.local/phase12-initial-live-verification.json`, `.local/phase12-frontend-results.json`, `.local/phase12-final-server-verification.json` (ignored local artifacts).

## Case 15 preservation

No recollection. Still one target, four runs, nine evidence records, 50 entities, 56 logical relationships and zero findings. Snapshot SHA-256 remains `e715e574c394f1c8947a03102b398c286c55b9230bbf1f96f4882cb379f78c2e`; PDF SHA-256 remains `62b4fd09a917a6105c55270a02fa3a2d30ae18b02dfa8acd2a0079020110fe3e`. HTML/PDF bytes match the pre-Phase 12 snapshot; label wrapping is preserved.

## Visual/manual review

Owner manual acceptance is complete for the workflows explicitly recorded above. Earlier browser automation was unavailable; offline handler and fixture-API coverage supplemented that environment limitation. Historical engineering PDF rendering/API checks remain separate from owner manual acceptance. No additional browser, manual, or live tests were performed for closure, and no further manual review is required to close Phase 12.

## Files created/changed

- `.env.example`, `app/config.py`, `app/main.py`
- `app/db/models.py`, `app/db/migrations/versions/007_active_verification.py`
- `app/active/__init__.py`, `app/active/policy.py`, `app/active/client.py`, `app/active/service.py`, `app/active/projection.py`, `app/active/views.py`
- `app/api/active.py`, `app/api/findings.py`, `app/api/investigation.py`
- `app/services/correlation.py`, `app/services/reporting.py`
- `app/static/index.html`, `app/static/css/main.css`, `app/static/js/active.js`, `app/static/js/console.js`, `app/static/js/findings.js`, `app/static/js/investigation.js`
- `tests/integration/test_active.py`, `tests/unit/test_active_transport.py`, `tests/unit/test_active_migration.py`, `tests/unit/test_console_shell.py`, `tests/js/test_active.cjs`
- `tests/integration/test_active_finding_resource.py`, `tests/integration/frontend_active_bridge.py`, `tests/js/test_prepared_state.cjs`, `tests/js/test_prepared_bridge.cjs`; existing findings/console frontend tests updated during corrections
- `scripts/migrate_phase12.py`, `scripts/verify_live_phase12.py`
- `README.md`, `SECURITY.md`, `docs/PHASE_12_HANDOFF.md`
- `docs/PHASE_12_FINDING_VERIFICATION_FIX.md`

Generated review artifacts: `output/pdf/spectre-case-16-phase12.html`, `output/pdf/spectre-case-16-phase12.pdf`, local verification JSON and PDF QA PNGs. No dependency was added.

## Known limitations and extension boundary

- **Background active runs are not durable across application restarts.** BackgroundTasks are not a durable job queue; restart does not resume queued/running jobs. Stale queued work can be cancelled. Interrupted running rows can be marked cancellation-requested but need operator review because their worker cannot finalize them after a crash. No automatic replay/contact occurs. Admission/rate controls are process-local; do not deploy multiple workers as a way to multiply active throughput.
- Cancellation is cooperative. An in-flight OS DNS/socket/TLS call may continue to its bounded deadline; later steps/positive commit are blocked. Kill/revoke cannot undo an already sent request.
- HTTPS verification deliberately fails on invalid certificates; failure codes do not identify a confirmed TLS vulnerability. No insecure retry or broad protocol/cipher audit.
- TCP acceptance/refusal is not service fingerprinting; timeouts remain unavailable. Modules only cover ports 80/443 and domain/URL targets. No private-lab exception.
- GET semantics depend on the target application. Investigators must choose a genuinely non-mutating specific path; the builder never automatically discovers paths or sends credentials.
- Query values are intentionally not saved and therefore cannot be replayed from stored history. Only approved selected response metadata and bounded public text previews are retained; arbitrary HTML bodies/certificate DER are not stored. Review notes/previews before sharing; unlabeled secrets cannot be identified perfectly.
- First 100 targets/grants/latest runs are shown in the UI; bounded-state labels are explicit. Complete report active history is limited to 10,000 records per category and existing graph/context/output budgets.
- Verify is limited to missing-header observations for the exact originally captured final URL, without query/custom-header changes. Ambiguous/changed responses fail to verify. Active rules do not assess exploitability, equivalent protections, risk probability or recency; original analyst workflow stays separate.
- Future safe modules may extend the same policy/client/service interfaces only with explicit scope, tests and approval. No mass scanning, brute force, exploitation, payload delivery, attack chaining, model installation or AI collection was introduced.

Phases 00-11 remain functional. Existing evidence was not modified; graph layouts were not reset; Phase 10 AI was not changed; no Ollama or external AI API was configured. Phase 12 is CLOSED and ready for Phase 13 planning. Phase 13 was NOT started.

### Manual-review finding verification corrections

See [Finding verification fix](PHASE_12_FINDING_VERIFICATION_FIX.md) for the detailed implementation-stage record. Its pending/manual-retest wording describes the earlier handoff; the final closure status and acceptance results in this document supersede that status. Issues discovered and fixed during manual acceptance:

1. **Finding handoff UX/error handling:** renamed the action to Prepare authorized verification, explained the second confirmation, validated handoff data/handlers and surfaced synchronous errors. Preparation never contacts the target.
2. **Domain target versus affected-resource contract:** admission now requires the exact resource backed by original same-case/same-target, hash-valid applicable evidence, rather than forcing domain targets to `/`. It does not permit arbitrary paths or weaken final-response comparison.
3. **Lost Finding association:** a nullable frontend variable could be cleared while prepared request fields remained, causing generic validation with `finding_id: null`, as observed in Run #16. That legitimate standalone observation and Evidence #88 were preserved without retroactive association.
4. **Fail-closed prepared state:** explicit standalone/finding/cancelled modes preserve non-invalidating refreshes and cancel invalidating context changes visibly. Identity/contract checks precede submission; stale preparation cannot silently omit finding_id. Final owner acceptance confirmed Run #17 retained finding_id=7 and Finding #7 Verification #3 linked Evidence #89 as verified.

Final automated results: **402 complete Python tests and 10 frontend suites passed**. No additional tests, collectors, active requests, migrations, or investigation-record mutations were performed for this documentation-only closure.
