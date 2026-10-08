# Phase 11 handoff: reports and export

Implemented Phase 11 only, following guide steps 68–73. No Phase 12 work, collection, model installation or AI invocation was added. The approved Graph UX and Phase 00–10 architecture remain intact.

## Architecture and formats

`app/services/reporting.py` constructs one explicit case-scoped snapshot of stored case, target, run, evidence, entity, relationship, finding and selected audit records. It reuses the Phase 08 investigation view and Phase 07 logical edge aggregation, rather than inventing another graph. The existing central persistence lock and one database transaction protect snapshot construction. No investigation data is written.

The shared report content includes case identity/status/owner/creation time, optional description, deterministic executive summary/counts, scope/methodology, targets and current scope/archive status, stored graph schematic, complete entity and logical-relationship indexes, findings and rubric, collector history, deterministic timeline, evidence appendix and limitations. The appendix includes evidence/run/target/entity IDs, source/provider, collector/version, capture time, SHA-256 and integrity verification. Raw provider JSON/body content is excluded.

Findings retain their stored title/description/type, target/entity, workflow status, rule/scoring version, independent severity/confidence, original severity/confidence, rule reasoning, recency and assessment state, analyst override/reason/notes, evidence IDs and relationship-support IDs. Exports do not recalculate scores or generate findings. Stored records and explanations remain authoritative; a report is not a new evidence record.

HTML is self-contained UTF-8 with inline CSS/SVG, escaped content and validated internal evidence navigation. PDF is generated offline with ReportLab, vector graph drawing, consistent A4 typography, page numbers and internal evidence links. No browser engine, subprocess, network resources, remote fonts or images are used. The two formats share exactly the same snapshot and narrative sections.

Reproduction: the same records, report version and redaction option produce identical HTML/PDF bytes. The digest covers the sanitized snapshot, sorted collections and deterministic event ordering. Events sort by stored UTC timestamp, event type, stable key. Report/auth/admin-access audits and generation wall-clock time are excluded, preventing export from changing the next report. Changes to stored investigation records appropriately change the digest. ReportLab's invariant PDF metadata supports byte replay; it is not an investigation timestamp.

## API, UI and roles

- `GET /api/cases/{case_id}/reports/preview?redact_notes=true`: authorized preview, case metadata/counts/digest/limitations; no-store response. Authorized viewers may preview.
- `POST /api/cases/{case_id}/reports/export`: strict JSON `{"format":"html","redact_notes":true}` or `pdf`; existing session, case mutation authorization and CSRF required. Investigator/admin export only; viewer export returns 403. Unrelated/nonexistent cases return 404, unauthenticated users 401.
- Reports is enabled in the existing sidebar. The page offers preview, redaction, explicit HTML/PDF download, status and safe errors. Nothing starts automatically beyond authorized preview reads.
- Downloads use same-origin credentials/CSRF and fixed filenames. Old case previews/download responses are discarded after case changes. Case changes clear the preview. Blob URLs are revoked. Collected/user text is rendered with text nodes.

## Security and privacy

Authorization precedes context construction. Targets/runs/evidence are joined through the current case. Findings must reference same-case targets/entities/evidence/support rows; original and active evidence IDs must be among their actual supports. Linked relationship evidence must also be in the finding's evidence links. Graph/node evidence references are checked against the appendix. Every raw evidence SHA-256 is recomputed using the existing canonical JSON algorithm; mismatches or invalid finding linkage fail closed with 409.

Field allowlists omit account/session data, raw provider bodies, arbitrary entity attributes, raw audit metadata and AI output. Default redaction omits case description, finding notes and severity-override reasons. Configured database secrets and common credential formats are scrubbed, including quoted JSON assignments, encoded credential query names, authorization tokens, URL userinfo and nested credential keys. A scrubbed provenance hash blocks export rather than being labeled verified. No secrets or exported text are logged in export audits.

Redaction is not complete anonymization. Case title, owner identity, targets, infrastructure, public observations and record IDs remain. Arbitrary unlabeled sensitive analyst text may evade heuristic credential scrubbing when note redaction is disabled. Review before sharing; downloaded copies cannot be revoked by later case permissions.

Application exports are in-memory responses, not server-side files. The browser cannot supply paths, filenames, arbitrary record selections or output templates; unknown fields/formats are rejected. Attachment/no-store/nosniff headers and restrictive sandbox CSP protect HTML delivery. All content is escaped; only server-validated internal numeric anchors create links. PDF does not fetch URLs or execute markup as code.

Successful `report.generated` audits contain actor/case/timestamp, format, report version, snapshot digest, redaction and byte count. Authorized generation failures record `report.failed` with a safe status/reason, excluding exception details or filesystem information. Normal authentication/administrator access auditing is preserved.

Limits reject an incomplete report: 10,000 records per targets/runs/evidence/findings/selected-audit category, existing graph limits of 5,000 entities and 10,000 support rows, 8 MiB serialized context, 20 MiB output. Two exports are admitted per process; busy requests return 429. Rendering failures return 503 without affecting investigations. The lock/admission model assumes the existing local single-process deployment.

Reports have no collector, controlled-client, AI-provider, command-execution or mutation capabilities. Opening Reports, changing redaction and downloading never collect. Historic archived/excluded target evidence is reported as history, without authorizing collection. Collector network-policy tests remain unchanged.

## Database and dependencies

No migration is required: reports are transient renderings of existing schema 006 records, with existing audit storage. No report table, persistent report output, evidence rewrite, foreign-key change or database recreation was introduced. Live MySQL revision remained 006; complete before/after comparisons confirmed existing investigation and audit rows unchanged.

Added runtime dependency: ReportLab 4.5.1, constrained `>=4.5,<5.0` in `requirements.txt`. Its installed transitive dependencies include Pillow and charset-normalizer. Added `requirements-dev.txt` with pypdf 6.19.0 and PyMuPDF 1.28.2 for PDF extraction/render QA; they are not required by application report generation. `pip check` passed. No frontend framework/build system, external PDF service or AI dependency was added.

## Files changed

| File | Change |
|---|---|
| `app/services/reporting.py` | Snapshot, integrity/link checks, redaction, shared content, deterministic HTML/PDF |
| `app/api/reports.py` | Authorized preview/export, CSRF, admission, safe responses/audits |
| `app/main.py` | Register reports router |
| `app/static/index.html` | Enable Reports navigation and report pane; local script |
| `app/static/js/reports.js` | Preview, options, explicit downloads, stale-case protection |
| `app/static/js/console.js` | Reports navigation and preview reset hooks only |
| `app/static/css/main.css` | Report page controls/preview styles only |
| `requirements.txt`, `requirements-dev.txt` | Runtime renderer and QA dependencies |
| `.gitignore` | Ignore sensitive generated exports and PDF intermediates |
| `tests/integration/test_reports.py` | 13 export/security/provenance/replay tests |
| `tests/js/test_reports.cjs` | Actual frontend handler tests |
| `tests/js/test_console.cjs` | Add Reports preview/navigation to existing console suite |
| `tests/unit/test_console_shell.py` | Enabled Reports shell contract; preserve all previous assertions |
| `scripts/verify_phase11.py` | Existing MySQL/API acceptance, fixed local output paths, preservation checks |
| `README.md`, `SECURITY.md`, this handoff | Report use, boundaries and verification |

`investigation.js`, Cytoscape, graph APIs, graph local storage/presentation, collector/network policy, findings/scoring, authorization, database models/migrations and AI architecture were not changed.

## Automated verification

Baseline before modification: **303 passed**, 76.29 seconds. Final full Phase 00–11 regression: **316 passed**, 74.25 seconds, with one existing Starlette/httpx deprecation warning. The final focused reports suite also passed **13 tests**. Existing standalone network-policy suite: **38 passed**, 0.75 seconds. No tests were removed or weakened.

New integration coverage includes HTML/PDF byte replay, evidence/provenance/navigation, original rule/override preservation, independent severity/confidence, no network/AI calls, empty cases, failed runs, partial/rate-limited/unavailable/negative states, archive history, malformed parsed data, timeline tie ordering, updated snapshot digest, logical-edge deduplication, hash failure, missing/foreign/malformed finding support, relationship-case isolation, owner/admin/viewer/unrelated access, CSRF, authentication, nonexistent cases, unknown formats/paths/selections, redaction/XSS/nested credential cases, optional PDF dependency failure, context limits and busy admission.

All **seven** offline JavaScript suites passed: investigation, findings, AI, console, graph presentation, populated graph and Reports. This includes the existing 2,000-node graph fixture, real Cytoscape interactions, dragging/resizing/persistence/certificate controls, evidence inspection, timeline, stale case isolation and no collection. Reports tests additionally verify explicit POST/CSRF, safe text, redaction options, failed export handling, blob cleanup, viewer read-only behavior and discarding stale downloads. Results are recorded privately in `.local/phase11-ui-verification.json`.

## Live MySQL/API verification

Existing **Case #15: IANA Infrastructure Investigation**, Target #26 `iana.org`, was the primary acceptance case. No recollection or seed fixture was used.

| Case | Targets | Runs | Evidence | Entities | Logical relationships | Findings | PDF pages |
|---|---:|---:|---:|---:|---:|---:|---:|
| 15 | 1 | 4 | 9 | 50 | 56 | 0 | 14 |
| 12 | 1 | 1 | 1 | 1 | 0 | 6 | 5 |

Case 15 HTML and PDF represent `iana.org`, IPv4 `192.0.43.8`, IPv6 `2001:500:88:200::8`, nameservers, mail servers, CT names, certificate entities and observed/derived relationships only as supported by the existing graph/evidence. All relationship evidence references resolve to the appendix. Successful runs 45/46/47 and failed DNS Run 44 with its stored error/warning remain present. Zero stored findings are represented as zero, without an invented assessment.

Case 12 verifies findings, original/current rule results, severity/confidence, analyst action history and links to Evidence #61. HTML/PDF replay was byte-identical for both cases. All nine Case 15 evidence hashes and the Case 12 evidence hash were verified during snapshot construction.

Before/after comparison of users, cases, membership, targets, runs, evidence, entities, relationships, findings, finding supports/revisions and pre-existing audits passed. Each acceptance-script invocation adds only eight report-generation and three normal login audit rows; existing rows are preserved. No migration, collector run, finding, entity or relationship was created. AI status was `configured=false`. Live CSRF/path rejection and unrelated/viewer case-isolation attempts passed. Results are privately recorded in `.local/phase11-live-verification.json`; generated reports are ignored in `output/pdf/`.

## Visual verification and manual review

Both PDFs were rendered with PyMuPDF and **every page** visually reviewed. Heading/record pagination was tightened after initial review; final 14-page/5-page outputs have readable text, vector diagrams, intact records, page numbers and no clipping/overlap. PDF text and evidence link annotations were checked separately. Intermediate raster QA files are in ignored `tmp/pdfs/`.

Browser automation currently exposes no apps/browsers. This is an automation limitation, not an application failure. Actual handler/offline tests and live APIs passed; the Reports screen and HTML print appearance still need owner visual review. SPECTRE is running at `http://127.0.0.1:8000`.

1. **Ctrl+F5**, sign in, choose **Case #15 · IANA Infrastructure Investigation** from the case library. Confirm `#15` in the top bar.
2. Open **Reports**. Confirm preview totals **1 target, 4 runs, 9 evidence, 50 entities, 56 relationships, 0 findings** and checked analyst-text redaction.
3. Download/open HTML, then PDF. Verify `iana.org`, both IPs, nameserver/mail/certificate relationships, scope, collector versions, successful runs 45–47 and failed Run 44. Inspect the evidence appendix and follow an infrastructure/relationship evidence link.
4. Open **Case #12 · Phase 06 live page verification → Reports**. Confirm six findings; download either format, inspect rule reasoning, separate severity/confidence, original result and click **Evidence #61** to reach provenance. Existing stored rule/analyst values are preserved, not recomputed.
5. Toggle note redaction and refresh preview if you want to compare sensitive-text inclusion. Review the result before sharing. Reopen the case, then **Settings → Audit activity**, to see `report.generated` entries.
6. Return to Graph. Confirm existing drag/resize/certificate/layout persistence remains intact. Reports do not change it.

## Known limitations and deferred work

- Graph schematic is a deterministic grid of at most 32 non-certificate entities; full certificate/all-entity and relationship indexes are retained. It is not a screenshot of the browser-local layout and has no interactive collection action.
- PDF uses portable built-in fonts. Unsupported Unicode is preserved as visible escape sequences; HTML retains Unicode. No multilingual font/shaping bundle was added.
- Current schema has no case update field or target notes; no timestamps/notes are invented. Case changes are available as stored audit events instead.
- No persisted report history/download recovery, selective evidence exports, custom report templates, raw evidence attachments, signature or chain-of-custody certification, AI summaries or general anonymization system was added. An embedded SHA-256 digest identifies snapshot content; it is not a digital signature.
- Larger cases exceeding bounded limits are rejected with no silently partial export. Rendering/admission is synchronous and process-local, suited to the current local deployment.
- Browser visual review and owner review of downloadable reports remain pending. Sharing/export viewers may differ in internal PDF-link navigation behavior.

Phase 11 stops here. Phase 12, active assessment and model installation remain unimplemented and require separate explicit approval.

## Final PDF label correction after manual approval

The owner confirmed HTML/PDF generation, report contents, evidence traceability and integrity information passed manual review. The requested final presentation correction affects the PDF schematic only: fixed 18-character slicing is replaced by Helvetica width measurement and deterministic wrapping at DNS/path boundaries, with up to three label lines. IDs/types remain separately readable and label backgrounds grow with the line count. Underlying values, snapshot digest, HTML, Graph UX, correlation, collection and AI are unchanged. Exceptionally long values use an explicit ellipsis after the third bounded line; their complete values remain in the infrastructure index.

Case 15's regenerated 14-page PDF was visually checked at full schematic/page resolution. **All 21 displayed values are complete**, including `www.rzm-epp.iana.org`, `rzm-iana-ote.iana.org`, `rzm-ote-epp.iana.org` and `sle-dashboard.iana.org`; there is no clipping or label overlap. The report snapshot digest remains `e715e574c394f1c8947a03102b398c286c55b9230bbf1f96f4882cb379f78c2e`. Two renders were byte-identical. Before/after comparisons covered every existing model table, including audits and sessions: all were unchanged; MySQL remains at revision 006. The running local server was reloaded to use the correction.

Added a report regression exercising full domain labels, measured bounds, a multi-line hostname, bounded long-value fallback, text extraction restricted to the actual drawing (not its index), unchanged stored graph data and PDF replay. Focused report tests: **14 passed**. Final complete regression: **317 passed**; the same pre-existing Starlette/httpx warning remains. Private checks are in `.local/phase11-label-verification.json`; the corrected artifact is `output/pdf/spectre-case-15.pdf`. Only `app/services/reporting.py`, `tests/integration/test_reports.py`, README test-count documentation and this handoff changed in the correction pass. Phase 12 remains unstarted.
