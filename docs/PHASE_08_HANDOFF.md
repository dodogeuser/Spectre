# Phase 08 handoff

Implemented and verified on **2026-10-06**, Asia/Beirut. Phase 08 only; Phase 09 has not begun. Automated API/regression, offline UI and live MySQL/server checks passed. **Actual-browser visual verification remains unavailable**: browser inventory exposes no surfaces, and native Firefox previously stopped for unsupported URL-policy enforcement. No bypass was attempted. Owner visual review remains recommended before approval.

## Graph architecture and behavior

Guide steps 49–54 are implemented. **Open stored graph** renders Phase 07 stored entities and grouped relationship supports through locally vendored **Cytoscape.js 3.33.1**. No competing graph table/model, new correlation rule or visualization-only edge exists. Node IDs reuse database IDs; edge IDs are deterministic endpoint/type keys. Solid edges are observed, dashed edges derived; node colors/type labels distinguish entities. The built-in grid layout supports pan/zoom.

The pinned npm package's SHA-512 integrity was verified before extracting the exact JS distribution/license files. `app/static/vendor/cytoscape.json` records origin, integrity and JS SHA-256. The MIT license is retained. No runtime CDN, external font or provider request is needed. Reference: [official Cytoscape.js documentation](https://js.cytoscape.org/).

Controls filter entity type/subdomain role, minimum relationship confidence and source; search values/entity IDs; focus a match; expand its stored neighbors; reset; and show more nodes. Expansion never fetches external targets or creates links. Initial rendering is 200 nodes, increasing by 200 to a 1,000-node display cap; visual edges cap at 3,000. Search/expansion operate within the full bounded server graph and respect filters. Counts, partial views, empty cases and no-match states are explicit. An entity select provides inspection without canvas clicking.

The evidence panel shows attributes, related relationships, capture-derived first/last times, source/provider/run/version, hashes and evidence. Edge inspection shows its rule, classification, confidence and supporting evidence. Raw evidence is fetched from the existing authorized endpoint only on inspection and rendered as inert JSON text. Local run links retain provenance navigation. Standalone URL nodes have their stored source/evidence even without redirects; no connecting edge is fabricated. Unsupported evidence produces no fabricated dates or links.

## Read-only APIs and node/edge types

- `GET /api/cases/{case_id}/investigation`: Phase 07 graph plus bounded source/evidence summaries on existing nodes/edges.
- `GET .../entities/{entity_id}/detail?offset=0`: existing node, related stored edges, 100 evidence summaries per page, first/last capture times and truncation status.
- `GET .../timeline?offset=0&limit=100`: deterministic event pages with offset/has_more; limit 1–100.

All are reads. Phase 07 APIs remain unchanged. Source annotations match stored normalized literals to existing entities using the Phase 07 pure planner; this neither persists nor invents graph data. Graph edges originate exclusively in existing stored supports.

Nodes: domain, evidence-relative subdomain role, IPv4/IPv6 IP, ASN, certificate, organization, URL. Edges reuse `resolves_to`, `nameserver`, `mail_server`, `alias_of`, `registration_nameserver`, `certificate_observed_on`, `subdomain_of`, `ptr_observed`, `announced_by`, `registered_to`, `redirects_to` and preserved legacy types. Confidence remains source/rule confidence, not severity or ownership. CT name association does not prove a served certificate.

## Timeline architecture

Events use stored `Evidence.captured_at` and grouped relationship `first_seen` from Phase 07's minimum supporting capture time. Types are `evidence.captured` and `relationship.first_seen`. No UI interaction time, estimated provider date or correlation-job time is substituted. Dates are labeled UTC.

Ordering is `(timestamp, event type, stable key)`; keys use evidence ID or endpoint/type relationship identity. Equal timestamps use deterministic lexical ties. Events identify source/type/classification and evidence/entity/run navigation where relevant. Pages hold 100 events. Replay does not change event order/count. Evidence capture events without correlated entities remain visible, allowing partially collected cases to be inspected.

## Security, isolation and limits

Every API requires existing authenticated case access; viewers read assigned cases only, unrelated users receive 404, and another case's entity cannot be inspected. Phase 07 graph validation excludes foreign-case evidence/endpoints. Evidence summaries join through same-case targets/runs. Existing mutations retain CSRF/audits; Phase 08 adds no mutation route.

All graph handlers use GET requests. No AI, collector, correlation job, external target navigation or provider transport runs from graph/timeline interactions. Text-node rendering prevents labels/raw evidence becoming HTML instructions. Case/inspection generation guards discard stale responses, and timeline request tokens reject older page results. Normal archived/excluded historical data remains readable; no discovered node receives target authorization.

Server bounds remain 5,000 entities, 10,000 support rows and 10,000 evidence records for annotation/timeline, with explicit truncation. Rendering/evidence/event pages add smaller UI bounds. Large cases may need future server-side filtered graph pagination; current limits are disclosed. Timeline entries with more than 20 evidence supports direct inspection to the corresponding graph relationship.

## Database and changed files

**No migration or DDL is required; MySQL remains 005 (head).** Existing models, foreign keys, evidence, entities and relationships are unchanged. No records were recreated, overwritten or deleted. Authentication sessions rotate normally and logins append audit records.

New files: `app/api/investigation.py`, `app/static/js/investigation.js`, `app/static/vendor/cytoscape.min.js`, `app/static/vendor/CYTOSCAPE_LICENSE`, `app/static/vendor/cytoscape.json`, `tests/integration/test_investigation.py`, `tests/js/test_investigation.cjs`, `scripts/verify_local_phase08.py`, this handoff.

Updated files: `app/main.py` (router), `app/static/index.html` (view/local scripts), `app/static/js/main.js` (case-change reset), `app/static/css/main.css`, `README.md`, `SECURITY.md`. No collectors, correlation rules, migrations, secrets or Python requirements changed.

## Automated verification

Full Phase 00–08 regression: **245 passed**, one inherited Starlette/httpx warning; final run 44.15 seconds. All Phase 00–07 regressions and network-policy tests remain included. Five new integration tests cover graph/detail/timeline evidence linkage, socket/DNS collection prohibition, deterministic tie ordering/pagination, viewer/unrelated RBAC, cross-case entity/support isolation, empty cases, standalone page provenance, replay-stable timeline, and a 5,052-node synthetic case with explicit 5,000-node truncation.

Offline JavaScript tests execute actual application handlers with real Cytoscape headlessly and an inert mock DOM. A 2,000-node/1,999-edge fixture verifies 200-node initial rendering, 400-node show-more, type/source/confidence filters, search focus, stored-neighbor expansion, duplicate-free visual IDs, edge inspection, inert malicious-looking raw data, reset, and GET-only requests. These are UI logic tests, not visual-browser rendering claims. Run `require('./tests/js/test_investigation.cjs')()` with Node; the available Node tool runtime was used because the local Node CLI is absent.

Compilation, dependency checks, package integrity/version and Alembic current passed. No network-policy controls were relaxed.

## Live server/MySQL verification

`python -m scripts.verify_local_phase08` passed through the restarted loopback HTTP server and existing database. It performs only reads after login, without collection/correlation jobs. Ignored report: `.local/phase08-verification.json`.

| Case | Entities | Relationships | Timeline events |
| --- | --- | --- | --- |
| 7, domain | 21 | 24 | 33 |
| 9, IPv4/IPv6 | 6 | 6 | 16 |
| 12, web metadata | 1 | 0 | 1 |

Checked every live graph node's detail, supporting evidence hashes, edge support coverage, duplicate prevention, repeated timeline pages/global ordering, observer access, unrelated-user rejection and local asset delivery. Exact before/after snapshots verified users/cases/targets/memberships/runs/evidence/entities/relationships unchanged. Existing audit rows remained unchanged; only expected `auth.login` audits could append. An initial verifier assertion counted those login audits as mutations; it was corrected, then passed without application changes. No new collector run/evidence/entity/relationship was created.

## Manual verification and known limitations

Browser inventory returned no supported surfaces. Canvas appearance, responsive layout and actual browser interaction have not been visually verified. Prior native Firefox policy limitation was respected. Offline real-library UI tests and live APIs do not replace visual review.

For owner review, refresh SPECTRE, open case 7 or 9 and choose **Open stored graph**. Inspect node/edge evidence, filters, search/focus, expansion and timeline. Case 12 shows a standalone URL; an empty case shows the empty state. These controls never collect. SPECTRE remains running at http://127.0.0.1:8000.

Grid positioning is functional rather than a tuned force layout; 1,000 visible nodes may still require focus/zoom. Bounded server views may omit later records and explicitly say so. Evidence annotation scans are bounded and can be costly in cases with many large stored records. Source/organization labels do not prove identity/ownership. Timeline includes evidence capture and relationship first observation, not every audit/provider event. Historical excluded/archived data remains visible. No scoring, findings workflow, AI or Phase 09 functionality was added.

**Stop after Phase 08; Phase 09 requires explicit approval.**
