# SPECTRE investigation console — UI/UX redesign handoff

Date: 2026-10-06 (Asia/Beirut). Numbered phases are paused. This work is not Phase 11. Reports/active assessment remain unimplemented; AI remains intentionally disabled. No Ollama/model installation or configuration was performed.

**Latest graph behavior:** the subsequent [Graph UX overhaul handoff](GRAPH_UX_OVERHAUL_HANDOFF.md) supersedes this document's initial-layout/label/legend behavior. It adds browser-local positions/sizes/viewport persistence, explicit-only automatic layouts and default certificate collapse, using real Case 15 for acceptance. The backend and collection/security boundaries below remain unchanged.


## UI/UX correction pass — current handoff

The approved console shell is preserved. The correction addresses omitted root targets, an automatically opened inspector, crowded controls, overly long discovery highlights, technical collector cards, zero badges and unclear empty/settings states. No numbered phase resumes.

**Correction baseline:** 301 passed, one inherited Starlette/httpx warning, 67.83s. **Final full regression:** 302 passed, one inherited Starlette/httpx warning, 65.61s. Existing network-policy, RBAC, isolation, CSRF, provenance, collector, findings and AI tests remain included.

### Root target rendering

`storedTargetRoots` reads only authorized, nonarchived stored targets. It maps IPv4/IPv6 to the existing IP entity type and merges only an exact entity type + canonical stored value match. A matching entity gains a TARGET label/outline; a target without a match gets visual ID `t<target_id>` and no edges. No database entity, relationship, evidence, finding, collection or timestamp is generated. The marker inspector identifies its real target ID, stored value/scope/create/update dates and absence of mapped infrastructure. It does **not** label an unmapped target "not collected": collection may have occurred without producing entities (as in Case 13).

Historical stored entities remain when a target is archived; their TARGET designation is removed. Standalone archived target markers disappear. Roots remain locatable when filters hide related infrastructure, and that behavior is disclosed. Additional target pages already loaded through target navigation can add markers; the initial target snapshot remains limited to the existing 100-record page. Root markers never affect the backend entity count or become edge endpoints.

### Interaction and presentation corrections

- Two toolbar rows separate search/results, layout/Fit from type/source/confidence/Reset. Refresh and the inline Inspector toggle sit in the graph page header. Search results can focus/inspect actual stored entities or targets. The legend is compact and collapsible; nameservers retain their actual domain nodes and relationship meaning rather than gaining a fabricated entity type.
- Inspector is closed by default, opens on selection, closes manually and returns the space to the graph. No floating reopen control exists. Background selection clears emphasis without resetting filters. Selected incident edges are emphasized; unrelated graph elements remain visible.
- Discovery outlines last 1.5 seconds, with cleanup at 1.6 seconds. Case-session seen sets prevent repeat highlights when IDs reappear. Initial load/page reload is a baseline. Reduced motion uses only the short static highlight; polling remains 12 seconds and never collects or relayouts continuously.
- Target cards add **Investigate** navigation. Existing overview/edit/archive workflows remain. Collector cards use human-readable names, purpose, real availability, version, latest stored state and **Open controls**. Compatibility comes exclusively from registry `supported_types`, then provider availability and stored target scope/archive state. Domain targets do not gain URL-only web metadata compatibility. Opening controls reads existing views; collecting still requires the existing explicit authorized buttons.
- Overview selects Add target / Begin investigation / Open graph based on actual loaded records. Counts use N+ for lower bounds with explanatory detail. Zero sidebar badges are hidden. Recent activity remains evidence/event-backed. Timeline/Evidence/Findings have clearer empty states; settings groups Case, Access, disabled AI and expandable Audit metadata. No secrets or model configuration are exposed.
- Shared grid headers keep titles/actions apart. Timeline has a readable maximum width; evidence rows and finding cards have larger text, and collector cards use responsive tracks. Desktop inspector remains a real grid column, with reflow at small widths instead of overlapping controls.

### Correction verification

All five offline JavaScript suites passed: existing graph (2,000-node fixture), findings and AI; full shipped console handlers; and the real Case 7 snapshot. Added checks cover default-closed/auto-open inspector, background deselection, canonical root merging, one-target/zero-entity/zero-edge state, root inspection, archive behavior, transition from target-only to a stored entity, new-ID timing, unchanged/reappearing/reloaded IDs, registry compatibility (domain versus URL-only web metadata), existing explicit controls, empty states, incremental graph positions, and GET-only navigation.

Three Python shell/layout contract tests pass. Static minimum-track checks cover 1920, 1600 and 1366px widths with an open inspector. **These are not browser pixel measurements:** visual collision/readability verification at 1920×1080, 1600×900 and 1366×768 remains manual. Browser inventory returned no apps or browsers; no screenshots were fabricated.

Read-only live API/MySQL verification passed again. Case 7 is the primary populated review case: **Phase 04 live provider verification**, Target **#13 example.com**, Target **#20 104.20.23.154**, **21 entities**, **24 relationships**, **33 timeline events**, **9 captured evidence records**. Both roots merge with existing entities, so there are still 21 visual nodes and 24 real edges. All three layouts have finite positions in the actual stored snapshot. Existing investigation rows, support/FK records and revision 006 were preserved; Evidence #61 hash, RBAC and case isolation passed; AI stays configured=false. No live provider query or collector run was needed for correction verification.

### Exact manual review

1. Open http://127.0.0.1:8000, press Ctrl+F5, sign in and choose **Case #7 — Phase 04 live provider verification**. Graph starts with the inspector closed; locate **example.com — TARGET** and **104.20.23.154 — TARGET** amongst 21 entities / 24 relationships.
2. Click example.com, inspect its real entity/target ID and supporting evidence, then select an edge and inspect its rule/support. Close the inspector and confirm reclaimed space. Click the graph background to restore normal emphasis. Search, filter, Fit, Reset and the three layouts must not start collection.
3. Open Timeline (33 events) and Evidence (9 captures). Inspect one record's actual source/run/timestamp/hash. Open Collectors, select example.com: DNS/registration/CT applicability follows the registry, while Web metadata is Not applicable. Open controls only; do not collect for UI review.
4. Open **Case #12 — Phase 06 live page verification**, Findings: six informational findings with separate confidence and unchanged reasoning/analyst workflows. Evidence #61 retains Example Domain, HTTP 200, Run #35 and provenance.
5. Optional root-only check: **Case #13 — Phase 10 synthetic prompt-injection verification** shows **example.org — TARGET**, zero correlated entities/edges and an honest no-infrastructure message. It already contains a synthetic evidence record, so "not collected" would be misleading.
6. Capture Case 7 graph/selected inspector at **1920×1080, 1600×900 and 1366×768**. Check header actions, toolbar, sidebar and inspector for overlap, and verify that closing the inspector expands the canvas. Also capture Collectors and Findings for review.

Known limits: visual browser QA remains pending; loaded-page counts and graph caps remain; run states require explicit refresh; no tooltips invent confidence; a target-only marker is not evidence. Reports, active assessment, Phase 11 and AI provider/model enablement remain deferred. Stop for review.

## Scope and files changed

Frontend: `app/static/index.html`, `app/static/css/main.css`, `app/static/js/main.js`, `app/static/js/investigation.js`, `app/static/js/findings.js`; new `app/static/js/console.js`.

Verification/documentation: `tests/js/test_populated_graph.cjs` (optional local snapshot test), new `tests/js/test_console.cjs`, `tests/unit/test_console_shell.py`, `scripts/verify_ui_redesign.py`, this handoff; updated `README.md`. Ignored local verification artifacts: `.local/ui-ux-verification.json` and `.local/ui-evidence61.json`.

No backend API, authentication/RBAC/CSRF rule, target normalization/scope, collector/framework/network policy, evidence model/hash/provenance, correlation rule, finding/severity/confidence rule, AI security architecture, database schema or migration was changed. Existing JS authentication/API request behavior is retained; main.js changes concern presentation, case-transition guards and view hooks only. MySQL remains **006 (head)**. No new frontend framework, build tooling, dependency or remote asset was introduced.

## Layout architecture

The viewport shell has a 60px top bar, compact sidebar, flexible main workspace, a 320px inspector (360px on large screens), and 38px activity bar. Case selection/creation uses a native dialog, while existing forms/handlers remain intact. The top bar shows real case title/ID, authenticated username/role/ID, sign-out and health-derived LOCAL/OFFLINE status. `/health` proves app liveness, not database health.

Sidebar sections: Overview, Targets, Graph, Timeline, Evidence, Findings, Collectors and Settings. Active sections use `aria-current="page"`. Reports and AI Assistant are disabled with explicit unavailable/provider-not-configured labels. Their presence adds no report/export or AI execution capability.

Graph is the initial case section. Dedicated panes replace the previous long scroll page. Overview shows real target/entity/relationship/evidence/finding/known-run counts, scope and stored activity. Settings retains case editing, membership and audit controls. Target create/edit/archive and provider overview buttons retain existing functionality, normalization, duplicate checks and server authorization. Target rows add actual creation/update timestamps.

## Graph interaction and inspector

The existing vendored Cytoscape 3.33.1 remains authoritative. Entity node IDs come from stored entities; target-only visual markers come from authorized target records (see correction notes below); visual edges keep existing logical `(from, to, type)` grouping and all evidence/support IDs. There are no invented stored entities or edges. A TARGET marker is a presentation of an existing target, not a correlated entity. The graph keeps existing type/source/minimum-confidence filtering, search focus, bounded display expansion, node inspection and stored-neighbor expansion. Fit and explicit Organic/Concentric/Grid re-layout controls were added. Normal node/edge selection emphasizes the selection/neighborhood and gently dims other elements; it does not hide unrelated nodes. Search/focus-neighbor actions explicitly restrict the view; Reset restores it.

Supported stored types are domain (including subdomain roles), IP, ASN, certificate, organization and URL. Restrained type colors/shapes distinguish them; labels show stored human-readable values. Certificate labels abbreviate the hash, with the full value in the inspector. Nameserver meaning is conveyed by actual stored relationship labels; no unsupported network/prefix/entity types are invented. Solid edges remain observed; derived edges are dashed, with an on-canvas legend.

The right inspector shows entity type/value/ID, stored first/last-seen timestamps, relationships, actual evidence, linked affected findings where available, and stored attributes. Entities have no independent confidence field, so the inspector never invents a 100% entity score: it labels the range of related relationship-support confidence instead. Edge inspection shows endpoints, type, observed/derived classification, rule explanation, confidence, first/last seen, support IDs and direct evidence links. This answers why two nodes are connected.

Evidence inspection shows source, capture time, run ID, collector/version/target where provided by loaded provenance, raw JSON and normalized observations as inert text. Run evidence and stored collector activity remain reachable. Finding cards separate severity and confidence, show descriptions/affected targets/rule IDs and evidence links. Existing rubric, original rule result, status/notes, analyst severity overrides and audited review remain unchanged. Finding evidence/detail panels scroll into view without animation.

## Discovery and update strategy

The initial graph snapshot is a baseline, never a discovery animation. Later snapshots compare actual stored entity IDs and logical edge keys against case-session seen-ID sets. Disappearance/reappearance does not rediscover an old ID. Only new IDs receive a short cyan outline (1.5 seconds); new nodes are positioned near an existing stored neighbor where available. Motion-enabled clients receive a restrained border transition; reduced-motion clients receive a static temporary outline. Unchanged nodes/edges do not pulse again, and replayed support does not create duplicate visual edges.

Updates are incremental: preserve the Cytoscape instance, positions, viewport and selection; add/remove/update only stored visual elements within the current display cap. Identical snapshots skip rendering. No page reload or automatic repeated layout is used. Layout runs on initial population or explicit operator re-layout; case-local refreshes preserve the graph instance. New records outside active filters/caps are disclosed rather than silently exceeding limits.

While Graph is active, a visible-page-only 12-second poll reads existing authorized investigation and timeline endpoints. At most one poll is in flight per case. There are no WebSockets, new backend routes or collector requests. Polling stops/invalidates on case changes and pauses in other sections/hidden tabs. Stale graph/detail/timeline/evidence/collector responses are discarded. Transient discovery timers are cleared on case reset. Health polling runs every 30 seconds while visible.

## Activity, timeline, evidence and collector states

The compact footer and expandable activity area use real stored timeline events. Small cases use their current page; larger cases fetch the final eight events from the bounded timeline to show recent activity. Event timestamps are stored timestamps, not invented discovery times. The timeline remains ordered by the backend's timestamp/type/stable key and links to evidence, entities, relationships and run evidence.

Evidence Explorer pages through the existing timeline and lists its `evidence.captured` events, fetching existing run evidence only when summary provenance is missing. Relationship-only pages can contain no evidence captures and explain that empty state. All evidence remains read-only. List status starts as **stored hash / not checked**; inspector verification uses browser SHA-256 over sorted canonical raw JSON and updates visible status only after a real match.

Browser/Python numeric serialization can differ (e.g. floats such as 1.0), so a differing browser hash is labeled **verify Python canonicalization before assuming corruption**, never asserted to be corruption. The backend's existing canonical hashing architecture is untouched. Evidence #61 matched Python canonical SHA-256 in live verification.

Collectors show actual configured availability and stored statuses/warnings/errors; no queued/partial/progress state is simulated. Stored run views refresh explicitly and inspect up to 20 loaded targets, displaying the latest 100 run cards. Existing per-target Domain/IP/Web views and explicit collection buttons remain available. Selecting a collector target only opens stored data. Scope/RBAC/CSRF checks remain server-enforced.

## Counts, performance and empty states

Counts never use evidence IDs as totals. Evidence counts use unique IDs from actual `evidence.captured` events in the loaded timeline page; graph-linked evidence alone is not treated as all case evidence. An incomplete/truncated event page displays a lower bound. Target/finding counts use their loaded API pages. **N+** clearly denotes a bounded/known subset, including known collector runs until a complete run snapshot is available. Overview explains snapshot/bound limitations. These are separate read snapshots, not an atomic backend statistics transaction.

Existing bounds remain: initial 200 visual nodes, Show more up to 1000, at most 3000 visual edges, existing server graph bounds. Search can focus stored nodes outside the initial display cap. A 2000-node fixture exercises filtering/focus/expansion without requiring all nodes to render at once. Backend graph reads may still be expensive for very large cases; the redesign adds no graph index or aggregate/statistics API.

Empty cases show zero/unknown honest metrics, no targets, no entities/relationships, no findings, no evidence and no stored activity. No fake data was added to production. Only pre-existing case records were used for live verification.

## Responsive and accessible behavior

Desktop is primary. Main graph fills the available viewport rather than a narrow card. Sidebar/inspector can collapse. The inspector starts closed. Below 980px it stays in a resized grid column; below 680px it reflows below the main pane. Navigation occupies its own grid column when expanded, rather than overlaying graph controls. ResizeObserver updates Cytoscape, and first-visible fitting handles graphs initially loaded while another pane is active.

Visible focus rings, labeled compact controls, skip navigation, native dialog focus behavior, keyboard entity selection, text state labels and `aria-live`/expanded/current attributes are included. Severity/confidence are semantically separate. Reduced-motion settings suppress heavy animation; important states never rely on color alone. Responsive styles/handler contracts are tested offline; exact geometry/contrast across physical screens awaits visual review.

## Verification

Original redesign baseline before modification: **299 passed**, 1 inherited Starlette/httpx warning, 66.66s.

Original redesign post-change complete regression: **301 passed**, 1 inherited Starlette/httpx warning, 69.11s. This includes all 299 previous tests and all 38 existing network-policy tests. The two new Python tests check unique shell IDs, all dedicated panes/nav, local assets, disabled AI/Reports structure, responsive/reduced-motion/focus contracts and read-only console methods.

Existing graph/findings/AI JS tests passed. Correction tests extend the console suite and add an optional offline populated-case layout check. New full-shipped-frontend offline test passed: shell/case library/sidebar, real Cytoscape load, node/edge inspector, evidence navigation/hash check, timeline/findings/activity, reduced-motion/new-ID outlines, unchanged-node behavior, incremental instance/position preservation, empty states, stale case poll rejection and GET-only navigation. The existing graph fixture also covers type/source/confidence filters and a 2000-node dataset. These are real handler/DOM tests with a test DOM and API fixtures, not visual screenshots or fabricated production discoveries.

Live API/MySQL verification (`python -m scripts.verify_ui_redesign`) passed with unchanged existing users/cases/targets/runs/evidence/entities/relationships/findings/support/revision rows. Normal login-session rotation remains expected. Verified:

| Case | Stored entities | Relationships | Timeline events | Findings | Loaded targets |
|---|---:|---:|---:|---:|---:|
| #7 Phase 04 live provider verification | 21 | 24 | 33 | 0 | 2 |
| #9 Phase 05 live provider verification | 6 | 6 | 16 | 0 | 2 |
| #12 Phase 06 live page verification | 1 | 0 | 1 | 6 | 1 |
| #13 Phase 10 synthetic prompt-injection verification | 0 | 0 | 1 | 0 | 1 |

All four live snapshots were untruncated. Evidence #61 retained Example Domain, Run #35 and its valid raw hash. Viewer authorized-case access, unrelated-user isolation and cross-case evidence rejection passed. AI configured=false in every checked case. No new collector run, investigation record, model or migration was created by this redesign.

## Manual verification status and exact review steps

Browser automation inventory returned no enabled browser/app surfaces. Visual verification is pending owner screenshots; this is not an application failure. SPECTRE is already running at **http://127.0.0.1:8000** and serves updated static files without a backend architecture restart.

1. **Ctrl+F5**, sign in as researcher, choose **Case #7 · Phase 04 live provider verification**. Confirm top bar case/user/LOCAL, active Graph sidebar item, large graph, closed inspector and compact activity bar. The graph should show **21 entities / 24 relationships**, with both stored targets visibly marked on their matching entities; the inspector starts closed. Capture this screen with a domain selected.
2. Click a domain and an edge. Confirm actual names, stored timestamps/support confidence, observed/derived legend, rule explanation, support IDs and evidence navigation. Try search, type/source/minimum-confidence filters, Fit, Reset and Expand stored neighbors. None should collect.
3. Open Timeline and Evidence. Case 7 has **33 timeline events / 9 evidence captures** at verification. Inspect evidence provenance; use the hash check and confirm no fake verified status before checking. Open Overview for real scope/counts. Try the empty-graph **Case #13**; it has one synthetic evidence capture, one standalone TARGET marker for example.org and no correlated entities or invented edges. It is a secondary root-state check, not the primary visual-review case.
4. Open **Case #12 · Phase 06 live page verification → Findings**. Confirm **6 findings**, informational severity, separate 95% confidence, rule/version/rubric/original result and Evidence #61 navigation. In Evidence inspect #61: Example Domain, HTTP 200, Target #24, Run #35 and stored SHA-256. Capture the findings screen.
5. Open Targets/Collectors/Settings. Confirm target create/edit/archive controls, actual scope/timestamps and real stored run states. Do not collect solely for UI review. Reports and AI Assistant must remain disabled. Narrow the window and toggle sidebar/inspector; ensure graph remains usable.

Optional discovery visual review: with an independently authorized legitimate collection/correlation update made through existing workflows, return to Graph and wait at most one poll interval. Only actually new stored IDs should briefly highlight. The redesign itself launches no collection merely to demonstrate animation.

## Known limitations and stop boundary

No visual browser screenshots were produced automatically. Large views/counts remain bounded; run activity needs explicit refresh, and relationship/evidence inspection is a selected snapshot rather than a streaming inspector. Browser hash serialization caveats are labeled. The interface adds no job-progress feed, WebSockets, reports/export, AI model/provider enablement or active assessment. Review screenshots before treating visual QA as complete.

Stop here. No numbered phase resumes without explicit approval.
