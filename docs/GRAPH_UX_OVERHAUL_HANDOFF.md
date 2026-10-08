# Investigation graph UX overhaul

2026-10-06. Graph presentation only. Phase 11 has not started.

## Changes and files

- `app/static/js/investigation.js`: local presentation state, drag/size persistence, explicit layouts, CT/hostname/type visibility, labels, parallel curves, zoom controls, selection status and inspector sources.
- `app/static/index.html`: organized graph controls, Hierarchical/Radial layout choices, certificate/hostname controls, visibility checkboxes, zoom, node-size actions, inline legend/status.
- `app/static/css/main.css`: graph controls and legend stay outside the canvas, responsive control groups and status styling.
- `tests/js/test_graph_presentation.cjs`: new real-Cytoscape presentation/persistence suite.
- `tests/js/test_investigation.cjs`: provide timers required by viewport persistence; existing assertions retained.
- `tests/js/test_populated_graph.cjs`: assert default collapse, then explicitly expand before the existing full-data assertions; run against both Case 7 and Case 15 and all four layouts.
- `tests/unit/test_console_shell.py`: graph-control/read-only frontend contract added.
- `scripts/verify_graph_ux.py`: read-only live Case 15 API/database/evidence-hash/isolation checks.
- README, this handoff and the prior UI handoff: updated review instructions.

No collector, correlation, evidence/provenance, database schema, authorization, scope, CSRF, network policy, findings or AI architecture was changed. No new dependency, graph API, migration, model or collector run was introduced.

## Analyst interaction

Nodes remain unlocked and draggable. Dragging never invokes a layout. The selected node has a stronger outline and its incident relationships become more prominent; unrelated nodes stay visible. Background selection clears emphasis. The collapsible inspector exposes full values, stored type, sources, evidence/run links, relationships and available timestamps. Confidence remains stored relationship-support confidence, never a fabricated entity certainty score.

Inspector actions provide Larger / Smaller / Reset size (24–100 units, eight-unit steps). Defaults are 54 for target roots, 28 for certificates and 34 otherwise. Sizes change actual Cytoscape node geometry; edges remain attached to the existing node endpoints. Target-only markers transfer saved position/size to their matching stored entity when one appears.

Organic, Hierarchical, Radial and Grid are explicit actions. The initial view uses deterministic placement, not an automatic force-layout pass. New nodes use a saved position or are placed near an existing related entity; no existing position is reset by polling, graph refresh or a newly discovered node. Apply layout deliberately arranges currently visible nodes and saves that arrangement. Hidden nodes retain their previous saved positions. Fit and zoom buttons are explicit; viewport restore preserves pan/zoom. Existing search focus and neighbor expansion still operate on stored data only.

Labels show value followed by type, or `iana.org\nTARGET` as two lines. Long values/certificate hashes are abbreviated; Inspector and the native canvas hover tooltip expose complete values. Targets use an outlined hexagon, other types use existing restrained shapes/colors plus text labels, and IPv4/IPv6 have separate labels. Labels have wrapping/backgrounds; layout spacing includes label dimensions. Solid/dashed relationship semantics are unchanged. Parallel relationships use Bezier curves with a 70-unit control-point step. Relationship labels appear on selection/adjacency/hover; **All edge labels** enables them explicitly.

Certificates default to **Collapsed**. Collapsed/Hidden both omit their real nodes and incident edges from the canvas; the summary distinguishes the modes and retains the actual stored count. Expanded restores real nodes and real relationships subject to normal filters/caps. Hostnames have the same controls. Additional type visibility controls coexist with existing type/source/confidence filters. These are display subsets, not aggregate graph nodes or invented aggregate edges. No stored CT record is deleted or changed. Roots stay locatable when infrastructure is filtered.

The toolbar separates search/layout, filters and view controls. Legend, zoom, group counts and status are outside the canvas rather than floating over nodes. Status reports visible/loaded entity and relationship counts, target count, selection and storage status. The existing 12-second read-only poll, initial/reload discovery baseline and 1.5-second new-ID highlight remain. Reduced motion uses static outlines. Expansion of previously stored nodes never simulates discovery.

## Persistence

Browser `localStorage`, key `spectre.graph.v1.u<authenticated_user_id>.c<case_id>`, stores only:

- visual node IDs with x/y positions and sizes;
- zoom/pan;
- certificate/hostname modes, hidden types and edge-label preference;
- schema version 1.

It contains no target values, evidence, provider responses, citations, secrets or credentials. State is read only after the normal authorized case load; only IDs belonging to the current authorized snapshot can be displayed. User/case keys do not grant API access. Local layout changes are allowed even for viewers because they mutate no investigation records.

Positions are saved on drag release, resizing, explicit layout, view changes and case teardown. Pan/zoom writes are debounced 250ms; pagehide flushes state. Restore validates IDs, finite coordinates, sizes, viewport and allowed preferences; payloads are bounded to 300KB/2,000 entries. Storage access/quota failure leaves the graph functional with session-memory persistence and an honest status message. Saved layouts are browser/profile-local, not shared across machines or analysts; clearing site storage loses them. A database migration is unnecessary.

## Verification

Baseline: **302 passed**, one inherited Starlette/httpx warning, 81.18s.

Full post-change regression: **303 passed**, one inherited warning, 65.66s. All previous backend/security/network-policy tests remain included. No existing assertion was weakened to conceal a failure: populated-graph full-data checks now explicitly expand certificates to test that mode.

Six offline JavaScript suites pass: graph (2,000-node fixture), console, findings, AI, populated graph and new presentation state. The populated suite runs against both existing cases 7 and 15. Presentation tests use actual shipped handlers and vendored Cytoscape, verifying drag/unlocked state, attached endpoints and node geometry, custom size, refresh/reopen/fresh-page restore, pan/zoom, certificate collapse/expand and restored certificate positions, new-node placement without moving existing nodes, explicit four-layout behavior, malformed/blocked storage, user/case separation, minimal storage content, unchanged-ID highlights and no collection calls. These are behavioral/layout-computation tests, not browser screenshots.

`python -m scripts.verify_graph_ux` passed using the existing MySQL database, revision **006**:

- Case **#15 — IANA Infrastructure Investigation**, Target **#26 iana.org**.
- **50 stored entities**, **56 stored logical relationships**, **29 certificates**.
- Default collapsed view: **21 visible entities / 24 visible relationships**, including the real iana.org root.
- Expanded certificate view: **50 entities / 56 relationships**, no duplicate visual edges.
- Four layouts produce finite positions against the real snapshot.
- Six supporting evidence hashes checked; every displayed stored relationship retains evidence/support IDs.
- Unauthorized observer/unrelated users receive 404 for case graph/timeline/targets.
- Existing investigation tables and original audit records preserved. The three normal test logins append expected `auth.login` audit entries and rotate sessions; no investigation mutation or collector event is created.
- AI remains configured=false. No network provider query was required for UI verification.

Local verification artifacts: `.local/ui-case15.json` and `.local/graph-ux-verification.json` (ignored). No production fixtures were inserted.

## Manual acceptance and remaining limitations

Browser inventory returned no enabled apps/browsers. Visual drag/label-collision/contrast verification remains pending owner review; no visual success is claimed from headless tests. The application is already serving the new static files.

1. Open http://127.0.0.1:8000, **Ctrl+F5**, sign in and choose **Case #15 — IANA Infrastructure Investigation**.
2. Confirm **iana.org / TARGET** is readable, certificates default to collapsed, and the status shows **21/50 entities, one target, 24/56 relationships** on a fresh unsaved view.
3. Choose **Hierarchical → Apply layout** or **Organic → Apply layout**, then Fit. Select a nameserver relationship and its RDAP corroborating edge; confirm separate curves, actual relationship types and evidence links. Labels are available on selection/hover or via All edge labels.
4. Drag iana.org and an IP to your preferred locations. Select a node, use Larger/Smaller/Reset and confirm attached edges. Refresh the graph, switch cases and return, then reload the page: positions/sizes should restore. Saved view preferences may change counts from the fresh defaults.
5. Expand Certificates: all 50 entities / 56 relationships are available before additional filters. Existing manually moved nodes must stay put. Use Apply layout only if you want a new arrangement. Collapse/expand certificates and hostnames, test type/source/confidence filters, pan/zoom and reset filters.
6. Open Inspector/evidence, verify full values, source/run/provenance and relationship confidence. Close Inspector to reclaim canvas width. Capture the default view, expanded view and selected Inspector at 1366×768 or your desktop resolution.

Limits: overlapping labels in a deliberately crowded manual arrangement cannot be prevented without overriding analyst positions; expanded CT groups may benefit from an explicit layout and zoom. Hidden groups are summarized by counts in controls rather than fabricated graph cluster edges. Graph/API display bounds remain. Layout storage is local, unencrypted presentation metadata only, and is not a collaboration or export feature. Reports/Phase 11 and AI/provider enablement remain deferred.

Stop here for manual review.
