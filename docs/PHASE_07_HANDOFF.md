# Phase 07 handoff

Implemented and verified on **2026-10-06** (Asia/Beirut). Phase 07 only; Phase 08 has not begun. Phase 06 approval includes acceptance of the browser automation limitation. Phase 07 verification uses automated tests and actual MySQL/API requests, including the running loopback server.

## Architecture

Guide steps 43–48 are implemented through `app/services/correlation.py` and case-bound API routes. The pure planning function validates normalized stored observations before mutation and emits deterministic canonical nodes and typed edges. The persistence phase processes evidence in ascending ID order, upserts canonical case-local nodes, and inserts only missing evidence-specific relationship supports. No collector, controlled HTTP client, AI model or remote operation participates in correlation.

`POST /api/cases/{case_id}/correlation/jobs` runs a bounded synchronous job; up to 500 evidence rows per request. `has_more` and `next_after` support explicit continuation through `?after=...`. This is a synchronous local job, not a background queue. Completed/failed jobs persist in the existing audit log with operator attribution, rules version, counts, continuation position and safe skip reasons. `GET .../correlation/jobs` lists that history, 100 records per page with offset.

`GET /api/cases/{case_id}/graph`, `/entities` and `/relationships` expose stored case facts. Graph reads perform no correlation or collection. Entity IDs are stable database IDs; graph edges group the same endpoint/type supports, retaining all evidence IDs and support IDs. Entities are ordered by ID and edges by endpoint/type; replay produces the same graph. No interactive graph, timeline, Cytoscape dependency or Phase 08 UI is included.

## Entity identities

| Type/role | Deterministic identity |
| --- | --- |
| Domain | Existing IDNA/lowercase canonical DNS name |
| Subdomain | Same canonical DNS node, with an evidence-relative `subdomain` role from suffix edges; no second identity for the same name |
| IP | Canonical IPv4 or compressed IPv6 literal |
| ASN | Valid 1–4294967295 decimal number rendered as `ASnumber` |
| Certificate | Valid lowercase 64-hex SHA-256 |
| Organization | Existing whitespace-collapse/casefold normalization of a provider organization label |
| URL | Existing canonical absolute HTTP/HTTPS URL normalization; redirect rules additionally enforce inherited HTTPS/public-literal policy |

Identity keys remain case/type/canonical SHA-256 under the existing database uniqueness constraint. Subdomain is a role because its meaning depends on a seed; separate domain/subdomain identities would duplicate earlier-phase DNS nodes. Organization deduplication equates labels within one case, not proven legal entities. Existing attributes and all pre-existing rows are preserved; Phase 07 does not overwrite them with new guessed attributes.

## Correlation rules

| Graph relationship | Classification | Confidence | Required stored support |
| --- | --- | --- | --- |
| `resolves_to` | observed | 0.95 | Valid DNS A/AAAA address with matching IP version |
| `nameserver` | observed | 0.95 | DNS NS answer |
| `mail_server` | observed | 0.95 | DNS MX answer, excluding null-MX dot |
| `alias_of` | observed | 0.95 | DNS CNAME answer |
| `registration_nameserver` | observed | 0.90 | Domain RDAP nameserver with matching seed |
| `certificate_observed_on` | observed | 0.90 | CT certificate hash and concrete DNS name; association only, not served-TLS verification |
| `subdomain_of` | derived | 0.95 | Concrete name ends with dot + domain seed; not wildcard inference |
| `ptr_observed` | observed | 0.95 | PTR observation with matching IP seed |
| `announced_by` | derived | 0.85 | Matching IP seed, observed routing prefix containing it, validated origin ASN |
| `registered_to` | observed | 0.80 | Matching IP RDAP allocation containing seed and organization with explicit `registrant` role |
| `redirects_to` | observed | 0.95 | Stored contiguous 301/302/303/307/308 response chain, HTTPS destinations, matching final URL |

Confidence constants describe confidence in each source/rule observation, not calibrated probabilities or verified ownership. The graph includes the rule explanation and observed/derived classification on each edge. Graph confidence is the minimum supporting-row confidence, preserving conservative legacy values.

Existing `certificate_names` rows are retained unchanged and displayed as `certificate_observed_on` supports. New jobs create only the new CT type. Legacy and new CT supports group into one graph edge, so preserving provenance does not duplicate graph noise. Wildcards do not create concrete host entities. Unsupported bootstrap/mock/holder responses, unsuccessful observations and unavailable/negative page states create no new links. Valid earlier observations in a failed partial collector run can still correlate; run failure alone does not invalidate retained validated evidence.

No domain organization ownership is inferred from nameservers, contacts, registrar roles, routing holder strings, matching names, AI suggestions or URL similarity. Registration relationships describe provider registration metadata, not current operators. PTR does not imply ownership. HTTP title/server hints and missing-header observations do not imply vulnerabilities or product identities. A web page without redirects yields a URL node and no invented redirect edge.

## Evidence linkage, time and database

Existing `relationships` already store one support row per endpoints/type/evidence ID, protected by `uq_relationship_evidence` and foreign keys. These rows remain the persistent source of truth. Graph edges aggregate their `evidence_ids`/`support_ids`; `first_seen` and `last_seen` are the minimum/maximum supporting evidence repository capture times. These fields are computed from immutable support records rather than duplicating potentially divergent timestamps in another table. No provenance is deleted when supports merge in the graph.

**No migration or DDL is necessary.** MySQL remains **005 (head)**. This implementation reuses the existing evidence/entity/relationship/audit schema. Foreign-key protection prevents deleting referenced evidence. Target deletion remains archive-only. New jobs skip excluded/archived targets and disallowed snapshots; old graph observations remain case-authorized historical evidence, with an explicit historical-scope note. Archived cases allow reads but reject new jobs.

Malformed/incomplete items or raw-hash mismatches are skipped with `invalid_or_incomplete_evidence`. Planning completes before writing an item. Unexpected failures roll back the whole job, then record a sanitized failure audit. The shared persistence lock is now reentrant and covers correlation writes plus completion audit/commit; collection retains the same lock. MySQL correlation additionally locks the case row. Database uniqueness prevents duplicate support/entity rows.

## Security and isolation

Mutating correlation requires the existing authenticated investigator/admin case access and CSRF. Viewers can read assigned cases only; unrelated users receive 404. Case-bound joins admit evidence only through that case's targets/runs. Graph reads require supporting evidence targets and both endpoint entities to be in the same case; foreign-case supports cannot leak through a manually inconsistent row. No target authorization is generated, and no job invokes network collection.

Graph output limits are 5,000 entities and 10,000 support rows, with `truncated` and numeric limits explicitly returned. List endpoints share those bounds; use the graph envelope to check truncation. Jobs have deterministic 500-row continuation. Limits/locking are intended for one server worker. Python adapters and direct database administrators remain trusted; this is not an administrator-resistant tamper-signature system.

## Automated tests

Full Phase 00–07 suite: **240 passed**, one inherited Starlette/httpx deprecation warning, 41.06 seconds. Includes the complete Phase 00–06 regressions and unchanged network-policy tests.

Sixteen new correlation tests cover deterministic replay, duplicate prevention, multiple supporting observations grouped without losing evidence IDs, first/last capture times, all relationship types, canonical ASN/IP/URL/organization values, subdomain roles without duplicate DNS identities, scope/archive handling, archived-case rejection, CSRF, viewer/unrelated RBAC, independent cases, malformed/hash-damaged/snapshot-invalid evidence, atomic rollback/failure audits, job history, cross-case support filtering, FK evidence-delete rejection and 500-row continuation. Fixture correlation blocks socket/DNS primitives to detect collection bypasses.

Python compilation and `pip check` passed. Alembic current returned 005 (head). No dependency or network-policy relaxation was introduced.

## Live MySQL and API verification

`scripts/verify_local_phase07.py` passed with local ASGI/actual MySQL and again with `--http` against the restarted server at `http://127.0.0.1:8000`. It correlates retained cases only; it does not provision/reset the database, create new cases or collect. Report: ignored `.local/phase07-verification.json`.

| Retained case | Graph entities | Grouped relationships | Result |
| --- | --- | --- | --- |
| 7, domain intelligence | 21 | 24 | DNS, registration, CT and suffix supports; replay inserted zero |
| 9, IPv4/IPv6 intelligence | 6 | 6 | PTR, ASN and explicit registrant associations; replay inserted zero |
| 12, web metadata | 1 | 0 | URL entity; no fabricated redirects; replay inserted zero |

Initial projection added 15 supports in case 7, three entities/four supports in case 9 and one URL entity in case 12. Every replay, including the live HTTP run, added zero entities/supports and returned identical graphs. All **60 evidence hashes** were recomputed; all **78 relationship supports** passed same-case endpoint/evidence/run/target checks. Existing InnoDB engines and schema revision were checked. Exact before/after snapshots verified every pre-existing users/cases/targets/memberships/audits/runs/evidence/entities/relationships row remained unchanged. Only new derived rows and audit records were added. Authentication sessions can rotate normally.

Live API checks covered job/history/graph/entity/relationship reads, completion audits, missing-CSRF rejection, observer read access and write denial, unrelated-user read/write 404, and no truncation in these cases. No external collection occurred. Manual browser automation is unnecessary for the Phase 07 JSON-only deliverables and remains limited as accepted during Phase 06 review.

## Files changed

New: `app/services/correlation.py`, `app/api/correlation.py`, `tests/integration/test_correlation.py`, `scripts/verify_local_phase07.py`, `docs/PHASE_07_HANDOFF.md`.

Updated: `app/main.py` (router registration), `app/services/domain_entities.py` (reentrant shared persistence lock), `README.md`, `SECURITY.md`. No models, migrations, provider adapters, secrets, collector behavior or dependencies were changed. Local report is ignored.

## Known limitations and review

Jobs are bounded synchronous requests, not a persistent scheduling/recovery queue. Audits provide completed/failed job history, without a separate running-job table. Large cases require cursor continuation; bounded graphs can be incomplete and explicitly say so. PostgreSQL/distributed-worker operation is not promised. Run one server worker; MySQL case locks and uniqueness are defense in depth, not a new shared collection limiter.

Only explicitly supported current normalized evidence shapes generate links. Arbitrary raw provider fields are not mined for speculative connections. Domain RDAP currently lacks normalized registrant organizations, so that relation is limited to explicit IP RDAP registrants. ASN holder names do not generate organization ownership links. Certificate name association does not prove installation on a host. Organization labels can refer to different real organizations despite matching text. DNS/PTR/registration/routing facts can be stale or contradictory; distinct evidence is retained, not reconciled into a guessed truth.

Scope changes do not erase historical graph evidence or cancel already admitted jobs. Raw hashes validate raw JSON reproducibility; normalized observations remain trusted application/database data. Some unsupported/error items count as processed with zero candidates, while malformed and scope-denied items have explicit skip reasons. Owner review remains required before continuing. **Stop after Phase 07; Phase 08 requires explicit approval.**
