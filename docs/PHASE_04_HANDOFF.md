# Phase 04 handoff

Implemented and verified 2026-10-05. Phase 04 only; Phase 05 requires explicit approval.

## Guide requirements and architecture

Guide steps 26–31 are implemented: six-type DNS, authoritative domain RDAP, documented CT search, normalized discovered entities, evidence/confidence-backed relationships, and a domain overview. Existing Phase 00–03 routes, account/case/target behavior, mock collector, scope, RBAC, CSRF and audit controls remain covered by the complete regression suite.

All collection enters the existing central executor. Registry entries are domain-only, passive, version `1.0.0`, independently configurable. Collectors receive immutable target snapshots and the controlled HTTP client; provider adapters use only that client and are replaceable by constructor injection. The API does not accept a provider URL or arbitrary headers. No AI collection integration, IP enrichment, brute force, scanning, exploitation or active assessment was added.

Providers:

| Collector | Provider | Bounded operation |
| --- | --- | --- |
| DNS | Cloudflare DoH | dnspython wire codec; A, AAAA, MX, NS, TXT, CNAME only |
| RDAP | IANA DNS bootstrap and selected authoritative HTTPS registry | Bootstrap plus one domain lookup; no WHOIS fallback |
| CT | SSLMate Cert Spotter CT Search API v1 | One page; at most 100 normalized unexpired issuances; 60-second host interval |

Documentation consulted: [Cloudflare wire-format DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/), [IANA bootstrap registry](https://www.iana.org/assignments/rdap-dns), [Cert Spotter API](https://sslmate.com/help/reference/ct_search_api_v1), and [dnspython message API](https://dnspython.readthedocs.io/en/stable/message-make.html).

## Database and provenance

Alembic 005 adds `entities` and `relationships`, explicitly InnoDB. Entities deduplicate by case, type and SHA-256 canonical key. Concrete domain/subdomain names share domain entities; `subdomain_of` records the seed-relative CT relationship. IP values use the existing normalization rules. Certificates use their provider fingerprint. Relationships require an evidence foreign key and confidence constrained to 0–1. Case and endpoint entity foreign keys are enforced. These are domain-specific projections, not a generic graph/correlation engine.

The live existing SPECTRE MySQL database was upgraded from 004 to 005. Exact snapshots of all eight existing application tables matched immediately before/after migration. New tables have five declared foreign keys; all application tables use InnoDB. No database was recreated or existing record deleted. MySQL DDL is not fully transactional; downgrade 005 drops its new tables and should only be used on disposable data.

Received response bytes remain base64 in raw JSON with HTTP metadata, resolved destination IP, final source reference and provider name. Evidence retains parsed data, capture time, raw SHA-256 and run reference; runs retain collector version, target/scope snapshot, operator and start/end times. Every displayed normalized fact links to the authorized evidence detail endpoint. Raw failures remain visible, with no projection from malformed/error responses. Validated partial responses may be retained on a failed run. Unexpected errors, outer deadline cancellation or database failures use the existing rollback behavior. Synthetic fixtures have explicit raw metadata and UI labels.

## Network and security controls

Existing HTTPS/443, all-public DNS answers, IP pinning, verified original-host TLS, checked redirects, bounded timeout/retry/body/concurrency/worker policies continue to apply. No TLS bypass, private-network exception, ambient credentials/proxies/cookies or direct target HTTP fetch was introduced. Three fixed Accept media types support DNS wire/JSON/RDAP. HTTP 429/503 defer the shared host limiter, respecting bounded numeric Retry-After and conservative fallback. CT does not paginate or retry rate-limit responses.

Scope and authorization are checked before provider access. Excluded/archived seeds cannot collect; active scope allows passive operations only. Viewers are read-only; unrelated accounts receive case-not-found. Reads never invoke collectors. Discovered names/IPs are data only and do not grant collection authorization. All collection state changes retain audit attribution and safe error codes. Confidence expresses confidence in a provider observation, not ownership or risk.

## Files changed for this phase

New implementation:

- `app/collectors/providers.py`, `domain_support.py`, `dns.py`, `rdap.py`, `ct.py`.
- `app/services/domain_entities.py`, `app/api/domain.py`.
- `app/db/migrations/versions/005_domain_intelligence.py`.

Updated implementation:

- `app/collectors/base.py`, `registry.py`; `app/services/collection.py`, `http_client.py`.
- `app/security/url_policy.py`, `rate_limit.py`; `app/config.py`, `main.py`, `app/db/models.py`.
- `app/static/index.html`, `app/static/js/main.js`, `app/static/css/main.css`.
- `requirements.txt`, `.env.example`; existing local `.env` credentials were preserved.

Tests, verification and documentation:

- `tests/domain_fixtures.py`; `tests/fixtures/domain_{dns,bootstrap,rdap,ct}.json`.
- `tests/unit/test_domain_parsers.py`, `tests/unit/test_network_policy.py`, `tests/integration/test_domain_intelligence.py`.
- `scripts/verify_local_phase04.py` (guarded one-time 004→005 migration + explicitly synthetic fixture checks).
- `scripts/check_phase04_live.py` (checks this retained verification dataset, including specific run/case/target IDs; not a generic provisioning script).
- `README.md`, `SECURITY.md`, this handoff. Private browser proof is `.local/phase04-domain-overview.png`, ignored by Git.

## Tests and verification results

- Full `python -m pytest -q`: **130 passed**, including every prior-phase test and the original network-policy tests. One existing upstream Starlette/httpx deprecation warning.
- `python -m compileall -q app tests scripts` and `python -m pip check` passed.
- Provider fixtures exercise successful DNS/RDAP/CT, malformed responses, HTTP 429/503, timeouts, partial DNS failure, NXDOMAIN/SERVFAIL, null MX, mismatched DNS question, invalid certificate dates/fingerprints, out-of-scope certificate names, wildcard handling, bootstrap URL rejection, independent disabling and canonical entity deduplication.
- API checks verify stored-only overview reads, unsupported IP collection, excluded scope, viewer writes, unrelated reads, evidence hashes and audit outcomes. Network checks verify pinned TLS, mixed/private DNS rejection, redirect/body/deadline/worker limits, fixed media types and backoff.
- Live migration/synthetic verification passed against existing MySQL. Retained case 6/target 12 is explicitly **synthetic**: runs 5–7 completed; run 8 failed `malformed_response` with raw evidence retained. These fixtures are never presented as actual intelligence.
- Real browser verification: researcher created case 7, target 13 `example.com`, passive scope. DNS run 9 completed with six evidence responses (#15–20), RDAP run 10 completed with bootstrap/authoritative evidence (#21–22), CT run 11 completed with evidence #23. The overview displayed DNS, registration, certificates, hashes, source citations, bounded coverage, wildcard caveats, infrastructure and started/completed audits.
- Browser viewer verification: observer can open assigned case 3 and its domain overview; collection controls are disabled. Live MySQL API checks separately proved all three collectors return 403 for excluded investigator requests and viewer writes, and 404 for unrelated case access, with a network stub that fails if contacted.
- Post-browser live check verified **21 stored evidence hashes** and **33 relationship references**, all case-aligned, plus three real completed domain runs and revision 005.

## Known limitations and review

Cert Spotter anonymous access is evaluation/quota-limited; sustained production use needs a separately reviewed authenticated adapter or replacement. No keys were hard-coded, requested or added. Provider availability and responses can change after this live verification.

CT covers one provider page and unexpired issuances only. It is not exhaustive historical CT; wildcards do not prove concrete host existence and certificates do not prove a live service. RDAP uses the exact domain seed; subdomains may lack a registration object. DNS observations can change or differ by resolver. No discovered infrastructure is contacted automatically.

Overview history is bounded to 30 runs, 100 evidence rows and 500 relationships. Earlier run evidence remains accessible. Source confidence rules are fixed and are not ownership attribution. Synthetic and real verification cases remain separate for review.

Inherited framework limitations remain: cooperative total deadlines, process-local limits/locking, a single server worker, no persistent queue/recovery or active-job cancellation on scope edits, and trusted Python adapters rather than a malicious-code sandbox. A hard process stop may leave a running record. No graph visualization, automated enrichment, AI, report generation or Phase 05 functionality exists.

Manual verification completed by the agent; owner review/approval is still required before advancing. SPECTRE remains running at http://127.0.0.1:8000. To review: sign in as researcher, open **Phase 04 live provider verification**, and choose **Domain overview**. Opening it makes no new provider request. Review the synthetic case to inspect the stored malformed-response failure. Independently disabled configuration was verified in automated tests; an optional owner check can toggle one flag in local `.env` and restart, then restore it.

The automation browser blocked direct navigation to the JSON evidence URL (`ERR_BLOCKED_BY_CLIENT`). Evidence detail and authorization were verified through local ASGI API requests against the actual MySQL database, and facts/citations were verified in the browser. The owner can additionally inspect the evidence link in their ordinary browser. This browser limitation did not affect provider runs or evidence persistence.
