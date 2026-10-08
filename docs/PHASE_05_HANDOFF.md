# Phase 05 handoff

Implemented and verified on 2026-10-05. Phase 05 only. Phase 06 requires explicit owner approval.

## Functionality and providers

Guide steps 32–36 are implemented: canonical IPv4/IPv6 entities and PTR observations, network allocation/organization RDAP, ASN/prefix enrichment behind replaceable provider contracts, and a stored-evidence IP overview. Optional reputation integration was intentionally left unconfigured; the overview explicitly gives no clean/malicious verdict. No geolocation, port scanning, service probing, recursive enrichment, AI invocation, or Phase 06 functionality was added.

| Collector/version | Provider | Operation |
| --- | --- | --- |
| `reverse_dns` 1.0.0 | Cloudflare DoH | One dnspython-encoded PTR query; parses CNAME/PTR records already in that response only |
| `ip_rdap` 1.0.0 | IANA IPv4/IPv6 bootstrap and authoritative RIR HTTPS service | Most-specific matching bootstrap prefix; one exact IP allocation lookup |
| `ip_asn` 1.0.0 | RIPE NCC RIPEstat / RIS | One network-info query, plus one containing-prefix overview when routing is observed |

Official references: [Cloudflare wire DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/), [IANA IPv4](https://www.iana.org/assignments/rdap-ipv4), [IANA IPv6](https://www.iana.org/assignments/rdap-ipv6), [RDAP IP query RFC 9082](https://www.rfc-editor.org/rfc/rfc9082.html), [RIPEstat network-info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info.html), [prefix-overview](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview.html), and [usage rules](https://stat.ripe.net/docs/data-api/ripestat-data-api).

Adapters implement explicit `ReverseDNSProvider`, `NetworkRDAPProvider` and `RoutingProvider` Protocol contracts and are replaceable through collector constructor injection. They receive the controlled client, not a database handle or transport of their own. Registry entries are passive, IPv4/IPv6 only and independently disabled by `SPECTRE_REVERSE_DNS_ENABLED`, `SPECTRE_IP_RDAP_ENABLED`, and `SPECTRE_IP_ASN_ENABLED` (restart after configuration changes).

## Architecture and database

POST collection enters the existing Phase 03 executor; no alternate execution path exists. Case mutation authorization, CSRF, target scope/archive state, registered/enabled capability and supported target type are checked before provider access. New IP admission additionally requires a public seed. Existing target recording continues to allow nonpublic seeds, but they cannot be sent to public providers.

The existing MySQL schema remains **005 (head)**. No Phase 05 migration or DDL is needed: existing run/evidence/entity/relationship tables hold these observations. Foreign keys and InnoDB engines were checked on the existing database. No database, table or existing project record was overwritten, recreated or deleted.

Live fixture verification took exact row snapshots of users, cases, targets, membership, audits, runs, evidence, entities and relationships and checked that every existing row remained unchanged after new verification data was added. Normal authentication can rotate/revoke login sessions; sessions were not treated as immutable project evidence.

Canonical IP entities reuse Phase 04 case/type/hash keys. PTR relationships connect an IP entity to a normalized domain, with evidence reference and confidence 0.95; this records an observation, not ownership. Projection occurs under the existing central persistence lock in the same transaction as evidence and outcome audit. ASN/prefix/organization data remains evidence-backed normalized observations, rather than introducing the later general correlation engine.

`GET /api/cases/{case_id}/targets/{target_id}/ip` reads stored observations only. It returns the newest 30 IP runs, up to 100 evidence rows and 500 related same-case DNS relationships. Related domains come solely from `resolves_to` evidence already stored in that case; cross-case facts are never included. Existing evidence/run/audit routes and the domain overview remain available.

## Evidence and failure behavior

Each received provider response retains source URL, provider attribution, HTTP metadata/public resolved IP, body bytes as base64, parsed observations, capture time, raw canonical SHA-256 and run reference. Runs retain operator, collector/version, immutable target/scope snapshot, start/end times, status and safe error codes. Every displayed IP fact cites the existing case-authorized evidence endpoint.

RDAP normalizes seed-containing allocation bounds, handle/name/type, registration statuses/events and organization vCards. Organization fields or explicit `kind=org` formatted names are accepted; personal formatted names/contact fields are not normalized into organization observations. Full provider responses remain raw authorized evidence. Registration country is labeled as registration metadata, not physical geolocation.

RIPEstat prefixes must contain the seed and have the correct IP version. Origin ASN lists are bounded, deduplicated and normalized; all observed origins are retained rather than selecting an assumed owner. Holder metadata is matched only to previously observed origins. Missing/unmatched holder metadata is explicitly partial. No route/PTR observed is provider-scoped and does not prove a global negative.

Malformed responses and HTTP errors retain raw evidence but project no invalid facts. A valid RIPE `error`/`maintenance` envelope at HTTP 200 produces `provider_unavailable`. Later RDAP/holder failure can retain validated earlier responses in a failed partial run. Timeout/network failures with no response retain a failed run and audit, without invented evidence. Unexpected errors or outer executor cancellation use the inherited atomic rollback behavior and can discard a run's partial evidence. HTTP 201 means a run was created; inspect its outcome.

Synthetic protocol fixtures carry `synthetic_fixture` raw metadata and are visibly labeled in the UI. They are kept in a separate case from live intelligence. Contact-redacted recorded response fixtures support offline parser regression tests without presenting them as current observations.

## Network/security controls and provider limits

All provider work uses the controlled HTTPS/443 client, with all-public destination DNS checks, IP pinning, original-host verified TLS, redirect revalidation, fixed headers/media types, no ambient cookies/proxies/credentials, total deadlines, bounded retries/body sizes and worker/run limits. The target IP is never a transport destination. No direct socket/HTTP/subprocess calls were introduced in collectors.

Cloudflare/IANA/RIR requests use the existing minimum one-second host interval. RIPE starts are at least two seconds apart per host; each ASN run makes at most two provider requests. Existing 429/503 Retry-After/backoff applies, without immediate retries of rate-limit responses. RIPE's documented limit is eight concurrent requests from one source IP, with registration requested for regular usage above 1,000 requests/day; SPECTRE retains its four-run process limit and performs sequential requests within each run. Provider policies can change.

Viewers cannot collect. Excluded/archived and nonpublic seeds are rejected. Unrelated users receive case-not-found. Collector denial/outcome audits retain operator attribution and safe reasons. Active authorization metadata still enables only passive collectors. No API secrets were added or hard-coded. AI has no collector route/tool.

## Automated and live verification

- Full `python -m pytest -q`: **198 passed**, including the complete Phase 00–04 regression suite and existing network-policy tests. One inherited Starlette/httpx deprecation warning.
- IPv4/IPv6 fixture success, raw/provenance/hash checks, canonical entity reuse and PTR relationships passed.
- Malformed responses, HTTP 429/503, timeouts, controlled-network errors, missing bootstrap services, partial later-request failures and HTTP-200 maintenance/error envelopes passed.
- Longest-prefix bootstrap selection, unsafe service rejection, seed/allocation/prefix mismatch, ASN types, date validation, organization/personal-name distinction, bounded PTR answers and resolver-scoped negatives passed.
- API tests verified CSRF, independently disabled collectors, viewer/unrelated access, excluded/archived scope, nonpublic admission, domain-type rejection, stored-only GETs, case-isolated related domains, evidence hashes and audits. Direct socket/DNS transport primitives were blocked during fixture integration tests to detect bypasses/scans.
- `alembic current`: **005 (head)**. Live MySQL engines/foreign keys and existing-row preservation passed; no migration was applied.
- `compileall` and `pip check` passed; collector source review found no direct socket/HTTP/subprocess bypass.

Live synthetic verification retained case **8**, IPv4/IPv6 targets **14/15**, completed runs **15–20** and partial failed ASN run **21**. Its first routing response remains valid evidence, with malformed holder response stored separately. Excluded target **16** and nonpublic target **17** were rejected without contacting providers. The observer has read-only membership in this explicitly synthetic case for review. Viewer writes and unrelated reads/writes were also checked through local API requests against the actual MySQL database.

Live public-provider browser verification retained case **9**, IPv4 target **18** (`8.8.8.8`) and IPv6 target **19** (`2001:4860:4860::8888`):

| Target | Reverse DNS | IP RDAP | ASN/prefix |
| --- | --- | --- | --- |
| IPv4 | run 22 completed; evidence 45 | run 23 completed; evidence 46–47 | run 24 completed; evidence 48–49 |
| IPv6 | run 25 completed; evidence 50 | run 26 completed; evidence 51–52 | run 27 completed; evidence 53–54 |

Observed PTR `dns.google`, authoritative ARIN allocation/organization metadata, RIPE origin AS15169 and containing IPv4/IPv6 prefixes. All requests went through the framework/guarded client. Post-run checks recomputed **52 stored evidence hashes**, checked **57 relationship references** and matching started/completed audits for all six real runs. Results are historical provider observations, not current ownership or service claims.

## Manual browser/API verification

The agent verified creation of both IP target types; separate collection controls; real PTR/RDAP/ASN results; provider attribution/capture times/hashes/evidence links; successful statuses and audits; synthetic/partial-failure labels; unconfigured reputation messaging; viewer-disabled controls; investigator-disabled excluded controls; and a live-browser nonpublic-seed rejection with `collector.denied` audit and no run/evidence creation.

An IP seed (`104.20.23.154`, target 20) was added to the existing Phase 04 live case **7**, solely to inspect its stored DNS relationship to `example.com` and evidence **15**. Opening the IP overview displayed that relationship and made no new collection request. Existing domain case/evidence records were preserved.

Evidence JSON and authorization were verified using local ASGI API requests backed by the real MySQL database. The automation browser's previously observed direct-JSON navigation block was not bypassed; an ordinary user browser may additionally open evidence links. Private screenshot proof is `.local/phase05-ip-overview.png`, ignored by Git.

## Files changed

New implementation: `app/collectors/ip_providers.py`, `app/collectors/ip_intelligence.py`, `app/services/ip_entities.py`, `app/api/ip.py`.

Updated implementation: `app/collectors/base.py`, `domain_support.py`, `registry.py`; `app/services/collection.py`; `app/config.py`, `app/main.py`; `app/static/index.html`, `js/main.js`, `css/main.css`; `.env.example`. Existing `.env` credentials and dependency requirements were preserved.

New verification files: `tests/ip_fixtures.py`, `tests/fixtures/ip_intelligence.json`, `tests/fixtures/ip_recorded_provider_shapes.json`, `tests/unit/test_ip_parsers.py`, `tests/integration/test_ip_intelligence.py`, `scripts/verify_local_phase05.py`, `scripts/check_phase05_live.py`. Updated docs: `README.md`, `SECURITY.md`, this handoff. Ignored local verification reports contain IDs/results, no credentials.

## Known limitations and review

Reputation feeds are optional and unconfigured; no reputation/geolocation verdict is available. Provider responses can be partial, stale, filtered or unavailable. RIPE origin/holder and RDAP registration are separate observations, not proof of who operates an address. PTR records do not prove ownership or a reachable service. Related domains are historical case evidence, not live reverse-IP enumeration.

Inherited framework limitations remain: cooperative ten-second default run deadline, bounded response sizes, process-local limits/locking, one server worker, no persistent queue/recovery, and trusted adapters rather than a malicious-code sandbox. Scope is checked at admission; editing it does not cancel an already admitted run. Process termination may leave a running record. Long responses/provider throttling may prevent otherwise legitimate enrichment; controls were not relaxed.

Fixture verifier creates additional labeled review records if re-run; the live checker expects the named retained case and exports public redacted fixtures. Neither script is an account/database provisioning tool. Raw RDAP may contain provider-published contact details and remains case-authorized local evidence; do not publish raw evidence casually.

SPECTRE remains running at http://127.0.0.1:8000. For owner review, open **Phase 05 live provider verification** and either IP overview. The synthetic case shows the retained partial failure; the observer can inspect it read-only. All required verification was performed by the agent; owner review/approval is still required before Phase 06. Work stops after Phase 05.
