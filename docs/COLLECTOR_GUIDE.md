# Collector maintenance guide

No new collector was added for Phase 13. Existing adapters remain replaceable behind the trusted static registry. Review app/collectors/base.py, registry.py, services/collection.py and controlled clients before changes.

A collector receives a scoped immutable target snapshot and controlled network client, not an arbitrary URL executor or database session. It returns bounded evidence with source/version/time and normalized observations. Preserve raw canonical hashes and distinguish observed, negative, partial, unavailable, rate-limited and failure results. Provider availability/terms can change; do not depend on undocumented authenticated scraping.

DNS/RDAP/CT/IP/ASN/web collectors have fixture success/failure tests. New adapters require separate approval, exact-host/SSRF/redirect/size/timeout review, RBAC/scope/audit tests, malformed-response fixtures and no uncontrolled network-dependent tests. Python plugins are trusted code, not a sandbox against malicious developers. Never import sockets/subprocess/general HTTP in a plugin to bypass framework policy. AI cannot register/invoke collectors.

The offline release demo uses the shipped mock collector only, clearly marked synthetic. It creates disposable SQLite fixtures rather than adding data to any user's MySQL investigation.
