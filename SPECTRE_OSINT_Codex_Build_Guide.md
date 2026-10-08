# SPECTRE OSINT Codex Build Guide

> Markdown conversion of the PDF build guide. Graphical figures are
> represented by their captions; the implementation plan, phase gates,
> prompts, and code-oriented content are preserved as text.

# SPECTRE

       OSINT Investigation & Attack-Surface Intelligence Platform

                      Step-by-Step Codex Build Guide

Research build specification • Python / FastAPI • MySQL •
HTML/CSS/JavaScript

                         Version 1.0 • October 2026

## 1. Project Mission

SPECTRE is a local-first OSINT investigation platform for cybersecurity
research. It accepts a lawful seed target such as a domain, IP address,
URL, organization name, username, or email address; gathers public
intelligence through controlled collectors; preserves evidence;
correlates entities; visualizes relationships; prioritizes findings; and
produces investigation reports.

The design goal is not "search everything about a person." The design
goal is reproducible cyber- infrastructure research with evidence
provenance, authorization boundaries, and a clean investigation
workflow.

### Core outcomes

-   Create and manage investigation cases.
-   Run passive OSINT collectors against supported target types.
-   Normalize findings into typed entities and relationships.
-   Preserve raw evidence, timestamps, source URLs/API identifiers,
    hashes, and collector versions.
-   Build a relationship graph and unified timeline.
-   Assign transparent confidence and risk scores.
-   Provide an AI assistant that can summarize stored evidence but
    cannot autonomously browse arbitrary targets or execute shell
    commands.
-   Export a professional case report.

### Non-goals for v1

-   Credential theft, leaked-password ingestion, doxxing, stalking,
    private-data brokerage, or bypassing access controls.
-   Exploit execution or vulnerability exploitation.
-   Unrestricted port scanning of third-party systems.
-   Automated account login, CAPTCHA bypass, scraping behind
    authentication, or evasion of provider controls.

## 2. Recommended Technology Stack

    Layer                              Choice                                        Reason
    Backend                            Python 3.12+ / FastAPI                        Strong async I/O, typed APIs,
                                                                                     OSINT ecosystem, clean module
                                                                                     boundaries.
    Frontend                           HTML5 + CSS + vanilla JavaScript              Simple local deployment and
                                                                                     easy debugging.
    Database                           MySQL 8                                       Cases, evidence, entities,
                                                                                     relationships, audit logs.
    ORM / migrations                   SQLAlchemy + Alembic                          Schema safety and repeatable
                                                                                     migrations.
    HTTP                               httpx                                         Timeouts, async requests,
                                                                                     redirects and TLS handling.
    Jobs                               BackgroundTasks initially;                    Avoid over-engineering v1 while
                                       Redis/RQ later                                leaving a queue upgrade path.

Graph UI Cytoscape.js Interactive entity graph without requiring a graph
database. Reports Jinja2 + WeasyPrint or HTML/PDF investigation exports.
ReportLab Tests pytest Unit, integration, fixtures, collector mocks.
Optional AI Local Ollama or configured API Evidence-grounded summaries
through a narrow read-only interface.

### Local development layout

Run FastAPI on localhost, MySQL locally, and serve the frontend from
FastAPI static files. Do not make WAMP a dependency for this project;
Python is the primary runtime. MySQL from an existing WAMP installation
can still be used if desired. **Figure 1. Evidence-first investigation
pipeline.**

## 3. Repository Blueprint

Create this structure before implementing features:

``` text
spectre/
  app/
    main.py
    config.py
    db/
       session.py models.py migrations/
    api/
       auth.py cases.py targets.py collectors.py graph.py reports.py
    services/
       normalization.py correlation.py scoring.py reporting.py
    collectors/
       base.py dns.py rdap.py ct.py ip.py headers.py
    security/
       rbac.py url_policy.py rate_limit.py secrets.py
    ai/
       assistant.py tools.py prompts.py
    static/
       css/ js/ images/
    templates/
  tests/
    unit/ integration/ fixtures/
  scripts/
  docs/
  .env.example
  requirements.txt
  README.md
```

### Codex rule

Codex should never jump ahead. At the end of each phase it must run the
phase tests, report files created/modified, list commands executed,
state known limitations, and stop for review.

## 4. Data Model

Table Purpose Important fields users Local accounts and roles id,
username, password_hash, role, created_at cases Investigation container
id, title, description, status, owner_id, created_at targets Seed or
discovered targets id, case_id, type, value, normalized_value,
scope_status collector_runs Reproducible execution record id, target_id,
collector, version, started_at, ended_at, status evidence Raw/parsed
source material id, run_id, source_type, source_ref, captured_at,
sha256, raw_json entities Normalized graph nodes id, case_id,
entity_type, canonical_value, attributes_json relationships Graph edges
from_entity_id, to_entity_id, relation_type, confidence, evidence_id

    findings                             Analyst-facing observations                   severity, title, description,
                                                                                       confidence, status, evidence_id
    notes                                Investigator notes                            case_id, author_id, body,
                                                                                       created_at
    audit_logs                           Security/audit trail                          actor_id, action, object_type,
                                                                                       object_id, timestamp,
                                                                                       metadata_json

**Figure 2. Example entity graph and evidence-backed relationships.**

## Phase 00 - Foundation & Safety Contract

Create a reproducible project skeleton and encode the project boundaries
before adding collectors.

### Implementation steps

## 1. Initialize Git repository, virtual environment, requirements, .env.example and README.

## 2. Create FastAPI app with /health and a minimal HTML landing page.

## 3. Add typed configuration with environment validation; secrets must never be committed.

## 4. Create a safety policy document defining passive collection, authorization requirements for active

      features, rate limits, data retention, and prohibited use.

## 5. Add centralized structured logging with secrets/redaction filters.

## 6. Add pytest and a smoke test for /health.

### Required deliverables

-   Runnable local server.
-   README with install/run commands.
-   SECURITY.md and RESEARCH_SCOPE.md.
-   Passing smoke test.

### Verification gate

-   Fresh clone can install dependencies and start without code edits.
-   No API keys or secrets appear in source or logs.
-   pytest passes.

### Codex handoff prompt

Implement Phase 00 only. Build the SPECTRE FastAPI skeleton,
configuration, health endpoint, static landing page, logging, pytest
smoke test, .env.example, README, SECURITY.md and RESEARCH_SCOPE.md. Do
not implement OSINT collection yet. Preserve a clean layered structure.
Run tests and stop.

## Phase 01 - Database, Accounts & RBAC

Add durable cases and local authorization before intelligence
collection.

### Implementation steps

## 7. Configure SQLAlchemy and Alembic for MySQL.

## 8. Create users, cases, case_members and audit_logs models/migrations.

## 9. Implement secure password hashing using Argon2id or bcrypt through a maintained library.

## 10. Implement session or token authentication suitable for a local web app.

## 11. Define roles: admin, investigator, viewer.

## 12. Enforce object-level case access in service/API layers.

## 13. Audit login, logout, case create/update, membership changes.

### Required deliverables

-   Migrations 001+.
-   Login/logout UI.
-   Case dashboard.
-   RBAC test suite.

### Verification gate

-   Viewer cannot mutate cases.
-   Investigator cannot access an unrelated case.
-   Admin access is explicit and audited.
-   Passwords are never stored/logged in plaintext.

### Codex handoff prompt

Implement Phase 01 only. Add MySQL SQLAlchemy models, Alembic
migrations, local authentication, admin/investigator/viewer RBAC, case
membership and audit logs. Add tests for object-level authorization. Do
not add collectors.

## Phase 02 - Case & Target Management

Create the investigation workflow and typed seed targets.

### Implementation steps

## 14. Add targets model with domain, IPv4, IPv6, URL, organization, username and email target types.

## 15. Normalize targets deterministically: lowercase domains, IDNA handling, canonical IPs, URL parsing,

    safe display values.

## 16. Add scope_status: passive_allowed, active_authorized, excluded.

## 17. Build create/edit/archive target UI.

## 18. Prevent duplicate canonical targets inside a case.

## 19. Record all target mutations in audit_logs.

### Required deliverables

-   Case detail page.
-   Target CRUD endpoints/UI.
-   Normalization service.
-   Validation tests.

### Verification gate

-   Malformed targets fail safely.
-   Normalization is deterministic.
-   Duplicate canonical values are rejected or merged predictably.
-   No network requests occur during target creation.

### Codex handoff prompt

Implement Phase 02 only. Add typed target management, deterministic
normalization, scope status, UI/API and tests. Target creation must
perform zero network collection.

## Phase 03 - Collector Framework

Build a safe plug-in contract before individual OSINT modules.

### Implementation steps

## 20. Create Collector base class with name, version, supported target types and collect() contract.

## 21. Create collector_runs and evidence models.

## 22. Implement per-host timeout, retry ceiling, user-agent, rate-limit and maximum-response-size policies.

## 23. Implement outbound URL policy: HTTPS preferred; deny localhost, RFC1918, link-local, metadata

    endpoints and unsupported schemes unless explicitly needed by a trusted collector.

## 24. Store raw response metadata plus normalized parsed output and SHA-256 hash.

## 25. Create mock collector and integration tests with no external network dependency.

### Required deliverables

-   Collector registry.
-   Evidence repository service.
-   Outbound request guard.
-   Mock collector tests.

### Verification gate

-   A malicious target cannot turn the collector into SSRF against
    local/private addresses.
-   Timeouts and response limits are enforced.
-   A collector failure does not corrupt the case.

### Codex handoff prompt

Implement Phase 03 only. Build the collector interface, registry,
collector_runs/evidence schema, safe HTTP client policy, SSRF
protections, limits, provenance and mock-based tests. Do not add real
providers yet.

## Phase 04 - Domain Intelligence

Implement the first useful passive intelligence vertical.

### Implementation steps

## 26. Add DNS collector for A/AAAA/MX/NS/TXT/CNAME using a maintained DNS library.

## 27. Add RDAP collector for registration/network metadata; prefer RDAP over legacy WHOIS parsing.

## 28. Add Certificate Transparency collector using a documented public endpoint/provider and conservative

    rate limits.

## 29. Normalize discovered domains/subdomains/IPs into entities.

## 30. Store every relationship with evidence reference and confidence.

## 31. Display a domain overview with DNS, registration, certificates and discovered infrastructure.

### Required deliverables

-   DNS collector.
-   RDAP collector.
-   CT collector.
-   Domain overview page.
-   Fixtures and parser tests.

### Verification gate

-   Collectors can be disabled independently.
-   Provider errors are visible but non-fatal.
-   Every displayed fact links to stored evidence.
-   No brute-force subdomain enumeration in this phase.

### Codex handoff prompt

Implement Phase 04 only. Add passive DNS, RDAP and
certificate-transparency collectors. Use documented public sources and
fixtures. Normalize entities and evidence-backed relationships. No
brute-force DNS and no active scanning.

## Phase 05 - IP & Network Intelligence

Add passive network ownership and infrastructure context.

### Implementation steps

## 32. Normalize IP entities and reverse-DNS observations.

## 33. Use RDAP for network allocation and organization metadata.

## 34. Add ASN/prefix enrichment from a legitimate public/API source with an adapter so providers can be

    replaced.

## 35. Optionally integrate reputation feeds only through documented APIs and store provider attribution.

## 36. Add IP overview showing reverse DNS, ASN/provider, related domains observed in this case, and

    reputation observations.

### Required deliverables

-   IP collector modules.
-   Provider adapter interface.
-   IP overview.
-   Tests with recorded fixtures.

### Verification gate

-   No port scan is performed.
-   Geolocation, if used, is coarse and labeled as approximate.
-   Reputation is attributed to its provider and timestamp.

### Codex handoff prompt

Implement Phase 05 only. Add passive IP/RDAP/ASN/reputation enrichment
behind provider adapters. Do not implement port scanning or service
probing.

## Phase 06 - Web Metadata Intelligence

Collect low-impact metadata from explicitly scoped public URLs.

### Implementation steps

## 37. Allow URL collection only when target scope permits it.

## 38. Fetch a single public page with strict redirect, size, timeout and content-type limits.

## 39. Capture status, final URL, selected response headers, title, server hints and security headers.

## 40. Do not crawl recursively in v1.

## 41. Do not execute browser JavaScript or submit forms.

## 42. Create findings for missing security headers only as informational observations, not proof of

    vulnerability.

### Required deliverables

-   URL metadata collector.
-   Header analysis.
-   Safe redirect policy.
-   UI evidence view.

### Verification gate

-   Private-network redirects are blocked.
-   Binary/oversized responses are aborted.
-   No authentication, form submission, crawling or exploit testing
    occurs.

### Codex handoff prompt

Implement Phase 06 only. Add a tightly constrained public-URL metadata
collector with SSRF-safe redirects, response limits and security-header
observations. No crawler, browser automation, login, form submission or
exploit checks.

## Phase 07 - Correlation Engine

Turn isolated facts into an investigation graph.

### Implementation steps

## 43. Create deterministic entity upsert rules for domain, subdomain, IP, ASN, certificate, organization and

    URL.

## 44. Create typed relationship rules such as resolves_to, announced_by, certificate_observed_on,

    redirects_to and registered_to where evidence supports them.

## 45. Add first_seen/last_seen, confidence and evidence IDs to edges.

## 46. Implement deduplication without deleting provenance.

## 47. Add correlation jobs that operate only on already collected evidence.

## 48. Expose graph JSON endpoint.

### Required deliverables

-   Correlation service.
-   Entity/relationship APIs.
-   Deduplication tests.
-   Graph endpoint.

### Verification gate

-   Same evidence replay does not create duplicate graph noise.
-   Every edge can be traced to one or more evidence records.
-   Confidence is rule-based and documented.

### Codex handoff prompt

Implement Phase 07 only. Build deterministic evidence-to-entity
correlation and relationship creation. Preserve provenance and make
processing idempotent. No new network collection.

## Phase 08 - Graph & Timeline UI

Make the investigation visually useful.

### Implementation steps

## 49. Integrate Cytoscape.js for graph rendering.

## 50. Add filters by entity type, confidence and source.

## 51. Clicking a node opens attributes, related evidence and timestamps.

## 52. Add a chronological timeline from evidence captured_at and relationship first_seen.

## 53. Add search/focus and "expand from stored evidence" controls.

## 54. Keep network collection separate from graph interaction.

### Required deliverables

-   Interactive graph.
-   Evidence side panel.
-   Timeline.
-   Graph filters/search.

### Verification gate

-   Large graphs remain usable through pagination/limits.
-   UI never invents edges.
-   Graph actions cannot trigger arbitrary collectors without an
    explicit target/action.

### Codex handoff prompt

Implement Phase 08 only. Build Cytoscape.js graph and timeline views
using stored entities/relationships/evidence. Add filters and evidence
drill-down. Do not silently launch collectors from graph clicks.

## Phase 09 - Transparent Scoring & Findings

Prioritize observations without pretending risk is certainty.

### Implementation steps

## 55. Define a documented scoring rubric based on evidence type, recency, confidence and security

    relevance.

## 56. Keep confidence separate from severity.

## 57. Generate findings from explicit rules, not an opaque model.

## 58. Support analyst status: open, accepted, false_positive, informational, resolved.

## 59. Allow analyst notes and manual severity adjustment with audit trail.

## 60. Show "why this score" breakdown.

### Required deliverables

-   Scoring service.
-   Rule catalog.
-   Findings UI.
-   Audit trail for overrides.

### Verification gate

-   Scores are deterministic for the same inputs.
-   Missing data does not become a negative finding.
-   Analyst overrides preserve original score and reason.

### Codex handoff prompt

Implement Phase 09 only. Add deterministic scoring and findings with
explainable rule breakdown, confidence separate from severity, analyst
workflow and audited overrides. **Figure 3. Security boundaries for
collectors and the AI assistant.**

## Phase 10 - Evidence-Grounded AI Assistant

Add AI only after the evidence model is trustworthy.

### Implementation steps

## 61. Create a read-only AI tool layer: get_case_summary, search_entities, get_entity_evidence, list_findings,

    explain_relationship.

## 62. The model receives only the current case and user-authorized evidence.

## 63. Require citations using internal evidence IDs in every factual answer.

## 64. Reject requests for arbitrary shell commands, arbitrary URL fetching, credential access or actions

    outside the case.

## 65. Treat retrieved web text as untrusted data; never allow it to override system/tool policy.

## 66. Add prompt-injection test fixtures containing hostile instructions inside evidence.

## 67. Support a local model through Ollama first; keep provider interface replaceable.

### Required deliverables

-   AI provider adapter.
-   Read-only tool interface.
-   Evidence citation renderer.
-   Prompt-injection tests.

### Verification gate

-   AI cannot call collectors directly.
-   AI cannot access another case.
-   Answers with unsupported factual claims are flagged or refused.
-   Hostile text inside evidence is treated as content, not
    instructions.

### Codex handoff prompt

Implement Phase 10 only. Add an optional evidence-grounded AI assistant
using a provider adapter. Tools must be read-only and case-scoped.
Require evidence IDs for factual claims. Add prompt- injection tests.
The AI must not browse, run shell commands, or launch collectors.

## Phase 11 - Reporting & Export

Turn a case into a defensible research artifact.

### Implementation steps

## 68. Create a report template with executive summary, scope, methodology, targets, findings, entity graph

    snapshot, timeline, evidence appendix and limitations.

## 69. Include collector names/versions and capture timestamps.

## 70. Include evidence references for every finding.

## 71. Support HTML export first, then PDF.

## 72. Add report generation audit event.

## 73. Add redaction option for sensitive notes before export.

### Required deliverables

-   HTML report.
-   PDF report.
-   Evidence appendix.
-   Export tests.

### Verification gate

-   Report can be reproduced from stored case data.
-   No secret/API key appears in exports.
-   Findings retain provenance and limitations.

### Codex handoff prompt

Implement Phase 11 only. Build reproducible HTML/PDF case reports from
stored data with scope, methodology, findings, graph/timeline, evidence
references, limitations and redaction controls.

## Phase 12 - Authorized Active Assessment - Optional

Keep active checks isolated from passive OSINT and disabled by default.

### Implementation steps

## 74. Create a separate feature flag ACTIVE_ASSESSMENT_ENABLED=false by default.

## 75. Require target scope_status=active_authorized plus explicit user confirmation.

## 76. Start only with low-impact checks such as DNS resolution verification or a single HTTP HEAD/GET

    already covered by the URL collector.

## 77. Do not implement exploitation, password attacks, stealth/evasion or mass scanning.

## 78. Log authorization context, operator, exact action and timestamp.

## 79. Add per-case kill switch and strict rate limits.

### Required deliverables

-   Disabled-by-default active module.
-   Authorization confirmation UI.
-   Audit records.
-   Safety tests.

### Verification gate

-   Feature is unreachable when disabled.
-   Excluded/passive-only targets cannot be actively assessed.
-   Every active request is attributable and rate-limited.

### Codex handoff prompt

Implement Phase 12 only as an OPTIONAL, disabled-by-default
authorization framework. Do not add exploit execution, credential
attacks, stealth, evasion or mass scanning. Add tests proving
passive-only targets cannot enter active workflows.

## Phase 13 - Hardening, QA & Release

Prepare the project for demonstration and open-source release.

### Implementation steps

## 80. Run dependency audit, static analysis and secret scanning.

## 81. Add CSRF protection where relevant, secure cookies, strict input validation and security headers.

## 82. Add database backup/restore scripts for local research.

## 83. Add fixture-based integration tests for every collector.

## 84. Add load limits for graph size, evidence payloads and report generation.

## 85. Create demo seed data that contains only synthetic/non-sensitive examples.

## 86. Write INSTALL.md, ARCHITECTURE.md, DATA_MODEL.md, COLLECTOR_GUIDE.md and

    CONTRIBUTING.md.

## 87. Tag v1.0.0 only after a clean fresh-install test.

### Required deliverables

-   Security checklist.
-   Fresh-install script/docs.
-   Synthetic demo case.
-   Release documentation.

### Verification gate

-   All tests pass from a fresh clone.
-   Secret scan is clean.
-   Demo works without private data.
-   No collector depends on undocumented scraping behavior.

### Codex handoff prompt

Implement Phase 13 only. Harden and document the existing system; do not
expand scope. Add security checks, synthetic demo data, fresh-install
verification, contributor docs and release checklist. Report all
remaining limitations.

## 5. Codex Operating Rules

-   One phase per Codex task. Never ask Codex to "build the whole
    platform" in one prompt.
-   Before modifying code, Codex should inspect the repository and
    summarize relevant existing files.
-   Preserve existing working behavior unless the current phase
    explicitly changes it.
-   Prefer small modules and typed interfaces over a single large file.
-   All external providers sit behind adapters; tests use mocks/fixtures
    and should not require the live internet.
-   Database changes require migrations; never silently edit production
    tables.
-   Every phase ends with tests, compile/import checks, changed-file
    list, commands run, limitations, and a STOP.
-   Never place API keys, passwords or tokens in code, fixtures,
    screenshots, reports or Git history.
-   Do not let AI-generated text become evidence. AI output is analysis;
    evidence comes from collectors or investigator input.

## 6. Suggested Phase Order & Milestones

    Milestone                          Phases                                        What you can demo
    M1 - Platform shell                00-02                                         Login, cases, targets, scope and
                                                                                     audit trail.
    M2 - Real OSINT MVP                03-06                                         Passive domain/IP/web metadata
                                                                                     collection with evidence.
    M3 - Investigation engine          07-09                                         Entity graph, timeline,
                                                                                     correlation and explainable
                                                                                     findings.
    M4 - Intelligence assistant        10                                            Evidence-grounded AI with
                                                                                     citations and injection
                                                                                     resistance.
    M5 - Research deliverable          11                                            Professional HTML/PDF case
                                                                                     reports.
    M6 - Controlled extension          12                                            Optional authorization-gated
                                                                                     active framework.
    M7 - Portfolio release             13                                            Hardened, documented,
                                                                                     synthetic demo and v1.0 release.

## 7. Definition of Done for v1.0

-   A researcher can create a case and add a domain/IP/URL seed.
-   Passive collectors run with strict network controls and record
    provenance.
-   Evidence is normalized into entities and evidence-backed
    relationships.
-   The graph and timeline explain how infrastructure is connected.
-   Findings are deterministic and explain their severity/confidence.
-   The AI assistant can summarize only stored case evidence and cites
    evidence IDs.
-   A professional report can be exported.
-   RBAC, audit logging, SSRF defenses, rate limits, secret handling and
    test coverage are demonstrable.
-   The repository can be installed from documentation on a clean
    machine.

## 8. First Codex Prompt to Use

Copy this into Codex to start the project:

You are building SPECTRE, a local-first OSINT investigation and
attack-surface intelligence platform for legitimate cybersecurity
research. Follow the project plan strictly one phase at a time.

START WITH PHASE 00 ONLY.

Requirements: - Python 3.12+ and FastAPI. - MySQL-ready configuration,
but do not create the application schema yet. - HTML/CSS/vanilla
JavaScript frontend served locally. - Create the repository structure
defined in the plan. - Add /health, a minimal landing page, typed
environment configuration, structured logging with secret redaction,
pytest smoke test, .env.example, README.md, SECURITY.md and
RESEARCH_SCOPE.md. - Passive OSINT only; do not implement collectors
yet. - No secrets in source. - Keep modules small and typed.

At completion: \## 1. Run tests and import/compile checks. \## 2. List
every file created or changed. \## 3. List commands run. \## 4. Explain
how to start the app. \## 5. State limitations. \## 6. STOP. Do not
begin Phase 01.

## Appendix A - Collector Contract

Every collector should expose the same conceptual contract:

``` python
class Collector:
    name: str
    version: str
    supported_types: set[str]

    async def collect(self, target, context) -> CollectorResult:
        # validate target type and scope
        # use only the controlled HTTP/DNS client
        # return raw evidence + normalized observations
        # never write directly to unrelated tables
        ...
```

CollectorResult should contain status, started/ended timestamps, source
references, raw response metadata, normalized observations,
warnings/errors, and enough information to reproduce parser behavior.

## Appendix B - Research Ethics & Safety Checklist

-   Use only public information or data you are authorized to access.
-   Respect source terms, robots/rate limits where applicable, and
    applicable law.
-   Minimize personal data; the primary v1 focus is cyber infrastructure
    and organizational attack surface.
-   Do not ingest password dumps or stolen credentials.
-   Do not circumvent authentication or access controls.
-   Keep active assessment disabled unless explicit authorization
    exists.
-   Make source attribution and collection time visible to the
    investigator.
-   Provide deletion/retention controls for research cases.
