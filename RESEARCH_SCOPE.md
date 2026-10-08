# Research scope and safety contract

## Purpose

SPECTRE supports reproducible cybersecurity research focused on public cyber infrastructure and organizational attack surfaces. Collect only public information or data the investigator is authorized to access. Respect source terms, applicable law, and provider controls.

## Collection boundaries

Phase 00 performs zero target collection. Later passive modules may query documented DNS, RDAP, certificate-transparency, and enrichment sources. A public-URL metadata request must be explicitly scoped, limited to one page, and constrained by redirect, content-type, size, and timeout policies. No recursive crawling, JavaScript execution, form submission, or authenticated scraping is permitted in v1.

## Authorization

Targets will have passive-allowed, active-authorized, or excluded scope. Excluded targets must not be collected. Public availability does not establish authorization for active testing. Active features must remain optional and disabled by default, and require explicit recorded authorization and action confirmation.

## Rate limits

Before enabling collectors, define per-provider and per-host limits, bounded concurrency, retry ceilings, and maximum response sizes. Honor stricter provider quotas and retry guidance. Fail closed when a collector lacks a declared policy; do not retry indefinitely or evade limits. No collection rate applies yet because no collectors exist.

## Evidence, retention, and deletion

Preserve source attribution, capture time, collector version, and evidence hashes. Minimize personal data. AI output is analysis, never source evidence. Before persistent evidence collection is enabled, implement case deletion and configurable retention. Proposed local default: retain case evidence until the investigator deletes the case; review retained cases every 90 days. Exports and backups must be covered by the investigator's deletion policy. Phase 00 stores no investigation data and writes no application log files.

## Prohibited use

- Credential theft, stolen credential/password-dump ingestion, password attacks, doxxing, stalking, or private-data brokerage.
- Exploitation, unauthorized or unrestricted scanning, mass scanning, stealth, or evasion.
- Authentication/access-control bypass, CAPTCHA bypass, automated account login, or scraping behind authentication.
- Using the AI assistant to run shell commands, fetch arbitrary targets, access another case, or launch collectors.

## Development gate

Implement one phase at a time. Validate with mocked or fixture-based tests, preserve existing behavior, document limitations, and stop for review after each phase.
