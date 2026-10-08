# Phase 13 — v1.0.0 release candidate handoff

Phase 13 implementation is complete; owner release approval and clean-machine acceptance remain pending. This is a release candidate, not a fully released v1.0.0. No tag, commit, push or deployment is performed.

## A–C. Architecture, security audit and fixes

Existing FastAPI/MySQL/evidence/correlation/findings/graph/timeline/report/AI/active boundaries remain. No Phase 13 migration, new OSINT collector, exploitation capability, investigation redesign or durable job queue was introduced. Existing case data/configuration were not changed or recollected.

| Severity | Finding / action |
| --- | --- |
| CRITICAL/HIGH | No confirmed application defect at these levels identified by the scoped local review; no claim of exhaustive penetration/CVE clearance. |
| MEDIUM | Missing login throttling: bounded process-local ten attempts/address/minute added before password verification. |
| MEDIUM | Missing console security headers: nosniff, frame denial, no-referrer, restrictive permissions and local-script CSP added; report sandbox CSP preserved. |
| MEDIUM | Access-log query/cookie leakage risk: query strings and common cookie/CSRF credential forms redacted; portable launcher disables access logs. |
| LOW | Configuration error disclosure / production safety: startup/doctor hide values; explicit production mode rejects blank/placeholder password, root DB account, insecure cookies and DEBUG. |
| LOW | Legacy passwordless-root provisioning retired; explicit documented least-privilege setup and prompted migration account replace it. |
| INFORMATIONAL | Baseline pins, portable test interpreter/installer, stale documentation, application version and packaging hygiene corrected. |

Password hashing remains Argon2; hashed opaque sessions, rotation/logout/expiry, HttpOnly/SameSite and HTTPS Secure cookies remain. Secure-cookie opt-in supports reviewed HTTPS deployments. RBAC/object authorization/case isolation, parameterized SQL, CSRF, inert DOM rendering, report escaping, exact-target grants, scope/kill-switch checks, SSRF/address pinning and bounded evidence/report/graph handling are preserved. No upload/import execution route exists. File utilities use pathlib, argument arrays and no shell=True; restore explicitly requires an accessible empty destination. Python adapters remain trusted code, not a sandbox.

## D–I. Portability, installation, bootstrap, configuration, doctor

Windows 10/11, Ubuntu/Debian and Kali are target platforms. Existing Windows CPython 3.14 development validation is not a clean Windows installation. Separate-machine Linux/Kali acceptance has NOT occurred and remains required. Installers preserve .env/database, create/reuse platform-specific venvs, install pinned application packages and prepare artifact directories without system-service/repository changes. Linux script uses LF and bash; WAMP is optional and never required.

MySQL 8 setup separates runtime DML from migration DDL privileges. `scripts.migrate` privately prompts for migration credentials without persisting them. `scripts.create_user` retains private password prompts and no defaults. Doctor performs only read-only configured DB revision/table checks, local config/version/directory checks and reports optional AI/active status without contacting providers. Production/runtime still uses MySQL; SQLite is disposable fixture/demo storage only. MySQL RSA authentication prerequisites are explicit and separately pending validation.

Application version is centralized at app/version.py and exposed by /version/OpenAPI. Portable app.run uses configured host/port, one worker and no access logs by default. There is no unused application secret: session tokens are opaque and hashed. Current .env is not overwritten. Runtime evidence stays in MySQL; browser exports are in-memory downloads; existing local artifacts are not relocated.

## J–L. Documentation, dependency audit and tests

New/updated README, INSTALL index, Windows/Linux installation, configuration, architecture, data model, collector guide, contributing, backup/recovery, troubleshooting, dependency audit and release checklist. SECURITY.md supplements existing boundaries. Historical phase handoffs are excluded from the public source-candidate payload to avoid distributing investigation acceptance metadata.

Baseline: 402 Python tests passed; 10 frontend suites previously passed. pip check passed. Exact installed runtime/dev locks created without upgrades. pip-audit/Bandit/Ruff unavailable locally; advisory-backed vulnerability audit not performed. RSA cryptography extra and Linux/Python-version resolution require clean-machine validation. See DEPENDENCY_AUDIT.md; local checks do not establish absence of CVEs or secrets.

Final automated results:

- Complete existing Windows regression: **422 Python tests passed**, 129.91 seconds; one existing Starlette/httpx deprecation warning. Baseline was 402; 20 release/security tests added.
- Extracted source-candidate Python regression: **422 passed**, 128.87 seconds, using the existing interpreter/dependencies, without private configuration. This is source portability validation, not a clean installation.
- **10 frontend suites passed**, including shipped-script preparation/submission bridges and real vendored Cytoscape. A private `.local` snapshot dependency discovered during extracted-package QA was replaced with a synthetic 21-entity/24-relationship fixture; no investigation data copied into the package.
- Read-only existing MySQL doctor passed migration-head, required tables/columns/foreign keys and InnoDB checks. Current active-enabled configuration reported as a warning; AI remains disabled. No migration or live database mutation performed.
- pip check, Python compile checks and PowerShell installer parsing passed. Linux shell line endings verified; bash/clean Linux execution unavailable.
- Local allowlist/heuristic audit found no high-priority matches; informational vendored/scanner TODO markers retained. This is not an advisory-backed dependency or exhaustive secret audit.
- Disposable mock-only demo, report creation, migration-from-empty SQLite, backup refusal and package manifest/exclusion tests passed. No live provider or active target requests occurred.

Candidate artifact: `dist/spectre-v1.0.0-rc.zip`, with per-file SHA-256 `RELEASE_MANIFEST.json`. Archive publication/tagging is not authorized by this handoff.

## M–N. Known limitations and deferred issues

- Active background runs are **not durable across application restarts**. No automatic replay/resume is added. Cancellation is cooperative and cannot recall a request already sent.
- Single-process locks/rates/limits and the login address bucket are not distributed. Shared proxy addresses may share the throttle; no multi-worker deployment is supported.
- Clean Windows and separate Kali/Linux/MySQL installation, advisory-backed dependency audit, optional RSA dependency validation, release-browser CSP smoke test and recovery drill remain pending.
- Exact baseline locks lack wheel hashes; this is a source candidate, not a reproducible binary build or dependency security guarantee.
- No project license chosen or dedicated disclosure address established; owner decisions needed before public release. No screenshots containing private investigations are published.
- Existing provider availability/rate limits, safe failure distinctions, extractive optional AI limitations and report/graph bounds remain. No Ollama/model install occurred.

## O. Files changed

app/version.py, config.py, main.py, run.py, doctor.py, logging_config.py, security/login_limit.py, api/auth.py; application User-Agent identity in active/client.py and services/http_client.py. Install/backup/migration/demo/audit/package scripts; retired legacy setup_local_database entry point. Requirements/runtime/dev locks and RSA prerequisite file, .gitignore/.gitattributes. Portable frontend bridge/runner and synthetic populated-graph fixture; release unit/integration tests. README, SECURITY, INSTALL, CONTRIBUTING and release documentation listed above. No models or migration revision changed.

## P–R. Release checklist, manual requirements and exact Kali steps

Use RELEASE_CHECKLIST.md; unchecked items remain honest release gates. No manual live OSINT/active verification was performed or required during Phase 13. Phase 12's approved real-world records were preserved.

1. On a separate Kali machine, record distro, CPython (3.12+) and MySQL 8 versions; do not silently substitute unverified MariaDB.
2. Verify/extract the source candidate and its SHA-256 manifest into a writable user directory; do not copy the Windows .venv/.env/private data.
3. Read INSTALL_LINUX.md. Run `bash scripts/install_linux.sh`, then `source .venv/bin/activate`. Record package/wheel failures rather than weakening versions/security.
4. Create a NEW MySQL database and separate local runtime/migration accounts using documented least-privilege grants. Configure private .env; `chmod 600 .env`. Resolve the documented RSA extra if required.
5. Run `python -m scripts.migrate --user spectre_migrate`, `python -m scripts.create_user administrator --role admin`, then `python -m app.doctor`.
6. Install requirements-dev.lock; run `python -m pytest -q`, `python -m pip check`, `python -m scripts.release_audit` and, with optional Node, `node tests/js/run.cjs`.
7. Run the isolated mock demo into a new output directory. Start SPECTRE on 127.0.0.1:8000; inspect version, headers, login, empty case/graph/timeline/findings, and synthetic reports. Do not collect or authorize targets for installation QA.
8. Review backup/restore on a separate empty recovery schema, restart limitations, private-file permissions and release checklist. Only then record actual Linux acceptance and decide the final release/tag.

Stop after Phase 13 implementation. Public release remains contingent on the separate-machine acceptance and owner review.


## Release-candidate branding integration (2026-10-07)

This is a presentation-only RC follow-up, not another development phase or final release. The approved `app/static/images/branding/spectre-logo.png` is unchanged (SHA-256 `c2f244ff5fece786f2ca54d3755b92cc76ac066288efd1ed0b94cfe39e3bd6a0`). Derived PNGs retain proportions; favicon squares add transparent padding rather than stretching/cropping.

Files changed: `app/static/index.html`, `app/static/css/main.css`, `README.md`, `app/services/reporting.py`, `app/api/reports.py`, `tests/integration/test_reports.py`, new `tests/unit/test_branding.py`, branding assets/asset README, this handoff and RELEASE_CHECKLIST.md. Release packager logic is unchanged; its existing app-tree allowlist includes the original and derived branding assets.

Assets: `spectre-ui.png` (96 x 91, 13,275 bytes), `spectre-display.png` (256 x 243, 71,643 bytes), `spectre-report.png` (128 x 121, 21,795 bytes); favicon PNGs at 16/32/180 pixels and ICO containing 16/32/48/64px sizes. The 1,439,412-byte original is not loaded by the application UI. All paths are repository/application-relative; no external images or new runtime dependencies.

Locations: authentication mark beside existing SPECTRE text; compact 30px navigation-header mark; browser icons; repository-relative README header; self-contained HTML report header and PDF first-page mark. UI/report logo images are decorative beside explicit SPECTRE text; README uses descriptive alt text. No JS/workflow/security model or investigation schema change.

HTML embeds only the bundled optimized image as a PNG data URI. Export CSP adds `img-src data:` while retaining sandbox/default-deny, no external images/scripts, and existing restrictions. PDF embeds its bundled optimized PNG using existing ReportLab. Snapshot data/hash, component versions, evidence rendering and links remain unchanged; generated report bytes change due to branding, but repeated exports of the same snapshot remain deterministic. Existing byte-replay and evidence-integrity regressions verify this distinction.

Verification: focused report/branding tests **15 passed**; all **10 frontend suites passed**. Full Python result and rebuilt archive integrity are recorded in the final completion entry below. Synthetic offline HTML/PDF generation succeeded; PDF first-page rendering was visually inspected with no logo distortion or content overlap. No live providers/active requests, existing investigation mutation, authorization changes or migration occurred.

Limitations/manual checks: fine source detail necessarily diminishes at favicon sizes. Actual browser appearance/cache refresh and GitHub README rendering remain owner checks: hard-refresh login; sign in and inspect compact header at desktop/laptop widths; check browser tab icon; inspect exported HTML offline and PDF logo/evidence links; view README on GitHub. Browser UI acceptance and clean Windows/Kali installation are NOT claimed. Existing release gates remain pending.

Final branding completion: **423 Python tests passed** in 130.30 seconds (one existing Starlette/httpx deprecation warning); **10 frontend suites passed**. All seven derived static image/icon routes returned exact asset bytes in an isolated application check. Both pages of the mock-only PDF were rendered and inspected; HTML embedded-image generation and repeated HTML/PDF byte equality were tested. Rebuilt `dist/spectre-v1.0.0-rc.zip` contains **177 payload files plus RELEASE_MANIFEST.json**; all manifest hashes and required branding entries verified. Original logo SHA-256 rechecked unchanged. This remains SPECTRE v1.0.0 Release Candidate; no clean-install or final-release acceptance added.


## Windows convenience launcher RC follow-up (2026-10-07)

`SPECTRE.exe` is now available in the installation root (25,088 bytes). It is a small AnyCPU .NET Framework Windows GUI launcher with an `asInvoker` manifest and the unchanged approved `app/static/images/branding/favicon.ico` embedded. It is not an installer, bundled application/Python runtime, Windows service or new development phase.

Source/build: `launcher/SpectreLauncher.cs`, `launcher/runtime_probe.py`, `launcher/build_windows.py`, optional equivalent `launcher/build_windows.ps1`, and `launcher/README.md`. Build using `python launcher/build_windows.py` with Windows' installed .NET Framework 4.x compiler. No downloads, bundler, additional application packages or Windows security-policy changes are required. The legacy compiler may vary PE timestamps, so repeatable build instructions do not promise byte-identical executables. Owner code signing remains pending; unsigned-executable SmartScreen prompts are possible.

The EXE derives the installation root from its own location, validates required application/configuration files and `.venv/Scripts/python.exe`, then privately probes existing Settings/dependencies. It does not contain or copy `.env` or database secrets. Only loopback `127.0.0.1`, `localhost` (normalized to IPv4), or `::1` is admitted; port defaults to configured 8000. Host/port values are validated again in the EXE and passed to the supported `python -m app.run` startup. Probes use fixed local `/version` and `/health` URLs with proxy/redirects disabled, bounded reads and timeouts. A per-session/port mutex coordinates launcher invocations. Matching ready 1.0.0 RC instances are reused; occupied unrecognized/unready ports fail closed. The default browser opens only after readiness.

No arbitrary shell input, elevation, firewall changes, automatic migration, DB writes, collectors, active verification or model/provider operations are introduced. The browser is opened using the operating system's default URL handler with a validated local URL. Application failures do not change investigation records. Startup dialogs provide installation/configuration/port/doctor guidance without echoing secrets. Linux/Kali `python -m app.run` remains independent.

Files changed: new launcher files above, `tests/integration/test_windows_launcher.py`, `tests/windows/LauncherHarness.cs`; `scripts/release_package.py`, `.gitignore`, README, INSTALL_WINDOWS, this handoff and RELEASE_CHECKLIST. Generated root EXE is ignored by Git; source/build instructions are retained. The packager includes launcher source and an existing EXE, allowing source-only Linux packaging when no EXE has been built. Combined Windows RC delivery contains the EXE.

Validation:
- Seven new Windows tests passed: relocated path with spaces/Unicode, real supported startup, browser callback after readiness, exactly one spawned server across repeated launch, missing application/runtime, invalid/private configuration error redaction, nonloopback refusal, occupied-port refusal, icon resource/package checks.
- Actual relocated GUI EXE smoke test started an isolated copied application on a separate loopback port and successfully returned from the default-browser handoff. The sandbox initially blocked the default-browser operation; the isolated test passed outside the automation sandbox. The copied fixture used synthetic configuration and automatic shutdown; no existing MySQL/target records were accessed. This is not clean-install acceptance or proof of visual browser rendering.
- Windows extracted icon was rendered and visually confirmed as the approved SPECTRE mark; `asInvoker` manifest confirmed. Explorer cache/multiple-size visual acceptance remains manual.
- Complete suite: **430 Python tests passed**, 136.74 seconds, one existing Starlette/httpx deprecation warning. **All 10 frontend suites passed**. Relevant package/executable checks were also rerun after optional-binary packaging adjustment (two passed).

Limitations: launcher health is application liveness, not MySQL readiness or cryptographic server/process identity. It reuses another matching local SPECTRE installation on the same port. The application continues after the launcher/browser exits; no new shutdown/tray/service is added. Startup timeout deliberately leaves a possibly working server running; retry/check existing processes before manual startup. Background active runs remain nondurable across restarts. Moving a whole install requires its base Python/dependencies still to be available; recreate the venv if necessary. No automatic Windows/MySQL installation or service startup is performed.

Manual checks still required: owner double-click/normal-user acceptance on the intended Windows installation, default-browser page rendering, Explorer icon at intended sizes/cache refresh, visible failure dialogs, concurrent-click experience, signing/SmartScreen review and actual clean Windows installation. Clean Kali/Linux and prior owner release gates remain unchecked. This remains SPECTRE v1.0.0 Release Candidate, not final v1.0.0.

Launcher RC archive completion: **185 payload files plus RELEASE_MANIFEST.json**; all per-file SHA-256 hashes, EXE/source/icon inclusion and private-file exclusions verified during rebuild.


### Launcher interruption recovery verification (2026-10-07)

Recovery inspection found the previous launcher task already completed: all five launcher source/build/documentation files, root `SPECTRE.exe` (25,088 bytes), approved embedded ICO, seven Windows regression cases/C# harness, README/Windows-install guidance, Git exclusions, packager inclusion, handoff/checklist entries and combined RC archive were present. The existing archive's 185 payload files matched the current release tree byte-for-byte (with intentional shell LF normalization), and every manifest hash verified. No empty/partial launcher files, missing deliverables or implementation repairs were found.

Completed during recovery: official Python build script successfully rebuilt in a separate relocated build directory; existing root EXE preserved unchanged (SHA-256 `a03639a6317e606d96d5a436ac049a2e0de856a09a39daab0aff31dd0aba4a8a`). Approved ICO 16/32/48/64px payloads were verified byte-for-byte inside the existing executable and its extracted icon visually checked. Source/executable checks found no developer-specific absolute paths. No application/launcher implementation or test source was changed.

Fresh full regression: **430 Python tests passed** in 148.33 seconds, with one existing Starlette/httpx deprecation warning; **all 10 frontend suites passed**. Windows integration reran supported startup in an isolated moved path with spaces/Unicode, readiness before browser callback, one spawned server across repeated launches, configuration/runtime failures, unsafe bind rejection and occupied-port refusal. These recovery tests used a browser callback; the prior actual GUI/default-browser smoke-test result is retained above and is not claimed as freshly repeated manual acceptance.

Only this handoff/checklist and the rebuilt RC archive changed during recovery. The archive was rebuilt to include this recovery record, retaining 185 payload files plus manifest; all hashes, EXE/source/icon inclusion and private-file exclusions verified again. No live collection, active verification, real investigation/authorization mutation or migration performed. Remaining owner normal-user/Explorer/browser/dialog/concurrent-click checks, code-signing review and clean Windows/Kali installation remain pending. SPECTRE is still v1.0.0 Release Candidate, not a final release.
