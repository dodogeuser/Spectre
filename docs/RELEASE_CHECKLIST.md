# v1.0.0 release candidate checklist

This is not a release approval/tag. Mark platform acceptance only after an actual clean-machine run. Phase 12 manual acceptance remains recorded in its handoff; it does not certify a clean installation.

- [ ] Clean Windows installation tested (existing development environment only so far).
- [ ] Clean Kali/Linux installation tested (separate machine REQUIRED; portability preparation is not acceptance).
- [x] Migrations from empty disposable SQLite DB tested; MySQL empty clean-machine migration remains pending.
- [ ] Migrations from existing MySQL DB tested specifically for release installation (Phase 12 previously verified upgrade to 007; Phase 13 adds no migration and does not touch live DB).
- [x] Final complete regression: 422 Python tests pass in workspace and extracted source candidate using existing dependencies.
- [x] Final frontend regression: 10 suites pass including fixture API bridge; private graph snapshot dependency replaced by synthetic data.
- [ ] Public Git history/payload reviewed for secrets; no project files were tracked at audit start, and no commit/push was made.
- [x] .env, .local, output, logs, temporary artifacts and caches excluded by Git/release policy.
- [x] .env.example contains placeholders, not real credentials.
- [x] README and security documentation reviewed/updated for candidate status.
- [x] Backup/restore guidance reviewed; restore refuses nonempty schema and needs explicit confirmation.
- [x] Active assessment disabled by default; current user's .env not changed.
- [x] No default production password or account seed.
- [x] Final report/evidence integrity regression passed within the complete 422-test suite.
- [x] Release version centralized: 1.0.0, release-candidate; collector/rule versions unchanged.
- [x] Known limitations documented, including nondurable active background runs.
- [ ] Advisory-backed dependency security audit completed; local pip consistency/heuristic audit is insufficient to claim CVE clearance.
- [ ] Optional MySQL RSA/cryptography extra validated where required by clean installation.
- [ ] Scrubbed screenshots and actual release browser/CSP smoke test reviewed.
- [ ] Project license selected by owner before public distribution; vendor license retained.
- [ ] Allowlisted candidate archive and integrity manifest reviewed.
- [ ] Final owner release decision after clean Kali/Linux acceptance; no v1.0.0 Git tag/publication yet.


### RC branding follow-up

- [x] Approved high-resolution source hash preserved; proportional optimized assets and padded favicon variants created locally.
- [x] Authentication/header, local favicon, repository-relative README and self-contained HTML/PDF branding integrated.
- [x] Report determinism/evidence-link tests pass; synthetic PDF visually rendered and reviewed.
- [x] All 10 frontend suites pass after branding.
- [ ] Owner browser check: hard refresh, login/header/favicon at desktop/laptop widths, offline HTML/PDF branding and evidence navigation; GitHub README appearance.
- [ ] Final release approval remains separate; clean Windows/Kali gates above remain unchecked.
- [x] Branding completion regression: 423 Python tests passed (422 baseline + one asset/package test); 10 frontend suites passed.
- [x] Rebuilt RC archive includes original/optimized logos and all favicon variants; complete per-file integrity manifest verified.


### Windows launcher RC follow-up

- [x] Dynamic-root Windows GUI EXE built from retained source with approved ICO and asInvoker manifest; no bundled configuration/secrets.
- [x] Local-only runtime/config checks, real readiness, existing-instance reuse and actionable startup failures tested in isolated moved installation.
- [x] Actual GUI EXE startup/default-browser handoff smoke test passed outside the automation sandbox; extracted icon visually checked.
- [x] Complete Python regression: 430 passed; all 10 frontend suites passed.
- [x] Combined RC package rebuilt with EXE/source/icon assets and integrity manifest verified; Linux source-only packaging remains supported.
- [ ] Owner normal-user double-click, Explorer icon, default-browser rendering, visible error-dialog and simultaneous-click acceptance on intended installation.
- [ ] Executable code signing/SmartScreen distribution review; no security controls disabled.
- [ ] Clean Windows/Kali installation and final-release approval remain pending, unchanged.


### Launcher recovery verification

- [x] Existing completed source, EXE, tests, documentation and RC payload inspected; no partial implementation found, valid work retained.
- [x] Official build script verified from separate relocated directory; original EXE unchanged and all four approved ICO payload sizes verified.
- [x] Fresh complete regression: 430 Python tests and 10 frontend suites passed, including readiness/reuse/failure/relocated-path tests.
- [x] Recovery record added and combined RC archive rebuilt; 185 payload hashes plus manifest verified.
- [ ] Previously pending owner manual checks, clean Windows/Kali acceptance, signing and final release approval remain pending.
