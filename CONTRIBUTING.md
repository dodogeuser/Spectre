# Contributing

Read RESEARCH_SCOPE.md, SECURITY.md and docs/ARCHITECTURE.md. Preserve scope/RBAC/CSRF, case isolation, evidence immutability, deterministic rules, source/version/hash attribution and optional read-only AI. Do not expand active capabilities or introduce unrestricted collection as a refactor.

Use CPython 3.12+ in a fresh .venv. Install requirements-dev.lock; run pytest -q, pip check, scripts.release_audit and node tests/js/run.cjs using an optional Node runtime. Tests use fixtures/injected transports, not public targets. SPECTRE_TEST_PYTHON can override the frontend bridge interpreter; it defaults to the platform's local .venv path. Keep scripts/install_linux.sh LF; no shell=True, developer paths or real secrets.

Do not commit .env, .local, output, logs, caches, SQL dumps or real acceptance artifacts. Migration changes require additive preservation tests and explicit review; never mutate live investigations to make a test pass. Do not silently change collector/rule versions when updating the application version.

Use the release allowlist/manifest, review all packaging contents and retain vendor licenses. Security concerns should be reported privately to the maintainer; no dedicated disclosure address has yet been established. A project license has not yet been selected, so public redistribution/contribution licensing needs owner review before release.
