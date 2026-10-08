# Troubleshooting

- Run python -m app.doctor from the project root. PASS/WARNING/FAIL output withholds secrets. It checks only the configured DB/schema and local paths; it does not invoke collectors or AI. /health alone is not a database-readiness check.
- Access denied: check MySQL service, account host restriction, correct schema, private .env password and runtime/migration grants. Never solve this by making the app a root account or granting global privileges. MySQL caching_sha2_password may require the documented RSA extra.
- Python too old / missing venv: use CPython 3.12+ and a matching distribution venv package. Do not reuse Windows .venv on Linux. Preserve an existing environment before replacing it.
- Import/dependency errors: use the same virtual-environment interpreter for pip and execution; run pip check. Locks reflect the validated Windows baseline, not completed Linux acceptance. Do not blindly upgrade all dependencies.
- Missing schema/head: back up, review pending Alembic changes, use the prompted migration account. Never downgrade a populated live database as a troubleshooting step.
- Invalid configuration: compare key names/types with .env.example; environment variables override the file. Restart after config changes. Secure cookies require HTTPS; local HTTP with that flag cannot retain login.
- Login 429: wait a minute. Throttling is process-local and by source address; proxies/shared addresses may share a bucket. Do not add workers to bypass limits.
- Graph/findings empty: legitimate empty states do not imply target safety. Graph actions do not collect. Choose an authorized explicit collector action only if needed.
- Prepared verification cancelled: prepare the finding again. Same-target refresh preserves it; case/target/identity changes cancel it. Starting standalone is explicit. Do not manually attach old evidence to repair association.
- Provider unavailable/partial/rate-limited: retain provenance and failure state; never treat unavailable intelligence as a negative finding. No provider contact is needed for installation tests.
- App restart during active work: jobs are not durable and are not automatically replayed. Review stored run state/cancellation manually before authorizing another action.
- CSP/UI rendering: hard-refresh local assets. Phase 13 adds self-only scripts with inline styles permitted for graph geometry. Verify the actual browser on the release machine; do not weaken CSP to allow remote scripts as a workaround.
- Reports: exports render in memory, bounded by existing limits; raw hashes must verify. Protect downloaded artifacts. Rendering failure does not justify changing historical evidence.
