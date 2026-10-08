<p align="center"><img src="app/static/images/branding/spectre-display.png" width="128" alt="SPECTRE logo"></p>

# SPECTRE v1.0.0 release candidate

Local-first, evidence-first OSINT and authorized infrastructure investigation. SPECTRE stores attributable evidence, correlates it deterministically, and provides an investigation console, findings, timelines and HTML/PDF reports. It is not an exploitation framework.

**Release status:** candidate only. Windows development regression passed; clean Windows and separate-machine Kali/Linux installation acceptance remain pending. No release tag has been created. See [release checklist](docs/RELEASE_CHECKLIST.md).

## Capabilities and safety

- Case management, normalized targets, owner/member/viewer RBAC and CSRF protection.
- Controlled DNS, RDAP, certificate-transparency, IP/ASN/reverse-DNS and HTTPS metadata adapters; availability depends on public providers.
- Raw/normalized evidence, timestamps, versions, SHA-256 integrity and evidence-linked deterministic entities/relationships/findings.
- Cytoscape graph, deterministic timeline, evidence inspection, explainable severity/confidence and analyst workflow.
- Stored-data-only HTML/PDF exports with provenance and integrity checks.
- Optional read-only local AI, disabled by default. No model is downloaded or required.
- Separately authorized active HTTP/HTTPS GET/HEAD/OPTIONS, TLS inspection and selected TCP ports 80/443. No exploitation, credential attacks or unrestricted scanning.

Passive collection still contacts third-party public services. Active enablement alone **does not authorize any target**: execution also requires authenticated case access, investigator permissions, active_authorized scope, a current exact-target/port grant, fresh confirmation and an unstopped case. Discovered hosts/IPs never inherit permission. Graph/search/filter/inspection do not collect.

## Install

Requires CPython 3.12+, MySQL 8, and an application virtual environment. WAMP is optional, not a dependency. Node is optional for frontend tests only; there is no frontend build pipeline.

- [Windows 10/11](docs/INSTALL_WINDOWS.md)
- [Ubuntu/Debian/Kali](docs/INSTALL_LINUX.md) ? prepared, not yet accepted on a separate Linux machine
- [Configuration reference](docs/CONFIGURATION.md)

From the repository root:

```powershell
# Windows PowerShell (review script first)
powershell -NoProfile -File scripts/install_windows.ps1
```

```bash
# Linux: review script first; no sudo/system configuration changes
bash scripts/install_linux.sh
source .venv/bin/activate
```

Installers preserve an existing .env/database and only prepare application dependencies/directories. Complete the documented MySQL database/user setup, replace configuration placeholders, apply migrations with the prompted migration account, and create a first account:

```text
python -m scripts.migrate --user spectre_migrate
python -m scripts.create_user administrator --role admin
python -m app.doctor
python -m app.run
```

On Windows, after setup you may double-click **SPECTRE.exe** in the installation directory. It waits for the local application before opening your browser and reuses an existing instance. This is a convenience launcher, not an installer or bundled Python runtime. See [launcher source/build instructions](launcher/README.md). Linux/Kali continue using `python -m app.run`.

Use `.\.venv\Scripts\python.exe` on Windows if the environment is not activated. Passwords are prompted; no default account/password is seeded. MySQL caching_sha2_password installations may additionally require the documented PyMySQL RSA extra; it is not part of the validated baseline lock.

## Run

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```bash
source .venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. `/health` is liveness only; `/version` reports application version/status. `python -m app.doctor` checks configuration, the configured database and schema, and directory readiness without collection or inference. `python -m app.run` honors configured bind settings and uses one worker.

127.0.0.1 is local-only. 0.0.0.0 exposes the listener to other machines; it is not a browser destination. Do not expose the development server directly to the Internet. Any non-loopback deployment needs separately reviewed TLS, firewall/proxy trust and access controls. Secure-cookie mode requires HTTPS; enabling it over local HTTP prevents session-cookie delivery.

## Investigation workflow

Create a case and scoped targets; explicitly collect through Collectors; correlate stored evidence; inspect graph/timeline; generate deterministic findings; review evidence and export reports. AI output remains separate from evidence/findings and cannot invoke collectors.

Finding verification uses **Prepare authorized verification ? Active / Validation ? Refresh stored history ? fresh confirmation ? explicit execution**. Preparation sends no request. Invalid identity/context changes cancel preparation visibly; no generic-validation fallback occurs. After cancellation, prepare again or deliberately choose **Start a new standalone request**.

## Architecture and data

FastAPI + SQLAlchemy/Alembic + MySQL, with HTML/CSS/vanilla JavaScript and locally served Cytoscape.js. Provider adapters remain replaceable behind controlled clients. No AI access to shell, files, arbitrary HTTP, collectors or mutation APIs. See [architecture](docs/ARCHITECTURE.md), [data model](docs/DATA_MODEL.md), [collector guide](docs/COLLECTOR_GUIDE.md), [security](SECURITY.md) and [responsible use](RESEARCH_SCOPE.md).

Evidence raw JSON is stored in MySQL. Report downloads render in memory; saved exports, synthetic demo files and operator logs are separate sensitive artifacts. Back up both database and relevant filesystem/configuration artifacts: [backup/restore](docs/BACKUP_RESTORE.md).

## Tests and offline demo

```text
python -m pip install -r requirements-dev.lock
python -m pytest -q
python -m pip check
python -m scripts.release_audit
node tests/js/run.cjs
python -m scripts.demo --output output/synthetic-demo
```

Node must be installed separately to run frontend tests; no automatic Node installation. Set SPECTRE_TEST_PYTHON to an existing virtual-environment interpreter when needed. The synthetic demo creates a NEW isolated SQLite directory and mock-only HTML/PDF reports; it never writes MySQL or contacts a target. SQLite is a fixture/demo dependency, not the supported production database.

Phase 12 baseline: 402 Python tests and 10 frontend suites. Current release results/limitations: [Phase 13 handoff](docs/PHASE_13_HANDOFF.md). [Dependency audit](docs/DEPENDENCY_AUDIT.md) distinguishes installed-package consistency from an advisory-database security audit.

## Screenshots

Screenshots pending a scrubbed release capture. Do not publish private case names, targets, evidence, credentials or local paths. Historical manual-acceptance artifacts are not included in the source candidate.

## Limitations and troubleshooting

Single-process local architecture: locks, login/network rates and inference/export admission are process-local. Active background runs are **not durable across application restarts**; no automatic replay/contact occurs. Provider failures are not negative findings. No distributed queue, multi-worker deployment support, account-recovery workflow or hosted service is supplied. See [troubleshooting](docs/TROUBLESHOOTING.md).

## Project structure

`app/api` routes; `app/db` models/migrations; `app/collectors` adapters; `app/active` authorized transports/lifecycle; `app/services` evidence/correlation/findings/reporting; `app/ai` constrained local assistant; `app/static` UI/vendor assets; `tests` fixtures/regression; `scripts` installation/release utilities; `docs` installation and handoffs.

## Release and contribution

See [contributing](CONTRIBUTING.md), [install index](INSTALL.md) and [release checklist](docs/RELEASE_CHECKLIST.md). Release archives use an explicit allowlist and per-file SHA-256 manifest. They exclude .env, .local, investigations, logs, output, caches, development history and acceptance artifacts. Review the archive before distribution; no publish/tag action is automatic.

No project license has been selected; do not infer permission to redistribute SPECTRE as open source. Third-party Cytoscape licensing is retained in `app/static/vendor/CYTOSCAPE_LICENSE`. A project license decision is required before public release. Use only for targets and activities you are authorized to investigate.
