# Phase 00 handoff

## Result

Foundation implemented; Phase 01 has not started. The original build guide is unchanged. Git initialized without creating a commit. Local `.venv` created and dependencies installed. No `.env`, credentials, application database, or investigation data created.

## Files created

- `.env.example`, `.gitignore`, `requirements.txt`, `pytest.ini`
- `README.md`, `SECURITY.md`, `RESEARCH_SCOPE.md`
- `app/__init__.py`, `app/config.py`, `app/logging_config.py`, `app/main.py`
- `app/static/index.html`, `app/static/css/main.css`, `app/static/js/main.js`
- `tests/unit/test_foundation.py`
- `docs/PHASE_00_HANDOFF.md`
- Placeholder `.gitkeep` files in `app/ai`, `app/api`, `app/collectors`, `app/db/migrations`, `app/security`, `app/services`, `app/static/images`, `app/templates`, `tests/fixtures`, `tests/integration`, `scripts`, and `docs`.

Generated environment artifacts: `.git`, `.venv`, Python bytecode caches, and pytest cache. Caches and the virtual environment are ignored by Git. No existing source files were modified.

## Commands executed

Read-only inspection:

```powershell
Get-ChildItem -Force
rg --files -g AGENTS.md -g requirements.txt -g pyproject.toml -g README.md
python --version
git status --short
Get-ChildItem -LiteralPath .. -Filter AGENTS.md -Force
python -m pip --version
```

The initial Git status reported that no repository existed. No applicable AGENTS.md was found. Python is 3.14.7.

Setup:

```powershell
$directories = @('app/db/migrations','app/api','app/services','app/collectors','app/security','app/ai','app/static/images','app/templates','tests/integration','tests/fixtures','scripts','docs')
foreach ($directory in $directories) { New-Item -ItemType Directory -Force -Path $directory | Out-Null; New-Item -ItemType File -Force -Path (Join-Path $directory '.gitkeep') | Out-Null }
git init
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Dependency installation first failed because sandbox networking was blocked, then succeeded with approved network access. Files were written with the patch tool.

Verification:

```powershell
.\.venv\Scripts\python.exe -m compileall -q app tests
git status --short --untracked-files=all
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -c "from app.main import app; print(app.title)"
.\.venv\Scripts\python.exe -m pip check
```

Results: 3 tests passed; compilation passed; import printed SPECTRE; no broken requirements. TestClient exercises lifespan, the health endpoint, landing page, and static assets without a live external network. Configuration validation and exception/message credential redaction also passed.

## Start

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. Configuration defaults allow startup without creating `.env`; README describes optional local configuration. No server process is left running.

## Limitations

- Authentication, database schema/connections, collectors, graph, AI, and reports are not implemented.
- Network safety controls are documented requirements for later phases; there are no collection requests in this phase.
- Tested on installed Python 3.14.7; Python 3.12 and a separate fresh-clone installation were not independently exercised.
- Dependencies use bounded version ranges rather than a lockfile.
- Installed Starlette emits a TestClient deprecation warning for httpx; all tests pass. Review test-client compatibility when pinning dependencies.
- Redaction covers configured credentials and common formats, not every possible secret. Avoid logging sensitive data.

STOP: review Phase 00 before starting Phase 01.
