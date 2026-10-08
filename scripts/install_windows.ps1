$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
python -c "import sys; sys.exit(0 if sys.version_info >= (3,12) else 'Python 3.12+ is required')"
if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.12+ first; see docs/INSTALL_WINDOWS.md' }
if (-not (Test-Path -LiteralPath '.venv')) { python -m venv .venv }
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) { throw 'Existing .venv is not a Windows environment; preserve/rename it and retry.' }
& .\.venv\Scripts\python.exe -m pip install -r requirements-runtime.lock
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
if (-not (Test-Path -LiteralPath '.env')) { Copy-Item -LiteralPath '.env.example' -Destination '.env' }
New-Item -ItemType Directory -Force -Path 'output/pdf','logs' | Out-Null
Write-Output 'Application dependencies ready. Existing .env/database untouched. Configure MySQL and .env, then migrate and provision an account; see docs/INSTALL_WINDOWS.md.'
