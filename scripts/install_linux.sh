#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v python3 >/dev/null || { echo 'Install Python 3.12+ and python3-venv first; see docs/INSTALL_LINUX.md'; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,12) else "Python 3.12+ is required")'
if [[ ! -d .venv ]]; then python3 -m venv .venv; fi
if [[ ! -x .venv/bin/python ]]; then echo 'Existing .venv is not a Linux environment; preserve/rename it and retry.'; exit 1; fi
.venv/bin/python -m pip install -r requirements-runtime.lock
if [[ ! -e .env ]]; then (umask 077; cp .env.example .env); fi
mkdir -p output/pdf logs
echo 'Application dependencies ready. Existing .env/database untouched. Configure MySQL and .env, then migrate and provision an account; see docs/INSTALL_LINUX.md.'
