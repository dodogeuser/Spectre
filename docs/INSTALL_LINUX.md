# Ubuntu / Debian / Kali installation preparation

Status: prepared, **not clean-installed or accepted on a separate Linux machine**. Automated portability checks do not establish Linux runtime support. Use a distribution/interpreter with CPython 3.12+ and MySQL 8. Some Debian/Ubuntu releases ship older Python: check first and provision a supported interpreter through a reviewed distribution method. SPECTRE does not add repositories or upgrade the OS.

Typical prerequisites to review (not executed automatically):

```bash
python3 --version
# Only if appropriate to your distribution and Python version:
sudo apt update
sudo apt install python3 python3-venv python3-pip default-mysql-client
```

Install/configure MySQL 8 separately using its supported distribution instructions. Kali's default MariaDB is not silently substituted: MariaDB compatibility is unverified. No WAMP is required. Do not use sudo pip or run SPECTRE as root.

From the extracted project root:

```bash
bash scripts/install_linux.sh
source .venv/bin/activate
chmod 600 .env
```

The script has LF line endings and is invoked with bash; executable mode is not required. It preserves existing .env/database data. A Windows .venv cannot be reused on Linux; preserve/rename it and create a new environment. Configure the new MySQL database and two least-privilege users using the SQL in [Windows installation](INSTALL_WINDOWS.md#new-database-only); those are MySQL SQL statements, not Windows-specific commands. Use private random passwords, and avoid MySQL history/transcripts when entering secrets.

```bash
python -m pip install -r requirements-mysql-rsa.txt  # if MySQL RSA authentication requires it
python -m scripts.migrate --user spectre_migrate
python -m scripts.create_user administrator --role admin
python -m app.doctor
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

No default production password exists. Doctor makes only configured database checks; it does not contact providers, download models or collect. Stop with Ctrl+C. For a separate-machine clean Kali test, then install developer dependencies and run:

```bash
python -m pip install -r requirements-dev.lock
python -m pytest -q
python -m pip check
# Optional separately installed Node runtime:
node tests/js/run.cjs
python -m scripts.demo --output output/synthetic-demo
```

Open the local UI, sign in, create an empty test case and inspect empty graph/timeline/findings. No OSINT/active requests are required for installation acceptance. Check security headers, version, reports from the isolated synthetic demo and restart behavior. Record exact distro/Python/MySQL versions and results in the release checklist; mark Linux complete only after this real installation/review. An installer failure, dependency wheel incompatibility or MySQL authentication issue must remain documented, not bypassed by weakening security.
