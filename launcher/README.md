# SPECTRE Windows convenience launcher

Double-click `SPECTRE.exe` in the installation root **after** following `docs/INSTALL_WINDOWS.md` to install Python/dependencies, configure your private `.env`, prepare MySQL and create an account. No admin privileges are needed for normal launch. The EXE is not the application or an installer; it contains no Python runtime, `.env`, credentials or investigation data.

The launcher uses its own executable directory, validates required files and `.venv/Scripts/python.exe`, and runs `python -m launcher.runtime_probe` followed by the supported `python -m app.run`. Configuration values and application exceptions are not echoed in dialogs. `SPECTRE_BIND_HOST` must be `127.0.0.1`, `localhost` (normalized to IPv4 loopback) or `::1`; `SPECTRE_BIND_PORT` defaults to 8000. Environment variables retain the application's existing precedence over `.env`. Non-loopback binding is refused. No shell commands, elevation, firewall changes, DB changes, collectors, active requests or provider calls occur.

Readiness requires successful bounded, redirect-disabled, proxy-disabled local `/version` and `/health` responses. A matching already-running 1.0.0 release-candidate instance is opened without another server. A per-user-session/port named mutex coordinates concurrent launcher invocations. An occupied port with an unrecognized/unready service fails closed. This recognizes a local endpoint, not cryptographic process identity or database readiness; health does not test MySQL. A different installed SPECTRE using the same port is reused by design.

Only after readiness is the fixed local URL opened in the default browser. The detached one-worker application keeps running when the launcher/browser exits. It does not restart on failure or auto-resume active jobs. Readiness timeout leaves the spawned process running rather than interrupting possible work; retry/check it before starting another server. To stop it, identify the installation's Python `-m app.run` process in Task Manager; ensure no jobs are running before ending it. There is no new tray/service/shutdown interface.

## Build (Windows)

From the repository root:

```powershell
python launcher/build_windows.py
```

The Python build script uses Windows .NET Framework 4.x `csc.exe` under `%WINDIR%`, requires its compiler/WinForms runtime (Windows 10/11 target), compiles `SpectreLauncher.cs` as an AnyCPU GUI executable, and embeds `app/static/images/branding/favicon.ico`. The source and explicit compiler flags are reproducible; legacy compiler PE timestamps mean builds are not guaranteed byte-identical. No download, external image, Python bundler or PowerShell execution-policy change is required. The optional PowerShell build script uses the same flags when local script policy permits. No Administrator manifest is requested. The executable is unsigned: Windows SmartScreen/reputation prompts may appear; do not disable security controls. Owner code signing/distribution review remains pending.

The release packager includes launcher source/build instructions/probe and icon assets, plus `SPECTRE.exe` when it has been built locally. Build the EXE on Windows before building a Windows/combined RC package. A source-only package can still be built on Linux without the Windows binary. Linux/Kali users ignore the EXE and use `python -m app.run`; existing cross-platform installation remains independent.

Move/extract the whole SPECTRE directory, not just the EXE. The EXE contains no developer path. A Python venv still depends on its installed base Python and may need recreating after a move/to another computer; run the platform installer if necessary. Writable installation/configuration and a working MySQL service remain prerequisites. Do not run untrusted modified launcher/application files.

Manual owner checks remain: double-click startup/default-browser behavior on the intended Windows installation, Explorer icon at multiple sizes, startup error dialogs, concurrent clicks and clean Windows installation. Automated tests use isolated loopback servers and mock browser callbacks; they are not clean-install acceptance.
