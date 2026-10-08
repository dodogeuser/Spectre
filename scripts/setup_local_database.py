"""Retired unsafe legacy setup; explicit DBA provisioning replaces it."""

def main():
    raise SystemExit("Legacy passwordless-root setup is retired. Follow docs/INSTALL_WINDOWS.md or docs/INSTALL_LINUX.md; existing configuration/databases are untouched.")

if __name__=="__main__":main()
