"""Portable local launcher: python -m app.run."""
import sys
import uvicorn
from pydantic import ValidationError
from app.config import Settings


def main():
    try:settings=Settings()
    except ValidationError:
        raise SystemExit("Invalid SPECTRE configuration; run python -m app.doctor (values withheld)")
    if not settings.mysql_password.get_secret_value() or settings.mysql_password.get_secret_value()=="CHANGE_ME":
        raise SystemExit("Database password is not configured; run python -m app.doctor before starting SPECTRE")
    if settings.bind_host not in {"127.0.0.1","localhost","::1"}:
        print("WARNING: non-loopback bind exposes SPECTRE to other hosts; use a reviewed HTTPS deployment.",file=sys.stderr)
    uvicorn.run("app.main:app",host=settings.bind_host,port=settings.bind_port,workers=1,access_log=False)


if __name__=="__main__":main()
