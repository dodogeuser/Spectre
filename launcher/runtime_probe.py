"""Private launcher config probe: stdout contains only loopback address and port."""
import json
import sys
from app.config import Settings


def main():
    try:
        if sys.version_info < (3, 12):
            raise ValueError('unsupported Python')
        settings = Settings()
        if settings.bind_host not in {'127.0.0.1', 'localhost', '::1'}:
            raise ValueError('nonlocal')
        if not settings.mysql_password.get_secret_value() or settings.mysql_password.get_secret_value() == 'CHANGE_ME':
            raise ValueError('unconfigured')
        # Probe required runtime packages before the GUI starts a detached server.
        import uvicorn, sqlalchemy, pymysql, argon2, reportlab  # noqa: F401
        host = '127.0.0.1' if settings.bind_host == 'localhost' else settings.bind_host
        print(json.dumps({'host': host, 'port': settings.bind_port}))
    except Exception:
        print('Configuration/runtime check failed. Check .env and run python -m app.doctor.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
