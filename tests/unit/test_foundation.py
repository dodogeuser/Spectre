import json
import logging

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.logging_config import RedactingJsonFormatter
from app.main import create_app


def test_health_and_landing():
    with TestClient(create_app(Settings(_env_file=None))) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        landing = client.get("/")
        assert landing.status_code == 200
        assert "SPECTRE" in landing.text
        assert client.get("/static/css/main.css").status_code == 200
        assert client.get("/static/js/main.js").status_code == 200


def test_invalid_environment_fails(monkeypatch):
    monkeypatch.setenv("SPECTRE_MYSQL_PORT", "70000")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_logs_redact_credentials_and_exception():
    formatter = RedactingJsonFormatter(("configured-credential",))
    try:
        raise RuntimeError("password=exception-credential")
    except RuntimeError:
        import sys
        exception = sys.exc_info()
    record = logging.LogRecord(
        "spectre", logging.ERROR, __file__, 1,
        'token=token-value Authorization: Bearer bearer-value '
        'mysql://user:url-credential@localhost configured-credential', (), exception,
    )
    output = formatter.format(record)
    for value in ("exception-credential", "token-value", "bearer-value", "url-credential", "configured-credential"):
        assert value not in output
    assert json.loads(output)["level"] == "ERROR"
