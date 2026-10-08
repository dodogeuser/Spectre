"""JSON logging with credential redaction at the output boundary."""

import json
import logging
import re
from datetime import datetime, timezone

from app.config import Settings

_CREDENTIAL = re.compile(
    r"(?i)(\b(?:password|passwd|token|api[_-]?key|secret|authorization|cookie|set-cookie|spectre_session|csrf_token)\b[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}&]+)"
)
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_URL_AUTH = re.compile(r"(://)[^\s/@]+:[^\s/@]+@")


class RedactingJsonFormatter(logging.Formatter):
    def __init__(self, secrets: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.secrets = tuple(value for value in secrets if value)

    def redact(self, value: str) -> str:
        value = re.sub(r'(\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^\s?\"]+)\?[^\s\"]*', r'\1?[REDACTED]', value)
        for secret in sorted(self.secrets, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        value = _BEARER.sub("[REDACTED]", value)
        value = _URL_AUTH.sub(r"\1[REDACTED]@", value)
        return _CREDENTIAL.sub(r"\1[REDACTED]", value)

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": self.redact(record.name),
            "message": self.redact(record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = self.redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(settings: Settings) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        RedactingJsonFormatter((settings.mysql_password.get_secret_value(),))
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
