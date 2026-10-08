"""Safe parse envelopes preserve even failed provider responses as evidence."""
import json

from app.collectors.base import EvidenceItem
from app.services.http_client import raw_response


class ProviderUnavailableError(ValueError):
    """A valid provider envelope explicitly reports unavailable data."""


def json_body(response):
    content_type = response.metadata.get("headers", {}).get("content-type", "").split(";", 1)[0].lower()
    if content_type not in {"application/json", "application/rdap+json"}:
        raise ValueError("Unexpected JSON media type")
    def reject_constant(value):
        raise ValueError("Non-finite JSON number")
    return json.loads(response.body, parse_constant=reject_constant)


def evidence(response, source_type, provider, parsed):
    return EvidenceItem(source_type=source_type, source_ref=response.source_ref,
                        raw_json={"provider": provider, **raw_response(response)},
                        parsed_json={"provider": provider, **parsed})


def safe_parse(response, source_type, provider, parser):
    if response.metadata["status"] != 200:
        return evidence(response, source_type, provider, {"status": "error", "error_code": "provider_http_error", "http_status": response.metadata["status"]}), "provider_http_error"
    try:
        parsed = parser(response)
        return evidence(response, source_type, provider, {"status": "ok", **parsed}), None
    except ProviderUnavailableError:
        return evidence(response, source_type, provider, {"status": "error", "error_code": "provider_unavailable"}), "provider_unavailable"
    except (ValueError, KeyError, TypeError, UnicodeError, IndexError, AttributeError):
        return evidence(response, source_type, provider, {"status": "error", "error_code": "malformed_response"}), "malformed_response"
