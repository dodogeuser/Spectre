import asyncio
import pytest
from app.collectors.base import CollectorContext, CollectorTarget
from app.collectors.web_metadata import WebMetadataCollector
from app.collectors.registry import default_registry
from app.config import Settings
from app.security.url_policy import NetworkPolicyError
from app.services.http_client import UnsupportedContentError
from tests.web_fixtures import WebFixtureHTTP


def collect(fixture, url="https://example.com/"):
    return asyncio.run(WebMetadataCollector().collect(CollectorTarget(1, "url", url, "passive_allowed"), CollectorContext(fixture)))


def test_inert_single_page_and_informational_findings():
    fixture = WebFixtureHTTP()
    result = collect(fixture)
    assert len(fixture.calls) == 1 and fixture.calls[0][1] == {"accept": "text/html,application/xhtml+xml"}
    item = result.evidence[0]
    assert result.status == "completed" and item.parsed_json["title"] == "Example & Evidence"
    assert item.raw_json["body_base64"] and item.parsed_json["availability"] == "observed"
    assert all(finding["severity"] == "informational" for finding in item.parsed_json["findings"])
    assert not any(finding["header"] == "x-content-type-options" for finding in item.parsed_json["findings"])


@pytest.mark.parametrize("status,state,outcome", [(404,"negative_http_response","completed"),(410,"negative_http_response","completed"),(429,"rate_limited","failed"),(503,"unavailable","failed"),(401,"unavailable","failed")])
def test_http_states_distinct_and_no_findings(status,state,outcome):
    result = collect(WebFixtureHTTP(status=status))
    assert result.status == outcome and result.evidence[0].parsed_json["availability"] == state
    assert result.evidence[0].parsed_json["findings"] == []


@pytest.mark.parametrize("body,media", [(b"%PDF-content","text/html"),(b"binary","image/png"),(b"hello\x00world","text/html")])
def test_binary_rejected(body,media):
    with pytest.raises(UnsupportedContentError):
        collect(WebFixtureHTTP(body=body,content_type=media))


@pytest.mark.parametrize("body,media", [(b"<title>unclosed","text/html"),(b"\xff","text/html; charset=utf-8"),(b"<title>x</title>","text/html; charset=unknown")])
def test_partial_parsing_not_negative_or_findings(body,media):
    result = collect(WebFixtureHTTP(body=body,content_type=media))
    assert result.evidence[0].parsed_json["availability"] == "partial" and result.warnings
    assert result.evidence[0].parsed_json["findings"] == []


def test_disabled_and_http_private_seeds():
    with pytest.raises(KeyError):
        default_registry(Settings(_env_file=None,web_metadata_enabled=False)).get("web_metadata")
    for url in ("http://example.com/","https://127.0.0.1/","https://user:pass@example.com/"):
        fixture = WebFixtureHTTP()
        with pytest.raises(NetworkPolicyError):
            collect(fixture,url)
        assert fixture.calls == []
