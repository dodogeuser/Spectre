import asyncio
import copy
import json

import dns.message
import pytest

from app.collectors.base import CollectorContext, CollectorTarget
from app.collectors.dns import DNSCollector, parse_dns
from app.collectors.rdap import RDAPCollector, parse_rdap, select_service
from app.collectors.ct import CTCollector, parse_ct
from app.collectors.registry import default_registry
from app.config import Settings
from app.services.http_client import HttpResult
from tests.domain_fixtures import FixtureHTTP, load


def response(document):
    return HttpResult("https://fixture.example/", {"status": 200, "headers": {"content-type": "application/json"}}, json.dumps(document).encode())


@pytest.mark.parametrize("collector,count", [(DNSCollector(), 6), (RDAPCollector(), 2), (CTCollector(), 1)])
def test_collectors_use_only_injected_client_and_preserve_raw(collector, count):
    client = FixtureHTTP()
    result = asyncio.run(collector.collect(CollectorTarget(1, "domain", "example.com", "passive_allowed"), CollectorContext(client)))
    assert result.status == "completed"
    assert len(client.calls) == count and len(result.evidence) == count
    for item in result.evidence:
        assert item.source_ref.startswith("https://")
        assert item.raw_json["body_base64"]
        assert item.raw_json["provider"]
        assert item.parsed_json["status"] == "ok"
    if collector.name == "dns":
        assert [item.parsed_json["query_type"] for item in result.evidence] == list(DNSCollector.record_types)
        assert all(call[1]["accept"] == "application/dns-message" for call in client.calls)
    if collector.name == "ct":
        assert client.calls[0][1]["host_interval"] == 60


@pytest.mark.parametrize("collector", [DNSCollector(), RDAPCollector(), CTCollector()])
@pytest.mark.parametrize("bad,status,error", [("malformed", 200, "malformed_response"), (None, 429, "provider_http_error"), (None, 503, "provider_http_error")])
def test_bad_provider_data_is_visible_raw_evidence(collector, bad, status, error):
    result = asyncio.run(collector.collect(CollectorTarget(1, "domain", "example.com", "passive_allowed"), CollectorContext(FixtureHTTP(bad=bad, http_status=status))))
    assert result.status == "failed" and result.error_code == error
    assert result.warnings and result.evidence
    assert result.evidence[0].raw_json["body_base64"]


def test_ct_scoped_names_wildcards_and_observation_dates():
    parsed = parse_ct(response(load("ct")), "example.com")
    certificate = parsed["certificates"][0]
    assert certificate["dns_names"] == ["example.com", "www.example.com"]
    assert certificate["wildcard_bases"] == ["example.com"]
    assert "unrelated.example.org" not in certificate["dns_names"]
    for field, value in (("cert_sha256", "bad"), ("not_before", "bad-date"), ("dns_names", "not-a-list")):
        bad = copy.deepcopy(load("ct"))
        bad[0][field] = value
        with pytest.raises(ValueError):
            parse_ct(response(bad), "example.com")


def test_rdap_domain_match_and_bootstrap_policy():
    assert parse_rdap(response(load("rdap")), "example.com")["domain"] == "example.com"
    with pytest.raises(ValueError):
        parse_rdap(response(load("rdap")), "example.org")
    bootstrap = {"services": [[["com"], ["http://unsafe.example/", "https://127.0.0.1/", "https://rdap.fixture.example/"]]]}
    assert select_service(response(bootstrap), "example.com")["selected_base"] == "https://rdap.fixture.example/"
    assert select_service(response(bootstrap), "example.org")["selected_base"] is None


@pytest.mark.parametrize("name", ["dns", "rdap", "ct"])
def test_independent_disable(name):
    settings = Settings(_env_file=None, **{name + "_enabled": False})
    registry = default_registry(settings)
    with pytest.raises(KeyError):
        registry.get(name)
    for other in {"dns", "rdap", "ct", "mock"} - {name}:
        assert registry.get(other)


@pytest.mark.parametrize("rcode", ["NOERROR", "NXDOMAIN", "SERVFAIL"])
def test_dns_negative_and_failure_responses(rcode):
    import dns.rcode
    query = dns.message.make_query("example.com", "MX")
    answer = dns.message.make_response(query)
    answer.set_rcode(dns.rcode.from_text(rcode))
    wire = HttpResult("https://fixture.example", {"status": 200, "headers": {"content-type": "application/dns-message"}}, answer.to_wire())
    parsed = parse_dns(wire, query)
    assert parsed["rcode"] == rcode and parsed["records"] == []
    assert bool(parsed.get("dns_error")) == (rcode == "SERVFAIL")


def test_dns_null_mx_and_mismatched_response():
    import dns.rrset
    query = dns.message.make_query("example.com", "MX")
    answer = dns.message.make_response(query)
    answer.answer.append(dns.rrset.from_text("example.com.", 60, "IN", "MX", "0 ."))
    wire = HttpResult("https://fixture.example", {"status": 200, "headers": {"content-type": "application/dns-message"}}, answer.to_wire())
    assert parse_dns(wire, query)["records"][0]["value"] == "."
    with pytest.raises(ValueError):
        parse_dns(wire, dns.message.make_query("other.example", "MX"))


def test_dns_partial_timeout_retains_received_evidence():
    class PartialHTTP(FixtureHTTP):
        async def get(self, url, **kwargs):
            if self.calls:
                raise TimeoutError("fixture timeout")
            return await super().get(url, **kwargs)
    result = asyncio.run(DNSCollector().collect(CollectorTarget(1, "domain", "example.com", "passive_allowed"), CollectorContext(PartialHTTP())))
    assert result.status == "failed" and result.error_code == "timeout"
    assert len(result.evidence) == 1 and result.evidence[0].parsed_json["status"] == "ok"
