import asyncio
import copy
import ipaddress
import json

import pytest
import dns.message
import dns.rcode
import dns.rrset

from app.collectors.base import CollectorContext, CollectorTarget
from app.collectors.ip_intelligence import ReverseDNSCollector, NetworkRDAPCollector, ASNCollector, parse_ptr, select_ip_service, parse_network_rdap, parse_routing, parse_prefix
from app.collectors.registry import default_registry
from app.config import Settings
from app.services.http_client import HttpResult
from app.security.url_policy import NetworkPolicyError
from tests.ip_fixtures import IPFixtureHTTP, load


def response(document):
    return HttpResult("https://fixture.example", {"status": 200, "headers": {"content-type": "application/json"}}, json.dumps(document).encode())


@pytest.mark.parametrize("collector,count", [(ReverseDNSCollector(), 1), (NetworkRDAPCollector(), 2), (ASNCollector(), 2)])
@pytest.mark.parametrize("address,kind", [("8.8.8.8", "ipv4"), ("2001:4860:4860::8888", "ipv6")])
def test_success_uses_only_controlled_client(collector, count, address, kind):
    client = IPFixtureHTTP()
    result = asyncio.run(collector.collect(CollectorTarget(1, kind, address, "passive_allowed"), CollectorContext(client)))
    assert result.status == "completed" and len(client.calls) == count and len(result.evidence) == count
    assert all(item.raw_json["body_base64"] and item.parsed_json["provider"] and item.parsed_json["status"] == "ok" for item in result.evidence)
    assert all(ipaddress.ip_address(address).compressed not in urlsplit_host(url) for url, _ in client.calls)


def urlsplit_host(url):
    from urllib.parse import urlsplit
    return urlsplit(url).hostname


@pytest.mark.parametrize("collector", [ReverseDNSCollector(), NetworkRDAPCollector(), ASNCollector()])
@pytest.mark.parametrize("mode,status,error", [("malformed", 200, "malformed_response"), (None, 429, "provider_http_error"), (None, 503, "provider_http_error")])
def test_provider_errors_preserve_raw(collector, mode, status, error):
    result = asyncio.run(collector.collect(CollectorTarget(1, "ipv4", "8.8.8.8", "passive_allowed"), CollectorContext(IPFixtureHTTP(mode, status))))
    assert result.status == "failed" and result.error_code == error and result.evidence
    assert result.evidence[0].parsed_json["status"] == "error" and result.evidence[0].raw_json["body_base64"]
    assert "negative finding" in result.warnings[0]


@pytest.mark.parametrize("collector", [NetworkRDAPCollector(), ASNCollector()])
@pytest.mark.parametrize("mode", ["timeout", "network_policy", "malformed"])
def test_partial_result_preserved(collector, mode):
    result = asyncio.run(collector.collect(CollectorTarget(1, "ipv4", "8.8.8.8", "passive_allowed"), CollectorContext(IPFixtureHTTP(mode, fail_at=2))))
    assert result.status == "failed" and result.evidence[0].parsed_json["status"] == "ok"
    assert len(result.evidence) == (2 if mode == "malformed" else 1)


def test_bootstrap_longest_prefix_and_safe_url():
    document = load()["bootstrap"]
    assert select_ip_service(response(document), ipaddress.ip_address("8.8.8.8"))["selected_base"] == "https://specific.fixture.example/"
    document["services"][1][1] = ["http://unsafe.example", "https://127.0.0.1", "https://safe.example/"]
    assert select_ip_service(response(document), ipaddress.ip_address("8.8.8.8"))["selected_base"] == "https://safe.example/"
    assert select_ip_service(response(document), ipaddress.ip_address("1.1.1.1"))["selected_base"] is None


def test_mismatched_rdap_routing_and_holder_are_rejected():
    address = ipaddress.ip_address("1.1.1.1")
    with pytest.raises(ValueError):
        parse_network_rdap(response(load()["rdap"]), address)
    with pytest.raises(ValueError):
        parse_routing(response(load()["routing"]), address)
    with pytest.raises(ValueError):
        parse_prefix(response(load()["prefix"]), "1.1.1.0/24", [13335])
    document = load()["routing"]
    document["data"]["asns"] = [True]
    with pytest.raises(ValueError):
        parse_routing(response(document), ipaddress.ip_address("8.8.8.8"))


@pytest.mark.parametrize("rcode", ["NOERROR", "NXDOMAIN", "SERVFAIL"])
def test_ptr_negative_is_provider_scoped_and_not_failure(rcode):
    query = dns.message.make_query("8.8.8.8.in-addr.arpa", "PTR")
    answer = dns.message.make_response(query)
    answer.set_rcode(dns.rcode.from_text(rcode))
    wire = HttpResult("https://fixture.example", {"status": 200, "headers": {"content-type": "application/dns-message"}}, answer.to_wire())
    parsed = parse_ptr(wire, query)
    assert parsed["records"] == []
    assert parsed["availability"] == ("unavailable" if rcode == "SERVFAIL" else "no_ptr_observed")


def test_unrelated_ptr_answer_not_accepted():
    query = dns.message.make_query("8.8.8.8.in-addr.arpa", "PTR")
    answer = dns.message.make_response(query)
    answer.answer.append(dns.rrset.from_text("1.1.1.1.in-addr.arpa.", 300, "IN", "PTR", "unrelated.example."))
    wire = HttpResult("https://fixture.example", {"status": 200, "headers": {"content-type": "application/dns-message"}}, answer.to_wire())
    assert parse_ptr(wire, query)["records"] == []


@pytest.mark.parametrize("name", ["reverse_dns", "ip_rdap", "ip_asn"])
def test_independent_disable(name):
    registry = default_registry(Settings(_env_file=None, **{name + "_enabled": False}))
    with pytest.raises(KeyError):
        registry.get(name)
    assert registry.get("dns") and registry.get("mock")


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "2001:db8::1"])
def test_nonpublic_seed_never_queries_provider(address):
    client = IPFixtureHTTP()
    with pytest.raises(NetworkPolicyError):
        asyncio.run(ReverseDNSCollector().collect(CollectorTarget(1, "ipv6" if ":" in address else "ipv4", address, "passive_allowed"), CollectorContext(client)))
    assert client.calls == []


def test_no_routing_observation_not_global_negative():
    document = load()["routing"]
    document["data"] = {"prefix": None, "asns": []}
    parsed = parse_routing(response(document), ipaddress.ip_address("8.8.8.8"))
    assert parsed["availability"] == "no_route_observed"
    assert "does not prove" in parsed["caveat"]


def test_organization_names_are_not_personal_names_and_dates_validated():
    from app.collectors.ip_intelligence import rdap_organizations
    entities = [{"roles": ["registrant"], "vcardArray": ["vcard", [["kind", {}, "text", "org"], ["fn", {}, "text", "Example Organization"]]]}]
    assert rdap_organizations(entities)[0]["name"] == "Example Organization"
    entities[0]["vcardArray"][1][0][3] = "individual"
    assert rdap_organizations(entities) == []
    document = load()["rdap"]
    document["events"][0]["eventDate"] = "invalid-date"
    with pytest.raises(ValueError):
        parse_network_rdap(response(document), ipaddress.ip_address("8.8.8.8"))


def test_holder_metadata_missing_is_explicitly_partial():
    document = load()["prefix"]
    document["data"]["asns"] = []
    parsed = parse_prefix(response(document), "8.8.8.0/24", [15169])
    assert parsed["availability"] == "partial_holder_metadata"


@pytest.mark.parametrize("status", ["error", "maintenance"])
def test_valid_provider_unavailable_envelope_preserves_raw(status):
    from app.collectors.domain_support import safe_parse
    document = {"status": status, "data_call_name": "network-info", "data": None}
    item, error = safe_parse(response(document), "ip_asn", "RIPEstat fixture", lambda result: parse_routing(result, ipaddress.ip_address("8.8.8.8")))
    assert error == "provider_unavailable" and item.parsed_json["status"] == "error"
    assert item.raw_json["body_base64"]


def test_contact_redacted_recorded_live_provider_shapes():
    import base64
    from pathlib import Path
    document = json.loads((Path(__file__).parents[1] / "fixtures/ip_recorded_provider_shapes.json").read_text(encoding="utf-8"))
    address = ipaddress.ip_address("8.8.8.8")
    query = dns.message.make_query(address.reverse_pointer, "PTR")
    query.id = 0
    wire = HttpResult("https://cloudflare-dns.com/dns-query", {"status": 200, "headers": {"content-type": "application/dns-message"}}, base64.b64decode(document["ptr_body_base64"]))
    assert parse_ptr(wire, query)["records"][0]["name"] == "dns.google"
    allocation = parse_network_rdap(response(document["ip_rdap"]), address)
    assert allocation["organizations"] and allocation["start_address"] == "8.8.8.0"
    routing = parse_routing(response(document["ip_asn"]), address)
    assert routing["asns"] == [15169] and routing["prefix"] == "8.8.8.0/24"
    assert parse_prefix(response(document["ip_asn_holder"]), routing["prefix"], routing["asns"])["holders"]
