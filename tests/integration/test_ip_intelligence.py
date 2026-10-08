import hashlib
import socket

import pytest
from sqlalchemy import select

from tests.integration.test_accounts_cases import system, login
from tests.ip_fixtures import IPFixtureHTTP
from tests.domain_fixtures import FixtureHTTP
from app.db.models import AuditLog, CollectorRun, Entity, Evidence, Relationship
from app.services.evidence import canonical_bytes

NAMES = ("reverse_dns", "ip_rdap", "ip_asn")


def setup(client, address="8.8.8.8"):
    headers = login(client, "owner")
    case_id = client.post("/api/cases", json={"title": "IP intelligence"}, headers=headers).json()["id"]
    target = client.post(f"/api/cases/{case_id}/targets", json={"type": "ipv6" if ":" in address else "ipv4", "value": address}, headers=headers).json()
    return headers, case_id, target["id"]


def install(monkeypatch, fixture):
    async def fixture_get(self, url, **kwargs):
        return await fixture.get(url, **kwargs)
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get", fixture_get)
    # Framework must not scan/probe/connect to the target outside the client.
    def denied(*a, **kw):
        raise AssertionError("Direct sockets are prohibited in IP collectors")
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)


@pytest.mark.parametrize("address", ["8.8.8.8", "2001:4860:4860::8888"])
def test_success_hashes_provenance_audit_and_entity_reuse(system, monkeypatch, address):
    client, factory = system
    headers, case_id, target_id = setup(client, address)
    fixture = IPFixtureHTTP()
    install(monkeypatch, fixture)
    base = f"/api/cases/{case_id}"
    for name in NAMES:
        run = client.post(f"{base}/targets/{target_id}/collectors/{name}/runs", headers=headers)
        assert run.status_code == 201
        assert run.json()["status"] == "completed" and run.json()["version"] == "1.0.0"
        assert run.json()["target_snapshot"]["normalized_value"] == address
    assert len(fixture.calls) == 5
    before_calls = len(fixture.calls)
    data = client.get(f"{base}/targets/{target_id}/ip").json()
    assert len(fixture.calls) == before_calls and len(data["observations"]) == 5
    assert data["reputation"]["availability"] == "not_configured" and data["reputation"]["observations"] == []
    for item in data["observations"]:
        evidence = client.get(f"{base}/evidence/{item['evidence_id']}").json()
        assert evidence["sha256"] == hashlib.sha256(canonical_bytes(evidence["raw_json"])).hexdigest()
        assert evidence["source_ref"].startswith("https://") and evidence["captured_at"]
        assert evidence["parsed_json"]["provider"]
    with factory() as db:
        assert len(list(db.scalars(select(Entity).where(Entity.entity_type == "ip")))) == 1
        relation = db.scalar(select(Relationship))
        assert relation.relation_type == "ptr_observed" and relation.confidence == 0.95
        actions = list(db.scalars(select(AuditLog.action).where(AuditLog.action.like("collector.%"))))
        assert actions.count("collector.started") == actions.count("collector.completed") == 3
    assert client.post(f"{base}/targets/{target_id}/collectors/reverse_dns/runs", headers=headers).json()["status"] == "completed"
    with factory() as db:
        assert len(list(db.scalars(select(Entity)))) == 2


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("mode,status,error", [("malformed", 200, "malformed_response"), ("timeout", 200, "timeout"), ("network_policy", 200, "network_policy"), (None, 429, "provider_http_error"), (None, 503, "provider_http_error")])
def test_failures_are_safe_and_audited(system, monkeypatch, name, mode, status, error):
    client, factory = system
    headers, case_id, target_id = setup(client)
    install(monkeypatch, IPFixtureHTTP(mode, status))
    base = f"/api/cases/{case_id}"
    run = client.post(f"{base}/targets/{target_id}/collectors/{name}/runs", headers=headers).json()
    assert run["status"] == "failed" and run["error_code"] == error and run["ended_at"]
    data = client.get(f"{base}/targets/{target_id}/ip").json()
    assert data["runs"][0]["status"] == "failed"
    if mode not in {"timeout", "network_policy"}:
        assert data["observations"][0]["parsed"]["status"] == "error"
    with factory() as db:
        assert not list(db.scalars(select(Relationship)))
        assert len(list(db.scalars(select(AuditLog).where(AuditLog.action == "collector.failed")))) == 1


@pytest.mark.parametrize("name", ["ip_rdap", "ip_asn"])
def test_partial_evidence_commit(system, monkeypatch, name):
    client, factory = system
    headers, case_id, target_id = setup(client)
    install(monkeypatch, IPFixtureHTTP("timeout", fail_at=2))
    base = f"/api/cases/{case_id}"
    run = client.post(f"{base}/targets/{target_id}/collectors/{name}/runs", headers=headers).json()
    assert run["status"] == "failed" and run["error_code"] == "timeout"
    evidence = client.get(f"{base}/runs/{run['id']}/evidence").json()
    assert len(evidence) == 1 and evidence[0]["parsed_json"]["status"] == "ok"


def test_scope_rbac_archive_csrf_and_disabled_before_network(system, monkeypatch):
    client, factory = system
    headers, case_id, target_id = setup(client)
    def no_network(*args, **kwargs):
        raise AssertionError("No provider request permitted")
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get", no_network)
    base = f"/api/cases/{case_id}"
    endpoint = f"{base}/targets/{target_id}"
    assert client.get(endpoint + "/ip").status_code == 200
    for name in NAMES:
        assert client.post(f"{endpoint}/collectors/{name}/runs").status_code == 403
        client.app.state.collector_registry.disabled = frozenset({name})
        assert client.post(f"{endpoint}/collectors/{name}/runs", headers=headers).status_code == 404
    client.app.state.collector_registry.disabled = frozenset()
    client.put(endpoint, json={"type": "ipv4", "value": "8.8.8.8", "scope_status": "excluded"}, headers=headers)
    for name in NAMES:
        assert client.post(f"{endpoint}/collectors/{name}/runs", headers=headers).status_code == 403
    client.put(endpoint, json={"type": "ipv4", "value": "8.8.8.8"}, headers=headers)
    client.put(f"{base}/members/4", headers=headers)
    viewer = login(client, "viewer")
    assert client.get(endpoint + "/ip").status_code == 200
    for name in NAMES:
        assert client.post(f"{endpoint}/collectors/{name}/runs", headers=viewer).status_code == 403
    other = login(client, "other")
    assert client.get(endpoint + "/ip").status_code == 404
    for name in NAMES:
        assert client.post(f"{endpoint}/collectors/{name}/runs", headers=other).status_code == 404
    headers = login(client, "owner")
    client.delete(endpoint, headers=headers)
    for name in NAMES:
        assert client.post(f"{endpoint}/collectors/{name}/runs", headers=headers).status_code == 403
    with factory() as db:
        assert not list(db.scalars(select(CollectorRun)))
        assert len(list(db.scalars(select(AuditLog).where(AuditLog.action == "collector.denied")))) == 9


@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "2001:db8::1", "::1"])
def test_nonpublic_ip_admission_denied(system, monkeypatch, address):
    client, factory = system
    headers, case_id, target_id = setup(client, address)
    def denied(*a, **kw):
        raise AssertionError("Nonpublic seed must not reach provider")
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get", denied)
    for name in NAMES:
        result = client.post(f"/api/cases/{case_id}/targets/{target_id}/collectors/{name}/runs", headers=headers)
        assert result.status_code == 403 and result.json()["detail"] == "IP intelligence requires a public IP seed"
    with factory() as db:
        assert not list(db.scalars(select(CollectorRun)))


def test_related_domains_case_isolated_with_citations_and_domain_rejection(system, monkeypatch):
    client, factory = system
    headers, case_id, target_id = setup(client)
    base = f"/api/cases/{case_id}"
    target = client.post(base + "/targets", json={"type": "domain", "value": "example.com"}, headers=headers).json()
    fixture = FixtureHTTP()
    async def fixture_get(self, url, **kwargs):
        return await fixture.get(url, **kwargs)
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get", fixture_get)
    run = client.post(f"{base}/targets/{target['id']}/collectors/dns/runs", headers=headers).json()
    assert run["status"] == "completed"
    # Reuse a domain-discovered IP without creating another entity or collecting it.
    target2 = client.post(base + "/targets", json={"type": "ipv4", "value": "192.0.2.20"}, headers=headers).json()
    data = client.get(f"{base}/targets/{target2['id']}/ip").json()
    assert data["related_domains"][0]["domain"] == "example.com"
    assert client.get(f"{base}/evidence/{data['related_domains'][0]['evidence_id']}").status_code == 200
    assert client.get(f"{base}/targets/{target_id}/ip").json()["related_domains"] == []
    other_case = client.post("/api/cases", json={"title": "Other case"}, headers=headers).json()["id"]
    other_target = client.post(f"/api/cases/{other_case}/targets", json={"type": "ipv4", "value": "192.0.2.20"}, headers=headers).json()
    assert client.get(f"/api/cases/{other_case}/targets/{other_target['id']}/ip").json()["related_domains"] == []
    for name in NAMES:
        assert client.post(f"{base}/targets/{target['id']}/collectors/{name}/runs", headers=headers).status_code == 422
    assert client.get(f"{base}/targets/{target['id']}/ip").status_code == 422


def test_provider_maintenance_at_http_200_is_audited_failure(system, monkeypatch):
    import json
    from app.services.http_client import HttpResult
    client, factory = system
    headers, case_id, target_id = setup(client)
    async def unavailable(self, url, **kwargs):
        return HttpResult(url, {"status": 200, "headers": {"content-type": "application/json"}}, json.dumps({"status": "maintenance", "data": None}).encode())
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get", unavailable)
    response = client.post(f"/api/cases/{case_id}/targets/{target_id}/collectors/ip_asn/runs", headers=headers)
    assert response.status_code == 201 and response.json()["status"] == "failed"
    assert response.json()["error_code"] == "provider_unavailable"
    with factory() as db:
        assert db.scalar(select(Evidence)).parsed_json["status"] == "error"
        assert db.scalar(select(AuditLog).where(AuditLog.action == "collector.failed")).metadata_json["error_code"] == "provider_unavailable"
