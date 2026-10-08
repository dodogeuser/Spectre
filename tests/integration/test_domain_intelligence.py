import asyncio
import hashlib

import pytest
from sqlalchemy import select

from tests.integration.test_accounts_cases import system, login
from tests.domain_fixtures import FixtureHTTP
from app.db.models import AuditLog, Entity, Evidence, Relationship
from app.services.evidence import canonical_bytes


def setup(client):
    headers = login(client, "owner")
    case_id = client.post("/api/cases", json={"title": "Domain intelligence"}, headers=headers).json()["id"]
    target = client.post(f"/api/cases/{case_id}/targets", json={"type": "domain", "value": "EXAMPLE.COM"}, headers=headers).json()
    return headers, case_id, target["id"]


def test_all_collectors_project_provenance_and_overview(system, monkeypatch):
    client, factory = system
    headers, case_id, target_id = setup(client)
    transport = FixtureHTTP()
    async def fixture_get(self, url, **kwargs):
        return await transport.get(url, **kwargs)
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get", fixture_get)
    for name in ("dns", "rdap", "ct"):
        response = client.post(f"/api/cases/{case_id}/targets/{target_id}/collectors/{name}/runs", headers=headers)
        assert response.status_code == 201 and response.json()["status"] == "completed"
    assert len(transport.calls) == 9
    data = client.get(f"/api/cases/{case_id}/targets/{target_id}/domain").json()
    assert len(data["runs"]) == 3 and len(data["observations"]) == 9
    assert data["relationships"] and data["entities"]
    values = {item["value"] for item in data["entities"]}
    assert {"example.com", "www.example.com", "192.0.2.20", "2001:db8::20"} <= values
    assert "unrelated.example.org" not in values and "*.example.com" not in values
    for relation in data["relationships"]:
        evidence = client.get(f"/api/cases/{case_id}/evidence/{relation['evidence_id']}")
        assert evidence.status_code == 200
        item = evidence.json()
        assert item["sha256"] == hashlib.sha256(canonical_bytes(item["raw_json"])).hexdigest()
        assert 0 <= relation["confidence"] <= 1
    with factory() as db:
        nodes_before = len(list(db.scalars(select(Entity))))
    assert client.post(f"/api/cases/{case_id}/targets/{target_id}/collectors/ct/runs", headers=headers).json()["status"] == "completed"
    with factory() as db:
        assert len(list(db.scalars(select(Entity)))) == nodes_before
        assert len(list(db.scalars(select(AuditLog).where(AuditLog.action == "collector.completed")))) == 4


@pytest.mark.parametrize("name", ["dns", "rdap", "ct"])
@pytest.mark.parametrize("mode", ["malformed", "http_error", "timeout"])
def test_provider_failure_raw_or_safe_error_and_no_projection(system, monkeypatch, name, mode):
    client, factory = system
    headers, case_id, target_id = setup(client)
    fixture = FixtureHTTP(bad="malformed" if mode == "malformed" else "timeout" if mode == "timeout" else None,
                          http_status=503 if mode == "http_error" else 200)
    async def fixture_get(self, url, **kwargs):
        return await fixture.get(url, **kwargs)
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get", fixture_get)
    run = client.post(f"/api/cases/{case_id}/targets/{target_id}/collectors/{name}/runs", headers=headers).json()
    assert run["status"] == "failed"
    assert run["error_code"] == {"malformed": "malformed_response", "http_error": "provider_http_error", "timeout": "timeout"}[mode]
    data = client.get(f"/api/cases/{case_id}/targets/{target_id}/domain").json()
    assert data["runs"][0]["status"] == "failed"
    assert data["relationships"] == []
    if mode != "timeout":
        assert data["observations"][0]["parsed"]["status"] == "error"
    with factory() as db:
        assert len(list(db.scalars(select(AuditLog).where(AuditLog.action == "collector.failed")))) == 1


def test_scope_rbac_no_collection_from_overview_and_ip_rejection(system, monkeypatch):
    client, _ = system
    headers, case_id, target_id = setup(client)
    def denied(*a, **kw):
        raise AssertionError("No provider access for rejected request or stored overview")
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get", denied)
    base = f"/api/cases/{case_id}"
    assert client.get(f"{base}/targets/{target_id}/domain").status_code == 200
    client.put(f"{base}/targets/{target_id}", json={"type": "domain", "value": "example.com", "scope_status": "excluded"}, headers=headers)
    for name in ("dns", "rdap", "ct"):
        assert client.post(f"{base}/targets/{target_id}/collectors/{name}/runs", headers=headers).status_code == 403
    ip = client.post(f"{base}/targets", json={"type": "ipv4", "value": "192.0.2.1"}, headers=headers).json()
    assert client.post(f"{base}/targets/{ip['id']}/collectors/rdap/runs", headers=headers).status_code == 422
    assert client.get(f"{base}/targets/{ip['id']}/domain").status_code == 422
    client.put(f"{base}/members/4", headers=headers)
    viewer = login(client, "viewer")
    assert client.get(f"{base}/targets/{target_id}/domain").status_code == 200
    assert client.post(f"{base}/targets/{target_id}/collectors/dns/runs", headers=viewer).status_code == 403
    other = login(client, "other")
    assert client.get(f"{base}/targets/{target_id}/domain").status_code == 404
    assert client.get(f"{base}/evidence/1").status_code == 404
