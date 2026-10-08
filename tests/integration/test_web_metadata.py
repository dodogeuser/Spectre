import hashlib
import socket
import pytest
from sqlalchemy import select
from tests.integration.test_accounts_cases import system, login
from tests.web_fixtures import WebFixtureHTTP
from app.db.models import AuditLog, Evidence, CollectorRun
from app.services.evidence import canonical_bytes
from app.services.http_client import ResponseLimitError
from app.security.url_policy import NetworkPolicyError


def setup(client):
    headers = login(client,"owner")
    case = client.post("/api/cases",json={"title":"Web metadata"},headers=headers).json()["id"]
    target = client.post(f"/api/cases/{case}/targets",json={"type":"url","value":"https://example.com/"},headers=headers).json()["id"]
    return headers,case,target


def install(monkeypatch,fixture):
    async def fixture_get(self,url,**kwargs):
        return await fixture.get(url,**kwargs)
    monkeypatch.setattr("app.services.http_client.ControlledHttpClient.get",fixture_get)
    def denied(*args,**kwargs):
        raise AssertionError("No direct sockets or external-resource loads")
    monkeypatch.setattr(socket,"create_connection",denied)
    monkeypatch.setattr(socket,"getaddrinfo",denied)


def test_success_provenance_and_stored_read(system,monkeypatch):
    client,factory = system
    headers,case,target = setup(client)
    fixture = WebFixtureHTTP()
    install(monkeypatch,fixture)
    base = f"/api/cases/{case}/targets/{target}"
    run = client.post(base+"/collectors/web_metadata/runs",headers=headers).json()
    assert run["status"] == "completed" and run["version"] == "1.0.0"
    data = client.get(base+"/web").json()
    assert len(fixture.calls) == 1 and data["observations"][0]["parsed"]["title"] == "Example & Evidence"
    item = client.get(f"/api/cases/{case}/evidence/{data['observations'][0]['evidence_id']}").json()
    assert item["sha256"] == hashlib.sha256(canonical_bytes(item["raw_json"])).hexdigest()
    with factory() as db:
        assert len(list(db.scalars(select(AuditLog).where(AuditLog.action == "collector.completed")))) == 1


@pytest.mark.parametrize("fixture,error", [(WebFixtureHTTP(error=TimeoutError()),"timeout"),(WebFixtureHTTP(error=NetworkPolicyError()),"network_policy"),(WebFixtureHTTP(error=ResponseLimitError()),"invalid_or_oversized_result"),(WebFixtureHTTP(content_type="application/pdf"),"unsupported_content_type"),(WebFixtureHTTP(status=429),"provider_http_error")])
def test_failure_audit_no_invalid_findings(system,monkeypatch,fixture,error):
    client,factory = system
    headers,case,target = setup(client)
    install(monkeypatch,fixture)
    run = client.post(f"/api/cases/{case}/targets/{target}/collectors/web_metadata/runs",headers=headers).json()
    assert run["status"] == "failed" and run["error_code"] == error
    with factory() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action=="collector.failed"))
        for evidence in db.scalars(select(Evidence)):
            assert evidence.parsed_json["findings"] == []


def test_rbac_scope_csrf_disabled_archived_and_unsupported(system,monkeypatch):
    client,factory = system
    headers,case,target = setup(client)
    fixture = WebFixtureHTTP(error=AssertionError("Rejected requests must not contact provider"))
    install(monkeypatch,fixture)
    base = f"/api/cases/{case}"
    endpoint = f"{base}/targets/{target}"
    assert client.post(endpoint+"/collectors/web_metadata/runs").status_code == 403
    client.app.state.collector_registry.disabled = frozenset({"web_metadata"})
    assert client.post(endpoint+"/collectors/web_metadata/runs",headers=headers).status_code == 404
    client.app.state.collector_registry.disabled = frozenset()
    client.put(endpoint,json={"type":"url","value":"https://example.com/","scope_status":"excluded"},headers=headers)
    assert client.post(endpoint+"/collectors/web_metadata/runs",headers=headers).status_code == 403
    client.put(endpoint,json={"type":"url","value":"https://example.com/"},headers=headers)
    client.put(base+"/members/4",headers=headers)
    viewer = login(client,"viewer")
    assert client.get(endpoint+"/web").status_code == 200
    assert client.post(endpoint+"/collectors/web_metadata/runs",headers=viewer).status_code == 403
    other = login(client,"other")
    assert client.get(endpoint+"/web").status_code == 404
    assert client.post(endpoint+"/collectors/web_metadata/runs",headers=other).status_code == 404
    headers=login(client,"owner")
    client.delete(endpoint,headers=headers)
    assert client.post(endpoint+"/collectors/web_metadata/runs",headers=headers).status_code == 403
    domain=client.post(base+"/targets",json={"type":"domain","value":"example.net"},headers=headers).json()["id"]
    assert client.get(f"{base}/targets/{domain}/web").status_code == 422
    assert client.post(f"{base}/targets/{domain}/collectors/web_metadata/runs",headers=headers).status_code == 422
    assert fixture.calls == []
