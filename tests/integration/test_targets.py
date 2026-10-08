import socket
import pytest
from sqlalchemy import select

from tests.integration.test_accounts_cases import system, login
from app.db.models import AuditLog, Target


def create_case(client, headers, title="Targets"):
    response = client.post("/api/cases", json={"title": title}, headers=headers)
    assert response.status_code == 201
    return response.json()["id"]


def test_target_crud_scope_audit_and_zero_network(system, monkeypatch):
    client, factory = system
    headers = login(client, "owner")
    case_id = create_case(client, headers)
    def deny_network(*args, **kwargs):
        raise AssertionError("Target management must not access the network")
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    monkeypatch.setattr(socket.socket, "connect", deny_network)
    path = f"/api/cases/{case_id}/targets"
    for kind, value in (("ipv4", "192.0.2.1"), ("ipv6", "2001:db8::1"),
                        ("url", "https://example.com/"), ("organization", "Example Company"),
                        ("username", "ExampleUser"), ("email", "user@example.com")):
        assert client.post(path, json={"type": kind, "value": value}, headers=headers).status_code == 201
    created = client.post(path, json={"type": "domain", "value": "EXAMPLE.COM."}, headers=headers)
    assert created.status_code == 201
    target = created.json()
    assert target["normalized_value"] == "example.com"
    assert target["scope_status"] == "passive_allowed"
    specific = f"{path}/{target['id']}"
    for scope in ("active_authorized", "excluded"):
        changed = client.put(specific, json={"type": "domain", "value": "example.org", "scope_status": scope}, headers=headers)
        assert changed.status_code == 200
        assert changed.json()["scope_status"] == scope
    assert client.get(specific).json()["normalized_value"] == "example.org"
    assert client.delete(specific, headers=headers).status_code == 204
    assert client.delete(specific, headers=headers).status_code == 204
    assert client.get(specific).json()["archived"] is True
    with factory() as db:
        actions = list(db.scalars(select(AuditLog).where(AuditLog.action.like("target.%"))))
        assert [row.action for row in actions] == ["target.create"] * 7 + ["target.update", "target.update", "target.archive"]
        assert all(row.actor_id == 2 and row.object_id == case_id for row in actions)
        assert actions[7].metadata_json["before"]["normalized_value"] == "example.com"
        assert db.get(Target, target["id"]).archived


def test_duplicates_and_case_isolation(system):
    client, factory = system
    headers = login(client, "owner")
    case_id = create_case(client, headers)
    other_case = create_case(client, headers, "Other case")
    path = f"/api/cases/{case_id}/targets"
    first = client.post(path, json={"type": "domain", "value": "Example.COM"}, headers=headers).json()
    assert client.post(path, json={"type": "domain", "value": "example.com."}, headers=headers).status_code == 409
    second = client.post(path, json={"type": "domain", "value": "example.org"}, headers=headers).json()
    assert client.put(f"{path}/{second['id']}", json={"type": "domain", "value": "example.com"}, headers=headers).status_code == 409
    assert client.get(f"{path}/{second['id']}").json()["normalized_value"] == "example.org"
    assert client.post(f"/api/cases/{other_case}/targets", json={"type": "domain", "value": "example.com"}, headers=headers).status_code == 201
    assert client.get(f"/api/cases/{other_case}/targets/{first['id']}").status_code == 404
    client.delete(f"{path}/{first['id']}", headers=headers)
    assert client.post(path, json={"type": "domain", "value": "example.com"}, headers=headers).status_code == 409
    with factory() as db:
        assert len(list(db.scalars(select(AuditLog).where(AuditLog.action == "target.create")))) == 3


def test_target_rbac_and_validation(system):
    client, _ = system
    headers = login(client, "owner")
    case_id = create_case(client, headers)
    path = f"/api/cases/{case_id}/targets"
    target = client.post(path, json={"type": "domain", "value": "example.com"}, headers=headers).json()
    specific = f"{path}/{target['id']}"
    assert client.post(path, json={"type": "domain", "value": "bad..example"}, headers=headers).status_code == 422
    assert client.post(path, json={"type": "domain", "value": "example.net", "scope_status": "invalid"}, headers=headers).status_code == 422
    assert client.post(path, json={"type": "domain", "value": "example.net"}).status_code == 403
    client.put(f"/api/cases/{case_id}/members/4", headers=headers)
    viewer = login(client, "viewer")
    assert client.get(path).status_code == 200
    assert client.get(specific).status_code == 200
    for method, endpoint in (("POST", path), ("PUT", specific), ("DELETE", specific)):
        assert client.request(method, endpoint, json={"type": "domain", "value": "example.net"}, headers=viewer).status_code == 403
    other = login(client, "other")
    assert client.get(path).status_code == 404
    assert client.get(specific).status_code == 404
    assert client.delete(specific, headers=other).status_code == 404
    admin = login(client, "admin")
    assert client.put(specific, json={"type": "domain", "value": "example.net"}, headers=admin).status_code == 200
    assert any(row["action"] == "admin.case_access" for row in client.get(f"/api/cases/{case_id}/audit").json())
    client.cookies.clear()
    assert client.get(path).status_code == 401
