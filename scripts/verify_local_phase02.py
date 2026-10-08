"""Provision private demo logins and verify Phase 02 against configured MySQL."""
import json
import secrets
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text

from app.api.auth import hasher
from app.config import get_settings
from app.db.models import User
from app.db.session import make_session_factory
from app.main import create_app
from app.security.rbac import audit


def main():
    destination = Path(".local/login-credentials.json")
    if destination.exists():
        raise SystemExit("Private credentials already exist; refusing to overwrite.")
    factory = make_session_factory(get_settings())
    credentials = {}
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "002"
        schema = inspect(db.bind)
        assert "targets" in schema.get_table_names()
        assert {"scope_status", "canonical_hash", "archived", "normalized_value"} <= {c["name"] for c in schema.get_columns("targets")}
        assert any(c["name"] == "uq_target_canonical" for c in schema.get_unique_constraints("targets"))
        for name, role in (("administrator", "admin"), ("researcher", "investigator"), ("observer", "viewer"), ("unrelated", "investigator")):
            if db.scalar(select(User).where(User.username == name)):
                raise SystemExit("Account name already exists; refusing to replace it.")
            password = secrets.token_urlsafe(20)
            user = User(username=name, role=role, password_hash=hasher.hash(password))
            db.add(user)
            db.flush()
            audit(db, None, "user.provision_local", "user", user.id, role=role)
            credentials[name] = {"password": password, "role": role, "id": user.id}
        db.commit()
    destination.parent.mkdir(exist_ok=True)
    with destination.open("x", encoding="utf-8") as output:
        json.dump(credentials, output, indent=2)
    with TestClient(create_app(get_settings(), factory)) as client:
        def login(name):
            client.cookies.clear()
            response = client.post("/api/auth/login", json={"username": name, "password": credentials[name]["password"]}, headers={"X-Spectre-Login": "1"})
            assert response.status_code == 200
            return {"X-CSRF-Token": response.json()["csrf_token"]}
        headers = login("researcher")
        case = client.post("/api/cases", json={"title": "Phase 02 live verification", "description": "Synthetic reserved-example seeds; no collection performed."}, headers=headers)
        assert case.status_code == 201
        case_id = case.json()["id"]
        path = f"/api/cases/{case_id}/targets"
        domain_id = None
        for kind, value, canonical in (
            ("domain", "EXAMPLE.COM.", "example.com"),
            ("ipv4", "192.0.2.1", "192.0.2.1"),
            ("ipv6", "2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
            ("url", "HTTPS://EXAMPLE.COM:443#part", "https://example.com/"),
            ("organization", "Example   Company", "example company"),
            ("username", "ExampleUser", "ExampleUser"),
            ("email", "User@EXAMPLE.COM", "User@example.com")):
            response = client.post(path, json={"type": kind, "value": value}, headers=headers)
            assert response.status_code == 201, response.status_code
            assert response.json()["normalized_value"] == canonical
            if kind == "domain":
                domain_id = response.json()["id"]
        assert client.post(path, json={"type": "domain", "value": "example.com"}, headers=headers).status_code == 409
        specific = f"{path}/{domain_id}"
        for scope in ("active_authorized", "excluded"):
            response = client.put(specific, json={"type": "domain", "value": "example.org", "scope_status": scope}, headers=headers)
            assert response.status_code == 200
            assert response.json()["scope_status"] == scope
        assert client.delete(specific, headers=headers).status_code == 204
        assert client.get(specific).json()["archived"] is True
        viewer_id = credentials["observer"]["id"]
        assert client.put(f"/api/cases/{case_id}/members/{viewer_id}", headers=headers).status_code == 204
        headers = login("observer")
        assert client.get(path).status_code == 200
        assert client.post(path, json={"type": "domain", "value": "example.net"}, headers=headers).status_code == 403
        login("unrelated")
        assert client.get(path).status_code == 404
        login("administrator")
        assert client.get(path).status_code == 200
        actions = {row["action"] for row in client.get(f"/api/cases/{case_id}/audit").json()}
        assert {"target.create", "target.update", "target.archive", "admin.case_access"} <= actions
    print("Live MySQL schema, seven target types, normalization, duplicates, scope/edit/archive, RBAC and audit checks passed.")
    print("Private login credentials: .local/login-credentials.json. Synthetic verification case retained.")


if __name__ == "__main__":
    main()
