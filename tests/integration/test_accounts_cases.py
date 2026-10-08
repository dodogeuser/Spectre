import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.auth import digest, hasher
from app.config import Settings
from app.db.models import AuditLog, Base, LoginSession, User, utcnow
from app.main import create_app


@pytest.fixture
def system():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as db:
        for name, role in (("admin", "admin"), ("owner", "investigator"), ("other", "investigator"), ("viewer", "viewer")):
            db.add(User(username=name, role=role, password_hash=hasher.hash("test-password-only")))
        db.commit()
    with TestClient(create_app(Settings(_env_file=None), factory)) as client:
        yield client, factory
    engine.dispose()


def login(client, username):
    client.cookies.clear()
    response = client.post("/api/auth/login", json={"username": username, "password": "test-password-only"}, headers={"X-Spectre-Login": "1"})
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def test_case_isolation_viewer_and_audited_admin(system):
    client, factory = system
    owner = login(client, "owner")
    response = client.post("/api/cases", json={"title": "Case A"}, headers=owner)
    assert response.status_code == 201
    case_id = response.json()["id"]
    assert client.put(f"/api/cases/{case_id}/members/4", headers=owner).status_code == 204
    other = login(client, "other")
    assert client.get("/api/cases").json() == []
    assert client.get(f"/api/cases/{case_id}").status_code == 404
    assert client.put(f"/api/cases/{case_id}", json={"title": "stolen"}, headers=other).status_code == 404
    assert client.put(f"/api/cases/{case_id}/members/3", headers=other).status_code == 404
    viewer = login(client, "viewer")
    assert client.get(f"/api/cases/{case_id}").status_code == 200
    assert client.post("/api/cases", json={"title": "denied"}, headers=viewer).status_code == 403
    assert client.put(f"/api/cases/{case_id}", json={"title": "denied"}, headers=viewer).status_code == 403
    assert client.delete(f"/api/cases/{case_id}/members/4", headers=viewer).status_code == 403
    admin = login(client, "admin")
    assert client.get(f"/api/cases/{case_id}").status_code == 200
    assert client.put(f"/api/cases/{case_id}", json={"title": "Reviewed", "status": "archived"}, headers=admin).status_code == 200
    assert client.delete(f"/api/cases/{case_id}/members/4", headers=admin).status_code == 204
    viewer = login(client, "viewer")
    assert client.get(f"/api/cases/{case_id}").status_code == 404
    with factory() as db:
        actions = list(db.scalars(select(AuditLog.action)))
        assert {"case.create", "case.update", "case.member_add", "case.member_remove", "admin.case_access"} <= set(actions)
        assert all("test-password-only" not in row.password_hash and row.password_hash.startswith("$argon2id$") for row in db.scalars(select(User)))


def test_session_csrf_logout_and_expiry(system):
    client, factory = system
    assert client.get("/api/cases").status_code == 401
    headers = login(client, "owner")
    cookie = client.cookies.get("spectre_session")
    assert "HttpOnly" in client.post("/api/auth/login", json={"username": "owner", "password": "test-password-only"}, headers={"X-Spectre-Login": "1"}).headers["set-cookie"]
    assert client.post("/api/cases", json={"title": "no csrf"}).status_code == 403
    headers = {"X-CSRF-Token": client.get("/api/auth/me").json()["csrf_token"]}
    with factory() as db:
        assert db.get(LoginSession, digest(cookie)) is None  # Rotation revoked old token.
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/auth/me").status_code == 401
    login(client, "owner")
    with factory() as db:
        session = db.get(LoginSession, digest(client.cookies.get("spectre_session")))
        session.expires_at = utcnow()
        db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_login_failures_and_membership_controls(system):
    client, factory = system
    response = client.post("/api/auth/login", json={"username": "owner", "password": ""}, headers={"X-Spectre-Login": "1"})
    assert response.status_code == 422
    assert "input" not in response.text
    assert client.post("/api/auth/login", json={"username": "owner", "password": "wrong"}).status_code == 403
    for name in ("owner", "missing"):
        response = client.post("/api/auth/login", json={"username": name, "password": "wrong"}, headers={"X-Spectre-Login": "1"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
    owner = login(client, "owner")
    case_id = client.post("/api/cases", json={"title": "Team"}, headers=owner).json()["id"]
    assert client.delete(f"/api/cases/{case_id}/members/2", headers=owner).status_code == 409
    assert client.put(f"/api/cases/{case_id}/members/3", headers=owner).status_code == 204
    other = login(client, "other")
    assert client.put(f"/api/cases/{case_id}", json={"title": "Updated"}, headers=other).status_code == 200
    assert client.put(f"/api/cases/{case_id}/members/4", headers=other).status_code == 403
    with factory() as db:
        assert len(list(db.scalars(select(AuditLog).where(AuditLog.action == "auth.login_failed")))) == 2


def test_password_and_session_secrets_never_enter_logs_or_audits(system, capsys):
    client, factory = system
    headers = login(client, "owner")
    token = client.cookies.get("spectre_session")
    csrf = headers["X-CSRF-Token"]
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    with factory() as db:
        records = list(db.scalars(select(AuditLog).order_by(AuditLog.id)))
        assert [(row.actor_id, row.action) for row in records] == [(2, "auth.login"), (2, "auth.logout")]
        audit_text = str([(row.action, row.metadata_json) for row in records])
        assert list(db.scalars(select(LoginSession))) == []
    logs = capsys.readouterr().err
    for secret in ("test-password-only", token, csrf):
        assert secret not in logs
        assert secret not in audit_text


def test_case_persistence_and_admin_list_audit(system):
    client, factory = system
    headers = login(client, "owner")
    created = client.post("/api/cases", json={"title": "Persistent case", "description": "Saved locally"}, headers=headers).json()
    # A separate application instance uses the same persistent session factory.
    with TestClient(create_app(Settings(_env_file=None), factory)) as restarted:
        login(restarted, "owner")
        assert restarted.get(f"/api/cases/{created['id']}").json()["description"] == "Saved locally"
        login(restarted, "admin")
        assert restarted.get("/api/cases").json()[0]["id"] == created["id"]
    with factory() as db:
        entry = db.scalar(select(AuditLog).where(AuditLog.action == "admin.case_list"))
        assert entry.actor_id == 1


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/api/cases", None),
    ("POST", "/api/cases", {"title": "Unauthorized"}),
    ("GET", "/api/cases/1", None),
    ("PUT", "/api/cases/1", {"title": "Unauthorized"}),
    ("PUT", "/api/cases/1/members/2", None),
    ("DELETE", "/api/cases/1/members/2", None),
    ("GET", "/api/cases/1/audit", None),
])
def test_every_case_endpoint_requires_authentication(system, method, path, body):
    client, _ = system
    assert client.request(method, path, json=body).status_code == 401
