"""Apply Phase 03 migrations and exercise offline framework on existing MySQL."""
import hashlib
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.collectors.registry import CollectorRegistry
from app.config import get_settings
from app.db.session import make_session_factory
from app.main import create_app
from app.services.evidence import canonical_bytes


def main():
    settings = get_settings()
    factory = make_session_factory(settings)
    def snapshot(db):
        order = {"users": "id", "cases": "id", "targets": "id", "audit_logs": "id",
                 "login_sessions": "token_hash", "case_members": "case_id,user_id"}
        return {table: [tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {key}"))]
                for table, key in order.items()}
    with factory() as db:
        revision = db.scalar(text("SELECT version_num FROM alembic_version"))
        if revision not in {"002", "003"}:
            raise SystemExit("Expected revision 002 or 003; no migration changes made.")
        before = snapshot(db)
    command.upgrade(Config("alembic.ini"), "004")
    with factory() as db:
        assert snapshot(db) == before
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "004"
        assert all(row[0] == "InnoDB" for row in db.execute(text("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")))
        inspector = inspect(db.bind)
        assert {"collector_runs", "evidence"} <= set(inspector.get_table_names())
        assert {"target_snapshot", "version", "actor_id", "error_code"} <= {c["name"] for c in inspector.get_columns("collector_runs")}
        assert {"sha256", "source_ref", "captured_at", "raw_json", "parsed_json"} <= {c["name"] for c in inspector.get_columns("evidence")}
        assert inspector.get_foreign_keys("evidence") and inspector.get_foreign_keys("collector_runs")
    credentials = json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    app = create_app(settings, factory)
    with TestClient(app) as client:
        def login(name):
            client.cookies.clear()
            response = client.post("/api/auth/login", json={"username": name, "password": credentials[name]["password"]}, headers={"X-Spectre-Login": "1"})
            assert response.status_code == 200
            return {"X-CSRF-Token": response.json()["csrf_token"]}
        headers = login("researcher")
        response = client.post("/api/cases", json={"title": "Phase 03 framework verification", "description": "Synthetic mock evidence only; zero external target requests."}, headers=headers)
        assert response.status_code == 201
        case_id = response.json()["id"]
        base = f"/api/cases/{case_id}"
        target = client.post(f"{base}/targets", json={"type": "domain", "value": "example.com"}, headers=headers).json()
        endpoint = f"{base}/targets/{target['id']}/collectors/mock/runs"
        run = client.post(endpoint, headers=headers).json()
        assert run["status"] == "completed"
        evidence = client.get(f"{base}/runs/{run['id']}/evidence").json()
        assert len(evidence) == 1 and evidence[0]["source_type"] == "synthetic"
        assert evidence[0]["sha256"] == hashlib.sha256(canonical_bytes(evidence[0]["raw_json"])).hexdigest()
        client.put(f"{base}/targets/{target['id']}", json={"type": "domain", "value": "example.com", "scope_status": "excluded"}, headers=headers)
        assert client.post(endpoint, headers=headers).status_code == 403
        assert client.put(f"{base}/members/{credentials['observer']['id']}", headers=headers).status_code == 204
        viewer = login("observer")
        assert client.get(f"{base}/runs/{run['id']}/evidence").status_code == 200
        assert client.post(endpoint, headers=viewer).status_code == 403
        login("unrelated")
        assert client.get(f"{base}/runs/{run['id']}/evidence").status_code == 404
        login("administrator")
        actions = {row["action"] for row in client.get(f"{base}/audit").json()}
        assert {"collector.started", "collector.completed", "collector.denied", "admin.case_access"} <= actions
    print("Phase 03 migrations applied through 004; existing rows preserved exactly across migration.")
    print("Live MySQL schema, mock evidence hash/provenance, scope/RBAC denial and audit checks passed.")
    print("Synthetic Phase 03 verification case retained for review.")


if __name__ == "__main__":
    main()
