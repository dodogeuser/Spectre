"""Non-destructive 004 -> 005 verification and synthetic provider fixtures on MySQL."""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.config import get_settings
from app.db.session import make_session_factory
from app.main import create_app
from app.services.evidence import canonical_bytes
from tests.domain_fixtures import FixtureHTTP


def main():
    settings = get_settings()
    factory = make_session_factory(settings)
    def snapshot(db):
        order = {"users": "id", "cases": "id", "targets": "id", "audit_logs": "id", "login_sessions": "token_hash",
                 "case_members": "case_id,user_id", "collector_runs": "id", "evidence": "id"}
        return {table: [tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {key}"))] for table, key in order.items()}
    with factory() as db:
        if db.scalar(text("SELECT version_num FROM alembic_version")) != "004":
            raise SystemExit("Expected 004; refusing to reapply or overwrite anything.")
        before = snapshot(db)
    command.upgrade(Config("alembic.ini"), "005")
    with factory() as db:
        assert snapshot(db) == before
        schema = inspect(db.bind)
        assert len(schema.get_foreign_keys("entities")) == 1
        assert len(schema.get_foreign_keys("relationships")) == 4
        assert all(row[0] == "InnoDB" for row in db.execute(text("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")))
    credentials = json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    fixtures = FixtureHTTP()
    async def fixture_get(self, url, **kwargs):
        return await fixtures.get(url, **kwargs)
    with patch("app.services.http_client.ControlledHttpClient.get", fixture_get), TestClient(create_app(settings, factory)) as client:
        login = client.post("/api/auth/login", json={"username": "researcher", "password": credentials["researcher"]["password"]}, headers={"X-Spectre-Login": "1"})
        assert login.status_code == 200
        headers = {"X-CSRF-Token": login.json()["csrf_token"]}
        case = client.post("/api/cases", json={"title": "Phase 04 synthetic fixture verification", "description": "Synthetic provider fixtures only. Evidence raw metadata is explicitly marked synthetic_fixture."}, headers=headers).json()
        base = f"/api/cases/{case['id']}"
        target = client.post(base + "/targets", json={"type": "domain", "value": "example.com"}, headers=headers).json()
        for name in ("dns", "rdap", "ct"):
            run = client.post(f"{base}/targets/{target['id']}/collectors/{name}/runs", headers=headers).json()
            assert run["status"] == "completed"
        overview = client.get(f"{base}/targets/{target['id']}/domain").json()
        assert len(overview["observations"]) == 9 and overview["relationships"]
        for item in overview["observations"]:
            evidence = client.get(f"{base}/evidence/{item['evidence_id']}").json()
            assert evidence["raw_json"]["metadata"]["synthetic_fixture"] is True
            assert evidence["sha256"] == hashlib.sha256(canonical_bytes(evidence["raw_json"])).hexdigest()
        actions = {entry["action"] for entry in client.get(base + "/audit").json()}
        assert {"collector.started", "collector.completed"} <= actions
        # Stored malformed provider response is visible, creates no successful fact.
        fixtures.bad = "malformed"
        run = client.post(f"{base}/targets/{target['id']}/collectors/ct/runs", headers=headers).json()
        assert run["status"] == "failed" and run["error_code"] == "malformed_response"
    print("Migration 005 applied; existing rows preserved; new tables use InnoDB with enforced foreign keys.")
    print("Live MySQL fixture success, failure, evidence hashes, domain projection and audit checks passed.")
    print("Synthetic verification case retained; no external provider requests were made by this script.")


if __name__ == "__main__":
    main()
