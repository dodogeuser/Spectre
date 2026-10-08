"""Non-destructive live transactional rollback and failed-run checks."""
import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.collectors.mock import MockCollector
from app.collectors.registry import CollectorRegistry
from app.config import get_settings
from app.db.models import CollectorRun, Evidence
from app.db.session import make_session_factory
from app.main import create_app


class FailureFixture(MockCollector):
    name = "failure_fixture"
    async def collect(self, target, context):
        raise RuntimeError("private fixture diagnostic")


def main():
    factory = make_session_factory(get_settings())
    with factory() as db:
        count = db.scalar(select(func.count()).select_from(Evidence))
        run = db.scalar(select(CollectorRun).where(CollectorRun.status == "completed"))
        assert run is not None
        db.add(Evidence(run_id=run.id, source_type="synthetic", source_ref="mock://rollback-check",
                        sha256="0" * 64, raw_json={}, parsed_json={}))
        db.flush()
        db.rollback()
        assert db.scalar(select(func.count()).select_from(Evidence)) == count
    credentials = json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    app = create_app(get_settings(), factory)
    app.state.collector_registry = CollectorRegistry((FailureFixture(),))
    with TestClient(app) as client:
        identity = client.post("/api/auth/login", json={"username": "researcher", "password": credentials["researcher"]["password"]}, headers={"X-Spectre-Login": "1"})
        assert identity.status_code == 200
        headers = {"X-CSRF-Token": identity.json()["csrf_token"]}
        case = client.post("/api/cases", json={"title": "Phase 03 failure isolation verification"}, headers=headers).json()
        case_id = case["id"]
        target = client.post(f"/api/cases/{case_id}/targets", json={"type": "domain", "value": "example.net"}, headers=headers).json()
        response = client.post(f"/api/cases/{case_id}/targets/{target['id']}/collectors/failure_fixture/runs", headers=headers)
        assert response.status_code == 201 and response.json()["status"] == "failed"
        assert response.json()["error_code"] == "collector_error"
        assert "private fixture diagnostic" not in response.text
        run_id = response.json()["id"]
        assert client.get(f"/api/cases/{case_id}/runs/{run_id}/evidence").json() == []
        assert client.get(f"/api/cases/{case_id}").json()["title"] == case["title"]
        actions = {row["action"] for row in client.get(f"/api/cases/{case_id}/audit").json()}
        assert {"collector.started", "collector.failed"} <= actions
    print("Live InnoDB rollback and sanitized failed-run/evidence/audit checks passed; synthetic failure case retained.")


if __name__ == "__main__":
    main()
