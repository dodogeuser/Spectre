"""Check retained Phase 04 verification records and live MySQL authorization."""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.config import get_settings
from app.db.models import Evidence, CollectorRun, Relationship, Target
from app.db.session import make_session_factory
from app.main import create_app
from app.services.evidence import canonical_bytes


def main():
    settings = get_settings()
    factory = make_session_factory(settings)
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "005"
        records = list(db.scalars(select(Evidence)))
        for evidence in records:
            assert evidence.sha256 == hashlib.sha256(canonical_bytes(evidence.raw_json)).hexdigest()
        runs = list(db.scalars(select(CollectorRun).where(CollectorRun.id.in_([9, 10, 11]))))
        assert len(runs) == 3 and all(run.status == "completed" for run in runs)
        assert {run.collector for run in runs} == {"dns", "rdap", "ct"}
        assert all(row[0] == "InnoDB" for row in db.execute(text("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")))
        relations = list(db.scalars(select(Relationship)))
        for relation in relations:
            evidence = db.get(Evidence, relation.evidence_id)
            run = db.get(CollectorRun, evidence.run_id)
            target = db.get(Target, run.target_id)
            assert target.case_id == relation.case_id and 0 <= relation.confidence <= 1
    credentials = json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    def no_network(*args, **kwargs):
        raise AssertionError("Rejected requests and stored reads must not contact providers")
    def login(client, username):
        response = client.post("/api/auth/login", json={"username": username, "password": credentials[username]["password"]}, headers={"X-Spectre-Login": "1"})
        assert response.status_code == 200
        return {"X-CSRF-Token": response.json()["csrf_token"]}
    with patch("app.services.http_client.ControlledHttpClient.get", no_network), TestClient(create_app(settings, factory)) as client:
        investigator = login(client, "researcher")
        for name in ("dns", "rdap", "ct"):
            assert client.post(f"/api/cases/3/targets/9/collectors/{name}/runs", headers=investigator).status_code == 403
        assert client.get("/api/cases/7/evidence/23").status_code == 200
        assert client.get("/api/cases/7/targets/13/domain").status_code == 200
        viewer = login(client, "observer")
        for name in ("dns", "rdap", "ct"):
            assert client.post(f"/api/cases/3/targets/9/collectors/{name}/runs", headers=viewer).status_code == 403
        assert client.get("/api/cases/7/evidence/23").status_code == 404
        other = login(client, "unrelated")
        assert client.get("/api/cases/7/targets/13/domain").status_code == 404
        for name in ("dns", "rdap", "ct"):
            assert client.post(f"/api/cases/7/targets/13/collectors/{name}/runs", headers=other).status_code == 404
    print(f"005 head; {len(records)} evidence hashes and {len(relations)} relationship references checked.")
    print("Real DNS/RDAP/CT runs completed; live MySQL scope, viewer and unrelated-account API restrictions passed.")


if __name__ == "__main__":
    main()
