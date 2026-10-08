"""Correlate retained case evidence through the API; never collect or provision."""
import hashlib
import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.config import get_settings
from app.db.models import CollectorRun, Entity, Evidence, Relationship, Target
from app.db.session import make_session_factory
from app.main import create_app
from app.services.evidence import canonical_bytes


def main():
    settings = get_settings()
    factory = make_session_factory(settings)
    tables = {"users": "id", "cases": "id", "targets": "id", "case_members": "case_id,user_id", "audit_logs": "id", "collector_runs": "id", "evidence": "id", "entities": "id", "relationships": "id"}
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "005"
        before = {table: [tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {key}"))] for table, key in tables.items()}
    credentials = json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    def login(client, name):
        client.cookies.clear()
        result = client.post("/api/auth/login", json={"username": name, "password": credentials[name]["password"]}, headers={"X-Spectre-Login": "1"})
        assert result.status_code == 200
        return {"X-CSRF-Token": result.json()["csrf_token"]}
    results = []
    if "--http" in sys.argv:
        import httpx
        transport = httpx.Client(base_url="http://127.0.0.1:8000", timeout=30, trust_env=False)
    else:
        transport = TestClient(create_app(settings, factory))
    with transport as client:
        headers = login(client, "researcher")
        for case in (7, 9, 12):
            base = f"/api/cases/{case}"
            result = client.post(base + "/correlation/jobs", headers=headers)
            assert result.status_code == 201 and not result.json()["has_more"]
            graph = client.get(base + "/graph").json()
            repeated = client.post(base + "/correlation/jobs", headers=headers)
            assert repeated.status_code == 201
            assert repeated.json()["entities_created"] == repeated.json()["supports_created"] == 0
            assert client.get(base + "/graph").json() == graph
            assert not graph["truncated"]
            assert all(row["evidence_ids"] and row["first_seen"] <= row["last_seen"] for row in graph["relationships"])
            assert client.get(base + "/entities").status_code == 200
            assert client.get(base + "/relationships").status_code == 200
            assert client.get(base + "/correlation/jobs").json()[0]["status"] == "completed"
            assert client.post(base + "/correlation/jobs").status_code == 403
            results.append({"case_id": case, "first_job": result.json(), "repeated_job": repeated.json(), "entities": len(graph["entities"]), "relationships": len(graph["relationships"]), "types": sorted({row["type"] for row in graph["relationships"]})})
        viewer = login(client, "observer")
        assert client.get("/api/cases/10/graph").status_code == 200
        assert client.post("/api/cases/10/correlation/jobs", headers=viewer).status_code == 403
        other = login(client, "unrelated")
        assert client.get("/api/cases/12/graph").status_code == 404
        assert client.post("/api/cases/12/correlation/jobs", headers=other).status_code == 404
    with factory() as db:
        for table, rows in before.items():
            after = {tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {tables[table]}"))}
            assert all(row in after for row in rows), f"Existing {table} records changed"
        evidence = list(db.scalars(select(Evidence)))
        for item in evidence:
            assert item.sha256 == hashlib.sha256(canonical_bytes(item.raw_json)).hexdigest()
        relations = list(db.scalars(select(Relationship)))
        for relation in relations:
            item = db.get(Evidence, relation.evidence_id)
            run = db.get(CollectorRun, item.run_id)
            target = db.get(Target, run.target_id)
            assert target.case_id == relation.case_id == db.get(Entity, relation.from_entity_id).case_id == db.get(Entity, relation.to_entity_id).case_id
        assert all(row[0] == "InnoDB" for row in db.execute(text("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")))
    report = {"cases": results, "revision": "005", "existing_records_preserved": True, "evidence_hashes_verified": len(evidence), "relationship_integrity_verified": len(relations), "network_collection": False, "rbac_csrf_isolation": "passed", "transport": "live loopback HTTP" if "--http" in sys.argv else "local ASGI"}
    Path(".local/phase07-verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
