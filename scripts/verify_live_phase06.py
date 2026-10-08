"""One scoped live HTTPS page through the central API; preserve existing records."""
import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import get_settings
from app.db.session import make_session_factory
from app.main import create_app
from app.security.url_policy import public_address
from app.services.evidence import canonical_bytes


def main():
    settings = get_settings()
    factory = make_session_factory(settings)
    tables = {"users": "id", "cases": "id", "targets": "id", "case_members": "case_id,user_id", "audit_logs": "id", "collector_runs": "id", "evidence": "id", "entities": "id", "relationships": "id"}
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "005"
        before = {table: [tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {key}"))] for table, key in tables.items()}
    credentials = json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    with TestClient(create_app(settings, factory)) as client:
        response = client.post("/api/auth/login", json={"username": "researcher", "password": credentials["researcher"]["password"]}, headers={"X-Spectre-Login": "1"})
        assert response.status_code == 200
        headers = {"X-CSRF-Token": response.json()["csrf_token"]}
        response = client.post("/api/cases", json={"title": "Phase 06 live page verification", "description": "One unauthenticated public HTTPS page; historical metadata observations only."}, headers=headers)
        assert response.status_code == 201
        case = response.json()["id"]
        base = f"/api/cases/{case}"
        response = client.post(base + "/targets", json={"type": "url", "value": "https://example.com/", "scope_status": "passive_allowed"}, headers=headers)
        assert response.status_code == 201
        target = response.json()["id"]
        response = client.post(f"{base}/targets/{target}/collectors/web_metadata/runs", headers=headers)
        assert response.status_code == 201
        run = response.json()
        records = client.get(f"{base}/runs/{run['id']}/evidence").json()
        for item in records:
            assert item["sha256"] == hashlib.sha256(canonical_bytes(item["raw_json"])).hexdigest()
            metadata = item["raw_json"]["metadata"]
            assert not metadata.get("synthetic_fixture")
            assert metadata["resolved_ip"] == public_address(metadata["resolved_ip"])
            assert item["source_ref"].startswith("https://")
            assert item["parsed_json"]["provider"]
            assert all(finding["severity"] == "informational" for finding in item["parsed_json"]["findings"])
        overview = client.get(f"{base}/targets/{target}/web")
        assert overview.status_code == 200
        audits = client.get(base + "/audit").json()
        assert any(row["action"] == "collector.started" and row["metadata"].get("run_id") == run["id"] for row in audits)
        outcome = "collector.completed" if run["status"] == "completed" else "collector.failed"
        assert any(row["action"] == outcome and row["metadata"].get("run_id") == run["id"] for row in audits)
        report = {"case_id": case, "target_id": target, "run_id": run["id"], "status": run["status"], "error_code": run["error_code"], "evidence_ids": [row["id"] for row in records], "observations": [row["parsed_json"] for row in records], "revision": "005", "manual_browser": "pending: browser automation surface unavailable"}
    with factory() as db:
        for table, rows in before.items():
            after = {tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {tables[table]}"))}
            assert all(row in after for row in rows), f"Existing {table} records changed"
        all_records = db.execute(text("SELECT raw_json, sha256 FROM evidence")).all()
        for raw, digest in all_records:
            document = json.loads(raw) if isinstance(raw, str) else raw
            assert digest == hashlib.sha256(canonical_bytes(document)).hexdigest()
    report.update(existing_records_preserved=True, all_hashes_verified=len(all_records))
    Path(".local/phase06-live-verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
