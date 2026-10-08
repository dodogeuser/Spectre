"""Non-destructive live MySQL fixture verification; no external collection."""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.config import get_settings
from app.db.session import make_session_factory
from app.main import create_app
from app.services.evidence import canonical_bytes
from tests.ip_fixtures import IPFixtureHTTP


def main():
    settings = get_settings()
    factory = make_session_factory(settings)
    # Existing login sessions can rotate/revoke as normal authentication occurs.
    order = {"users": "id", "cases": "id", "targets": "id", "audit_logs": "id", "case_members": "case_id,user_id",
             "collector_runs": "id", "evidence": "id", "entities": "id", "relationships": "id"}
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "005"
        before = {table: [tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {key}"))] for table, key in order.items()}
        schema = inspect(db.bind)
        assert len(schema.get_foreign_keys("entities")) == 1 and len(schema.get_foreign_keys("relationships")) == 4
        assert all(row[0] == "InnoDB" for row in db.execute(text("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")))
    credentials = json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    fixture = IPFixtureHTTP()
    async def fixture_get(self, url, **kwargs):
        return await fixture.get(url, **kwargs)
    def login(client, username):
        response = client.post("/api/auth/login", json={"username": username, "password": credentials[username]["password"]}, headers={"X-Spectre-Login": "1"})
        assert response.status_code == 200
        return {"X-CSRF-Token": response.json()["csrf_token"]}
    with patch("app.services.http_client.ControlledHttpClient.get", fixture_get), TestClient(create_app(settings, factory)) as client:
        headers = login(client, "researcher")
        case = client.post("/api/cases", json={"title": "Phase 05 synthetic fixture verification", "description": "Synthetic IP protocol fixtures only, not real intelligence. Provider responses carry synthetic_fixture metadata."}, headers=headers).json()
        base = f"/api/cases/{case['id']}"
        targets = []
        for kind, value in (("ipv4", "8.8.8.8"), ("ipv6", "2001:4860:4860::8888")):
            target = client.post(base + "/targets", json={"type": kind, "value": value}, headers=headers).json()
            targets.append(target)
            for name in ("reverse_dns", "ip_rdap", "ip_asn"):
                run = client.post(f"{base}/targets/{target['id']}/collectors/{name}/runs", headers=headers).json()
                assert run["status"] == "completed"
            overview = client.get(f"{base}/targets/{target['id']}/ip").json()
            assert len(overview["observations"]) == 5
            for item in overview["observations"]:
                evidence = client.get(f"{base}/evidence/{item['evidence_id']}").json()
                assert evidence["raw_json"]["metadata"]["synthetic_fixture"]
                assert evidence["sha256"] == hashlib.sha256(canonical_bytes(evidence["raw_json"])).hexdigest()
        fixture.mode, fixture.fail_at = "malformed", len(fixture.calls) + 2
        result = client.post(f"{base}/targets/{targets[0]['id']}/collectors/ip_asn/runs", headers=headers).json()
        assert result["status"] == "failed" and result["error_code"] == "malformed_response"
        evidence = client.get(f"{base}/runs/{result['id']}/evidence").json()
        assert len(evidence) == 2 and evidence[0]["parsed_json"]["status"] == "ok"
        before_calls = len(fixture.calls)
        excluded = client.post(base + "/targets", json={"type": "ipv4", "value": "1.1.1.1", "scope_status": "excluded"}, headers=headers).json()
        private = client.post(base + "/targets", json={"type": "ipv4", "value": "10.0.0.1"}, headers=headers).json()
        for name in ("reverse_dns", "ip_rdap", "ip_asn"):
            for target in (excluded, private):
                assert client.post(f"{base}/targets/{target['id']}/collectors/{name}/runs", headers=headers).status_code == 403
        # Read-only access to the explicit fixture case is retained for browser review.
        assert client.put(base + "/members/3", headers=headers).status_code == 204
        viewer = login(client, "observer")
        assert client.get(f"{base}/targets/{targets[0]['id']}/ip").status_code == 200
        for name in ("reverse_dns", "ip_rdap", "ip_asn"):
            assert client.post(f"{base}/targets/{targets[0]['id']}/collectors/{name}/runs", headers=viewer).status_code == 403
        unrelated = login(client, "unrelated")
        assert client.get(f"{base}/targets/{targets[0]['id']}/ip").status_code == 404
        for name in ("reverse_dns", "ip_rdap", "ip_asn"):
            assert client.post(f"{base}/targets/{targets[0]['id']}/collectors/{name}/runs", headers=unrelated).status_code == 404
        assert len(fixture.calls) == before_calls
        login(client, "researcher")
        actions = {row["action"] for row in client.get(base + "/audit").json()}
        assert {"collector.started", "collector.completed", "collector.failed", "collector.denied"} <= actions
    with factory() as db:
        for table, rows in before.items():
            after = {tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {order[table]}"))}
            assert all(row in after for row in rows), f"Existing {table} records changed"
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "005"
    report = {"case_id": case["id"], "targets": [target["id"] for target in targets], "partial_failed_run": result["id"], "revision": "005",
              "existing_records_preserved": True, "fixture_only": True}
    Path(".local/phase05-fixture-verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
