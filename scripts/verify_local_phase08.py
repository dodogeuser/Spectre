"""Read-only Phase 08 live server/MySQL checks; no collection or correlation jobs."""
import hashlib
import json
from pathlib import Path

import httpx
from sqlalchemy import text
from app.config import get_settings
from app.db.session import make_session_factory
from app.services.evidence import canonical_bytes


def main():
    factory = make_session_factory(get_settings())
    tables = {"users":"id", "cases":"id", "targets":"id", "case_members":"case_id,user_id", "audit_logs":"id", "collector_runs":"id", "evidence":"id", "entities":"id", "relationships":"id"}
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "005"
        before = {table: [tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {key}"))] for table,key in tables.items()}
    credentials = json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    def login(client,name):
        client.cookies.clear()
        response = client.post("/api/auth/login", json={"username":name,"password":credentials[name]["password"]}, headers={"X-Spectre-Login":"1"})
        assert response.status_code == 200
    checks = []
    with httpx.Client(base_url="http://127.0.0.1:8000", timeout=30, trust_env=False) as client:
        login(client,"researcher")
        for case in (7,9,12):
            base = f"/api/cases/{case}"
            response = client.get(base+"/investigation")
            assert response.status_code == 200
            graph = response.json()
            supports = {row["id"] for row in graph["evidence"]}
            assert all(set(edge["evidence_ids"]) <= supports for edge in graph["relationships"])
            assert len({(edge["from"],edge["to"],edge["type"]) for edge in graph["relationships"]}) == len(graph["relationships"])
            for node in graph["entities"]:
                detail = client.get(f"{base}/entities/{node['id']}/detail")
                assert detail.status_code == 200
                for evidence in detail.json()["evidence"]:
                    item = client.get(f"{base}/evidence/{evidence['id']}").json()
                    assert item["sha256"] == hashlib.sha256(canonical_bytes(item["raw_json"])).hexdigest()
            events=[];offset=0
            while True:
                page=client.get(f"{base}/timeline?offset={offset}").json()
                assert page == client.get(f"{base}/timeline?offset={offset}").json()
                events.extend(page["events"])
                if not page["has_more"]: break
                offset += 100
            assert events == sorted(events,key=lambda e:(e["timestamp"],e["type"],e["key"]))
            assert len({event["key"] for event in events}) == len(events)
            checks.append({"case_id":case,"entities":len(graph["entities"]),"relationships":len(graph["relationships"]),"timeline_events":len(events)})
        login(client,"observer")
        assert client.get("/api/cases/10/investigation").status_code == 200
        assert client.get("/api/cases/10/timeline").status_code == 200
        login(client,"unrelated")
        for route in ("investigation","timeline","entities/1/detail"):
            assert client.get("/api/cases/12/"+route).status_code == 404
        assert client.get("/static/vendor/cytoscape.min.js").status_code == 200
        assert client.get("/static/js/investigation.js").status_code == 200
    with factory() as db:
        for table, rows in before.items():
            after=[tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {tables[table]}"))]
            if table == "audit_logs":
                assert all(row in after for row in rows), "Existing audit records changed"
                assert all(row[2] == "auth.login" for row in after if row not in rows), "Read-only verification wrote a non-login audit"
            else:
                assert after == rows, f"Read views changed {table}"
    report={"cases":checks,"revision":"005","existing_records_unchanged":True,"read_only_no_collection":True,"ordering_linkage_rbac":"passed","manual_browser":"unavailable: no browser surface; prior native browser policy limitation persists"}
    Path(".local/phase08-verification.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__": main()
