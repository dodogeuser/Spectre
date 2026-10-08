"""Non-destructive Phase 06 MySQL fixture/API verification, no public requests."""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.config import get_settings
from app.db.session import make_session_factory
from app.main import create_app
from app.services.evidence import canonical_bytes
from tests.web_fixtures import WebFixtureHTTP


def main():
    settings=get_settings(); factory=make_session_factory(settings)
    tables={"users":"id","cases":"id","targets":"id","case_members":"case_id,user_id","audit_logs":"id","collector_runs":"id","evidence":"id","entities":"id","relationships":"id"}
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version"))=="005"
        assert all(row[0]=="InnoDB" for row in db.execute(text("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")))
        before={table:[tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {key}"))] for table,key in tables.items()}
    credentials=json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    fixture=WebFixtureHTTP()
    async def fixture_get(self,url,**kwargs): return await fixture.get(url,**kwargs)
    def login(client,name):
        response=client.post("/api/auth/login",json={"username":name,"password":credentials[name]["password"]},headers={"X-Spectre-Login":"1"})
        assert response.status_code==200
        return {"X-CSRF-Token":response.json()["csrf_token"]}
    with patch("app.services.http_client.ControlledHttpClient.get",fixture_get),TestClient(create_app(settings,factory)) as client:
        headers=login(client,"researcher")
        case=client.post("/api/cases",json={"title":"Phase 06 synthetic fixture verification","description":"Inert HTML and synthetic HTTP states only; explicitly labeled, not live intelligence."},headers=headers).json()
        base=f"/api/cases/{case['id']}"
        target=client.post(base+"/targets",json={"type":"url","value":"https://example.com/"},headers=headers).json()
        endpoint=f"{base}/targets/{target['id']}/collectors/web_metadata/runs"
        runs=[]
        for status,body,media,expected in [(200,None,"text/html","completed"),(404,None,"text/html","completed"),(429,None,"text/html","failed"),(200,b"<title>unclosed","text/html","completed"),(200,b"pdf","application/pdf","failed")]:
            fixture.status,fixture.body,fixture.content_type=status,body,media
            response=client.post(endpoint,headers=headers)
            assert response.status_code==201 and response.json()["status"]==expected
            runs.append(response.json()["id"])
        data=client.get(f"{base}/targets/{target['id']}/web").json()
        assert len(data["observations"])==4
        assert {item["parsed"]["availability"] for item in data["observations"]}=={"observed","negative_http_response","rate_limited","partial"}
        for item in data["observations"]:
            evidence=client.get(f"{base}/evidence/{item['evidence_id']}").json()
            assert evidence["sha256"]==hashlib.sha256(canonical_bytes(evidence["raw_json"])).hexdigest()
        count=len(fixture.calls)
        assert client.post(endpoint).status_code==403
        excluded=client.post(base+"/targets",json={"type":"url","value":"https://example.org/","scope_status":"excluded"},headers=headers).json()
        assert client.post(f"{base}/targets/{excluded['id']}/collectors/web_metadata/runs",headers=headers).status_code==403
        assert client.put(base+"/members/3",headers=headers).status_code==204
        viewer=login(client,"observer")
        assert client.get(f"{base}/targets/{target['id']}/web").status_code==200
        assert client.post(endpoint,headers=viewer).status_code==403
        other=login(client,"unrelated")
        assert client.get(f"{base}/targets/{target['id']}/web").status_code==404
        assert client.post(endpoint,headers=other).status_code==404
        assert len(fixture.calls)==count
        login(client,"researcher")
        actions={row["action"] for row in client.get(base+"/audit").json()}
        assert {"collector.started","collector.completed","collector.failed","collector.denied"}<=actions
    with factory() as db:
        for table,rows in before.items():
            after={tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {tables[table]}"))}
            assert all(row in after for row in rows),f"Existing {table} records changed"
    report={"case_id":case["id"],"target_id":target["id"],"excluded_target_id":excluded["id"],"run_ids":runs,"revision":"005","existing_records_preserved":True,"fixture_only":True}
    Path(".local/phase06-fixture-verification.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report))


if __name__=="__main__": main()
