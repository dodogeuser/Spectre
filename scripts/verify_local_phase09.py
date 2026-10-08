"""Live Phase 09 API/MySQL verification using retained public page evidence only."""
import hashlib
import json
from pathlib import Path
import httpx
from sqlalchemy import text
from app.config import get_settings
from app.db.session import make_session_factory
from app.services.evidence import canonical_bytes


def main():
    factory=make_session_factory(get_settings())
    tables={"users":"id","cases":"id","targets":"id","case_members":"case_id,user_id","audit_logs":"id","collector_runs":"id","evidence":"id","entities":"id","relationships":"id"}
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version"))=="006"
        before={table:[tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {key}"))] for table,key in tables.items()}
    credentials=json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    def login(client,name):
        client.cookies.clear()
        result=client.post("/api/auth/login",json={"username":name,"password":credentials[name]["password"]},headers={"X-Spectre-Login":"1"})
        assert result.status_code==200
        return {"X-CSRF-Token":result.json()["csrf_token"]}
    with httpx.Client(base_url="http://127.0.0.1:8000",timeout=30,trust_env=False) as client:
        headers=login(client,"researcher");base="/api/cases/12"
        first=client.post(base+"/findings/generate",headers=headers)
        assert first.status_code==201
        findings=client.get(base+"/findings").json()["findings"]
        assert len(findings)==6
        assert all(row["severity"]=="informational" and row["confidence"]==.95 for row in findings)
        repeated=client.post(base+"/findings/generate",headers=headers).json()
        assert repeated["created"]==repeated["updated"]==0 and repeated["unchanged"]==6
        assert client.get(base+"/findings").json()["findings"]==findings
        for finding in findings:
            detail=client.get(base+f"/findings/{finding['id']}").json()
            assert detail["entity_id"] is not None and detail["target_id"]==24
            assert detail["generated_json"]["evidence_ids"]==[61]
            assert detail["generated_json"]["why"] and detail["generated_json"]["scoring_version"]=="1.0.0"
            assert any(row["id"]==61 for row in detail["evidence"])
            evidence=client.get(base+"/evidence/61").json()
            assert evidence["sha256"]==hashlib.sha256(canonical_bytes(evidence["raw_json"])).hexdigest()
            assert evidence["parsed_json"]["title"]=="Example Domain" and evidence["run_id"]==35
            assert client.get(base+f"/entities/{detail['entity_id']}/detail").status_code==200
        finding=findings[0];path=base+f"/findings/{finding['id']}"
        override_test=False
        if first.json()["created"]==6 or (finding["override_reason"]=="Verification complete; restore rule severity." and finding["status"]=="informational" and finding["notes"]=="" and finding["severity_override"] is None):
            changed=client.patch(path,json={"severity_override":"low","override_reason":"Phase 09 verification: analyst severity remains separate from observation confidence.","status":"accepted","notes":"Temporary Phase 09 verification note."},headers=headers).json()
            assert changed["severity"]=="low" and changed["confidence"]==.95
            assert changed["original_json"]==finding["original_json"]
            restored=client.patch(path,json={"severity_override":None,"override_reason":"Verification complete; restore rule severity.","status":finding["status"],"notes":finding["notes"]},headers=headers).json()
            assert restored["severity"]=="informational" and restored["original_json"]==finding["original_json"]
            override_test=True
        assert client.post(base+"/findings/generate").status_code==403
        assert client.patch(path,json={"status":"open"}).status_code==403
        actions={row["action"] for row in client.get(base+"/audit").json()}
        assert {"finding.generated","findings.generated"}<=actions
        if override_test:assert {"finding.status_changed","finding.updated","finding.severity_overridden"}<=actions
        viewer=login(client,"observer")
        assert client.get("/api/cases/10/findings").status_code==200
        assert client.post("/api/cases/10/findings/generate",headers=viewer).status_code==403
        other=login(client,"unrelated")
        assert client.get(base+"/findings").status_code==404
        assert client.get(path).status_code==404
        assert client.patch(path,json={"status":"open"},headers=other).status_code==404
        assert client.post(base+"/findings/generate",headers=other).status_code==404
    with factory() as db:
        for table,rows in before.items():
            after={tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY {tables[table]}"))}
            assert all(row in after for row in rows),f"Existing {table} row changed"
            if table!="audit_logs":assert len(after)==len(rows),f"Unexpected write to {table}"
        assert db.scalar(text("SELECT COUNT(*) FROM finding_evidence fe JOIN findings f ON f.id=fe.finding_id JOIN evidence e ON e.id=fe.evidence_id JOIN collector_runs r ON r.id=e.run_id JOIN targets t ON t.id=r.target_id WHERE f.case_id<>t.case_id"))==0
    report={"case_id":12,"target_id":24,"entity_id":findings[0]["entity_id"],"run_id":35,"evidence_id":61,"finding_ids":[row["id"] for row in findings],"revision":"006","replay":"passed","provenance_hash_explanation":"passed","rbac_csrf_audit":"passed","analyst_override_verified":override_test,"previous_records_preserved":True,"new_collection":False}
    Path(".local/phase09-verification.json").write_text(json.dumps(report,indent=2),encoding="utf-8");print(json.dumps(report))


if __name__=="__main__":main()
