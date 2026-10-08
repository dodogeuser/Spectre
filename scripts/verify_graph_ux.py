"""Read-only Case 15 acceptance snapshot; no collection or graph-state DB writes."""
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
    tables=("users","cases","case_members","targets","collector_runs","evidence","entities","relationships","findings","finding_evidence","finding_relationships","finding_revisions","audit_logs")
    with factory() as db:
        before={table:[tuple(r) for r in db.execute(text(f"SELECT * FROM {table} ORDER BY 1"))] for table in tables}
        revision=db.scalar(text("SELECT version_num FROM alembic_version"))
    credentials=json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    with httpx.Client(base_url="http://127.0.0.1:8000",trust_env=False,timeout=20) as client:
        client.post("/api/auth/login",json={"username":"researcher","password":credentials["researcher"]["password"]},headers={"X-Spectre-Login":"1"}).raise_for_status()
        snapshot={}
        for name,path in (("graph","investigation"),("targets","targets"),("timeline","timeline")):
            response=client.get("/api/cases/15/"+path);response.raise_for_status();snapshot[name]=response.json()
        graph=snapshot["graph"];assert graph["case_id"]==15
        assert any(t["normalized_value"]=="iana.org" and t["case_id"]==15 for t in snapshot["targets"])
        support=set()
        for edge in graph["relationships"]:
            assert edge["evidence_ids"] and edge["support_ids"];support.update(edge["evidence_ids"])
        for evidence_id in support:
            r=client.get(f"/api/cases/15/evidence/{evidence_id}");r.raise_for_status();e=r.json()
            assert hashlib.sha256(canonical_bytes(e["raw_json"])).hexdigest()==e["sha256"]
        assert client.get("/api/cases/15/ai/status").json()["configured"] is False
        for username in ("observer","unrelated"):
            client.cookies.clear();client.post("/api/auth/login",json={"username":username,"password":credentials[username]["password"]},headers={"X-Spectre-Login":"1"}).raise_for_status()
            for path in ("investigation","timeline","targets"):
                assert client.get("/api/cases/15/"+path).status_code==404
    with factory() as db:
        for table,rows in before.items():
            after=[tuple(r) for r in db.execute(text(f"SELECT * FROM {table} ORDER BY 1"))]
            if table=="audit_logs":
                assert after[:len(rows)]==rows,"Existing audit records changed"
                assert len(after)-len(rows)==3 and all(r[2]=="auth.login" for r in after[len(rows):]),"Unexpected non-login audit event"
            else:
                assert rows==after,f"Unexpected write to {table}"
        assert db.scalar(text("SELECT version_num FROM alembic_version"))==revision
    Path(".local/ui-case15.json").write_text(json.dumps(snapshot,ensure_ascii=False),encoding="utf-8")
    report={"case":15,"entities":len(graph["entities"]),"relationships":len(graph["relationships"]),"certificates":sum(n["type"]=="certificate" for n in graph["entities"]),"evidence_hashes_checked":len(support),"investigation_rows_unchanged":True,"existing_audit_rows_preserved":True,"normal_login_audit_events":3,"revision":revision,"case_isolation":"passed","collection_started":False,"ai_enabled":False,"visual_verification":"owner review required"}
    Path(".local/graph-ux-verification.json").write_text(json.dumps(report,indent=2),encoding="utf-8");print(json.dumps(report))


if __name__=="__main__":
    main()
