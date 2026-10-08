"""Read-only live console/API checks; no collection, fixtures, AI or schema changes."""
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
    tables=("cases","case_members","targets","collector_runs","evidence","entities","relationships","findings","finding_evidence","finding_relationships","finding_revisions","users")
    with factory() as db:
        before={name:[tuple(row) for row in db.execute(text(f"SELECT * FROM {name}"))] for name in tables}
        audit_before={row[0]:tuple(row) for row in db.execute(text("SELECT * FROM audit_logs"))}
        assert db.scalar(text("SELECT version_num FROM alembic_version"))=="006"
    credentials=json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    def login(client,name):
        client.cookies.clear();r=client.post("/api/auth/login",json={"username":name,"password":credentials[name]["password"]},headers={"X-Spectre-Login":"1"});assert r.status_code==200
    report={"revision":"006","schema_changed":False,"collection_started":False,"ai_enabled":False,"cases":{}}
    with httpx.Client(base_url="http://127.0.0.1:8000",trust_env=False,timeout=20) as client:
        assert client.get("/health").json()["status"]=="ok"
        html=client.get("/").text;assert 'id="inspector-shell"' in html and 'data-pane="graph"' in html
        for name in ("main","investigation","findings","console","ai"):
            assert client.get(f"/static/js/{name}.js").status_code==200
        login(client,"researcher")
        for case_id in (7,9,12,13):
            base=f"/api/cases/{case_id}"
            case=client.get(base);assert case.status_code==200
            graph=client.get(base+"/investigation").json();timeline=client.get(base+"/timeline").json();findings=client.get(base+"/findings").json();targets=client.get(base+"/targets").json()
            assert all(row["case_id"]==case_id for row in targets)
            for edge in graph["relationships"]:assert edge["evidence_ids"] and edge["support_ids"]
            assert client.get(base+"/collectors").status_code==200
            assert client.get(base+"/ai/status").json()["configured"] is False
            report["cases"][str(case_id)]={"title":case.json()["title"],"entities":len(graph["entities"]),"relationships":len(graph["relationships"]),"timeline_events":timeline["bounded_total"],"findings":len(findings["findings"]),"targets_in_page":len(targets),"truncated":graph["truncated"] or timeline["truncated"]}
            report["cases"][str(case_id)]["targets"]=[{"id":t["id"],"type":t["type"],"value":t["normalized_value"],"archived":t["archived"]} for t in targets]
            if case_id==7:
                Path(".local/ui-case7.json").write_text(json.dumps({"graph":graph,"targets":targets,"timeline":timeline},ensure_ascii=False),encoding="utf-8")
        item=client.get("/api/cases/12/evidence/61").json();assert item["parsed_json"]["title"]=="Example Domain" and item["run_id"]==35
        assert hashlib.sha256(canonical_bytes(item["raw_json"])).hexdigest()==item["sha256"]
        Path(".local/ui-evidence61.json").write_text(json.dumps(item,ensure_ascii=False),encoding="utf-8")
        assert client.get("/api/cases/7/evidence/61").status_code==404
        login(client,"observer");assert client.get("/api/cases/10/investigation").status_code==200;assert client.get("/api/cases/12/investigation").status_code==404
        login(client,"unrelated")
        for path in ("investigation","timeline","findings","targets","evidence/61"):
            assert client.get("/api/cases/12/"+path).status_code==404
    with factory() as db:
        for name,rows in before.items():assert rows==[tuple(row) for row in db.execute(text(f"SELECT * FROM {name}"))],f"Unexpected write to {name}"
        audit_after={row[0]:tuple(row) for row in db.execute(text("SELECT * FROM audit_logs"))}
        assert all(audit_after.get(key)==row for key,row in audit_before.items()),"Existing audit rows changed"
    report.update({"existing_investigation_rows_unchanged":True,"existing_audit_rows_preserved":True,"rbac_case_isolation":"passed","evidence_61_hash":"verified","browser_visual":"manual verification required"})
    Path(".local/ui-ux-verification.json").write_text(json.dumps(report,indent=2),encoding="utf-8");print(json.dumps(report))


if __name__=="__main__":main()
