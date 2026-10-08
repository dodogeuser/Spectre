"""Phase 11 acceptance on existing MySQL records, without collection or fixtures."""
import hashlib
import json
from io import BytesIO
from pathlib import Path

import httpx
from pypdf import PdfReader
from sqlalchemy import text

from app.config import get_settings
from app.db.session import make_session_factory


def main():
    factory=make_session_factory(get_settings())
    tables=("users","cases","case_members","targets","collector_runs","evidence","entities","relationships","findings","finding_evidence","finding_relationships","finding_revisions","audit_logs")
    with factory() as db:
        before={table:[tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY 1"))] for table in tables}
        revision=db.scalar(text("SELECT version_num FROM alembic_version"))
    credentials=json.loads(Path(".local/login-credentials.json").read_text(encoding="utf-8"))
    results={}
    with httpx.Client(base_url="http://127.0.0.1:8000",trust_env=False,timeout=60) as client:
        auth=client.post("/api/auth/login",json={"username":"researcher","password":credentials["researcher"]["password"]},headers={"X-Spectre-Login":"1"});auth.raise_for_status()
        csrf={"X-CSRF-Token":auth.json()["csrf_token"]}
        assert client.get("/api/cases/15/ai/status").json()["configured"] is False
        out=Path("output/pdf");out.mkdir(parents=True,exist_ok=True)
        for case in (15,12):
            preview=client.get(f"/api/cases/{case}/reports/preview");preview.raise_for_status();data=preview.json()
            content={}
            for format in ("html","pdf"):
                path=f"/api/cases/{case}/reports/export"
                response=client.post(path,json={"format":format,"redact_notes":True},headers=csrf);response.raise_for_status()
                replay=client.post(path,json={"format":format,"redact_notes":True},headers=csrf);replay.raise_for_status()
                assert response.content==replay.content,"Export is not reproducible"
                assert response.headers["x-spectre-snapshot-sha256"]==data["snapshot_sha256"]
                content[format]=response.content;(out/f"spectre-case-{case}.{format}").write_bytes(response.content)
            html=content["html"].decode("utf-8")
            reader=PdfReader(BytesIO(content["pdf"]));pdf_text="\n".join(p.extract_text() for p in reader.pages)
            assert "Evidence appendix" in pdf_text and "SHA-256" in pdf_text
            graph=client.get(f"/api/cases/{case}/investigation");graph.raise_for_status();graph=graph.json()
            for edge in graph["relationships"]:
                assert edge["type"] in html
                for eid in edge["evidence_ids"]:assert f'href="#evidence-{eid}"' in html and f'id="evidence-{eid}"' in html
            if case==15:
                assert data["case"]["title"]=="IANA Infrastructure Investigation"
                for value in ("iana.org","192.0.43.8","2001:500:88:200::8"):
                    assert any(n["value"]==value for n in graph["entities"])
                    assert value in html and value in pdf_text
                assert all(kind in html for kind in ("nameserver","mail_server","subdomain_of","certificate_observed_on"))
                assert "Run #44" in html and "collector_error" in html
                for run in (45,46,47):assert f"Run #{run}" in html
            else:
                assert data["counts"]["findings"]>=1
                assert "Original rule:" in html and "Why:" in html and 'href="#evidence-61"' in html
            results[str(case)]={"counts":data["counts"],"digest":data["snapshot_sha256"],"pdf_pages":len(reader.pages),"html_bytes":len(content["html"]),"pdf_bytes":len(content["pdf"]),"replay_identical":True,"support_links_verified":True}
        assert client.post("/api/cases/15/reports/export",json={"format":"html"}).status_code==403
        assert client.post("/api/cases/15/reports/export",json={"format":"html","path":"../secret"},headers=csrf).status_code==422
        for username in ("observer","unrelated"):
            client.cookies.clear()
            auth=client.post("/api/auth/login",json={"username":username,"password":credentials[username]["password"]},headers={"X-Spectre-Login":"1"});auth.raise_for_status()
            assert client.get("/api/cases/15/reports/preview").status_code==404
            assert client.post("/api/cases/15/reports/export",json={"format":"pdf"},headers={"X-CSRF-Token":auth.json()["csrf_token"]}).status_code==404
    with factory() as db:
        for table,rows in before.items():
            after=[tuple(row) for row in db.execute(text(f"SELECT * FROM {table} ORDER BY 1"))]
            if table=="audit_logs":
                assert after[:len(rows)]==rows,"Existing audits changed"
                new=after[len(rows):]
                assert len(new)==11 and all(row[2] in {"auth.login","report.generated"} for row in new)
                assert sum(row[2]=="report.generated" for row in new)==8
            else:assert rows==after,f"Investigation table changed: {table}"
        assert db.scalar(text("SELECT version_num FROM alembic_version"))==revision
    report={"cases":results,"schema_revision":revision,"existing_records_preserved":True,"export_audits":8,"normal_login_audits":3,"csrf":True,"path_rejection":True,"case_isolation":True,"ai_configured":False,"collection_started":False}
    Path(".local/phase11-live-verification.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report))


if __name__=="__main__":
    main()
