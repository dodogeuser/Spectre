"""Stored-data exports, provenance, isolation, escaping and offline PDF regression."""
import hashlib
from io import BytesIO
from unittest.mock import patch

import pytest
from pypdf import PdfReader
from sqlalchemy import select, func

from app.db.models import AuditLog, CollectorRun, Evidence, Finding, FindingEvidence, FindingRelationship, Target
from app.services.evidence import canonical_bytes
from app.services.reporting import clean_text
from tests.integration.test_accounts_cases import system, login
from tests.integration.test_findings import setup, observation
from tests.integration.test_correlation import seed


def export(client, case, headers, format="html", **options):
    return client.post(f"/api/cases/{case}/reports/export", json={"format":format,**options}, headers=headers)


def prepared(system):
    client, factory, headers, case, target, evidence = setup(system)
    assert client.post(f"/api/cases/{case}/correlation/jobs",headers=headers).status_code==201
    assert client.post(f"/api/cases/{case}/findings/generate",headers=headers).status_code==201
    return client,factory,headers,case,target,evidence


def test_html_pdf_reproducible_stored_evidence_and_no_network_ai(system):
    client,factory,headers,case,target,evidence=prepared(system)
    with factory() as db:
        before=[db.scalar(select(func.count()).select_from(model)) for model in (Target,CollectorRun,Evidence,Finding)]
    with patch("socket.create_connection",side_effect=AssertionError("No outbound request")),patch("socket.getaddrinfo",side_effect=AssertionError("No DNS")),patch("app.ai.provider.OllamaProvider.answer",create=True,side_effect=AssertionError("No AI")):
        preview=client.get(f"/api/cases/{case}/reports/preview").json()
        assert preview["counts"]["findings"]==6 and preview["counts"]["evidence"]==1
        first=export(client,case,headers);second=export(client,case,headers)
        assert first.status_code==200 and first.content==second.content
        pdf=export(client,case,headers,"pdf");replay=export(client,case,headers,"pdf")
        assert pdf.status_code==200 and pdf.content.startswith(b"%PDF-") and pdf.content==replay.content
    assert "img-src data:" in first.headers["content-security-policy"]
    html=first.text
    assert 'src="data:image/png;base64,' in html
    assert 'class="report-brand"' in html
    assert "Confidence: 0.95" in html and "Severity: informational" in html
    assert "Original rule: informational / 0.95" in html and "web.missing_header." in html
    assert f'href="#evidence-{evidence}"' in html and f'id="evidence-{evidence}"' in html
    assert f"Target #{target}" in html and "SHA-256:" in html and "Integrity: verified" in html
    assert "No numeric risk score" in html and "Snapshot SHA-256" in html
    reader=PdfReader(BytesIO(pdf.content));text="\n".join(p.extract_text() for p in reader.pages)
    assert "Evidence appendix" in text and "web.missing_header" in text and f"Evidence #{evidence}" in text
    assert any(page.images for page in reader.pages), "PDF contains approved logo"
    assert any(page.get("/Annots") for page in reader.pages),"PDF references must be clickable"
    assert first.headers["x-spectre-snapshot-sha256"]==preview["snapshot_sha256"]
    assert first.headers["cache-control"]=="no-store" and "sandbox" in first.headers["content-security-policy"]
    assert first.headers["content-disposition"]==f'attachment; filename="spectre-case-{case}.html"'
    assert client.get(f"/api/cases/{case}/ai/status").json()["configured"] is False
    with factory() as db:
        assert before==[db.scalar(select(func.count()).select_from(model)) for model in (Target,CollectorRun,Evidence,Finding)]
        audits=list(db.scalars(select(AuditLog).where(AuditLog.action=="report.generated")))
        assert len(audits)==4 and {a.metadata_json["format"] for a in audits}=={"html","pdf"}
        assert all(a.object_id==case and a.actor_id==2 for a in audits)
        assert all("notes" not in a.metadata_json and "path" not in a.metadata_json for a in audits)


def test_case_isolation_rbac_csrf_and_invalid_requests(system):
    client,_,headers,case,_,_=prepared(system)
    base=f"/api/cases/{case}"
    assert client.put(base+"/members/4",headers=headers).status_code==204
    assert export(client,case,{}).status_code==403
    viewer=login(client,"viewer")
    assert client.get(base+"/reports/preview").json()["can_export"] is False
    assert export(client,case,viewer).status_code==403
    other=login(client,"other")
    assert client.get(base+"/reports/preview").status_code==404
    assert export(client,case,other).status_code==404
    admin=login(client,"admin")
    assert export(client,case,admin).status_code==200
    assert export(client,999999,admin).status_code==404
    for body in ({"format":"../../secret"},{"format":"html","path":"C:/secret"},{"format":"pdf","evidence_ids":[999]},{"format":"html","redact_notes":"false"}):
        assert client.post(base+"/reports/export",json=body,headers=admin).status_code==422
    client.cookies.clear()
    assert client.get(base+"/reports/preview").status_code==401
    assert export(client,case,headers).status_code==401


def test_redaction_escaping_and_never_export_credentials_or_raw_bodies(system):
    client,factory,headers,case,_,evidence=prepared(system)
    assert client.put(f"/api/cases/{case}",json={"title":"<script>alert(1)</script>","description":"private analyst description"},headers=headers).status_code==200
    with factory() as db:
        f=db.scalar(select(Finding));f.notes="secret investigator note <img src=x onerror=alert(1)>";f.severity_override="high";f.override_reason="api_key=example-sensitive-value"
        e=db.get(Evidence,evidence);e.source_ref="https://example.com/?%61pi_key=encoded-sensitive-value&ok=1"
        db.get(CollectorRun,e.run_id).warnings_json=[{"api_key":"nested-sensitive-value"}]
        db.commit()
    redacted=export(client,case,headers).text
    assert "<script>alert" not in redacted and "&lt;script&gt;alert" in redacted
    assert "private analyst description" not in redacted and "secret investigator note" not in redacted
    assert "encoded-sensitive-value" not in redacted and "example-sensitive-value" not in redacted
    included=export(client,case,headers,redact_notes=False).text
    assert "private analyst description" in included and "secret investigator note &lt;img" in included
    assert "Severity: high | Confidence: 0.95" in included
    assert "Original rule: informational / 0.95" in included
    assert "example-sensitive-value" not in included and "encoded-sensitive-value" not in included
    assert "body_base64" not in included and "$argon2" not in included
    assert "nested-sensitive-value" not in included
    assert "configured-db-secret" not in clean_text("raw configured-db-secret",["configured-db-secret"])
    for text in ('{"api_key":"json-sensitive-value"}',"password='quoted-sensitive-value'","Authorization: Bearer sensitive-bearer"):
        assert "sensitive-value" not in clean_text(text) and "sensitive-bearer" not in clean_text(text)


def test_empty_failed_partial_negative_and_archived_history(system):
    client,factory=system;headers=login(client,"owner")
    case=client.post("/api/cases",json={"title":"Empty"},headers=headers).json()["id"]
    empty=export(client,case,headers);assert empty.status_code==200
    assert "No stored records" in empty.text and "not a confirmed negative" in empty.text
    target=client.post(f"/api/cases/{case}/targets",json={"type":"url","value":"https://example.com/"},headers=headers).json()["id"]
    with factory() as db:
        db.add(CollectorRun(target_id=target,actor_id=2,collector="web_metadata",version="1.0.0",status="failed",error_code="timeout",target_snapshot={},warnings_json=["Provider unavailable"]))
        db.commit()
    for availability,http in (("partial",200),("rate_limited",429),("unavailable",503),("negative_http_response",404)):
        observation(factory,target,availability=availability,http=http)
    assert client.delete(f"/api/cases/{case}/targets/{target}",headers=headers).status_code==204
    assert client.put(f"/api/cases/{case}",json={"title":"Empty","status":"archived"},headers=headers).status_code==200
    result=export(client,case,headers);assert result.status_code==200
    for word in ("failed","timeout","partial","rate_limited","unavailable","negative_http_response","Archived: True"):
        assert word in result.text
    assert "not proof of absence" in result.text


@pytest.mark.parametrize("corruption",["hash","cross_case","missing_support","malformed_ids"])
def test_invalid_integrity_or_finding_support_fails_closed(system,corruption):
    client,factory,headers,case,target,evidence=prepared(system)
    with factory() as db:
        finding=db.scalar(select(Finding))
        if corruption=="hash":db.get(Evidence,evidence).sha256="0"*64
        elif corruption=="missing_support":
            db.delete(db.get(FindingEvidence,(finding.id,evidence)))
        elif corruption=="malformed_ids":finding.generated_json={**finding.generated_json,"evidence_ids":[{}]}
        else:
            other_case=client.post("/api/cases",json={"title":"Other"},headers=headers).json()["id"]
            other_target=client.post(f"/api/cases/{other_case}/targets",json={"type":"url","value":"https://example.com/"},headers=headers).json()["id"]
            foreign=observation(factory,other_target)
            db.add(FindingEvidence(finding_id=finding.id,evidence_id=foreign))
        db.commit()
    assert export(client,case,headers).status_code==409
    with factory() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action=="report.failed")) is not None


def test_renderer_failure_optional_pdf_dependency_and_limits(system):
    client,_,headers,case,_,_=prepared(system)
    with patch("app.api.reports.pdf_report",side_effect=ImportError("missing PDF dependency")):
        assert export(client,case,headers,"pdf").status_code==503
        assert export(client,case,headers,"html").status_code==200
        assert client.get(f"/api/cases/{case}/investigation").status_code==200
    with patch("app.services.reporting.MAX_CONTEXT_BYTES",1):
        assert export(client,case,headers).status_code==413
    from app.api.reports import export_slots
    assert export_slots.acquire(False) and export_slots.acquire(False)
    try:assert export(client,case,headers).status_code==429
    finally:export_slots.release();export_slots.release()


def test_regenerated_finding_reports_historical_support_and_new_assessment(system):
    client,factory,headers,case,target,original=prepared(system)
    latest=observation(factory,target,http=429,availability="rate_limited")
    assert client.post(f"/api/cases/{case}/findings/generate",headers=headers).status_code==201
    response=export(client,case,headers);assert response.status_code==200
    assert "Assessment: rate_limited" in response.text
    assert f"Evidence #{original}" in response.text and f"Evidence #{latest}" in response.text
    assert "Latest collection does not establish" in response.text


def test_relationship_support_navigation_and_replayed_edge_deduplication(system):
    client,factory=system;headers,case,_,eid=seed(client,factory)
    with factory() as db:
        original=db.get(Evidence,eid)
        db.add(Evidence(run_id=original.run_id,source_type=original.source_type,source_ref=original.source_ref,raw_json=original.raw_json,parsed_json=original.parsed_json,sha256=original.sha256))
        db.commit()
    for _ in range(2):assert client.post(f"/api/cases/{case}/correlation/jobs",headers=headers).status_code==201
    assert client.get(f"/api/cases/{case}/reports/preview").json()["counts"]["relationships"]==1
    report=export(client,case,headers);assert report.status_code==200
    assert "resolves_to" in report.text and "observed" in report.text and "Support IDs:" in report.text
    assert f'href="#evidence-{eid}"' in report.text
    # A stored malformed provider body is indexed, not interpreted as a new fact.
    with factory() as db:db.get(Evidence,eid).parsed_json=["malformed"];db.commit()
    assert export(client,case,headers).status_code==200


def test_relationship_link_in_finding_is_case_scoped(system):
    client,factory,headers,case,_,_=prepared(system)
    other_headers,other,_,_=seed(client,factory)
    assert client.post(f"/api/cases/{other}/correlation/jobs",headers=other_headers).status_code==201
    graph=client.get(f"/api/cases/{other}/graph").json()
    with factory() as db:
        finding=db.scalar(select(Finding).where(Finding.case_id==case))
        db.add(FindingRelationship(finding_id=finding.id,relationship_id=graph["relationships"][0]["support_ids"][0]));db.commit()
    assert export(client,case,other_headers).status_code==409


def test_timeline_tie_order_and_changed_stored_evidence_changes_digest(system):
    from app.services.reporting import snapshot
    from app.db.models import Case
    client,factory,headers,case,target,_=prepared(system)
    with factory() as db:
        data=snapshot(db,db.get(Case,case))
        assert data["events"]==sorted(data["events"],key=lambda e:(e["timestamp"],e["type"],e["key"]))
        digest=data["snapshot_sha256"]
    observation(factory,target,availability="partial")
    assert client.get(f"/api/cases/{case}/reports/preview").json()["snapshot_sha256"]!=digest


def test_pdf_schematic_wraps_full_domain_labels_without_changing_values(system):
    import pymupdf
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from app.services.reporting import pdf_label_lines
    labels=["www.rzm-epp.iana.org","rzm-iana-ote.iana.org","rzm-ote-epp.iana.org","sle-dashboard.iana.org","long-subdomain-label.another-subdomain.example.org"]
    for value in labels:
        lines=pdf_label_lines(value)
        assert ''.join(lines)==value and len(lines)<=3
        assert all(stringWidth(line,'Helvetica',8)<=108 for line in lines)
        assert pdf_label_lines(value)==lines
    assert len(pdf_label_lines(labels[-1]))>1
    long_lines=pdf_label_lines('a'*253)
    assert len(long_lines)==3 and long_lines[-1].endswith('...')
    assert all(stringWidth(line,'Helvetica',8)<=108 for line in long_lines)
    client,factory=system
    headers,case,_,_=seed(client,factory,parsed={"status":"ok","rcode":"NOERROR","records":[{"owner":"example.com","record_type":"NS","value":value} for value in labels]})
    assert client.post(f"/api/cases/{case}/correlation/jobs",headers=headers).status_code==201
    before=client.get(f"/api/cases/{case}/investigation").json()
    first=export(client,case,headers,'pdf');second=export(client,case,headers,'pdf')
    assert first.status_code==200 and first.content==second.content
    doc=pymupdf.open(stream=first.content,filetype='pdf')
    graph_page=next(page for page in doc if 'Discovered infrastructure' in page.get_text())
    # Only the drawing, excluding the complete entity index below it.
    heading=graph_page.search_for('Discovered infrastructure')[0]
    caption=graph_page.search_for('Stored non-certificate schematic.')[0]
    graph_text=graph_page.get_text(clip=pymupdf.Rect(42,heading.y1,553,caption.y0)).replace('\n','')
    for value in labels:assert value in graph_text
    assert before==client.get(f"/api/cases/{case}/investigation").json()
