import base64
import hashlib
from datetime import datetime,timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import CollectorRun,Evidence,Finding,FindingEvidence,FindingRevision,Relationship,Target,Entity
from app.services.evidence import canonical_bytes
from app.services.findings import score,RULES,VERSION
from tests.integration.test_accounts_cases import system,login


def observation(factory,target,headers=None,availability="observed",http=200,corrupt=False):
    headers={"content-type":"text/html; charset=utf-8",**(headers or {})}
    raw={"metadata":{"status":http,"headers":headers},"body_base64":base64.b64encode(b"<title>Example</title>").decode()}
    parsed={"status":"ok" if http==200 else "error","availability":availability,"http_status":http,"headers":headers,"requested_url":"https://example.com/","final_url":"https://example.com/"}
    with factory() as db:
        run=CollectorRun(target_id=target,actor_id=2,collector="web_metadata",version="1.0.0",status="completed" if http==200 else "failed",started_at=datetime(2026,10,6)+timedelta(seconds=len(list(db.scalars(select(CollectorRun))))),target_snapshot={"type":"url","normalized_value":"https://example.com/","scope_status":"passive_allowed"})
        db.add(run);db.flush()
        item=Evidence(run_id=run.id,source_type="web_metadata",source_ref="https://example.com/",raw_json=raw,parsed_json=parsed,sha256="0"*64 if corrupt else hashlib.sha256(canonical_bytes(raw)).hexdigest(),captured_at=run.started_at)
        db.add(item);db.commit();return item.id


def setup(system,**kwargs):
    client,factory=system;headers=login(client,"owner")
    case=client.post("/api/cases",json={"title":"Findings"},headers=headers).json()["id"]
    target=client.post(f"/api/cases/{case}/targets",json={"type":"url","value":"https://example.com/"},headers=headers).json()["id"]
    evidence=observation(factory,target,**kwargs)
    return client,factory,headers,case,target,evidence


def test_generation_explanation_links_replay_and_no_network(system):
    client,factory,headers,case,target,evidence=setup(system)
    base=f"/api/cases/{case}"
    client.post(base+"/correlation/jobs",headers=headers)
    with patch("socket.create_connection",side_effect=AssertionError("No collection")),patch("socket.getaddrinfo",side_effect=AssertionError("No DNS")):
        first=client.post(base+"/findings/generate",headers=headers)
        assert first.status_code==201 and first.json()["created"]==6
        before=client.get(base+"/findings").json()
        replay=client.post(base+"/findings/generate",headers=headers).json()
        assert replay["created"]==replay["updated"]==0 and replay["unchanged"]==6
        assert before==client.get(base+"/findings").json()
    for finding in before["findings"]:
        assert finding["severity"]=="informational" and finding["confidence"]==.95
        assert finding["status"]=="informational" and finding["rule_version"]==VERSION
        assert finding["generated_json"]["why"] and finding["entity_id"] is not None
        detail=client.get(base+f"/findings/{finding['id']}").json()
        assert detail["evidence"][0]["id"]==evidence
        assert detail["original_json"]==finding["generated_json"]
    assert len(client.get(base+"/findings/rules").json()["rules"])==6
    actions={row["action"] for row in client.get(base+"/audit").json()}
    assert {"finding.generated","findings.generated"}<=actions


def test_overrides_status_notes_and_original_preserved(system):
    client,factory,headers,case,_,_=setup(system);base=f"/api/cases/{case}"
    client.post(base+"/findings/generate",headers=headers)
    original=client.get(base+"/findings").json()["findings"][0];path=base+f"/findings/{original['id']}"
    assert client.patch(path,json={"severity_override":"high"},headers=headers).status_code==422
    changed=client.patch(path,json={"severity_override":"high","override_reason":"Analyst context requires review","status":"accepted","notes":"Review note"},headers=headers).json()
    assert changed["severity"]=="high" and changed["confidence"]==original["confidence"]
    assert changed["original_json"]==original["original_json"] and changed["generated_json"]==original["generated_json"]
    assert client.patch(path,json={"confidence":1},headers=headers).status_code==422
    client.post(base+"/findings/generate",headers=headers)
    assert client.get(path).json()["severity_override"]=="high"
    for status in ("open","false_positive","informational","resolved"):
        assert client.patch(path,json={"status":status},headers=headers).json()["status"]==status
    reset=client.patch(path,json={"severity_override":None,"override_reason":"Return to recorded rule assessment"},headers=headers).json()
    assert reset["severity"]=="informational" and reset["confidence"]==.95
    revisions=client.get(path).json()["revisions"]
    assert any(row["snapshot"]["override_reason"]=="Analyst context requires review" for row in revisions)
    assert {row["action"] for row in client.get(base+"/audit").json()} >= {"finding.status_changed","finding.updated"}
    assert client.get(base+"/findings?severity=high").json()["findings"]==[]


def test_new_evidence_updates_same_finding_and_retains_support(system):
    client,factory,headers,case,target,first_evidence=setup(system);base=f"/api/cases/{case}"
    client.post(base+"/findings/generate",headers=headers)
    initial=client.get(base+"/findings").json()["findings"]
    header=RULES[initial[0]["rule_id"]]["header"]
    next_evidence=observation(factory,target,headers={header:"configured"})
    result=client.post(base+"/findings/generate",headers=headers).json()
    assert result["created"]==0 and result["updated"]==6
    detail=client.get(base+f"/findings/{initial[0]['id']}").json()
    assert detail["generated_json"]["rule_state"]=="not_observed_in_latest_response"
    assert detail["original_json"]==initial[0]["original_json"]
    assert {row["id"] for row in detail["evidence"]}=={first_evidence,next_evidence}
    assert len(client.get(base+"/findings").json()["findings"])==6
    third=observation(factory,target)
    client.post(base+"/findings/generate",headers=headers)
    detail=client.get(base+f"/findings/{initial[0]['id']}").json()
    assert detail["generated_json"]["evidence_ids"]==[third] and len(detail["evidence"])==3


@pytest.mark.parametrize("options",[{"availability":"partial"},{"http":429,"availability":"rate_limited"},{"http":503,"availability":"unavailable"},{"http":404,"availability":"negative_http_response"},{"corrupt":True}])
def test_incomplete_failure_negative_hash_data_never_creates_findings(system,options):
    client,_,headers,case,_,_=setup(system,**options)
    assert client.post(f"/api/cases/{case}/findings/generate",headers=headers).json()["created"]==0
    assert client.get(f"/api/cases/{case}/findings").json()["findings"]==[]


def test_failure_retains_historical_observation_not_new_negative(system):
    client,factory,headers,case,target,_=setup(system);base=f"/api/cases/{case}"
    client.post(base+"/findings/generate",headers=headers)
    observation(factory,target,http=429,availability="rate_limited")
    client.post(base+"/findings/generate",headers=headers)
    findings=client.get(base+"/findings").json()["findings"]
    assert all(row["generated_json"]["assessment_state"]=="rate_limited" and row["generated_json"]["rule_state"]=="historical_unverified" for row in findings)


def test_scope_empty_rbac_csrf_isolation_archives(system):
    client,_,headers,case,target,_=setup(system);base=f"/api/cases/{case}"
    assert client.post(base+"/findings/generate").status_code==403
    client.post(base+"/findings/generate",headers=headers)
    finding=client.get(base+"/findings").json()["findings"][0]["id"]
    assert client.patch(base+f"/findings/{finding}",json={"status":"open"}).status_code==403
    client.put(base+"/members/4",headers=headers)
    viewer=login(client,"viewer")
    assert client.get(base+f"/findings/{finding}").status_code==200
    assert client.post(base+"/findings/generate",headers=viewer).status_code==403
    assert client.patch(base+f"/findings/{finding}",json={"status":"open"},headers=viewer).status_code==403
    other=login(client,"other")
    for route in ("findings",f"findings/{finding}","findings/rules"):
        assert client.get(base+"/"+route).status_code==404
    assert client.post(base+"/findings/generate",headers=other).status_code==404
    empty=client.post("/api/cases",json={"title":"Empty"},headers=other).json()["id"]
    assert client.post(f"/api/cases/{empty}/findings/generate",headers=other).json()["created"]==0
    assert client.get(f"/api/cases/{empty}/findings/{finding}").status_code==404
    headers=login(client,"owner")
    client.delete(base+f"/targets/{target}",headers=headers)
    assert client.post(base+"/findings/generate",headers=headers).json()["skipped"]
    assert client.get(base+f"/findings/{finding}").status_code==200
    client.put(base,json={"title":"Archived","status":"archived"},headers=headers)
    assert client.post(base+"/findings/generate",headers=headers).status_code==403
    assert client.patch(base+f"/findings/{finding}",json={"status":"open"},headers=headers).status_code==403


def test_relationship_context_and_foreign_support_filter(system):
    client,factory,headers,case,target,evidence=setup(system);base=f"/api/cases/{case}"
    with factory() as db:
        item=db.get(Evidence,evidence)
        item.raw_json={**item.raw_json,"metadata":{**item.raw_json["metadata"],"redirects":[{"url":"https://example.com/","status":302,"location":"https://example.org/"}]}}
        item.parsed_json={**item.parsed_json,"final_url":"https://example.org/"};item.source_ref="https://example.org/"
        item.sha256=hashlib.sha256(canonical_bytes(item.raw_json)).hexdigest();db.commit()
    client.post(base+"/correlation/jobs",headers=headers)
    with factory() as db:
        rel_id=db.scalar(select(Relationship.id).where(Relationship.evidence_id==evidence))
    client.post(base+"/findings/generate",headers=headers)
    finding=client.get(base+"/findings").json()["findings"][0]["id"]
    assert client.get(base+f"/findings/{finding}").json()["relationships"][0]["id"]==rel_id
    with factory() as db:
        db.delete(db.get(Evidence,evidence))
        with pytest.raises(IntegrityError):db.commit()
        db.rollback()


def test_recency_deterministic_without_severity_confidence_coupling():
    class Item:
        id=1;captured_at=datetime(2026,1,1);parsed_json={"requested_url":"https://example.com/"}
    rule=next(iter(RULES.values()))
    fresh=score(Item(),datetime(2026,1,2),rule);old=score(Item(),datetime(2026,3,1),rule)
    assert fresh["recency"]["category"]=="recent" and old["recency"]["category"]=="historical"
    assert fresh["severity"]==old["severity"] and fresh["confidence"]==old["confidence"]
    assert old==score(Item(),datetime(2026,3,1),rule)


def test_generation_failure_rolls_back_all_findings(system,monkeypatch):
    client,factory,headers,case,_,_=setup(system)
    from app.api import findings
    original=findings.generate
    def fail(*args,**kwargs):original(*args,**kwargs);raise RuntimeError("fixture failure")
    monkeypatch.setattr(findings,"generate",fail)
    assert client.post(f"/api/cases/{case}/findings/generate",headers=headers).status_code==500
    with factory() as db:
        assert list(db.scalars(select(Finding)))==[] and list(db.scalars(select(FindingRevision)))==[]
    assert "findings.failed" in {row["action"] for row in client.get(f"/api/cases/{case}/audit").json()}


@pytest.mark.parametrize("kind",["malformed","excluded","failed_run"])
def test_malformed_excluded_and_no_response_paths(system,kind):
    client,factory,headers,case,target,evidence=setup(system)
    with factory() as db:
        item=db.get(Evidence,evidence)
        if kind=="malformed":item.parsed_json={"status":"ok","availability":"observed","headers":None}
        elif kind=="excluded":db.get(Target,target).scope_status="excluded"
        else:
            db.add(CollectorRun(target_id=target,actor_id=2,collector="web_metadata",version="1.0.0",status="failed",started_at=datetime(2026,10,7),target_snapshot={"scope_status":"passive_allowed","normalized_value":"https://example.com/"}))
        db.commit()
    assert client.post(f"/api/cases/{case}/findings/generate",headers=headers).json()["created"]==0


def test_version_change_preserves_initial_rule_result(system,monkeypatch):
    client,_,headers,case,_,_=setup(system);base=f"/api/cases/{case}"
    client.post(base+"/findings/generate",headers=headers)
    original=client.get(base+"/findings").json()["findings"][0]
    from app.services import findings
    monkeypatch.setattr(findings,"VERSION","1.1.0")
    result=client.post(base+"/findings/generate",headers=headers).json()
    assert result["created"]==0 and result["updated"]==6
    changed=client.get(base+f"/findings/{original['id']}").json()
    assert changed["rule_version"]=="1.1.0" and changed["original_json"]==original["original_json"]
