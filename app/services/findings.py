"""Phase 09 explicit rule catalog and explainable categorical scoring, no network/AI."""
import hashlib
from sqlalchemy import select, func

from app.collectors.web_metadata import SECURITY_HEADERS
from app.db.models import Case, CollectorRun, Entity, Evidence, Finding, FindingEvidence, FindingRelationship, FindingRevision, Relationship, Target, utcnow
from app.security.rbac import audit
from app.services.evidence import canonical_bytes
from app.services.correlation import plan

VERSION = "1.0.0"
SEVERITIES = ("informational", "low", "medium", "high", "critical")
STATUSES = ("open", "accepted", "false_positive", "informational", "resolved")
RULES = {f"web.missing_header.{header}": {"id":f"web.missing_header.{header}","version":VERSION,"header":header,"severity":"informational","confidence":0.95,"description":"Header not present in one complete unauthenticated HTML response. Applicability and equivalent protections require review; this is not proof of vulnerability."} for header in SECURITY_HEADERS}


def state(finding):
    return {"generated":finding.generated_json,"status":finding.status,"notes":finding.notes,"severity_override":finding.severity_override,"override_reason":finding.override_reason,"entity_id":finding.entity_id,"rule_version":finding.rule_version}


def revision(db, finding, user, kind):
    db.add(FindingRevision(finding_id=finding.id,actor_id=user.id,change_type=kind,snapshot_json=state(finding)))


def assess(item, run):
    if run is None:
        return "not_collected"
    if item is None:
        return "collection_failure" if run.status == "failed" else "no_evidence"
    try:
        p, raw = item.parsed_json, item.raw_json
        if item.sha256 != hashlib.sha256(canonical_bytes(raw)).hexdigest():
            return "invalid_evidence"
        if item.source_type != "web_metadata" or run.collector != "web_metadata":
            return "unsupported_evidence"
        if p.get("availability") != "observed" or p.get("status") != "ok":
            return p.get("availability") if p.get("availability") in {"partial","unavailable","rate_limited","negative_http_response"} else "invalid_evidence"
        metadata = raw["metadata"]
        headers = metadata["headers"]
        if run.status != "completed" or p["http_status"] != 200 or metadata["status"] != 200 or not isinstance(headers,dict) or not isinstance(p["headers"],dict):
            return "invalid_evidence"
        if headers.get("content-type", "").split(";",1)[0].strip().lower() not in {"text/html","application/xhtml+xml"}:
            return "invalid_evidence"
        if p["requested_url"] != run.target_snapshot["normalized_value"] or p["final_url"] != item.source_ref:
            return "invalid_evidence"
        for key in SECURITY_HEADERS:
            if headers.get(key) != p["headers"].get(key) or (key in headers and not isinstance(headers[key],str)):
                return "invalid_evidence"
        return "observed"
    except (ValueError,TypeError,KeyError,AttributeError):
        return "invalid_evidence"


def score(item, anchor, rule):
    age = max(0,(anchor-item.captured_at).days)
    return {"severity":rule["severity"],"confidence":rule["confidence"],"priority":"informational","affected_url":item.parsed_json["requested_url"],"evidence_type":"complete_unauthenticated_html_headers","recency":{"age_days":age,"reference_captured_at":anchor.isoformat(),"category":"recent" if age <= 30 else "historical","recent_threshold_days":30},"rule_state":"observed","evidence_ids":[item.id],"assessment_evidence_id":item.id,"assessment_state":"observed","why":["Direct captured response lacks the selected header; evidence hash verified.","Severity is informational because header applicability/equivalent protection is unassessed.","Confidence 0.95 describes this captured-header observation, not exploitability or ownership.","Recency uses the latest stored capture time in this case, never the wall clock; <=30 days is recent.","Priority remains informational regardless of recency/confidence; no numeric risk score or vulnerability verdict."]}


def generate(db, case_id, user, after=0):
    # The API holds the shared write lock through outcome audit and commit.
    db.execute(select(Case.id).where(Case.id == case_id).with_for_update()).all()
    targets = list(db.scalars(select(Target).where(Target.case_id==case_id,Target.type=="url",Target.id>after).order_by(Target.id).limit(101)))
    anchor = db.scalar(select(func.max(Evidence.captured_at)).join(CollectorRun).join(Target).where(Target.case_id==case_id))
    report={"version":VERSION,"created":0,"updated":0,"unchanged":0,"skipped":[],"has_more":len(targets)>100,"next_after":after}
    for target in targets[:100]:
        report["next_after"]=target.id
        if target.archived or target.scope_status=="excluded":
            report["skipped"].append({"target_id":target.id,"reason":"scope_or_archive"});continue
        run=db.scalar(select(CollectorRun).where(CollectorRun.target_id==target.id,CollectorRun.collector=="web_metadata").order_by(CollectorRun.started_at.desc(),CollectorRun.id.desc()).limit(1))
        if run and (not isinstance(run.target_snapshot,dict) or run.target_snapshot.get("scope_status") not in {"passive_allowed","active_authorized"}):
            report["skipped"].append({"target_id":target.id,"reason":"snapshot_scope"});continue
        item=db.scalar(select(Evidence).where(Evidence.run_id==run.id).order_by(Evidence.captured_at.desc(),Evidence.id.desc()).limit(1)) if run else None
        assessment=assess(item,run)
        existing={row.rule_id:row for row in db.scalars(select(Finding).where(Finding.case_id==case_id,Finding.target_id==target.id).with_for_update())}
        entity=db.scalar(select(Entity).where(Entity.case_id==case_id,Entity.entity_type=="url",Entity.canonical_value==(run.target_snapshot.get("normalized_value") if run else target.normalized_value)))
        for rule_id,rule in RULES.items():
            finding=existing.get(rule_id)
            missing=assessment=="observed" and not item.parsed_json["headers"].get(rule["header"])
            if not missing and finding is None:continue
            if missing:
                generated=score(item,anchor,rule)
            else:
                generated={**finding.generated_json,"rule_state":"not_observed_in_latest_response" if assessment=="observed" else "historical_unverified","assessment_state":assessment,"assessment_evidence_id":item.id if item else None,"assessment_run_id":run.id if run else None,"assessment_reason":"Latest complete response includes this header; previous absence is historical, not current." if assessment=="observed" else "Latest collection does not establish current header absence. Retained evidence supports only the historical observation."}
            generated={**generated,"rule_id":rule_id,"rule_version":VERSION,"scoring_version":VERSION}
            desired_entity=entity.id if missing and entity else (finding.entity_id if finding else None)
            changed=finding is None or finding.generated_json!=generated or finding.rule_version!=VERSION or finding.entity_id!=desired_entity
            if finding is None:
                finding=Finding(case_id=case_id,target_id=target.id,entity_id=entity.id if entity else None,rule_id=rule_id,rule_version=VERSION,finding_type="missing_security_header",title=f"Header not observed: {rule['header']}",description=rule["description"],status="informational",generated_json=generated,original_json=generated,notes="",override_reason="")
                db.add(finding);db.flush();report["created"]+=1;kind="generated"
            elif changed:
                finding.generated_json=generated;finding.rule_version=VERSION;finding.entity_id=desired_entity;finding.updated_at=utcnow();report["updated"]+=1;kind="regenerated"
            else:
                report["unchanged"]+=1;continue
            ids=set(generated["evidence_ids"])
            if generated.get("assessment_evidence_id") is not None:ids.add(generated["assessment_evidence_id"])
            for evidence_id in ids:
                if db.get(FindingEvidence,(finding.id,evidence_id)) is None:db.add(FindingEvidence(finding_id=finding.id,evidence_id=evidence_id))
            # Redirect support is contextual, never a precondition for a missing-header observation.
            if item and assessment=="observed":
                try:
                    _,expected_edges=plan(item,run)
                except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
                    expected_edges=[]
                for rel in db.scalars(select(Relationship).where(Relationship.case_id==case_id,Relationship.evidence_id==item.id,Relationship.relation_type=="redirects_to")):
                    a,b=db.get(Entity,rel.from_entity_id),db.get(Entity,rel.to_entity_id)
                    support=((a.entity_type,a.canonical_value),(b.entity_type,b.canonical_value),rel.relation_type)
                    if a.case_id==b.case_id==case_id and support in expected_edges and db.get(FindingRelationship,(finding.id,rel.id)) is None:db.add(FindingRelationship(finding_id=finding.id,relationship_id=rel.id))
            db.flush();revision(db,finding,user,kind)
            audit(db,user,"finding."+kind,"case",case_id,finding_id=finding.id,rule_id=rule_id,version=VERSION,evidence_ids=sorted(ids))
    return report
