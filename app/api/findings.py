from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, ConfigDict
from typing import Literal
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.db.models import CollectorRun, Entity, Evidence, Finding, FindingEvidence, FindingRelationship, FindingRevision, FindingVerification, ActiveRun, Relationship, Target, User, utcnow
from app.db.session import get_db
from app.security.rbac import audit, require_case
from app.services.domain_entities import domain_write_lock
from app.services.findings import RULES, VERSION, generate, revision, state

router=APIRouter(prefix="/api/cases/{case_id}",tags=["deterministic findings"])


def get_finding(db,case_id,finding_id):
    finding=db.scalar(select(Finding).join(Target,Finding.target_id==Target.id).where(Finding.id==finding_id,Finding.case_id==case_id,Target.case_id==case_id))
    if finding is None:raise HTTPException(404,"Finding not found")
    if finding.entity_id is not None:
        entity=db.get(Entity,finding.entity_id)
        if entity is None or entity.case_id!=case_id:raise HTTPException(404,"Finding not found")
    return finding


def serialize(finding):
    return {key:getattr(finding,key) for key in ("id","case_id","target_id","entity_id","rule_id","rule_version","finding_type","title","description","status","generated_json","original_json","notes","severity_override","override_reason","created_at","updated_at")} | {"severity":finding.severity_override or finding.generated_json["severity"],"confidence":finding.generated_json["confidence"]}


@router.get("/findings/rules")
def rules(case_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    require_case(db,user,case_id);db.commit()
    return {"version":VERSION,"rules":list(RULES.values()),"rubric":"Categorical informational priority. Severity and observation confidence are independent. Recency is <=30 days relative to newest stored case capture; never wall clock. No numeric risk score."}


@router.post("/findings/generate",status_code=201)
def generate_findings(case_id:int,after:int=Query(0,ge=0),user:User=Depends(current_user),db:Session=Depends(get_db)):
    case=require_case(db,user,case_id,mutate=True)
    if case.status=="archived":raise HTTPException(403,"Archived case cannot generate findings")
    try:
        with domain_write_lock:
            result=generate(db,case_id,user,after)
            audit(db,user,"findings.generated","case",case_id,**result);db.commit()
        return result
    except Exception:
        db.rollback();audit(db,user,"findings.failed","case",case_id,reason="generation_error");db.commit()
        raise HTTPException(500,"Finding generation failed; no partial changes committed")


@router.get("/findings")
def listing(case_id:int,offset:int=Query(0,ge=0),status:str|None=None,severity:str|None=None,user:User=Depends(current_user),db:Session=Depends(get_db)):
    require_case(db,user,case_id)
    query=select(Finding).join(Target,Finding.target_id==Target.id).where(Finding.case_id==case_id,Target.case_id==case_id)
    if status:query=query.where(Finding.status==status)
    if severity:query=query.where(func.coalesce(Finding.severity_override,Finding.generated_json["severity"].as_string())==severity)
    rows=list(db.scalars(query.order_by(Finding.id).offset(offset).limit(101)))
    values=[serialize(get_finding(db,case_id,row.id)) for row in rows[:100]]
    db.commit();return {"findings":values,"has_more":len(rows)>100,"next_offset":offset+100}


@router.get("/findings/{finding_id}")
def detail(case_id:int,finding_id:int,offset:int=Query(0,ge=0),user:User=Depends(current_user),db:Session=Depends(get_db)):
    require_case(db,user,case_id);finding=get_finding(db,case_id,finding_id)
    result=serialize(finding)
    target=db.get(Target,finding.target_id)
    result["target"]={"id":target.id,"value":target.normalized_value,"archived":target.archived,"scope_status":target.scope_status}
    rows=db.execute(select(Evidence,CollectorRun).join(FindingEvidence,FindingEvidence.evidence_id==Evidence.id).join(CollectorRun,Evidence.run_id==CollectorRun.id).join(Target,CollectorRun.target_id==Target.id).where(FindingEvidence.finding_id==finding.id,Target.case_id==case_id).order_by(Evidence.id).offset(offset).limit(101)).all()
    result["evidence"]=[{"id":item.id,"run_id":run.id,"source_ref":item.source_ref,"source_type":item.source_type,"captured_at":item.captured_at,"sha256":item.sha256,"active_support":item.id in finding.generated_json["evidence_ids"],"assessment_support":item.id==finding.generated_json.get("assessment_evidence_id")} for item,run in rows[:100]]
    result["evidence_has_more"]=len(rows)>100
    relationships=[]
    for rel in db.scalars(select(Relationship).join(FindingRelationship,FindingRelationship.relationship_id==Relationship.id).where(FindingRelationship.finding_id==finding.id,Relationship.case_id==case_id).order_by(Relationship.id).limit(100)):
        item=db.get(Evidence,rel.evidence_id);run=db.get(CollectorRun,item.run_id);target=db.get(Target,run.target_id)
        a,b=db.get(Entity,rel.from_entity_id),db.get(Entity,rel.to_entity_id)
        if target.case_id==a.case_id==b.case_id==case_id:
            relationships.append({"id":rel.id,"from":rel.from_entity_id,"to":rel.to_entity_id,"type":rel.relation_type,"evidence_id":rel.evidence_id,"confidence":rel.confidence,"role":"contextual_redirect_support"})
    result["relationships"]=relationships
    result['verifications']=[{'id':v.id,'active_run_id':v.active_run_id,'state':v.state,'reason':v.reason,'evidence_id':v.evidence_id,'created_at':v.created_at} for v in db.scalars(select(FindingVerification).join(ActiveRun,FindingVerification.active_run_id==ActiveRun.id).where(FindingVerification.finding_id==finding.id,ActiveRun.case_id==case_id,ActiveRun.target_id==finding.target_id).order_by(FindingVerification.id))]
    result["revisions"]=[{"id":row.id,"actor_id":row.actor_id,"change_type":row.change_type,"created_at":row.created_at,"snapshot":row.snapshot_json} for row in db.scalars(select(FindingRevision).where(FindingRevision.finding_id==finding.id).order_by(FindingRevision.id.desc()).limit(50))]
    db.commit();return result


class FindingUpdate(BaseModel):
    model_config=ConfigDict(extra="forbid")
    status:Literal["open","accepted","false_positive","informational","resolved"]|None=None
    notes:str|None=Field(default=None,max_length=10000)
    severity_override:Literal["informational","low","medium","high","critical"]|None=None
    override_reason:str|None=Field(default=None,max_length=2000)


@router.patch("/findings/{finding_id}")
def update(case_id:int,finding_id:int,data:FindingUpdate,user:User=Depends(current_user),db:Session=Depends(get_db)):
    case=require_case(db,user,case_id,mutate=True)
    if case.status=="archived":raise HTTPException(403,"Archived case findings are read-only")
    with domain_write_lock:
        finding=get_finding(db,case_id,finding_id)
        old=state(finding)
        fields=data.model_fields_set
        if "severity_override" in fields:
            reason=(data.override_reason or "").strip()
            if not reason:raise HTTPException(422,"Severity override or reset requires a reason")
            finding.severity_override=data.severity_override;finding.override_reason=reason
        elif "override_reason" in fields:raise HTTPException(422,"Override reason requires a severity override or reset")
        if data.status is not None:finding.status=data.status
        if data.notes is not None:finding.notes=data.notes
        if old!=state(finding):
            finding.updated_at=utcnow();revision(db,finding,user,"analyst_update")
            audit(db,user,"finding.updated","case",case_id,finding_id=finding.id,status=finding.status,severity_override=finding.severity_override)
            if old["status"]!=finding.status:
                audit(db,user,"finding.status_changed","case",case_id,finding_id=finding.id,before=old["status"],after=finding.status)
            if old["severity_override"]!=finding.severity_override:
                audit(db,user,"finding.severity_overridden","case",case_id,finding_id=finding.id,before=old["severity_override"],after=finding.severity_override,rule_severity=finding.generated_json["severity"],confidence=finding.generated_json["confidence"])
        db.commit();return serialize(finding)
