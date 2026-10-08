"""Explicit non-destructive active authorization and lifecycle endpoints."""
import hashlib
from typing import Literal
from fastapi import APIRouter,BackgroundTasks,Depends,HTTPException,Query,Request
from pydantic import BaseModel,ConfigDict,Field,StrictBool
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.active.policy import RunOptions,target_host,request_url,destination
from app.active.service import allowed,compatible,verification_resource,execute,run_dict
from app.api.auth import current_user
from app.api.targets import get_target
from app.db.models import ActiveAuthorization,ActiveCaseControl,ActiveRun,FindingVerification,User,utcnow
from app.db.session import get_db
from app.security.rbac import require_case,audit
from app.services.domain_entities import domain_write_lock
from app.services.evidence import canonical_bytes
from app.services.reporting import clean_text

router=APIRouter(prefix='/api/cases/{case_id}/active',tags=['authorized active verification'])


class Grant(BaseModel):
    model_config=ConfigDict(extra='forbid')
    confirmed:Literal[True]
    note:str=Field(default='',max_length=1000)
    ports:list[Literal[80,443]]=Field(default_factory=lambda:[443],min_length=1,max_length=2)


class Control(BaseModel):
    model_config=ConfigDict(extra='forbid')
    stopped:StrictBool
    confirmed:Literal[True]


def enabled(request):
    if not request.app.state.settings.active_assessment_enabled:raise HTTPException(403,'Active assessment is disabled by default; enable local configuration explicitly')


def grant_dict(row):
    return {k:getattr(row,k) for k in ('id','case_id','target_id','granted_by','granted_at','scope_json','note','revoked_at','revoked_by')}


@router.get('')
def overview(case_id:int,request:Request,offset:int=Query(0,ge=0),user:User=Depends(current_user),db:Session=Depends(get_db)):
    case=require_case(db,user,case_id)
    grants=list(db.scalars(select(ActiveAuthorization).where(ActiveAuthorization.case_id==case_id).order_by(ActiveAuthorization.id.desc()).limit(100)))
    rows=list(db.scalars(select(ActiveRun).where(ActiveRun.case_id==case_id).order_by(ActiveRun.id.desc()).offset(offset).limit(101)))
    control=db.get(ActiveCaseControl,case_id)
    result={'enabled':request.app.state.settings.active_assessment_enabled,'stopped':bool(control and control.stopped),'can_authorize':user.role!='viewer' and (user.role=='admin' or case.owner_id==user.id),'can_execute':user.role!='viewer','authorizations':[grant_dict(g) for g in grants],'runs':[run_dict(db,r) for r in rows[:100]],'has_more':len(rows)>100,'authorizations_bounded':len(grants)==100,'modules':['http','tls','service','validation','manual'],'limits':{'ports':[80,443],'methods':['GET','HEAD','OPTIONS'],'total_seconds':20,'connect_seconds':5,'body_bytes':65536,'redirects':2,'concurrency':1,'host_interval_seconds':2}}
    db.commit();return result


@router.post('/targets/{target_id}/authorization',status_code=201)
def authorize(case_id:int,target_id:int,data:Grant,request:Request,user:User=Depends(current_user),db:Session=Depends(get_db)):
    enabled(request);case=require_case(db,user,case_id,mutate=True,manage=True)
    if case.status=='archived':raise HTTPException(403,'Archived case cannot authorize active operations')
    with domain_write_lock:
        target=get_target(db,case_id,target_id)
        if target.archived or target.scope_status!='active_authorized':raise HTTPException(403,'Set explicit active_authorized target scope first')
        host=target_host(target)
        # Locking read also serializes grant replacement under MySQL.
        db.execute(select(ActiveAuthorization).where(ActiveAuthorization.target_id==target_id).with_for_update()).all()
        for old in db.scalars(select(ActiveAuthorization).where(ActiveAuthorization.target_id==target_id,ActiveAuthorization.revoked_at.is_(None))):
            old.revoked_at=utcnow();old.revoked_by=user.id
            audit(db,user,'active.authorization_revoked','case',case_id,authorization_id=old.id,target_id=target_id)
        grant=ActiveAuthorization(case_id=case_id,target_id=target_id,granted_by=user.id,scope_json={'host':host,'ports':sorted(set(data.ports)),'methods':['GET','HEAD','OPTIONS'],'target_type':target.type,'target_value':target.normalized_value},note=clean_text(data.note,(request.app.state.settings.mysql_password.get_secret_value(),)))
        db.add(grant);db.flush();audit(db,user,'active.authorization_granted','case',case_id,authorization_id=grant.id,target_id=target_id,host=host,ports=grant.scope_json['ports']);db.commit()
        return grant_dict(grant)


@router.delete('/authorizations/{authorization_id}',status_code=204)
def revoke(case_id:int,authorization_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    require_case(db,user,case_id,mutate=True,manage=True)
    with domain_write_lock:
        grant=db.get(ActiveAuthorization,authorization_id)
        if not grant or grant.case_id!=case_id:raise HTTPException(404,'Authorization not found')
        if grant.revoked_at is None:
            grant.revoked_at=utcnow();grant.revoked_by=user.id
            audit(db,user,'active.authorization_revoked','case',case_id,authorization_id=grant.id,target_id=grant.target_id)
        db.commit()


@router.put('/control')
def control(case_id:int,data:Control,user:User=Depends(current_user),db:Session=Depends(get_db)):
    require_case(db,user,case_id,mutate=True,manage=not data.stopped)
    with domain_write_lock:
        row=db.get(ActiveCaseControl,case_id)
        if row is None:row=ActiveCaseControl(case_id=case_id);db.add(row)
        row.stopped=data.stopped;row.updated_by=user.id;row.updated_at=utcnow()
        audit(db,user,'active.case_stopped' if data.stopped else 'active.case_resumed','case',case_id)
        db.commit();return {'stopped':row.stopped}


@router.post('/targets/{target_id}/runs',status_code=201)
def request_run(case_id:int,target_id:int,data:RunOptions,background:BackgroundTasks,request:Request,user:User=Depends(current_user),db:Session=Depends(get_db)):
    enabled(request)
    with domain_write_lock:
        target,grant=allowed(db,user,case_id,target_id)
        if data.module not in {'tls','service'}:
            try:destination(request_url(grant.scope_json['host'],data),grant.scope_json['host'],grant.scope_json['ports'])
            except ValueError:raise HTTPException(422,'Request leaves the authorized destination')
        if data.module=='service' and not set(data.ports)<=set(grant.scope_json['ports']):raise HTTPException(403,'Requested port not explicitly authorized')
        if data.module=='tls' and 443 not in grant.scope_json['ports']:raise HTTPException(403,'TLS port not authorized')
        if data.finding_id is not None:
            finding=compatible(db,case_id,target_id,data.finding_id)
            if data.module not in {'http','validation'}:raise HTTPException(422,'Finding verification requires the HTTP or validation module')
            if data.method not in {'GET','HEAD'}:raise HTTPException(422,'Finding verification requires GET or HEAD')
            if data.query:raise HTTPException(422,'Finding verification does not permit query parameters')
            if data.headers:raise HTTPException(422,'Finding verification does not permit custom headers')
            resource=verification_resource(db,finding,grant)
            if data.path!=resource.path:raise HTTPException(422,'Finding verification path must exactly match its evidence-backed affected resource')
            if data.scheme!=resource.scheme:raise HTTPException(422,'Finding verification scheme/port must exactly match its evidence-backed affected resource')
        actual_ports=sorted(set(data.ports)) if data.module=='service' else [443 if data.module=='tls' or data.scheme=='https' else 80]
        action={'module':data.module,'method':data.method,'scheme':data.scheme,'path':data.path,'query_keys':sorted(data.query),'query_sha256':hashlib.sha256(canonical_bytes(data.query)).hexdigest(),'header_names':sorted(data.headers),'ports':actual_ports,'finding_id':data.finding_id}
        run=ActiveRun(case_id=case_id,target_id=target_id,authorization_id=grant.id,actor_id=user.id,module=data.module,action_json=action)
        db.add(run);db.flush()
        audit(db,user,'active.requested','case',case_id,active_run_id=run.id,target_id=target_id,authorization_id=grant.id,**action)
        if data.finding_id is not None:
            db.add(FindingVerification(finding_id=data.finding_id,active_run_id=run.id,reason='Explicitly requested; no verification result yet.'))
            audit(db,user,'finding.verification_requested','case',case_id,finding_id=data.finding_id,active_run_id=run.id)
        db.commit();result=run_dict(db,run)
    background.add_task(execute,request.app.state.session_factory,request.app.state.settings,request.app.state.active_limiter,run.id,data,request.state.login_session.token_hash,request.app.state.active_client_factory)
    return result


@router.post('/runs/{run_id}/cancel')
def cancel(case_id:int,run_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    require_case(db,user,case_id,mutate=True)
    with domain_write_lock:
        row=db.get(ActiveRun,run_id)
        if not row or row.case_id!=case_id:raise HTTPException(404,'Active run not found')
        if row.status in {'queued','running'}:
            row.cancel_requested=True
            if row.status=='queued':
                row.status='cancelled';row.ended_at=utcnow()
                v=db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==row.id))
                if v:v.state='failed_to_verify';v.reason='Cancelled before execution; original observation is unchanged.'
            audit(db,user,'active.cancelled','case',case_id,active_run_id=row.id)
        db.commit();return run_dict(db,row)
