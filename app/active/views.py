"""Case-isolated stored active context for timeline and deterministic reports."""
from sqlalchemy import select
from app.db.models import ActiveAuthorization,ActiveRun,ActiveCaseControl,FindingVerification,Finding,Target,Evidence


def stored(db,case_id,redact=True):
    grants=list(db.scalars(select(ActiveAuthorization).join(Target,ActiveAuthorization.target_id==Target.id).where(ActiveAuthorization.case_id==case_id,Target.case_id==case_id).order_by(ActiveAuthorization.id).limit(10001)))
    runs=list(db.scalars(select(ActiveRun).join(Target,ActiveRun.target_id==Target.id).where(ActiveRun.case_id==case_id,Target.case_id==case_id).order_by(ActiveRun.id).limit(10001)))
    if len(grants)>10000 or len(runs)>10000:
        from fastapi import HTTPException
        raise HTTPException(413,'Active history exceeds complete snapshot limit')
    verifications=list(db.scalars(select(FindingVerification).join(ActiveRun,FindingVerification.active_run_id==ActiveRun.id).join(Finding,FindingVerification.finding_id==Finding.id).where(ActiveRun.case_id==case_id,Finding.case_id==case_id,ActiveRun.target_id==Finding.target_id).order_by(FindingVerification.id).limit(10001)))
    if len(verifications)>10000:
        from fastapi import HTTPException
        raise HTTPException(413,'Verification history exceeds snapshot limit')
    control=db.get(ActiveCaseControl,case_id)
    if not grants and not runs and not control:return None
    valid_runs={r.id:r for r in runs}
    grant_data=[{k:getattr(g,k) for k in ('id','target_id','granted_by','granted_at','scope_json','revoked_at','revoked_by')}|{'note':'[Analyst text omitted]' if redact and g.note else g.note} for g in grants]
    run_data=[]
    for r in runs:
        ids=list(db.scalars(select(Evidence.id).where(Evidence.run_id==r.collector_run_id))) if r.collector_run_id else []
        run_data.append({k:getattr(r,k) for k in ('id','target_id','actor_id','module','version','authorization_id','requested_at','started_at','ended_at','status','error_code','action_json','collector_run_id','result_json')}|{'evidence_ids':ids})
    verification_data=[{k:getattr(v,k) for k in ('id','finding_id','active_run_id','state','reason','evidence_id','created_at')} for v in verifications if v.active_run_id in valid_runs]
    return {'authorizations':grant_data,'runs':run_data,'verifications':verification_data,'case_stopped':bool(control and control.stopped)}


def events(data):
    result=[]
    def add(at,kind,key,source,run=None,evidence=None):
        if at is not None:result.append({'timestamp':at,'type':kind,'key':key,'source':source,'source_ref':'stored active history','evidence_ids':[evidence] if evidence else [],'run_ids':[run['collector_run_id']] if run and run['collector_run_id'] else [],'active_run_id':run['id'] if run else None,'entity_ids':[]})
    if not data:return result
    for g in data['authorizations']:
        add(g['granted_at'],'active.authorization_granted',f"active-authorization:{g['id']}:grant",f"Authorization #{g['id']} granted · Target #{g['target_id']}")
        add(g['revoked_at'],'active.authorization_revoked',f"active-authorization:{g['id']}:revoke",f"Authorization #{g['id']} revoked")
    for r in data['runs']:
        for at,kind in ((r['requested_at'],'requested'),(r['started_at'],'started'),(r['ended_at'],r['status'])):
            add(at,'active.'+kind,f"active-run:{r['id']}:{kind}",f"Active run #{r['id']} · {r['module']} · {kind}",r)
    by_id={r['id']:r for r in data['runs']}
    for v in data['verifications']:
        r=by_id[v['active_run_id']]
        add(v['created_at'],'finding.verification_requested',f"verification:{v['id']}:requested",f"Finding #{v['finding_id']} · verification requested",r)
        if r['ended_at']:
            add(r['ended_at'],'finding.verification',f"verification:{v['id']}:result",f"Finding #{v['finding_id']} · {v['state']}",r,v['evidence_id'])
    return result
