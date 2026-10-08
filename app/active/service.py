"""Central active lifecycle: fresh authorization gates, measured evidence, no passive execution."""
import asyncio
import hashlib
import threading
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import select

from app.active.client import ActiveClient,safe_url
from app.active.policy import target_host,SENSITIVE,destination
from app.db.models import ActiveAuthorization,ActiveCaseControl,ActiveRun,Case,CollectorRun,Evidence,Finding,FindingEvidence,FindingVerification,LoginSession,Target,User,utcnow
from app.security.rbac import require_case,audit
from app.security.url_policy import NetworkPolicyError
from app.services.domain_entities import domain_write_lock
from app.services.evidence import canonical_bytes
from app.services.correlation import correlate
from app.services.findings import RULES
from app.services.reporting import clean_text,normalize

VERSION='1.0.0'
admission=threading.BoundedSemaphore(1)


def allowed(db,user,case_id,target_id,authorization_id=None):
    case=require_case(db,user,case_id,mutate=True)
    target=db.get(Target,target_id)
    if not target or target.case_id!=case_id:raise HTTPException(404,'Target not found')
    if case.status=='archived' or target.archived or target.scope_status!='active_authorized':raise HTTPException(403,'Target/case is not explicitly active-authorized')
    control=db.get(ActiveCaseControl,case_id)
    if control and control.stopped:raise HTTPException(403,'Case active kill switch is stopped')
    query=select(ActiveAuthorization).where(ActiveAuthorization.case_id==case_id,ActiveAuthorization.target_id==target_id,ActiveAuthorization.revoked_at.is_(None))
    if authorization_id is not None:query=query.where(ActiveAuthorization.id==authorization_id)
    grant=db.scalar(query.order_by(ActiveAuthorization.id.desc()).limit(1))
    if not grant or grant.scope_json.get('target_type')!=target.type or grant.scope_json.get('target_value')!=target.normalized_value or grant.scope_json.get('host')!=target_host(target):
        raise HTTPException(403,'Explicit current target authorization required')
    return target,grant


def compatible(db,case_id,target_id,finding_id):
    finding=db.get(Finding,finding_id)
    if not finding or finding.case_id!=case_id or finding.target_id!=target_id:raise HTTPException(404,'Finding not found for this target')
    if finding.rule_id not in RULES:raise HTTPException(422,'This finding has no supported safe verification rule')
    return finding


def verification_resource(db,finding,grant):
    """Admit only an immutable finding resource backed by original, applicable evidence.

    No resolver/transport is called here. Normal destination policy still applies.
    """
    try:
        original=finding.original_json
        affected=original['affected_url']
        parts=urlsplit(affected)
        if parts.query or parts.fragment:raise ValueError('Query/fragment')
        resource=destination(affected,grant.scope_json['host'],grant.scope_json['ports'])
        ids=original['evidence_ids'][:100]
        if not isinstance(ids,list) or not ids:raise ValueError('Missing original support')
    except (KeyError,TypeError,ValueError,AttributeError):
        raise HTTPException(422,'Finding affected resource is malformed or outside current exact-host/port authorization')
    supports=db.execute(select(Evidence,CollectorRun).join(CollectorRun,Evidence.run_id==CollectorRun.id).join(Target,CollectorRun.target_id==Target.id).join(FindingEvidence,FindingEvidence.evidence_id==Evidence.id).where(FindingEvidence.finding_id==finding.id,Evidence.id.in_(ids),Target.case_id==finding.case_id,Target.id==finding.target_id)).all()
    for evidence,run in supports:
        try:
            if run.status!='completed' or evidence.sha256!=hashlib.sha256(canonical_bytes(evidence.raw_json)).hexdigest():continue
            if evidence.source_type in {'active_http','active_validation','active_manual'} and run.collector==evidence.source_type:
                raw=evidence.raw_json;http=raw['measurements']['http']
                applicable=(raw['mode']=='active' and raw['target_id']==finding.target_id and http['availability']=='observed' and http['http_status']==200 and http['method'] in {'GET','HEAD'} and not http.get('scope_boundary') and http['url']==evidence.source_ref==affected and http['headers'].get('content-type','').split(';')[0].strip().lower() in {'text/html','application/xhtml+xml'} and not http['headers'].get(RULES[finding.rule_id]['header']))
            elif evidence.source_type=='web_metadata' and run.collector=='web_metadata':
                # This collector's controlled transport is GET-only. Reuse its
                # existing complete-response/hash/normalization applicability gate.
                from app.services.findings import assess
                applicable=assess(evidence,run)=='observed' and evidence.parsed_json['requested_url']==affected and not evidence.raw_json['metadata']['headers'].get(RULES[finding.rule_id]['header'])
                if applicable:destination(evidence.source_ref,grant.scope_json['host'],grant.scope_json['ports'])
            else:continue
            if applicable:return resource
        except (KeyError,TypeError,ValueError,AttributeError):continue
    raise HTTPException(422,'Finding resource has no applicable hash-valid original supporting evidence for this case and target')


def run_dict(db,run):
    return {key:getattr(run,key) for key in ('id','case_id','target_id','authorization_id','actor_id','module','version','action_json','requested_at','started_at','ended_at','status','collector_run_id','result_json','error_code','cancel_requested')}|{'evidence_ids':list(db.scalars(select(Evidence.id).where(Evidence.run_id==run.collector_run_id))) if run.collector_run_id else []}


def guard_for(factory,settings,run_id,session_hash):
    def guard():
        if not settings.active_assessment_enabled:raise HTTPException(403,'Active execution disabled')
        with factory() as db:
            run=db.get(ActiveRun,run_id)
            if not run or run.cancel_requested or run.status!='running':raise HTTPException(409,'Active run cancelled or no longer running')
            session=db.get(LoginSession,session_hash)
            if not session or session.user_id!=run.actor_id or session.expires_at<=utcnow():raise HTTPException(401,'Requesting session expired or revoked')
            user=db.get(User,run.actor_id)
            allowed(db,user,run.case_id,run.target_id,run.authorization_id)
    return guard


def verification(db,user,run,evidence,payload):
    record=db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==run.id))
    if not record:return
    finding=compatible(db,run.case_id,run.target_id,record.finding_id)
    http=payload.get('http',{})
    original_ids=finding.original_json.get('evidence_ids',[])[:100]
    supports=list(db.scalars(select(Evidence).join(CollectorRun,Evidence.run_id==CollectorRun.id).join(Target,CollectorRun.target_id==Target.id).join(FindingEvidence,FindingEvidence.evidence_id==Evidence.id).where(FindingEvidence.finding_id==finding.id,Evidence.id.in_(original_ids),Target.case_id==run.case_id,Target.id==run.target_id)))
    original_urls={safe_url(e.source_ref) for e in supports if e.sha256==hashlib.sha256(canonical_bytes(e.raw_json)).hexdigest() and not urlsplit(e.source_ref).query}
    # A same-host redirect is applicable only when it reaches the exact originally captured resource.
    valid=run.status=='completed' and http.get('availability')=='observed' and http.get('http_status')==200 and http.get('method') in {'GET','HEAD'} and http.get('headers',{}).get('content-type','').split(';')[0].strip().lower() in {'text/html','application/xhtml+xml'} and http.get('url') in original_urls and not http.get('scope_boundary')
    if valid:
        absent=not http['headers'].get(RULES[finding.rule_id]['header'])
        record.state='verified' if absent else 'not_confirmed'
        record.reason='Header absence confirmed in this authorized capture; no exploitability established.' if absent else 'Header present in this capture; original historical observation is preserved.'
        if db.get(FindingEvidence,(finding.id,evidence.id)) is None:db.add(FindingEvidence(finding_id=finding.id,evidence_id=evidence.id))
    else:
        record.state='failed_to_verify';record.reason='No complete applicable response. Failure is not evidence that the original finding is false.'
    record.evidence_id=evidence.id
    audit(db,user,'finding.verification_completed','case',run.case_id,active_run_id=run.id,finding_id=finding.id,state=record.state)


def project_findings(db,user,run,evidence,payload):
    http=payload.get('http',{})
    if http.get('availability')!='observed' or not 200<=http.get('http_status',0)<300:return
    checks=[];headers=http.get('headers',{})
    html_response=headers.get('content-type','').split(';')[0].strip().lower() in {'text/html','application/xhtml+xml'}
    if http['http_status']==200 and run.action_json['path']=='/' and http.get('method') in {'GET','HEAD'} and html_response:
        for key,rule in RULES.items():
            if rule['header']=='strict-transport-security' and urlsplit(http['url']).scheme!='https':continue
            if not headers.get(rule['header']):checks.append((key,'Header not observed: '+rule['header'],rule['description']))
        if http.get('directory_listing_signature'):checks.append(('active.http.directory_listing','Directory listing signature observed','Captured root HTML matched an index-title/link signature. Content sensitivity and exploitability are not established.'))
    if http.get('method')=='OPTIONS' and any(method.strip().upper() in {'PUT','DELETE','PATCH','TRACE','CONNECT'} for method in headers.get('allow','').split(',')):
        checks.append(('active.http.advertised_methods','Additional HTTP methods advertised','OPTIONS advertised additional methods; they were not executed and availability/exploitability is unverified.'))
    if headers.get('access-control-allow-origin')=='*':checks.append(('active.http.cors_wildcard','Wildcard CORS origin observed','Wildcard origin was observed. This may be intentional for public data and does not establish sensitive-data exposure.'))
    if headers.get('server'):checks.append(('active.http.server_metadata','Server metadata exposed','A Server response header was observed. Reported software is unverified; no vulnerability is established.'))
    for key,title,description in checks:
        finding=db.scalar(select(Finding).where(Finding.case_id==run.case_id,Finding.target_id==run.target_id,Finding.rule_id==key))
        if finding is not None:continue  # Preserve original rule/analyst result; explicit Verify records later assessments.
        result={'severity':'informational','confidence':.95,'rule_state':'observed','assessment_state':'observed','evidence_ids':[evidence.id],'rule_id':key,'rule_version':VERSION,'scoring_version':VERSION,'why':['Direct authorized '+http['method']+' response observation with verified evidence hash.','Informational priority; applicability, equivalent protections and exploitability are not assessed.','Confidence 0.95 refers only to this captured observation; not vulnerability probability.']}
        result.update(priority='informational',affected_url=http['url'],evidence_type='authorized_active_response')
        finding=Finding(case_id=run.case_id,target_id=run.target_id,rule_id=key,rule_version=VERSION,finding_type='active_configuration_observation',title=title,description=description,status='informational',generated_json=result,original_json=result)
        db.add(finding);db.flush();db.add(FindingEvidence(finding_id=finding.id,evidence_id=evidence.id))
        audit(db,user,'finding.generated','case',run.case_id,finding_id=finding.id,rule_id=key,mode='active')


def execute(factory,settings,limiter,run_id,options,session_hash,client_factory=ActiveClient):
    acquired=admission.acquire(False)
    guard=guard_for(factory,settings,run_id,session_hash)
    try:
        with factory() as db:
            run=db.get(ActiveRun,run_id);user=db.get(User,run.actor_id)
            if run.cancel_requested or run.status!='queued':return
            target,grant=allowed(db,user,run.case_id,run.target_id,run.authorization_id)
            run.status='running';run.started_at=utcnow()
            shadow=CollectorRun(target_id=target.id,actor_id=user.id,collector='active_'+run.module,version=VERSION,status='running',target_snapshot={'type':target.type,'normalized_value':target.normalized_value,'scope_status':target.scope_status,'active_authorization_id':grant.id},warnings_json=[])
            db.add(shadow);db.flush();run.collector_run_id=shadow.id
            audit(db,user,'active.started','case',run.case_id,active_run_id=run.id,module=run.module,authorization_id=grant.id);db.commit()
            host=grant.scope_json['host'];ports=grant.scope_json['ports']
        if not acquired:raise RuntimeError('active_capacity')
        payload=asyncio.run(client_factory(host,ports,guard,limiter).call(options))
        guard()
        finish(factory,settings,run_id,payload,None)
    except Exception as exc:
        code='cancelled' if isinstance(exc,HTTPException) else 'timeout' if isinstance(exc,(TimeoutError,asyncio.TimeoutError)) else 'network_policy' if isinstance(exc,NetworkPolicyError) else 'tls_validation' if isinstance(exc,__import__('ssl').SSLCertVerificationError) else 'response_limit' if isinstance(exc,__import__('app.services.http_client',fromlist=['ResponseLimitError']).ResponseLimitError) else 'network_unavailable' if isinstance(exc,OSError) else 'active_error'
        finish(factory,settings,run_id,{'failure':{'code':code,'meaning':'No verified observation; failure is not a negative finding.'}},code)
    finally:
        if acquired:admission.release()


def finish(factory,settings,run_id,payload,error):
    with domain_write_lock,factory() as db:
        run=db.get(ActiveRun,run_id);user=db.get(User,run.actor_id)
        if run.status in {'completed','failed','cancelled'}:return
        # Final grant/case/role check prevents committing new facts after revocation.
        try:
            if run.cancel_requested or not settings.active_assessment_enabled:raise HTTPException(403,'Stopped')
            allowed(db,user,run.case_id,run.target_id,run.authorization_id)
        except HTTPException:error='cancelled';payload={'failure':{'code':'cancelled','meaning':'Authorization or run revoked; no positive result committed.'}}
        run.status='cancelled' if error=='cancelled' else 'failed' if error else 'completed'
        run.error_code=error;run.ended_at=utcnow()
        shadow=db.get(CollectorRun,run.collector_run_id) if run.collector_run_id else None
        if shadow:
            shadow.status='completed' if not error else 'failed';shadow.ended_at=run.ended_at;shadow.error_code=error
            raw=normalize({'mode':'active','active_run_id':run.id,'authorization_id':run.authorization_id,'module':run.module,'version':VERSION,'target_id':run.target_id,'action':run.action_json,'measurements':payload},(settings.mysql_password.get_secret_value(),))
            raw['authorization_id']=run.authorization_id  # Numeric FK, never an HTTP Authorization credential.
            evidence=Evidence(run_id=shadow.id,source_type='active_'+run.module,source_ref=(payload.get('http',{}).get('url') or 'https://'+db.get(ActiveAuthorization,run.authorization_id).scope_json['host']+'/'),raw_json=raw,parsed_json={'status':'ok' if not error else 'error','mode':'active','availability':payload.get('http',{}).get('availability',payload.get('availability','observed' if not error else 'unavailable')),'measurements':raw['measurements']},sha256=hashlib.sha256(canonical_bytes(raw)).hexdigest())
            db.add(evidence);db.flush()
            if not error:
                correlate(db,run.case_id,evidence.id-1)
                project_findings(db,user,run,evidence,raw['measurements'])
            verification(db,user,run,evidence,raw['measurements'])
            run.result_json={'evidence_ids':[evidence.id],'availability':evidence.parsed_json['availability'],'summary':raw['measurements']}
            audit(db,user,'active.evidence_captured','case',run.case_id,active_run_id=run.id,evidence_id=evidence.id)
        if not shadow:
            record=db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==run.id))
            if record:
                record.state='failed_to_verify';record.reason='Execution stopped before a usable capture; original observation is preserved.'
                audit(db,user,'finding.verification_completed','case',run.case_id,active_run_id=run.id,finding_id=record.finding_id,state=record.state)
        audit(db,user,'active.'+run.status,'case',run.case_id,active_run_id=run.id,error_code=error)
        if run.module=='manual':audit(db,user,'active.manual_executed','case',run.case_id,active_run_id=run.id,status=run.status)
        db.commit()
