"""Deterministic active acceptance; all transports/resolvers are injected fixtures."""
import hashlib
import pytest
from sqlalchemy import select
from app.active.client import ActiveClient
from app.active.policy import RunOptions,destination
from app.security.url_policy import NetworkPolicyError
from app.services.http_client import ResponseLimitError
from app.services.evidence import canonical_bytes
from app.db.models import Evidence,Finding,FindingVerification,AuditLog,ActiveAuthorization,ActiveRun,ActiveCaseControl,Target,LoginSession
from tests.integration.test_accounts_cases import system,login


class Limiter:
    def reserve(self,*args):return 0
    def defer(self,*args):pass


def response(dest,address,method,headers,deadline,guard):
    guard()
    return {'url':dest.url.split('?')[0],'http_status':200,'headers':{'content-type':'text/html','server':'fixture'},'resolved_ip':address,'elapsed_ms':1,'body_bytes':0,'body_sha256':hashlib.sha256(b'').hexdigest(),'directory_listing_signature':False}


def prepare(system,transport=response):
    client,factory=system;h=login(client,'owner')
    case=client.post('/api/cases',json={'title':'Active fixture'},headers=h).json()['id']
    target=client.post(f'/api/cases/{case}/targets',json={'type':'domain','value':'example.com','scope_status':'active_authorized'},headers=h).json()['id']
    root=f'/api/cases/{case}/active';client.app.state.settings.active_assessment_enabled=True
    client.app.state.active_limiter=Limiter()
    client.app.state.active_client_factory=lambda host,ports,guard,limiter:ActiveClient(host,ports,guard,limiter,resolver=lambda *a:['93.184.216.34'],http_transport=transport,tls_transport=lambda d,a,deadline,g:{'host':d.host,'port':443,'resolved_ip':a,'fingerprint_sha256':'a'*64,'certificate_verified':True},service_transport=lambda d,a,deadline,g:{'host':d.host,'port':d.port,'resolved_ip':a,'reachability':'reachable'})
    return client,factory,h,case,target,root


def grant(c,h,root,target,ports=[80,443]):
    r=c.post(f'{root}/targets/{target}/authorization',json={'confirmed':True,'ports':ports,'note':'Owned fixture'},headers=h)
    assert r.status_code==201,r.text
    return r.json()['id']


def run(c,h,root,target,**kwargs):
    r=c.post(f'{root}/targets/{target}/runs',json={'module':'http','confirmed':True,**kwargs},headers=h)
    assert r.status_code==201,r.text
    return c.get(root).json()['runs'][0]


def test_feature_scope_grant_revocation_and_kill(system):
    c,f,h,case,t,root=prepare(system)
    body={'module':'http','confirmed':True}
    assert c.post(f'{root}/targets/{t}/runs',json=body,headers=h).status_code==403
    c.app.state.settings.active_assessment_enabled=False
    assert c.post(f'{root}/targets/{t}/authorization',json={'confirmed':True},headers=h).status_code==403
    c.app.state.settings.active_assessment_enabled=True;gid=grant(c,h,root,t)
    assert c.put(f'{root}/control',json={'stopped':True,'confirmed':True},headers=h).status_code==200
    assert c.post(f'{root}/targets/{t}/runs',json=body,headers=h).status_code==403
    c.put(f'{root}/control',json={'stopped':False,'confirmed':True},headers=h)
    assert run(c,h,root,t)['status']=='completed'
    assert c.delete(f'{root}/authorizations/{gid}',headers=h).status_code==204
    assert c.post(f'{root}/targets/{t}/runs',json=body,headers=h).status_code==403
    assert c.put(f'/api/cases/{case}/targets/{t}',json={'type':'domain','value':'example.com','scope_status':'passive_allowed'},headers=h).status_code==200
    assert c.post(f'{root}/targets/{t}/authorization',json={'confirmed':True},headers=h).status_code==403

    assert c.put(f'/api/cases/{case}/targets/{t}',json={'type':'domain','value':'example.com','scope_status':'excluded'},headers=h).status_code==200
    assert c.post(f'{root}/targets/{t}/runs',json=body,headers=h).status_code==403


@pytest.mark.parametrize('module',['http','validation','manual','tls','service'])
def test_evidence_graph_timeline_report(system,module):
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t)
    result=run(c,h,root,t,module=module)
    assert result['status']=='completed',result
    with f() as db:
        evidence=db.get(Evidence,result['evidence_ids'][0])
        assert evidence.source_type=='active_'+module
        assert evidence.sha256==hashlib.sha256(canonical_bytes(evidence.raw_json)).hexdigest()
        assert evidence.raw_json['authorization_id']==result['authorization_id']
        assert {'active.requested','active.started','active.completed','active.evidence_captured'}<=set(db.scalars(select(AuditLog.action)))
    graph=c.get(f'/api/cases/{case}/investigation').json()
    assert any(n['type']=='service' for n in graph['entities']),graph
    assert all(e['evidence_ids'] for e in graph['relationships'])
    timeline=c.get(f'/api/cases/{case}/timeline').json()
    assert any(e['type']=='active.completed' for e in timeline['events'])
    for fmt in ['html','pdf']:
        report=c.post(f'/api/cases/{case}/reports/export',json={'format':fmt},headers=h)
        assert report.status_code==200,report.text[:200]
        again=c.post(f'/api/cases/{case}/reports/export',json={'format':fmt},headers=h)
        assert again.content==report.content
        if fmt=='html':assert 'Active Verification' in report.text


@pytest.mark.parametrize('error,code',[(TimeoutError,'timeout'),(ResponseLimitError,'response_limit'),(NetworkPolicyError,'network_policy'),(OSError,'network_unavailable')])
def test_failures_are_not_negative_findings(system,error,code):
    def fail(*args):raise error('fixture private detail')
    c,f,h,case,t,root=prepare(system,fail);grant(c,h,root,t)
    result=run(c,h,root,t);assert result['status']=='failed' and result['error_code']==code
    with f() as db:
        assert list(db.scalars(select(Finding)))==[]
        assert 'fixture private detail' not in str(db.get(Evidence,result['evidence_ids'][0]).raw_json)


@pytest.mark.parametrize('change',[{'method':'DELETE'},{'ports':[22]},{'path':'//evil.example/'},{'path':'/%252fexample.com'},{'path':'/../secret'},{'headers':{'Authorization':'test'}},{'headers':{'Host':'evil.example'}},{'query':{'token':'x'}},{'query':{'x':'https://evil.example'}},{'confirmed':False},{'module':'scan'},{'url':'https://evil.example'}])
def test_request_validation(system,change):
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t)
    assert c.post(f'{root}/targets/{t}/runs',json={'module':'manual','confirmed':True,**change},headers=h).status_code==422
    assert c.get(root).json()['runs']==[]


def test_rbac_csrf_isolation(system):
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t)
    assert c.post(f'{root}/targets/{t}/runs',json={'module':'http','confirmed':True}).status_code==403
    other=login(c,'other');assert c.get(root).status_code==404
    assert c.post(f'{root}/targets/{t}/runs',json={'module':'http','confirmed':True},headers=other).status_code==404
    h=login(c,'owner');c.put(f'/api/cases/{case}/members/4',headers=h);c.put(f'/api/cases/{case}/members/3',headers=h)
    viewer=login(c,'viewer');assert c.get(root).status_code==200
    assert c.post(f'{root}/targets/{t}/runs',json={'module':'http','confirmed':True},headers=viewer).status_code==403
    other=login(c,'other');assert c.post(f'{root}/targets/{t}/authorization',json={'confirmed':True},headers=other).status_code==403
    assert c.put(f'{root}/control',json={'stopped':True,'confirmed':True},headers=other).status_code==200
    assert c.put(f'{root}/control',json={'stopped':False,'confirmed':True},headers=other).status_code==403


def test_finding_verify_preserves_original_and_failed_state(system):
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t);run(c,h,root,t)
    with f() as db:
        finding=db.scalar(select(Finding).where(Finding.rule_id.like('web.missing_header.%')));fid=finding.id;original=finding.original_json
    result=run(c,h,root,t,module='validation',finding_id=fid)
    with f() as db:
        assert db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==result['id'])).state=='verified'
        assert db.get(Finding,fid).original_json==original
    def fail(*args):raise TimeoutError()
    c.app.state.active_client_factory=lambda host,ports,guard,limiter:ActiveClient(host,ports,guard,limiter,resolver=lambda *a:['93.184.216.34'],http_transport=fail)
    result=run(c,h,root,t,module='validation',finding_id=fid)
    with f() as db:
        assert db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==result['id'])).state=='failed_to_verify'
        assert db.get(Finding,fid).original_json==original


@pytest.mark.parametrize('url',['http://example.com:443/','https://example.com:0/','https://sub.example.com/','https://localhost/','https://127.0.0.1/','file:///etc/passwd','https://example.com@evil.example/'])
def test_exact_destination(url):
    with pytest.raises(NetworkPolicyError):destination(url,'example.com',[80,443])


def test_external_redirect_not_followed(system):
    calls=[]
    def redirect(dest,address,method,headers,deadline,guard):
        calls.append(dest.url);return response(dest,address,method,headers,deadline,guard)|{'http_status':302,'headers':{'location':'https://evil.example/'}}
    c,f,h,case,t,root=prepare(system,redirect);grant(c,h,root,t)
    result=run(c,h,root,t)
    assert result['result_json']['availability']=='partial' and len(calls)==1


@pytest.mark.parametrize('stop',['revoke','kill','cancel','archive','edit','logout'])
def test_mid_operation_revocation_cannot_commit_positive_results(system,stop):
    from app.db.models import utcnow
    c,f,h,case,t,root=prepare(system);gid=grant(c,h,root,t)
    calls=[]
    def stop_during_transport(dest,address,method,headers,deadline,guard):
        calls.append(dest.url)
        with f() as db:
            if stop=='revoke':db.get(ActiveAuthorization,gid).revoked_at=utcnow()
            if stop=='kill':db.add(ActiveCaseControl(case_id=case,stopped=True,updated_by=2))
            if stop=='cancel':db.scalar(select(ActiveRun)).cancel_requested=True
            if stop=='archive':db.get(Target,t).archived=True
            if stop=='edit':db.get(Target,t).normalized_value='different.example'
            if stop=='logout':
                for session in db.scalars(select(LoginSession)):db.delete(session)
            db.commit()
        return response(dest,address,method,headers,deadline,lambda:None)
    c.app.state.active_client_factory=lambda host,ports,guard,limiter:ActiveClient(host,ports,guard,limiter,resolver=lambda *a:['93.184.216.34'],http_transport=stop_during_transport)
    r=c.post(f'{root}/targets/{t}/runs',json={'module':'http','confirmed':True},headers=h)
    assert r.status_code==201 and len(calls)==1
    with f() as db:
        runrow=db.scalar(select(ActiveRun));assert runrow.status=='cancelled'
        assert list(db.scalars(select(Finding)))==[]
        assert db.scalar(select(Evidence)).parsed_json['availability']=='unavailable'


def test_present_header_not_confirmed_and_original_immutable(system):
    from app.services.findings import RULES
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t);run(c,h,root,t)
    with f() as db:
        finding=db.scalar(select(Finding).where(Finding.rule_id.like('web.missing_header.%')));fid=finding.id;original=finding.original_json;header=RULES[finding.rule_id]['header']
    def present(*args):
        result=response(*args);result['headers'][header]='fixture protection';return result
    c.app.state.active_client_factory=lambda host,ports,guard,limiter:ActiveClient(host,ports,guard,limiter,resolver=lambda *a:['93.184.216.34'],http_transport=present)
    result=run(c,h,root,t,module='validation',finding_id=fid)
    with f() as db:
        assert db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==result['id'])).state=='not_confirmed'
        assert db.get(Finding,fid).original_json==original


def test_query_values_not_persisted_and_replay_no_duplicate_findings(system):
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t)
    run(c,h,root,t,module='manual',query={'view':'unique-value-123'},headers={'Accept-Language':'en'})
    with f() as db:before=len(list(db.scalars(select(Finding))))
    run(c,h,root,t)
    with f() as db:
        assert len(list(db.scalars(select(Finding))))==before
        assert 'unique-value-123' not in str([e.raw_json for e in db.scalars(select(Evidence))])
        assert 'unique-value-123' not in str([e.metadata_json for e in db.scalars(select(AuditLog))])


def test_cancel_queued_run_creates_no_evidence(system,monkeypatch):
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t)
    monkeypatch.setattr('app.api.active.execute',lambda *args:None)
    queued=run(c,h,root,t);assert queued['status']=='queued'
    cancelled=c.post(f"{root}/runs/{queued['id']}/cancel",headers=h).json()
    assert cancelled['status']=='cancelled' and cancelled['evidence_ids']==[]
    with f() as db:assert list(db.scalars(select(Evidence)))==[]


def test_only_port_80_grant_service_succeeds_tls_blocks(system):
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t,[80])
    assert run(c,h,root,t,module='service',ports=[80])['status']=='completed'
    assert run(c,h,root,t,module='http',scheme='http')['action_json']['ports']==[80]
    assert c.post(f'{root}/targets/{t}/runs',json={'module':'tls','confirmed':True},headers=h).status_code==403


def test_partial_service_retains_observed_port(system):
    c,f,h,case,t,root=prepare(system);grant(c,h,root,t)
    def service(dest,address,deadline,guard):
        if dest.port==443:raise TimeoutError()
        return {'host':dest.host,'port':80,'resolved_ip':address,'reachability':'reachable'}
    c.app.state.active_client_factory=lambda host,ports,guard,limiter:ActiveClient(host,ports,guard,limiter,resolver=lambda *a:['93.184.216.34'],service_transport=service)
    result=run(c,h,root,t,module='service',ports=[80,443])
    assert result['status']=='completed' and result['result_json']['availability']=='partial'
    assert result['result_json']['summary']['services'][0]['port']==80


def test_empty_active_case_read_is_not_collection(system):
    c,f=system;h=login(c,'owner');case=c.post('/api/cases',json={'title':'Empty'},headers=h).json()['id']
    c.app.state.active_client_factory=lambda *a:pytest.fail('Reading active history must not collect')
    data=c.get(f'/api/cases/{case}/active').json()
    assert data['enabled'] is False and data['runs']==[] and data['authorizations']==[]


@pytest.mark.parametrize('destination_path,expected',[('/login','verified'),('/changed','failed_to_verify')])
def test_verification_requires_same_original_final_resource(system,destination_path,expected):
    def login_response(*args):return response(*args)|{'url':'https://example.com/login'}
    c,f,h,case,t,root=prepare(system,login_response);grant(c,h,root,t);run(c,h,root,t)
    with f() as db:fid=db.scalar(select(Finding).where(Finding.rule_id.like('web.missing_header.%'))).id
    def next_response(*args):return response(*args)|{'url':'https://example.com'+destination_path}
    c.app.state.active_client_factory=lambda host,ports,guard,limiter:ActiveClient(host,ports,guard,limiter,resolver=lambda *a:['93.184.216.34'],http_transport=next_response)
    result=run(c,h,root,t,module='validation',path='/login',finding_id=fid)
    with f() as db:assert db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==result['id'])).state==expected
