"""Finding preparation payload against the real API; fixture DB/transport only."""
import copy
import hashlib

import pytest
from sqlalchemy import select,func

from app.db.models import ActiveRun,AuditLog,CollectorRun,Evidence,Finding,FindingEvidence,FindingVerification
from app.services.evidence import canonical_bytes
from tests.integration.test_accounts_cases import system
from tests.integration.test_active import prepare,grant,run,response


def setup_resource(system):
    calls=[]
    def transport(*args):
        calls.append(args[0].url)
        return response(*args)|{'url':'https://example.com/login'}
    c,f,h,case,target,root=prepare(system,transport)
    gid=grant(c,h,root,target,ports=[443]);run(c,h,root,target)
    with f() as db:
        finding=db.scalar(select(Finding).where(Finding.rule_id=='web.missing_header.strict-transport-security'))
        fid=finding.id;eid=finding.original_json['evidence_ids'][0]
    calls.clear()
    body={'module':'validation','method':'HEAD','scheme':'https','path':'/login','query':{},'headers':{},'ports':[443],'confirmed':True,'finding_id':fid}
    return c,f,h,case,target,root,gid,fid,eid,calls,body


@pytest.mark.parametrize('method',['GET','HEAD'])
def test_domain_finding_login_prepared_payload_admitted(system,method):
    c,f,h,case,target,root,gid,fid,eid,calls,body=setup_resource(system)
    with f() as db:original=copy.deepcopy(db.get(Finding,fid).original_json)
    body['method']=method
    result=c.post(f'{root}/targets/{target}/runs',headers=h,json=body)
    assert result.status_code==201,result.text
    assert calls==['https://example.com/login']
    with f() as db:
        verification=db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==result.json()['id']))
        assert verification.state=='verified'
        assert db.get(Finding,fid).original_json==original
        assert db.get(ActiveRun,result.json()['id']).authorization_id==gid


@pytest.mark.parametrize('failure',[
    'path','host','subdomain','port','scheme','cross_case','cross_target','malformed',
    'hash','unsupported','unlinked','bad_method_evidence','partial','bad_status','header_present',
    'POST','OPTIONS','query','headers','confirmation','revoked','module',
])
def test_finding_resource_rejected_before_transport_and_records(system,failure):
    c,f,h,case,target,root,gid,fid,eid,calls,body=setup_resource(system)
    if failure=='path':body['path']='/admin'
    if failure=='scheme':body['scheme']='http'
    if failure in {'POST','OPTIONS'}:body['method']=failure
    if failure=='query':body['query']={'page':'1'}
    if failure=='headers':body['headers']={'Accept':'text/plain'}
    if failure=='confirmation':del body['confirmed']
    if failure=='module':body['module']='manual'
    if failure=='revoked':assert c.delete(f'{root}/authorizations/{gid}',headers=h).status_code==204
    foreign=None
    if failure in {'cross_case','cross_target'}:
        other_case=c.post('/api/cases',json={'title':'Other fixture'},headers=h).json()['id'] if failure=='cross_case' else case
        foreign=c.post(f'/api/cases/{other_case}/targets',json={'type':'domain','value':'other.example','scope_status':'active_authorized'},headers=h).json()['id']
    with f() as db:
        finding=db.get(Finding,fid);evidence=db.get(Evidence,eid)
        if failure in {'host','subdomain','port','malformed'}:
            url={'host':'https://evil.example/login','subdomain':'https://sub.example.com/login','port':'https://example.com:8443/login','malformed':'not a URL'}[failure]
            finding.original_json={**finding.original_json,'affected_url':url}
        if foreign:db.get(CollectorRun,evidence.run_id).target_id=foreign
        if failure=='hash':evidence.sha256='0'*64
        if failure=='unsupported':evidence.source_type='synthetic'
        if failure=='unlinked':db.delete(db.get(FindingEvidence,(fid,eid)))
        if failure in {'bad_method_evidence','partial','bad_status','header_present'}:
            raw=copy.deepcopy(evidence.raw_json);http=raw['measurements']['http']
            if failure=='bad_method_evidence':http['method']='OPTIONS'
            if failure=='partial':http['availability']='partial'
            if failure=='bad_status':http['http_status']=404
            if failure=='header_present':http['headers']['strict-transport-security']='max-age=1'
            evidence.raw_json=raw;evidence.sha256=hashlib.sha256(canonical_bytes(raw)).hexdigest()
        db.commit()
        original=copy.deepcopy(finding.original_json)
        counts=lambda:[db.scalar(select(func.count()).select_from(model)) for model in (ActiveRun,FindingVerification,Evidence,AuditLog)]
        before=counts()
    result=c.post(f'{root}/targets/{target}/runs',headers=h,json=body)
    assert result.status_code in {403,422},result.text
    assert calls==[]
    with f() as db:
        assert counts()==before
        assert db.get(Finding,fid).original_json==original
    if failure=='path':assert 'path must exactly match' in result.json()['detail']
    if failure=='OPTIONS':assert 'requires GET or HEAD' in result.json()['detail']
    if failure=='module':assert 'HTTP or validation module' in result.json()['detail']
