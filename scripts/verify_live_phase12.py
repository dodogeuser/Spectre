"""Explicit owner-authorized manual acceptance, NOT a pytest suite.

Never invoke before deterministic suites pass. Contacts only getwooperly.com,
with same-host public-address pinning; revokes the grant when finished.
"""
import hashlib
import json
import argparse
from io import BytesIO
from pathlib import Path
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import inspect,text,select
from app.config import get_settings
from app.db.session import make_session_factory
from app.db.models import Case,Evidence,Finding,ActiveAuthorization,utcnow
from app.main import create_app
from app.services.evidence import canonical_bytes
from app.services.reporting import snapshot,pdf_report,html_report


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--resume-case',type=int);parser.add_argument('--verify-finding-only',action='store_true');args=parser.parse_args()
    assert not args.verify_finding_only or args.resume_case,'Finding-only acceptance requires an existing authorized case'
    settings=get_settings();assert not settings.active_assessment_enabled,'Leave deployment flag disabled; acceptance uses a temporary in-process opt-in'
    factory=make_session_factory(settings);engine=factory.kw['bind']
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version'))=='007'
        historical={}
        for table in inspect(engine).get_table_names():
            if table in {'login_sessions','alembic_version'}:continue
            keys=inspect(engine).get_pk_constraint(table)['constrained_columns']
            historical[table]=(keys,{tuple(row[k] for k in keys):dict(row) for row in db.execute(text(f'SELECT * FROM `{table}`')).mappings()})
        case15=snapshot(db,db.get(Case,15));baseline15=case15['snapshot_sha256'];pdf15=pdf_report(case15);html15=html_report(case15)
    credentials=json.loads(Path('.local/login-credentials.json').read_text(encoding='utf-8'))
    live=settings.model_copy(update={'active_assessment_enabled':True})
    results={'deployment_active_enabled':False,'case15_before_digest':baseline15,'checks':[],'runs':[],'browser_visual_verification':'Unavailable: no browser surface exposed','scope':'getwooperly.com only, no third-party redirects followed'}
    out=Path('.local/phase12-live-verification.json');grant_id=None;root=None
    if args.verify_finding_only:
        previous=json.loads(out.read_text());assert previous['case_id']==args.resume_case
        Path('.local/phase12-initial-live-verification.json').write_text(json.dumps(previous,indent=2))
        results['runs']=previous['runs'];results['checks']=previous['checks']
    with TestClient(create_app(live,factory)) as client:
        auth=client.post('/api/auth/login',json={'username':'researcher','password':credentials['researcher']['password']},headers={'X-Spectre-Login':'1'});assert auth.status_code==200
        headers={'X-CSRF-Token':auth.json()['csrf_token']}
        case=client.get(f'/api/cases/{args.resume_case}') if args.resume_case else client.post('/api/cases',json={'title':'Wooperly Authorized Security Assessment','description':'Owner-authorized non-destructive Phase 12 acceptance only.'},headers=headers)
        assert case.status_code in {200,201} and case.json()['title']=='Wooperly Authorized Security Assessment'
        case_id=case.json()['id'];root=f'/api/cases/{case_id}/active';results['case_id']=case_id
        if args.resume_case:
            target_data=next(t for t in client.get(f'/api/cases/{case_id}/targets').json() if t['normalized_value']=='getwooperly.com' and t['type']=='domain')
        else:
            target=client.post(f'/api/cases/{case_id}/targets',json={'type':'domain','value':'getwooperly.com','scope_status':'passive_allowed'},headers=headers);assert target.status_code==201
            target_data=target.json()
        target_id=target_data['id'];results['target_id']=target_id
        path=f'{root}/targets/{target_id}/runs'
        assert client.post(path,json={'module':'http','confirmed':True},headers=headers).status_code==403
        results['checks'].append('revoked/no grant rejected' if args.resume_case else 'passive-only target rejected')
        if not args.resume_case:assert client.put(f'/api/cases/{case_id}/targets/{target_id}',json={'type':'domain','value':'getwooperly.com','scope_status':'active_authorized'},headers=headers).status_code==200
        grant=client.post(f'{root}/targets/{target_id}/authorization',json={'confirmed':True,'ports':[80,443],'note':'Domain owned and controlled by analyst. Authorized for non-destructive SPECTRE Phase 12 verification.'},headers=headers);assert grant.status_code==201
        grant_id=grant.json()['id'];results['authorization_id']=grant_id
        try:
            actions=[{'module':'http','scheme':'http','method':'HEAD'}, {'module':'http','method':'HEAD'}, {'module':'tls'}, {'module':'validation','method':'HEAD'}, {'module':'validation','method':'OPTIONS'}, {'module':'http','method':'GET','path':'/robots.txt'}, {'module':'http','method':'GET','path':'/.well-known/security.txt'}, {'module':'service','ports':[80,443]}, {'module':'manual','method':'HEAD','path':'/','query':{'spectre':'verification'},'headers':{'Accept':'text/html'}}]
            for action in ([] if args.verify_finding_only else actions):
                response=client.post(path,json={'confirmed':True,**action},headers=headers);assert response.status_code==201,response.text
                row=client.get(root).json()['runs'][0];results['runs'].append(row);out.write_text(json.dumps(results,indent=2,default=str))
                # Stop repeated contact if public connectivity is unavailable.
                if row['status']=='failed' and row['error_code'] in {'network_unavailable','timeout','network_policy'}:
                    results['limitation']='Live network path unavailable; stopped remaining target requests rather than retrying';break
            findings=client.get(f'/api/cases/{case_id}/findings').json()['findings']
            compatible=next((f for f in findings if f['rule_id'].startswith('web.missing_header.')),None)
            if compatible:
                response=client.post(path,json={'module':'validation','method':'HEAD','finding_id':compatible['id'],'confirmed':True},headers=headers);assert response.status_code==201
                row=client.get(root).json()['runs'][0];results['runs'].append(row)
                detail=client.get(f"/api/cases/{case_id}/findings/{compatible['id']}").json();results['finding_verification']=detail['verifications']
            else:results['finding_verification']='No applicable missing-header finding from live response; fixture coverage verifies all states'
        finally:
            assert client.delete(f'{root}/authorizations/{grant_id}',headers=headers).status_code==204
            assert client.post(path,json={'module':'http','confirmed':True},headers=headers).status_code==403
            results['revocation_blocks']=True
        graph=client.get(f'/api/cases/{case_id}/investigation').json();timeline=client.get(f'/api/cases/{case_id}/timeline').json()
        results['graph']={'entities':len(graph['entities']),'relationships':len(graph['relationships']),'types':sorted({r['type'] for r in graph['relationships']})}
        assert all(r['evidence_ids'] for r in graph['relationships'])
        results['timeline']={'count':len(timeline['events']),'active_events':sum(e['type'].startswith('active.') for e in timeline['events'])}
        output=Path('output/pdf');output.mkdir(parents=True,exist_ok=True)
        for fmt in ('html','pdf'):
            response=client.post(f'/api/cases/{case_id}/reports/export',json={'format':fmt},headers=headers);assert response.status_code==200,response.text[:200]
            replay=client.post(f'/api/cases/{case_id}/reports/export',json={'format':fmt},headers=headers);assert replay.content==response.content
            (output/f'spectre-case-{case_id}-phase12.{fmt}').write_bytes(response.content)
            content=response.text if fmt=='html' else '\n'.join(p.extract_text() for p in PdfReader(BytesIO(response.content)).pages)
            assert 'Active Verification' in content
        with factory() as db:
            for row in results['runs']:
                for eid in row['evidence_ids']:
                    evidence=db.get(Evidence,eid);assert evidence.sha256==hashlib.sha256(canonical_bytes(evidence.raw_json)).hexdigest()
            for table,(keys,before) in historical.items():
                after={tuple(row[k] for k in keys):dict(row) for row in db.execute(text(f'SELECT * FROM `{table}`')).mappings()}
                assert all(after.get(k)==v for k,v in before.items()),f'Historical data modified: {table}'
            final15=snapshot(db,db.get(Case,15));assert final15['snapshot_sha256']==baseline15
            assert pdf_report(final15)==pdf15 and html_report(final15)==html15
            results['case15']={'unchanged_digest':baseline15,'counts':final15['counts'],'pdf_sha256':hashlib.sha256(pdf15).hexdigest(),'pdf_byte_identical':True,'html_byte_identical':True,'no_recollection':True}
        results['historical_records_preserved']=True;results['evidence_hashes_verified']=True
    out.write_text(json.dumps(results,indent=2,default=str))
    print(json.dumps({k:v for k,v in results.items() if k!='runs'},indent=2))


if __name__=='__main__':main()
