"""Line-based local fixture bridge for shipped JS -> real API. No sockets/live DB."""
import copy
import json
import sys
from sqlalchemy import select
from app.db.models import ActiveRun,Evidence,Finding,FindingEvidence,FindingVerification
from tests.integration.test_accounts_cases import system
from tests.integration.test_active_finding_resource import setup_resource


def main():
    fixture=system.__wrapped__()
    try:
        environment=next(fixture)
        c,f,h,case,target,root,gid,fid,eid,calls,body=setup_resource(environment)
        detail=c.get(f'/api/cases/{case}/findings/{fid}',headers=h).json()
        with f() as db:
            original=copy.deepcopy(db.get(Finding,fid).original_json)
            source=copy.deepcopy(db.get(Evidence,eid).raw_json)
        print(json.dumps(detail),flush=True)
        payload=json.loads(sys.stdin.readline())
        if 'authorization' in payload:
            grant=c.post(f'{root}/targets/{target}/authorization',headers=h,json=payload['authorization'])
            assert grant.status_code==201,grant.text
            gid=grant.json()['id']
            print(json.dumps({'authorized':True}),flush=True)
            payload=json.loads(sys.stdin.readline())
        assert payload['finding_id']==fid
        result=c.post(f'{root}/targets/{target}/runs',headers=h,json=payload)
        assert result.status_code==201,result.text
        rid=result.json()['id']
        with f() as db:
            assert db.get(ActiveRun,rid).action_json['finding_id']==fid
            verification=db.scalar(select(FindingVerification).where(FindingVerification.active_run_id==rid))
            assert verification.state=='verified'
            assert verification.evidence_id!=eid
            assert db.get(FindingEvidence,(fid,verification.evidence_id)) is not None
            assert db.get(Finding,fid).original_json==original
            assert db.get(Evidence,eid).raw_json==source
            new_eid=verification.evidence_id
        detail=c.get(f'/api/cases/{case}/findings/{fid}',headers=h).json()
        assert any(v['active_run_id']==rid and v['evidence_id']==new_eid for v in detail['verifications'])
        assert any(e['id']==new_eid for e in detail['evidence'])
        assert calls==['https://example.com/login']
        print(json.dumps({'passed':True,'frontend_payload_used':True,'finding_association':True,'detail_evidence_link':True,'original_immutable':True}),flush=True)
    finally:fixture.close()


if __name__=='__main__':main()
