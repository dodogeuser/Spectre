from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.api.collectors import serialize_run
from app.api.targets import get_target
from app.db.models import CollectorRun, Entity, Evidence, Relationship, Target, User
from app.db.session import get_db
from app.security.rbac import require_case

router = APIRouter(prefix="/api/cases/{case_id}", tags=["domain intelligence"])


@router.get("/evidence/{evidence_id}")
def evidence_detail(case_id: int, evidence_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    row = db.scalar(select(Evidence).join(CollectorRun).join(Target).where(Evidence.id == evidence_id, Target.case_id == case_id))
    if row is None:
        raise HTTPException(404, "Evidence not found")
    db.commit()
    return {key: getattr(row, key) for key in ("id", "run_id", "source_type", "source_ref", "captured_at", "sha256", "raw_json", "parsed_json")}


@router.get("/targets/{target_id}/domain")
def overview(case_id: int, target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    target = get_target(db, case_id, target_id)
    if target.type != "domain":
        raise HTTPException(422, "Domain overview requires a domain target")
    runs = list(db.scalars(select(CollectorRun).where(CollectorRun.target_id == target_id, CollectorRun.collector.in_(["dns", "rdap", "ct"]))
                           .order_by(CollectorRun.id.desc()).limit(30)))
    run_ids = [run.id for run in runs]
    evidence = list(db.scalars(select(Evidence).where(Evidence.run_id.in_(run_ids)).order_by(Evidence.id.desc()).limit(100)))
    relations = list(db.scalars(select(Relationship).where(Relationship.case_id == case_id, Relationship.evidence_id.in_([row.id for row in evidence]))
                               .order_by(Relationship.id.desc()).limit(500)))
    node_ids = {value for edge in relations for value in (edge.from_entity_id, edge.to_entity_id)}
    nodes = list(db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.id.in_(node_ids))))
    db.commit()
    return {"target_id": target_id, "domain": target.normalized_value, "scope_status": target.scope_status,
            "runs": [serialize_run(run) for run in runs],
            "observations": [{"evidence_id": row.id, "run_id": row.run_id, "source_type": row.source_type,
                              "source_ref": row.source_ref, "captured_at": row.captured_at, "sha256": row.sha256,
                              "synthetic_fixture": bool(row.raw_json.get("metadata", {}).get("synthetic_fixture")),
                              "parsed": row.parsed_json} for row in evidence],
            "entities": [{"id": row.id, "type": row.entity_type, "value": row.canonical_value} for row in nodes],
            "relationships": [{"id": row.id, "from": row.from_entity_id, "to": row.to_entity_id,
                               "type": row.relation_type, "confidence": row.confidence, "evidence_id": row.evidence_id} for row in relations],
            "limits": "Newest 30 domain runs, 100 evidence records and 500 relationships; observations may be historical."}
