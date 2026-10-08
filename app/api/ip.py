"""Case-authorized stored IP intelligence; GET never performs collection."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.api.collectors import serialize_run
from app.api.targets import get_target
from app.db.models import CollectorRun, Entity, Evidence, Relationship, User
from app.db.session import get_db
from app.security.rbac import require_case

router = APIRouter(prefix="/api/cases/{case_id}", tags=["IP intelligence"])


@router.get("/targets/{target_id}/ip")
def overview(case_id: int, target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    target = get_target(db, case_id, target_id)
    if target.type not in {"ipv4", "ipv6"}:
        raise HTTPException(422, "IP overview requires an IPv4 or IPv6 target")
    runs = list(db.scalars(select(CollectorRun).where(CollectorRun.target_id == target_id,
        CollectorRun.collector.in_(["reverse_dns", "ip_rdap", "ip_asn"])).order_by(CollectorRun.id.desc()).limit(30)))
    records = list(db.scalars(select(Evidence).where(Evidence.run_id.in_([run.id for run in runs])).order_by(Evidence.id.desc()).limit(100)))
    root = db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.entity_type == "ip", Entity.canonical_value == target.normalized_value))
    related = []
    if root is not None:
        rows = db.execute(select(Relationship, Entity).join(Entity, Entity.id == Relationship.from_entity_id).where(
            Relationship.case_id == case_id, Entity.case_id == case_id, Entity.entity_type == "domain",
            Relationship.to_entity_id == root.id, Relationship.relation_type == "resolves_to").order_by(Relationship.id.desc()).limit(500))
        related = [{"domain": entity.canonical_value, "evidence_id": relation.evidence_id, "confidence": relation.confidence,
                    "relationship": "resolves_to"} for relation, entity in rows]
    db.commit()
    return {"target_id": target.id, "ip": target.normalized_value, "scope_status": target.scope_status,
        "runs": [serialize_run(run) for run in runs],
        "observations": [{"evidence_id": row.id, "run_id": row.run_id, "source_type": row.source_type,
            "source_ref": row.source_ref, "captured_at": row.captured_at, "sha256": row.sha256,
            "synthetic_fixture": bool(row.raw_json.get("metadata", {}).get("synthetic_fixture")), "parsed": row.parsed_json} for row in records],
        "related_domains": related, "reputation": {"availability": "not_configured", "observations": [],
            "message": "No reputation feed configured; this is not a clean or malicious verdict."},
        "limits": "Newest 30 IP runs, 100 evidence records and 500 case DNS relationships; observations may be historical."}
