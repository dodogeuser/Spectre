from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.api.collectors import serialize_run
from app.api.targets import get_target
from app.db.models import CollectorRun, Evidence, User
from app.db.session import get_db
from app.security.rbac import require_case

router = APIRouter(prefix="/api/cases/{case_id}", tags=["web metadata"])


@router.get("/targets/{target_id}/web")
def overview(case_id: int, target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    target = get_target(db, case_id, target_id)
    if target.type != "url":
        raise HTTPException(422, "Web metadata requires a URL target")
    runs = list(db.scalars(select(CollectorRun).where(CollectorRun.target_id == target_id, CollectorRun.collector == "web_metadata").order_by(CollectorRun.id.desc()).limit(30)))
    records = list(db.scalars(select(Evidence).where(Evidence.run_id.in_([run.id for run in runs])).order_by(Evidence.id.desc()).limit(30)))
    db.commit()
    return {"target_id": target.id, "url": target.normalized_value, "scope_status": target.scope_status,
        "runs": [serialize_run(run) for run in runs], "observations": [{"evidence_id": row.id, "run_id": row.run_id,
            "source_ref": row.source_ref, "captured_at": row.captured_at, "sha256": row.sha256,
            "synthetic_fixture": bool(row.raw_json.get("metadata", {}).get("synthetic_fixture")), "parsed": row.parsed_json} for row in records],
        "limits": "Newest 30 runs/responses only; observations may be historical."}
