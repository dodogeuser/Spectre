from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.db.models import User, AuditLog
from sqlalchemy import select
from app.db.session import get_db
from app.security.rbac import audit, require_case
from app.services.correlation import correlate, graph
from app.services.domain_entities import domain_write_lock

router = APIRouter(prefix="/api/cases/{case_id}", tags=["stored evidence correlation"])


@router.get("/correlation/jobs")
def jobs(case_id: int, offset: int = Query(0, ge=0), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    rows = list(db.scalars(select(AuditLog).where(AuditLog.object_type == "case", AuditLog.object_id == case_id, AuditLog.action.in_(["correlation.completed", "correlation.failed"])).order_by(AuditLog.id.desc()).offset(offset).limit(100)))
    result = [{"id": row.id, "actor_id": row.actor_id, "timestamp": row.timestamp, "status": row.action.removeprefix("correlation."), "result": row.metadata_json} for row in rows]
    db.commit()
    return result


@router.post("/correlation/jobs", status_code=201)
def job(case_id: int, after: int = Query(0, ge=0), user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = require_case(db, user, case_id, mutate=True)
    if case.status == "archived":
        raise HTTPException(403, "Archived case cannot correlate")
    try:
        with domain_write_lock:
            result = correlate(db, case_id, after)
            audit(db, user, "correlation.completed", "case", case_id, **result)
            db.commit()
        return result
    except Exception:
        db.rollback()
        audit(db, user, "correlation.failed", "case", case_id, reason="correlation_error")
        db.commit()
        raise HTTPException(500, "Correlation failed; no partial changes committed")


@router.get("/graph")
def read_graph(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    result = graph(db, case_id)
    db.commit()
    return result


@router.get("/entities")
def entities(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return read_graph(case_id, user, db)["entities"]


@router.get("/relationships")
def relationships(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return read_graph(case_id, user, db)["relationships"]
