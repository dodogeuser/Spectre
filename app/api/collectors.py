from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.api.targets import get_target
from app.db.models import CollectorRun, Evidence, Target, User
from app.db.session import get_db
from app.security.rbac import require_case
from app.services.collection import run_collection

router = APIRouter(prefix="/api/cases/{case_id}", tags=["collector framework"])


def serialize_run(run):
    return {key: getattr(run, key) for key in ("id", "target_id", "actor_id", "collector", "version", "status", "started_at", "ended_at", "error_code", "target_snapshot", "warnings_json")}


@router.get("/collectors")
def list_collectors(case_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    db.commit()
    registry = request.app.state.collector_registry
    return [{"name": collector.name, "version": collector.version, "supported_types": sorted(collector.supported_types),
             "passive": collector.passive, "enabled": collector.name not in registry.disabled}
            for collector in registry.entries.values()]


@router.post("/targets/{target_id}/collectors/{collector_name}/runs", status_code=201)
def collect(case_id: int, target_id: int, collector_name: str, request: Request,
            user: User = Depends(current_user), db: Session = Depends(get_db)):
    state = request.app.state
    run = run_collection(db, user, case_id, target_id, collector_name, state.collector_registry,
                         state.settings, state.host_limiter, state.collector_admission)
    return serialize_run(run)


@router.get("/targets/{target_id}/runs")
def list_runs(case_id: int, target_id: int, offset: int = Query(0, ge=0), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    get_target(db, case_id, target_id)
    runs = list(db.scalars(select(CollectorRun).where(CollectorRun.target_id == target_id).order_by(CollectorRun.id.desc()).offset(offset).limit(100)))
    db.commit()
    return [serialize_run(run) for run in runs]


@router.get("/runs/{run_id}/evidence")
def read_evidence(case_id: int, run_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    run = db.scalar(select(CollectorRun).join(Target).where(CollectorRun.id == run_id, Target.case_id == case_id))
    if run is None:
        raise HTTPException(404, "Run not found")
    rows = list(db.scalars(select(Evidence).where(Evidence.run_id == run_id).order_by(Evidence.id).limit(100)))
    db.commit()
    return [{key: getattr(row, key) for key in ("id", "run_id", "source_type", "source_ref", "captured_at", "sha256", "raw_json", "parsed_json")} for row in rows]
