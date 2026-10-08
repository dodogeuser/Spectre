import hashlib
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.db.models import Target, User, utcnow
from app.db.session import get_db
from app.security.rbac import audit, require_case
from app.services.normalization import normalize

router = APIRouter(prefix="/api/cases/{case_id}/targets", tags=["targets"])


class TargetInput(BaseModel):
    type: Literal["domain", "ipv4", "ipv6", "url", "organization", "username", "email"]
    value: str = Field(min_length=1, max_length=2048)
    scope_status: Literal["passive_allowed", "active_authorized", "excluded"] = "passive_allowed"


def serialize(target: Target) -> dict:
    return {key: getattr(target, key) for key in (
        "id", "case_id", "type", "value", "normalized_value", "scope_status", "archived", "created_at", "updated_at")}


def get_target(db: Session, case_id: int, target_id: int) -> Target:
    target = db.get(Target, target_id)
    if target is None or target.case_id != case_id:
        raise HTTPException(404, "Target not found")
    return target


def assign(target: Target, data: TargetInput) -> None:
    try:
        display, canonical = normalize(data.type, data.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    target.type, target.value, target.normalized_value = data.type, display, canonical
    target.canonical_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    target.scope_status = data.scope_status
    target.updated_at = utcnow()


def save(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "A canonical target of this type already exists in this case (including archived targets)") from exc


@router.get("")
def list_targets(case_id: int, offset: int = Query(0, ge=0), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    rows = list(db.scalars(select(Target).where(Target.case_id == case_id).order_by(Target.id).offset(offset).limit(100)))
    db.commit()
    return [serialize(row) for row in rows]


@router.post("", status_code=201)
def create_target(case_id: int, data: TargetInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id, mutate=True)
    target = Target(case_id=case_id)
    assign(target, data)
    db.add(target)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "A canonical target of this type already exists in this case (including archived targets)") from exc
    audit(db, user, "target.create", "case", case_id, target_id=target.id, type=target.type, scope_status=target.scope_status)
    save(db)
    return serialize(target)


@router.get("/{target_id}")
def read_target(case_id: int, target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    target = get_target(db, case_id, target_id)
    db.commit()
    return serialize(target)


@router.put("/{target_id}")
def update_target(case_id: int, target_id: int, data: TargetInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id, mutate=True)
    target = get_target(db, case_id, target_id)
    before = serialize(target)
    assign(target, data)
    audit(db, user, "target.update", "case", case_id, target_id=target.id,
          before={key: before[key] for key in ("type", "value", "normalized_value", "scope_status")},
          after={key: getattr(target, key) for key in ("type", "value", "normalized_value", "scope_status")})
    save(db)
    return serialize(target)


@router.delete("/{target_id}", status_code=204)
def archive_target(case_id: int, target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id, mutate=True)
    target = get_target(db, case_id, target_id)
    if not target.archived:
        target.archived = True
        target.updated_at = utcnow()
        audit(db, user, "target.archive", "case", case_id, target_id=target.id)
    save(db)
