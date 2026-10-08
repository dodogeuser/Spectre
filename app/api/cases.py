from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.db.models import AuditLog, Case, CaseMember, User
from app.db.session import get_db
from app.security.rbac import audit, require_case

router = APIRouter(prefix="/api/cases", tags=["cases"])


class CaseInput(BaseModel):
    title: str = Field(min_length=1, max_length=200, pattern=r"\S")
    description: str = Field(default="", max_length=10000)
    status: Literal["open", "archived"] = "open"


def serialize(case: Case) -> dict:
    return {"id": case.id, "title": case.title, "description": case.description,
            "status": case.status, "owner_id": case.owner_id, "created_at": case.created_at}


@router.get("")
def list_cases(user: User = Depends(current_user), db: Session = Depends(get_db), offset: int = 0):
    if offset < 0:
        raise HTTPException(422, "Offset must be nonnegative")
    query = select(Case).order_by(Case.id).offset(offset).limit(100)
    if user.role != "admin":
        query = query.where(or_(Case.owner_id == user.id,
                               Case.id.in_(select(CaseMember.case_id).where(CaseMember.user_id == user.id))))
    else:
        audit(db, user, "admin.case_list", "case", offset=offset)
        db.commit()
    return [serialize(case) for case in db.scalars(query)]


@router.post("", status_code=201)
def create_case(data: CaseInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role == "viewer":
        raise HTTPException(403, "Viewer access is read-only")
    case = Case(title=data.title.strip(), description=data.description, status=data.status, owner_id=user.id)
    db.add(case)
    db.flush()
    db.add(CaseMember(case_id=case.id, user_id=user.id))
    audit(db, user, "case.create", "case", case.id)
    db.commit()
    return serialize(case)


@router.get("/{case_id}")
def get_case(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = require_case(db, user, case_id)
    db.commit()
    return serialize(case)


@router.put("/{case_id}")
def update_case(case_id: int, data: CaseInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = require_case(db, user, case_id, mutate=True)
    case.title, case.description, case.status = data.title.strip(), data.description, data.status
    audit(db, user, "case.update", "case", case.id)
    db.commit()
    return serialize(case)


@router.put("/{case_id}/members/{user_id}", status_code=204)
def add_member(case_id: int, user_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id, mutate=True, manage=True)
    if db.get(User, user_id) is None:
        raise HTTPException(404, "User not found")
    if db.get(CaseMember, (case_id, user_id)) is None:
        db.add(CaseMember(case_id=case_id, user_id=user_id))
        audit(db, user, "case.member_add", "case", case_id, member_id=user_id)
    db.commit()


@router.delete("/{case_id}/members/{user_id}", status_code=204)
def remove_member(case_id: int, user_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = require_case(db, user, case_id, mutate=True, manage=True)
    if user_id == case.owner_id:
        raise HTTPException(409, "Cannot remove the case owner")
    member = db.get(CaseMember, (case_id, user_id))
    if member:
        db.delete(member)
        audit(db, user, "case.member_remove", "case", case_id, member_id=user_id)
    db.commit()


@router.get("/{case_id}/audit")
def case_audit(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    db.commit()
    records = db.scalars(select(AuditLog).where(AuditLog.object_type == "case", AuditLog.object_id == case_id)
                         .order_by(AuditLog.id.desc()).limit(100))
    return [{"id": row.id, "actor_id": row.actor_id, "action": row.action,
             "timestamp": row.timestamp, "metadata": row.metadata_json} for row in records]
