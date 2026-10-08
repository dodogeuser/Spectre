from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.models import AuditLog, Case, CaseMember, User


def audit(db: Session, user: User | None, action: str, kind: str, object_id: int | None = None, **metadata) -> None:
    db.add(AuditLog(actor_id=user.id if user else None, action=action,
                    object_type=kind, object_id=object_id, metadata_json=metadata))


def require_case(db: Session, user: User, case_id: int, *, mutate: bool = False, manage: bool = False) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "Case not found")
    member = db.get(CaseMember, (case_id, user.id))
    if user.role != "admin" and case.owner_id != user.id and member is None:
        raise HTTPException(404, "Case not found")
    if mutate and user.role == "viewer":
        raise HTTPException(403, "Viewer access is read-only")
    if manage and user.role != "admin" and case.owner_id != user.id:
        raise HTTPException(403, "Only the owner or an administrator can manage membership")
    if user.role == "admin":
        audit(db, user, "admin.case_access", "case", case_id, mutate=mutate)
    return case
