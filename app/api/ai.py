import re
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.ai.provider import ProviderError
from app.ai.service import INSUFFICIENT, NOTICE, context_for, intent, validate_answer
from app.ai.tools import CaseReadTools
from app.api.auth import current_user
from app.db.models import User
from app.db.session import get_db
from app.security.rbac import audit, require_case

router = APIRouter(prefix="/api/cases/{case_id}/ai", tags=["read-only AI assistant"])


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=1000)
    entity_id: int | None = Field(default=None, gt=0)
    relationship_id: int | None = Field(default=None, gt=0)


@router.get("/status")
def status(case_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id); db.commit()
    provider = request.app.state.ai_provider
    return {"configured": bool(getattr(provider, "enabled", False)), "provider": provider.name,
            "model": provider.model, "notice": NOTICE,
            "privacy": "Only bounded authorized case context is sent to local Ollama at 127.0.0.1:11434. No external provider or conversation history."}


@router.post("/questions")
def ask(case_id: int, data: Question, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    tools = CaseReadTools(db, user, case_id)
    provider = request.app.state.ai_provider
    audit(db, user, "ai.requested", "case", case_id, provider=provider.name, model=provider.model)
    db.commit()
    mode = intent(data.question)
    # Revalidate explicit record IDs even for unsupported requests; no global lookup.
    try:
        if data.entity_id:
            tools.get_entity_evidence(data.entity_id)
        if data.relationship_id:
            tools.explain_relationship(data.relationship_id)
    except HTTPException:
        audit(db, user, "ai.refused", "case", case_id, reason="record_outside_context"); db.commit()
        raise
    if mode in ("prohibited", "unsupported"):
        audit(db, user, "ai.refused", "case", case_id, reason=mode); db.commit()
        return {"status": "refused" if mode == "prohibited" else "insufficient", "claims": [],
                "message": "The assistant cannot execute actions or access URLs, credentials or other cases." if mode == "prohibited" else INSUFFICIENT,
                "notice": NOTICE}
    try:
        context = context_for(tools, mode, data.entity_id, data.relationship_id)
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError, AttributeError):
        audit(db, user, "ai.failed", "case", case_id, reason="invalid_context"); db.commit()
        raise HTTPException(503, "AI context unavailable; investigation data is unchanged") from None
    authorized_refs = {("evidence", evidence_id) for fact in context["facts"] for evidence_id in fact["evidence_ids"]}
    authorized_refs.update((record["type"], record["id"]) for fact in context["facts"] for record in fact["records"])
    for kind, record_id in re.findall(r"\b(evidence|finding|entity|relationship|run|target|case)\s*#?\s*(\d+)\b", data.question, re.I):
        reference = (kind.lower(), int(record_id))
        if reference != ("case", case_id) and reference not in authorized_refs:
            audit(db, user, "ai.refused", "case", case_id, reason="record_outside_context"); db.commit()
            raise HTTPException(404, "Record not available in the authorized AI context")
    if not context["facts"]:
        audit(db, user, "ai.refused", "case", case_id, reason="insufficient_context"); db.commit()
        return {"status": "insufficient", "message": INSUFFICIENT, "claims": [], "notice": NOTICE}
    db.commit()  # Release the read transaction before waiting on inference.
    try:
        result = validate_answer(provider.answer(data.question, context), context)
    except ProviderError as exc:
        audit(db, user, "ai.failed", "case", case_id, reason=exc.code, provider=provider.name, model=provider.model); db.commit()
        raise HTTPException(503, "AI unavailable or output rejected: " + exc.code) from None
    except Exception:
        audit(db, user, "ai.failed", "case", case_id, reason="provider_failure"); db.commit()
        raise HTTPException(503, "AI unavailable; investigation data is unchanged") from None
    # Membership may have changed while inference was running. Recheck before disclosure.
    db.expire_all(); require_case(db, user, case_id)
    audit(db, user, "ai.completed", "case", case_id, provider=provider.name, model=provider.model,
          claim_count=len(result["claims"]), status=result["status"]); db.commit()
    return result | {"case_id": case_id}
