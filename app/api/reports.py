"""Audited, case-authorized, stored-data-only report downloads."""
import logging
from threading import BoundedSemaphore
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.db.models import User
from app.db.session import get_db
from app.security.rbac import audit, require_case
from app.services.domain_entities import domain_write_lock
from app.services.reporting import VERSION, html_report, pdf_report, snapshot

router = APIRouter(prefix="/api/cases/{case_id}/reports", tags=["reports and export"])
export_slots = BoundedSemaphore(2)


class ExportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["html", "pdf"]
    redact_notes: StrictBool = True


def context(db, case, request, redact_notes):
    # Credentials are only used for output redaction; never placed in the report.
    secrets = (request.app.state.settings.mysql_password.get_secret_value(),)
    with domain_write_lock:
        return snapshot(db, case, redact_notes, secrets)


@router.get("/preview")
def preview(case_id: int, request: Request, response: Response, redact_notes: bool = Query(True),
            user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = require_case(db, user, case_id)
    data = context(db, case, request, redact_notes)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {"report_version": VERSION, "case": data["case"], "counts": data["counts"],
            "snapshot_sha256": data["snapshot_sha256"], "redact_notes": redact_notes,
            "limitations": data["limitations"], "formats": ["html", "pdf"],
            "can_export": user.role != "viewer"}


@router.post("/export")
def export(case_id: int, options: ExportOptions, request: Request,
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    # Existing authentication dependency enforces CSRF before export.
    case = require_case(db, user, case_id, mutate=True)
    if not export_slots.acquire(blocking=False):
        raise HTTPException(429, "Report generator busy; retry later")
    try:
        data = context(db, case, request, options.redact_notes)
        content = html_report(data) if options.format == "html" else pdf_report(data)
        if len(content) > 20 * 1024 * 1024:
            raise HTTPException(413, "Report exceeds download size budget")
        audit(db, user, "report.generated", "case", case_id, format=options.format,
              report_version=VERSION, snapshot_sha256=data["snapshot_sha256"],
              redact_notes=options.redact_notes, byte_count=len(content))
        db.commit()
        return Response(content, media_type="text/html" if options.format == "html" else "application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="spectre-case-{case_id}.{options.format}"',
                                 "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Content-Security-Policy": "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
                                 "X-Spectre-Snapshot-SHA256": data["snapshot_sha256"]})
    except HTTPException as exc:
        db.rollback()
        audit(db, user, "report.failed", "case", case_id, format=options.format, status_code=exc.status_code)
        db.commit()
        raise
    except Exception:
        db.rollback()
        logging.getLogger("spectre").error("Report generation failed")
        audit(db, user, "report.failed", "case", case_id, format=options.format, reason="render_error")
        db.commit()
        raise HTTPException(503, "Report generation unavailable; investigation records are unchanged")
    finally:
        export_slots.release()
