"""Only execution entry point: authorize, snapshot, run, atomically persist, audit."""
import asyncio
import threading

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import text

from app.collectors.base import CollectorContext, CollectorResult, CollectorTarget
from app.db.models import CollectorRun, Target, utcnow
from app.security.rbac import audit, require_case
from app.security.url_policy import NetworkPolicyError
from app.services.evidence import store_evidence
from app.services.http_client import ControlledHttpClient, ResponseLimitError, UnsupportedContentError
from app.services.domain_entities import domain_write_lock, project_domain_evidence
from app.services.ip_entities import project_ip_evidence
from app.security.url_policy import public_address


def run_collection(db, user, case_id, target_id, collector_name, registry, settings, limiter, admission):
    require_case(db, user, case_id, mutate=True)
    target = db.get(Target, target_id)
    if target is None or target.case_id != case_id:
        raise HTTPException(404, "Target not found")
    if db.get_bind().dialect.name == "mysql":
        engines = list(db.scalars(text("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() "
            "AND TABLE_NAME IN ('users','cases','case_members','audit_logs','login_sessions','targets','collector_runs','evidence','alembic_version')")))
        foreign_keys = db.scalar(text("SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS "
            "WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME IN ('collector_runs','evidence')"))
        if len(engines) != 9 or any(engine != "InnoDB" for engine in engines) or foreign_keys < 3:
            raise HTTPException(503, "Collector storage requires transactional migration 004")
        if collector_name in {"dns", "rdap", "ct", "reverse_dns", "ip_rdap", "ip_asn"}:
            domain_engines = list(db.scalars(text("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('entities','relationships')")))
            if len(domain_engines) != 2 or any(engine != "InnoDB" for engine in domain_engines):
                raise HTTPException(503, "Domain collector storage requires migration 005")
    if target.archived or target.scope_status not in {"passive_allowed", "active_authorized"}:
        audit(db, user, "collector.denied", "case", case_id, target_id=target_id, reason="target_scope")
        db.commit()
        raise HTTPException(403, "Archived or excluded target cannot be collected")
    try:
        collector = registry.get(collector_name)
    except KeyError as exc:
        audit(db, user, "collector.denied", "case", case_id, target_id=target_id, reason="collector_unavailable")
        db.commit()
        raise HTTPException(404, "Collector unavailable") from exc
    if not collector.passive or target.type not in collector.supported_types:
        audit(db, user, "collector.denied", "case", case_id, target_id=target_id, reason="unsupported_collector")
        db.commit()
        raise HTTPException(422, "Collector does not support this passive target")
    if collector.name in {"reverse_dns", "ip_rdap", "ip_asn"}:
        try:
            public_address(target.normalized_value)
        except NetworkPolicyError as exc:
            audit(db, user, "collector.denied", "case", case_id, target_id=target_id, reason="nonpublic_ip_seed")
            db.commit()
            raise HTTPException(403, "IP intelligence requires a public IP seed") from exc
    if not admission.acquire(blocking=False):
        audit(db, user, "collector.denied", "case", case_id, target_id=target_id, reason="concurrency_limit")
        db.commit()
        raise HTTPException(429, "Collector concurrency limit reached")
    try:
        snapshot = CollectorTarget(target.id, target.type, target.normalized_value, target.scope_status)
        run = CollectorRun(target_id=target.id, actor_id=user.id, collector=collector.name, version=collector.version,
                           status="running", target_snapshot={"type": snapshot.type, "normalized_value": snapshot.normalized_value,
                                                             "scope_status": snapshot.scope_status})
        db.add(run)
        db.flush()
        run_id = run.id
        audit(db, user, "collector.started", "case", case_id, run_id=run_id, target_id=target_id, collector=collector.name, version=collector.version)
        db.commit()

        async def execute():
            context = CollectorContext(ControlledHttpClient(settings, limiter))
            return await asyncio.wait_for(collector.collect(snapshot, context), timeout=settings.collector_timeout_seconds)

        try:
            result = CollectorResult.model_validate(asyncio.run(execute()))
            if any(len(warning) > 1000 for warning in result.warnings):
                raise ValueError("Warning limit exceeded")
            with domain_write_lock:
                records = store_evidence(db, run_id, result, settings.collector_max_response_bytes * 2)
                db.flush()
                if collector.name in {"dns", "rdap", "ct"}:
                    project_domain_evidence(db, case_id, snapshot.normalized_value, records)
                elif collector.name in {"reverse_dns", "ip_rdap", "ip_asn"}:
                    project_ip_evidence(db, case_id, snapshot.normalized_value, records)
                run.status, run.ended_at, run.warnings_json = result.status, utcnow(), result.warnings
                run.error_code = result.error_code if result.status == "failed" else None
                audit(db, user, "collector." + result.status, "case", case_id, run_id=run_id,
                      evidence_count=len(records), error_code=run.error_code)
                db.commit()
        except (Exception, asyncio.CancelledError) as exc:
            db.rollback()  # No partial evidence or success audit survives.
            run = db.get(CollectorRun, run_id)
            run.status, run.ended_at = "failed", utcnow()
            if isinstance(exc, asyncio.CancelledError):
                code = "cancelled"
            elif isinstance(exc, NetworkPolicyError):
                code = "network_policy"
            elif isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
                code = "timeout"
            elif isinstance(exc, UnsupportedContentError):
                code = "unsupported_content_type"
            elif isinstance(exc, (ResponseLimitError, ValueError, ValidationError)):
                code = "invalid_or_oversized_result"
            else:
                code = "collector_error"
            run.error_code = code
            audit(db, user, "collector.failed", "case", case_id, run_id=run_id, error_code=code)
            db.commit()
        return run
    finally:
        admission.release()


def admission_limit():
    return threading.BoundedSemaphore(4)
