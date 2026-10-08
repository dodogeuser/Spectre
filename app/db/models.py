"""Case access and authentication persistence."""

from datetime import datetime, timezone

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import UniqueConstraint


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin','investigator','viewer')", name="ck_user_role"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="open")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CaseMember(Base):
    __tablename__ = "case_members"
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    object_type: Mapped[str] = mapped_column(String(50))
    object_id: Mapped[int | None] = mapped_column(nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)


class LoginSession(Base):
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("case_id", "type", "canonical_hash", name="uq_target_canonical"),
        CheckConstraint("type IN ('domain','ipv4','ipv6','url','organization','username','email')", name="ck_target_type"),
        CheckConstraint("scope_status IN ('passive_allowed','active_authorized','excluded')", name="ck_target_scope"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(Text)
    normalized_value: Mapped[str] = mapped_column(Text)
    canonical_hash: Mapped[str] = mapped_column(String(64))
    scope_status: Mapped[str] = mapped_column(String(30), default="passive_allowed")
    archived: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CollectorRun(Base):
    __tablename__ = "collector_runs"
    __table_args__ = (CheckConstraint("status IN ('running','completed','failed')", name="ck_run_status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    collector: Mapped[str] = mapped_column(String(50))
    version: Mapped[str] = mapped_column(String(50))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20))
    error_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    target_snapshot: Mapped[dict] = mapped_column(JSON)
    warnings_json: Mapped[list] = mapped_column(JSON, default=list)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("collector_runs.id"), index=True)
    source_type: Mapped[str] = mapped_column(String(50))
    source_ref: Mapped[str] = mapped_column(Text)
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    sha256: Mapped[str] = mapped_column(String(64))
    raw_json: Mapped[dict] = mapped_column(JSON)
    parsed_json: Mapped[dict] = mapped_column(JSON)


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("case_id", "entity_type", "canonical_hash", name="uq_entity_canonical"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(30))
    canonical_value: Mapped[str] = mapped_column(Text)
    canonical_hash: Mapped[str] = mapped_column(String(64))
    attributes_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Relationship(Base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("from_entity_id", "to_entity_id", "relation_type", "evidence_id", name="uq_relationship_evidence"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_relationship_confidence"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    from_entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"))
    to_entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"))
    relation_type: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[float]
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("case_id", "target_id", "rule_id", name="uq_finding_rule_target"),
        CheckConstraint("status IN ('open','accepted','false_positive','informational','resolved')", name="ck_finding_status"),
        CheckConstraint("severity_override IS NULL OR severity_override IN ('informational','low','medium','high','critical')", name="ck_finding_override"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(100))
    rule_version: Mapped[str] = mapped_column(String(30))
    finding_type: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(250))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="informational")
    generated_json: Mapped[dict] = mapped_column(JSON)
    original_json: Mapped[dict] = mapped_column(JSON)
    notes: Mapped[str] = mapped_column(Text, default="")
    severity_override: Mapped[str | None] = mapped_column(String(20), nullable=True)
    override_reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), primary_key=True)


class FindingRelationship(Base):
    __tablename__ = "finding_relationships"
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    relationship_id: Mapped[int] = mapped_column(ForeignKey("relationships.id"), primary_key=True)


class FindingRevision(Base):
    __tablename__ = "finding_revisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    change_type: Mapped[str] = mapped_column(String(30))
    snapshot_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ActiveAuthorization(Base):
    __tablename__ = "active_authorizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    granted_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    scope_json: Mapped[dict] = mapped_column(JSON)
    note: Mapped[str] = mapped_column(Text, default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class ActiveCaseControl(Base):
    __tablename__ = "active_case_controls"
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), primary_key=True)
    stopped: Mapped[bool] = mapped_column(default=False)
    updated_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ActiveRun(Base):
    __tablename__ = "active_runs"
    __table_args__ = (CheckConstraint("status IN ('queued','running','completed','failed','cancelled')", name="ck_active_run_status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    authorization_id: Mapped[int] = mapped_column(ForeignKey("active_authorizations.id"))
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    module: Mapped[str] = mapped_column(String(30))
    version: Mapped[str] = mapped_column(String(30), default="1.0.0")
    action_json: Mapped[dict] = mapped_column(JSON)
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    collector_run_id: Mapped[int | None] = mapped_column(ForeignKey("collector_runs.id"), unique=True, nullable=True)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(default=False)


class FindingVerification(Base):
    __tablename__ = "finding_verifications"
    __table_args__ = (CheckConstraint("state IN ('observed','verified','not_confirmed','failed_to_verify')",name="ck_finding_verification_state"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    active_run_id: Mapped[int] = mapped_column(ForeignKey("active_runs.id"), unique=True)
    state: Mapped[str] = mapped_column(String(30), default="observed")
    reason: Mapped[str] = mapped_column(Text, default="")
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
