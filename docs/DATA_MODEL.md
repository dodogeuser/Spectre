# Data model

Current Alembic head: 007; no Phase 13 schema migration.

users/login_sessions support hashed passwords, opaque hashed sessions, role and expiry. cases/case_members enforce ownership/membership. targets retain canonical type/value, case, scope/archive state and timestamps. collector_runs preserve actor, collector/version, immutable target snapshot and lifecycle. evidence retains raw/normalized JSON, source reference, capture time and SHA-256.

entities and relationships preserve canonical uniqueness and evidence support; case-bound graph/timeline are views over stored data. findings retain deterministic rule/version, original/generated result, analyst workflow, evidence/relationship supports and revisions. audit_logs record attributable safe operation metadata.

active_authorizations bind exact target type/value/host/ports and grant/revocation; active_case_controls contain case stop state; active_runs retain safe action/lifecycle and shadow collector provenance; finding_verifications link a requested finding/run to result/evidence independently of immutable originals. Failed/intermediate evidence remains historical data, not a false-negative finding.

MySQL tables require transactional InnoDB foreign keys. Use dedicated runtime DML credentials and separately prompted migration DDL credentials. Backup all schema records plus saved artifacts/configuration; never manually rewrite evidence or retroactively invent associations to repair a workflow.
