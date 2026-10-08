# Architecture

Single-process local FastAPI application; SQLAlchemy transactions and Alembic-managed MySQL 8; HTML/CSS/vanilla JavaScript with local Cytoscape.js. Existing component boundaries remain intact in v1.0.0 candidate.

Authenticated case-scoped routes ? target/scope/RBAC gates ? explicit central collector framework ? controlled pinned HTTP/DNS adapters ? canonical hashed evidence ? deterministic correlation and evidence supports ? graph/timeline ? deterministic findings and analyst review ? bounded HTML/PDF rendering. Collection is never triggered by graph navigation, reports or AI.

Active verification has a separate controlled client/lifecycle, exact-host/port grants, fresh confirmation and repeated authorization checks. Prepared Finding identity is explicit, revalidated and fail-closed. Model inference is optional, read-only, local and citation-validated. No general tool executor or arbitrary network client is exposed.

Process-local locks/rates and BackgroundTasks deliberately remain unchanged. One worker is required; active jobs are not durable across restart. app.doctor only reads configured DB metadata/state. Install/migration/backup/release tools are explicit operator actions, never startup side effects. The app does not automatically create tables, seed accounts or migrate existing records.
