# Configuration

Run from the project root. Settings load .env and SPECTRE_-prefixed environment variables (environment wins); unknown .env keys and invalid values fail clearly. get_settings startup errors and doctor withhold supplied values. .env.example contains placeholders only; installers never overwrite .env. Protect it with owner-only permissions and back it up encrypted.

| Variable prefix SPECTRE_ | Default / meaning |
| --- | --- |
| APP_NAME | SPECTRE |
| ENVIRONMENT | local; local/development/production |
| BIND_HOST / BIND_PORT | 127.0.0.1 / 8000, used by python -m app.run; direct uvicorn CLI flags take precedence independently |
| MYSQL_HOST / MYSQL_PORT | 127.0.0.1 / 3306; configured DB only, never an investigation target |
| MYSQL_DATABASE / MYSQL_USER | spectre / spectre; dedicated database and runtime user |
| MYSQL_PASSWORD | No usable default; replace CHANGE_ME in the example |
| SECURE_COOKIES | false for loopback HTTP; true requires HTTPS |
| SESSION_HOURS | 8, valid 1?24 |
| LOG_LEVEL | INFO; DEBUG/INFO/WARNING/ERROR/CRITICAL |
| OUTPUT_DIR | output; Path-valued tooling/artifact directory, relative to working directory or explicit absolute path |
| ACTIVE_ASSESSMENT_ENABLED | false; opt-in does not authorize any target |
| AI_ENABLED / AI_MODEL | false / empty; existing local model only; no install/download |
| AI_TIMEOUT_SECONDS | 30, valid 1?60 |
| COLLECTOR_TIMEOUT_SECONDS / RETRIES | 10 / 1; ranges 0.1?60 / 0?2 |
| COLLECTOR_MAX_RESPONSE_BYTES | 1048576; range 1024?5242880 |
| COLLECTOR_HOST_INTERVAL_SECONDS / MAX_REDIRECTS | 1 / 3; ranges 0.1?60 / 0?5 |
| DNS_ENABLED / RDAP_ENABLED / CT_ENABLED | true; execution still requires scope/RBAC |
| REVERSE_DNS_ENABLED / IP_RDAP_ENABLED / IP_ASN_ENABLED | true |
| WEB_METADATA_ENABLED | true |

No application signing secret is needed: session tokens are cryptographically random opaque values, stored hashed in MySQL; they are not signed cookies/JWTs. Do not invent an unused APP_SECRET key. No provider API-key setting is shipped. Model endpoint is fixed local loopback; no external AI credentials are accepted.

Production mode requires a nonempty/non-placeholder DB password, a non-root DB user, secure cookies and non-DEBUG logging. It does not configure TLS or make the application an Internet-ready deployment. Loopback HTTP remains the default. Forwarded-header/proxy trust and non-loopback exposure need separate review.

Logs go to stderr as redacted JSON; app.run disables access logs by default. Direct uvicorn invocations may emit access logs, whose query strings/cookies/common credential forms are redacted by the configured formatter. No prompt/body/credential logging is intended; redaction cannot discover every unlabeled secret. Redirect operator logs only into a protected location. No automatic log-file path or retention policy is imposed.

Evidence lives in MySQL; report exports render in memory and download to the browser. OUTPUT_DIR is for prepared artifact/doctor tooling, not a relocated database/evidence store. Doctor does not move or create directories. Installers prepare default output/pdf and logs; create and protect a custom OUTPUT_DIR yourself. Temporary/cached acceptance artifacts are excluded from release packaging. Existing output is never moved by configuration changes.

Active limits remain intentionally fixed: ports 80/443; GET/HEAD/OPTIONS; total 20s, connection/read 5s, 64KiB body, bounded headers/two redirects, single-process concurrency/rates. Login is limited to ten attempts per source address per minute with bounded process-local state. Graph/report bounds and collector timeouts remain unchanged; see SECURITY.md.
