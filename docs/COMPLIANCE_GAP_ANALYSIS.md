# CyCentra 360 — Compliance Readiness Assessment
**Date:** 2026-05-25
**Frameworks:** GDPR (EU) · SOC 2 Type II · EU AI Act
**Status:** Gap Analysis
**Scope:** Full repository review — backend, correlation engine, UEBA/ML, OIDC/RBAC, ASM, portal, CI/CD

---

## Executive Summary

CyCentra 360 is a cybersecurity platform that processes significant quantities of personal data — usernames, email addresses, IP addresses, behavioural baselines, and security events attributed to named individuals — making GDPR compliance a primary obligation. The platform has a strong security engineering foundation: RBAC with PostgreSQL backing, structured audit trails, OIDC/OAuth SSO with approval workflows, bcrypt password hashing, Azure/HashiCorp Vault secret management, and an ML-in-shadow-mode safety gate. However, it lacks the legal framework documentation (privacy notice, lawful basis register, DPA templates), data subject rights endpoints, encryption-at-rest for PII, log retention controls, and several SOC 2 operational controls that auditors will require. The AI subsystem — a SIEM correlation engine with 35 deterministic rules, an ML anomaly layer, and LLM narrative generation — is best classified as **Limited Risk** under the EU AI Act, though the UEBA profiling capability that directly influences security decisions about named individuals introduces higher-risk characteristics that require transparency disclosures and human oversight documentation to pass regulatory scrutiny.

**21 gaps · 22 passed checks across 3 frameworks — 6 Critical · 9 High · 4 Medium (gaps) · 22 PASS**

---

## 1. GDPR Readiness

### 1.1 What is Compliant Today

**PASS-G-1: Minimal-Purpose User Schema**
- **Requirement:** GDPR Article 5(1)(c) (data minimisation)
- **Evidence:** `cy_users` table (`blueprints/rbac/manager.py`) stores only `email`, `name`, `role`, `auth_type`, `created_at`, `updated_at`, `approval_status`. No unnecessary personal attributes are collected. The schema is purposeful and proportionate to the user management function.
- **Status:** PASS

---

**PASS-G-2: User Account Deletion Implemented and Audited**
- **Requirement:** GDPR Article 17 (right to erasure — partial)
- **Evidence:** `_delete_user()` in `blueprints/rbac/manager.py` executes `DELETE FROM cy_users WHERE email = %s` and immediately writes an `auth_event("rbac_user_deleted", ...)` audit record. The operation is admin-gated (403 returned for non-admin callers).
- **Status:** PASS (partial — cascade to UEBA/risk tables is missing; see GAP-G-4)

---

**PASS-G-3: Passwords Hashed with bcrypt rounds=12**
- **Requirement:** GDPR Article 32 (security of processing)
- **Evidence:** `blueprints/rbac/manager.py` uses `bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))`. No plaintext passwords are stored or returned at any point. Password comparison uses constant-time `bcrypt.checkpw()`.
- **Status:** PASS

---

**PASS-G-4: Secure Session Cookie Configuration**
- **Requirement:** GDPR Article 32, Recital 83
- **Evidence:** `core/config.py` sets `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="None"`, `SESSION_COOKIE_DOMAIN=".{BASE_DOMAIN}"`, and a 1-day TTL. Cookies cannot be read by JavaScript, are not sent over plain HTTP, and are scoped to the base domain.
- **Status:** PASS

---

**PASS-G-5: Structured Authentication Audit Trail**
- **Requirement:** GDPR Article 5(2) (accountability), Article 32
- **Evidence:** `auth_event()` in `core/helpers.py` writes structured JSON to `/var/log/cycentra/auth.log` for every login, logout, OIDC token issuance, RBAC change, and password reset. Each entry contains `timestamp`, `action`, `user_email`, `ip`, and `outcome`. The audit blueprint (`blueprints/audit/routes.py`) merges auth and application logs, supports date-range filtering, and exports to CSV/JSON.
- **Status:** PASS

---

**PASS-G-6: Secrets Loaded from Vault — Not Hardcoded**
- **Requirement:** GDPR Article 32 (appropriate technical measures)
- **Evidence:** `core/kv_secrets.py` integrates with Azure Key Vault and HashiCorp Vault. OAuth client secrets, database passwords, and API keys are loaded at process startup from Vault. The `_SECRET_KEYS` list in `blueprints/system/routes.py` masks known secret fields in all API responses — secrets are never returned to the frontend.
- **Status:** PASS

---

**PASS-G-7: SSO Approval Gate — Data Protection by Design**
- **Requirement:** GDPR Article 25 (data protection by design and by default)
- **Evidence:** `blueprints/auth/oauth.py` — SSO auto-provisioning is controlled by `sso_require_approval` and `sso_auto_provision` flags. When `sso_require_approval=True`, new federated users are placed in `pending` status with no data access until an admin approves. `approval_status`, `approval_requested_at`, `approval_resolved_at` columns are tracked in `cy_users`.
- **Status:** PASS

---

**PASS-G-8: GRC Module Includes GDPR Questionnaire**
- **Requirement:** GDPR Articles 5, 13–22 (operationalised compliance processes)
- **Evidence:** `blueprints/comp/routes.py` implements GDPR questionnaire controls covering Articles 13–22 including Art.22 human review requirements. A Statement of Applicability for ISO 27001 Annex A is also generated. The GRC module tracks evidence attachments and finding status.
- **Status:** PASS

---

### 1.2 Gaps and Remediation

---

**GAP-G-1: No Privacy Notice, Lawful Basis Register, or Records of Processing Activities**
- **Requirement:** GDPR Articles 13, 14, 30 (ROPA), Article 6 (lawful basis)
- **Current state:** No `privacy_policy.md`, `ROPA.md`, `data_processing_agreement.md`, or equivalent exists anywhere in the repository. The UEBA module creates rolling profiles of named users (`ueba_baselines` table: `username`, `typical_hours`, `typical_agents`) with indefinite retention. The `cy_users` table stores names and emails. The SIEM `alerts` table stores `username` and `src_ip` linked to individuals. None of this is inventoried.
- **Gap:** No documented lawful basis for processing security event data including UEBA profiles.
- **Remediation:**
  1. Create `docs/ROPA.md` enumerating: purpose, data categories, data subjects, retention periods, recipients (cloud AI providers), and lawful basis for: user account management, security monitoring (alerts/UEBA), audit logging, ASM scanning, and GRC data.
  2. Add `docs/PRIVACY_NOTICE.md` describing what data is collected during platform use and user rights.
  3. For each AI provider receiving data (Anthropic, Gemini, DeepSeek), execute a Data Processing Agreement and document it in `docs/DPA_REGISTER.md`.
- **Priority:** Critical

---

**GAP-G-2: UEBA Profiling Without Article 22 Disclosure or Oversight Mechanism**
- **Requirement:** GDPR Articles 13(2)(f), 22 (automated decision-making and profiling)
- **Current state:** `cysiemstack/correlation_engine/ueba.py` builds per-user behavioural baselines — `typical_hours`, `typical_agents`, `avg_fail_rate`. The ML layer (`ueba_ml.py`) trains Isolation Forest models per named user stored as `{username}.pkl` files. Risk scores are computed per named user in the `risk_scores` table. These outputs feed incident severity escalation with no mandatory human gate (`correlator.py`).
- **Gap:** Data subjects (employees being profiled) receive no notification. The system escalates incident severity based on these profiles without a mandatory human review step.
- **Remediation:**
  1. Add a `ueba_profiling_notice_shown` platform configuration flag and surface a disclosure notice during initial setup.
  2. Implement a human-review gate in `iris_connector.py` for any incident escalation where `ueba_flags` is non-empty.
  3. Add `GET /api/ueba/profile/<username>` (admin-gated) returning an exportable profile for DSAR responses.
  4. Document profiling activity and lawful basis in the ROPA.
- **Priority:** Critical

---

**GAP-G-3: Personal Data Sent to External LLM Providers Without Data Processing Agreements**
- **Requirement:** GDPR Articles 28 (processor), 44–49 (international transfers), Article 5(1)(b) (purpose limitation)
- **Current state:** `cysiemstack/correlation_engine/llm_enricher.py` builds a context string containing `incident.affected_users` (named users), `incident.affected_agents` (hostnames), `incident.src_ips`, and `alert.username` values, and sends this to external cloud providers: Anthropic (`api.anthropic.com`), Google Gemini (`generativelanguage.googleapis.com`), and DeepSeek (`api.deepseek.com`) via `ai_router.py`. The `_store_to_cymind_memory()` function sends the same data to CyMind as persistent episodic memory with no documented retention period.
- **Gap:** No DPA exists with any cloud LLM provider. For EU deployments, transfers to US-based APIs require Standard Contractual Clauses (SCCs). CyMind memory retains incident data indefinitely.
- **Remediation:**
  1. Add a `_anonymise_for_cloud()` helper in `llm_enricher.py` that replaces `incident.affected_users` entries with hashed identifiers (e.g., `hashlib.sha256(username.encode()).hexdigest()[:8]`) when `provider` is not `cymind` or `local`.
  2. Add a `allow_cloud_pii: bool = False` toggle in `ai_router.py` that enforces anonymisation when a cloud provider is selected.
  3. Execute and document DPAs/SCCs with Anthropic, Google, and DeepSeek in `docs/DPA_REGISTER.md`.
  4. Add `cymind_memory_retention_days` configuration and an automated cleanup job in `correlation_engine/main.py`.
- **Priority:** Critical

---

**GAP-G-4: No Data Retention Policy or Automated Data Deletion**
- **Requirement:** GDPR Article 5(1)(e) (storage limitation), Article 17 (right to erasure)
- **Current state:** The `alerts`, `incidents`, `ueba_baselines`, `ueba_anomalies`, `risk_scores` tables and auth/audit log files have no retention period defined anywhere in the codebase. The backup script (`blueprints/backup/routes.py`) implements `RETAIN_COUNT=14` and `RETAIN_DAYS=30` for backup archives only — not for the underlying data. The `_delete_user()` function in `manager.py` deletes the `cy_users` row but does NOT cascade-delete associated `ueba_baselines`, `ueba_anomalies`, `risk_scores`, or audit entries.
- **Gap:** Personal data is retained indefinitely. User deletion does not erase behavioural profiles, anomaly records, or historical audit entries.
- **Remediation:**
  1. Add `DATA_RETENTION_DAYS` environment variable (default 365) and a weekly scheduler job in `correlation_engine/main.py` that runs retention purges across `alerts`, `incidents`, `ueba_anomalies`, `ueba_baselines`, `risk_scores`.
  2. Extend `_delete_user()` in `manager.py` to cascade-delete from `ueba_baselines WHERE username = %s`, `ueba_anomalies WHERE username = %s`, and `risk_scores WHERE entity_id = %s AND entity_type = 'user'`.
  3. Add logrotate configuration for `/var/log/cycentra/auth.log` and `audit.log` (rotate weekly, retain 52 weeks).
  4. Implement `POST /api/admin/gdpr/erase/<email>` that performs full cascade deletion with a confirmation audit record.
- **Priority:** High

---

**GAP-G-5: No Encryption at Rest for Personal Data**
- **Requirement:** GDPR Article 32, Recital 83
- **Current state:** The `cy_users` table stores `email`, `name`, `sso_id` in plaintext PostgreSQL columns. `ai_settings.json` stores API keys in plaintext JSON. The `ueba_baselines` table stores `username` and behavioural profiles unencrypted. ML model files are stored as unencrypted pickle files at `MODEL_DIR / f"{username}.pkl"` (`ueba_ml.py`). Backup archives include `.env` files containing `GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_SECRET`, `SMTP_PASSWORD` in plaintext.
- **Gap:** No column-level or filesystem encryption for personal data at rest. Backup archives are not encrypted.
- **Remediation:**
  1. Enable PostgreSQL `pgcrypto` or Transparent Data Encryption (TDE) for `cy_users` columns containing PII.
  2. Encrypt backup archives with AES-256-GCM using a `BACKUP_ENCRYPTION_KEY` from Vault before writing to disk (`backup/routes.py`).
  3. Add HMAC-signed serialization for ML model files in `ueba_ml.py` (see also GAP-A-3).
  4. Move `ai_settings.json` secrets to the Vault backend (`core/kv_secrets.py`).
- **Priority:** High

---

**GAP-G-6: No Data Subject Rights (DSAR) Endpoints**
- **Requirement:** GDPR Articles 15 (access), 16 (rectification), 17 (erasure), 20 (portability)
- **Current state:** The only user-data endpoint is `GET /api/rbac/users` (admin-only, returns all users). No self-service portal exists for individuals to request their data, request corrections, or trigger erasure. The GRC questionnaire mentions DSAR processes aspirationally — no implementation exists.
- **Gap:** No DSAR workflow is implemented.
- **Remediation:**
  1. `GET /api/auth/me/data` — returns the authenticated user's `cy_users` record, their `ueba_baselines` entry, their `ueba_anomalies`, and last 30 audit entries.
  2. `DELETE /api/auth/me` — performs cascade deletion (see GAP-G-4).
  3. `PATCH /api/auth/me` — allows updating `name` (rectification).
  4. Document the 30-day response SLA in a DSAR process document.
- **Priority:** High

---

**GAP-G-7: Default Insecure SECRET_KEY**
- **Requirement:** GDPR Article 32
- **Current state:** `core/config.py`: `SECRET_KEY = os.environ.get("SECRET_KEY", "change_this_to_something_secure_32ch")`. This default value signs all Flask session cookies. If the environment variable is not set on a fresh deployment, all session cookies are signed with a known publicly visible default key.
- **Gap:** A predictable default `SECRET_KEY` allows session forgery — a high-severity vulnerability.
- **Remediation:**
  1. In `core/config.py`, replace the default with a startup assertion: `if SECRET_KEY == "change_this_to_something_secure_32ch": raise RuntimeError("SECRET_KEY not configured")`.
  2. Add `SECRET_KEY` to `FLASK_KV_MAP` in `core/kv_secrets.py` so it is always fetched from Vault in production.
- **Priority:** Critical

---

**GAP-G-8: Auth Logs Readable by Viewer-Role Users**
- **Requirement:** GDPR Article 32, Article 5(1)(f)
- **Current state:** `GET /api/auth/logs` in `blueprints/auth/oauth.py` returns the last 100 auth events including full email addresses, IP addresses, roles, and authentication outcomes. The endpoint checks only `session.get("user_email")` — **any authenticated user including `viewer` role** can call it and see all other users' login history.
- **Gap:** Viewer-role users can view other users' authentication histories, leaking personal data.
- **Remediation:**
  1. Add a role check: require `admin` or `analyst` role. Return 403 otherwise.
  2. Add an `email` filter parameter that non-admin users can only use with their own email.
- **Priority:** High

---

## 2. SOC 2 Type II Readiness

### 2.1 Trust Services Criteria Coverage

| TSC | Status | Evidence Present | Key Gaps |
|-----|--------|-----------------|----------|
| **CC1 — Control Environment** | Partial | RBAC role hierarchy, approval workflow, admin-gated operations | No formal information security policy, no vendor management program |
| **CC2 — Communication & Information** | Partial | Audit trail, structured logging, GRC module | No incident response plan, no SLA documentation |
| **CC3 — Risk Assessment** | Partial | Risk Register in GRC module, auto-risk population from findings | No formal annual risk assessment process, no threat model document |
| **CC4 — Monitoring** | Good | SIEM with 35 correlation rules, UEBA, Wazuh monitoring, CIS-CAT SCA, audit stats | No external vulnerability scanning of platform itself, no pen test record |
| **CC5 — Logical & Physical Access** | Partial | RBAC, OIDC SSO, approval workflow, session revocation via nginx | No MFA enforcement, no account lockout, access reviews not automated |
| **CC6 — Logical & Physical Access Controls** | Partial | bcrypt passwords, secure cookies, Vault for secrets | No encryption at rest for PII, in-memory OIDC token store issues, no mTLS between services |
| **CC7 — System Operations** | Partial | Health endpoint, backup/restore, scheduled tasks, version management | No log retention policy, no RTO/RPO targets, no DR plan |
| **CC8 — Change Management** | Partial | GitHub Actions CI/CD with version stamping (`deploy.yml`) | No formal change approval workflow, no staging gate, no rollback procedure |
| **CC9 — Risk Mitigation** | Low | GRC compliance module with questionnaires | No vendor risk management, no supply chain assessment for Docker images |
| **A1 — Availability** | Partial | Health check at `/health`, scheduler watchdog, SIEM uptime monitoring | No uptime SLA, no load testing evidence, no HA/failover configuration |
| **PI1 — Processing Integrity** | Partial | Alert normalisation with suppression, FP pattern learning | No input validation framework, dynamic SQL in `comp/routes.py` |
| **C1 — Confidentiality** | Low | Role-based data access, masked API keys | No data classification policy, UEBA ML models unencrypted |
| **P — Privacy** | Low | User deletion endpoint exists | No privacy notice, no ROPA, UEBA profiling without consent mechanism |

---

### 2.2 What is Compliant Today

**PASS-S-1: RBAC with 5 Defined Roles and Principle of Least Privilege**
- **TSC:** CC5.2, CC6.3
- **Evidence:** `blueprints/rbac/manager.py` enforces 5 roles (`admin`, `analyst`, `viewer`, `cyiris`, `cysoar`) with a strict privilege hierarchy. Every `/api/` route checks `session.get("user_email")` → 401 and `get_user_role()` → 403. `ROLE_APPS` in `core/config.py` constrains which application modules each role can access. Privilege escalation is blocked — a `viewer` cannot invoke analyst-tier endpoints.
- **Status:** PASS

---

**PASS-S-2: Real-Time Session Revocation via nginx Auth Gate**
- **TSC:** CC6.2, CC6.8
- **Evidence:** nginx proxies all requests through `auth_request /api/auth/verify`. The `/api/auth/verify` endpoint (`blueprints/auth/oauth.py`) checks the session cookie on every request. A user whose session is deleted or whose account is disabled is denied access on the next request — no stale session window. Session cookies have a 1-day TTL with `HttpOnly` and `Secure` flags.
- **Status:** PASS

---

**PASS-S-3: OIDC/OAuth SSO with Federated Identity**
- **TSC:** CC6.1
- **Evidence:** `blueprints/oidc/provider.py` implements a full OIDC IdP (`.well-known/openid-configuration`, `/oidc/authorize`, `/oidc/token`, `/oidc/userinfo`, `/oidc/introspect`) with RS256-signed JWTs. `blueprints/auth/oauth.py` handles Google OAuth 2.0 and Microsoft OAuth 2.0 with state-parameter CSRF protection. Federated users inherit platform RBAC roles post-authentication.
- **Status:** PASS

---

**PASS-S-4: Paginated, Filterable, Exportable Audit Log**
- **TSC:** CC4.1, CC7.2
- **Evidence:** `blueprints/audit/routes.py` provides `GET /api/audit/logs` with pagination, date-range filtering, severity filtering, and CSV/JSON export. The endpoint aggregates both auth events and application audit events. Audit stats (`/api/audit/stats`) provide summary metrics for monitoring dashboards. Wazuh agent tails `auth.log` and forwards events to the SIEM for real-time detection.
- **Status:** PASS

---

**PASS-S-5: Weekly Automated Audit Report Generation**
- **TSC:** CC4.2, CC7.4
- **Evidence:** `cysiemstack/correlation_engine/audit_reporter.py` generates a weekly structured JSON report of all auto-closed false-positive incidents, grouped by rule, with per-rule FP counts. This provides continuous evidence of the monitoring activity SOC 2 auditors require.
- **Status:** PASS

---

**PASS-S-6: Vault-Backed Secrets Management**
- **TSC:** CC6.1, CC6.7
- **Evidence:** `core/kv_secrets.py` implements lazy-loaded integration with Azure Key Vault and HashiCorp Vault. `FLASK_KV_MAP` and `ENGINE_KV_MAP` enumerate all secrets to fetch. Existing env values take precedence (idempotent). Secrets are never returned to the frontend — `_SECRET_KEYS` list in `blueprints/system/routes.py` masks them in all API responses.
- **Status:** PASS

---

**PASS-S-7: CI/CD with Versioned Releases and Concurrency Guard**
- **TSC:** CC8.1
- **Evidence:** `deploy.yml` builds the React SPA and Python wheel from source on every push to `main`. Version is stamped into the build and published to GitHub Releases. Concurrency group `deploy-${{ github.ref }}` with `cancel-in-progress: true` prevents parallel deploys on the same ref. Release history provides a complete change audit trail.
- **Status:** PASS

---

**PASS-S-8: Backup and Restore with Safety Snapshot and Path Traversal Protection**
- **TSC:** A1.2, CC7.5
- **Evidence:** `blueprints/backup/routes.py` implements pre-restore safety snapshots (automatic backup before any restore), path traversal protection for archive download (only files within `BACKUP_DIR` are served), optional PostgreSQL dump inclusion, and configurable `RETAIN_COUNT`/`RETAIN_DAYS` for archive rotation.
- **Status:** PASS (backup encryption gap exists; see GAP-S-5)

---

**PASS-S-9: Health Endpoint and Scheduler Watchdog**
- **TSC:** A1.1
- **Evidence:** `GET /health` returns system health status. The APScheduler in the correlation engine includes a watchdog job that monitors engine cycle completion. The platform status endpoint (`/api/platform/status`) auto-refreshes module state every 5 seconds in the frontend.
- **Status:** PASS

---

**PASS-S-10: False-Positive Suppression and Rule Confidence Management**
- **TSC:** PI1.2
- **Evidence:** The correlation engine implements `FpPattern` tracking (`correlation_engine/fp_pattern_store.py`) — analyst-identified FP patterns suppress future matching alerts. `apply_feedback_adjustments()` in `feedback_store.py` automatically reduces rule confidence when a rule's FP rate exceeds 80% over 30 days. This provides documented, auditable processing-integrity controls.
- **Status:** PASS

---

### 2.3 Gaps and Remediation

---

**GAP-S-1: No Multi-Factor Authentication (MFA) Enforcement**
- **Requirement:** SOC 2 CC6.1
- **Current state:** Local authentication (`blueprints/auth/oauth.py`) requires only email and password. No TOTP, SMS, or push-factor mechanism exists. Google and Microsoft OAuth flows delegate MFA to the IdP but do not verify or require it.
- **Gap:** SOC 2 CC6.1 requires MFA for remote and privileged access.
- **Remediation:**
  1. Integrate `pyotp` library into the local authentication flow in `oauth.py`. Add `totp_secret` column to `cy_users` and a `/api/auth/mfa/enroll` endpoint.
  2. Add `mfa_required` flag per role in `core/config.py:ROLE_APPS` — require MFA for `admin` accounts at minimum.
  3. Add `acr_values=mfa` to OIDC authorization requests in Google/Microsoft OAuth flows.
- **Priority:** Critical

---

**GAP-S-2: No Account Lockout / Brute-Force Protection for Local Authentication**
- **Requirement:** SOC 2 CC6.7
- **Current state:** The `auth_local()` endpoint in `blueprints/auth/oauth.py` accepts unlimited password attempts. No rate limiting, no lockout counter, no IP-based throttling.
- **Gap:** An attacker can make unlimited login attempts against any local account.
- **Remediation:**
  1. Add `failed_login_count` and `lockout_until` columns to `cy_users`.
  2. In `auth_local()`, after 5 failures set `lockout_until = NOW() + INTERVAL '15 minutes'` and return 423. Check `lockout_until` on every login attempt.
  3. Add Flask-Limiter to `/auth/local` — e.g., `@limiter.limit("10 per minute")`.
  4. Log lockout events via `auth_event("login_locked", ...)`.
- **Priority:** Critical

---

**GAP-S-3: In-Memory OIDC Token Store — Unbounded Growth and Multi-Worker Inconsistency**
- **Requirement:** SOC 2 CC6.6
- **Current state:** `_AUTH_CODES: dict = {}` and `_ACCESS_TOKENS: dict = {}` in `blueprints/oidc/provider.py` are process-level Python dicts. Expired entries are checked but never purged — dicts grow unbounded. In a multi-worker gunicorn deployment, each worker has its own in-memory dict, making tokens from worker A unvalidatable by worker B.
- **Gap:** Unbounded memory growth + multi-worker correctness failure.
- **Remediation:**
  1. Replace in-memory dicts with Redis-backed storage using `redis-py`.
  2. If Redis is unavailable, add a periodic APScheduler cleanup task to purge expired entries from both dicts every 5 minutes.
- **Priority:** High

---

**GAP-S-4: Dynamic SQL Construction Without Structural Guardrails**
- **Requirement:** SOC 2 PI1.2
- **Current state:** Multiple UPDATE queries in `blueprints/comp/routes.py` construct SQL using f-strings with column names sourced from `allowed` tuples. SELECT statements with WHERE clauses also append generated SQL strings. While values are properly parameterized, the pattern fails code security reviews.
- **Gap:** Structurally dangerous SQL construction pattern; brittle if `allowed` entries ever contain SQL keywords.
- **Remediation:**
  1. Replace all dynamic UPDATE queries with explicit per-field parameterized statements or SQLAlchemy `update()` constructs.
  2. Migrate COUNT(*) filter patterns to fully parameterized SQLAlchemy queries.
- **Priority:** Medium

---

**GAP-S-5: Backup Archives Contain Plaintext Secrets**
- **Requirement:** SOC 2 CC6.1, CC6.7
- **Current state:** `blueprints/backup/routes.py` collects all `.env` files from `/opt/cycentra/` into backup archives, including files containing `SECRET_KEY`, `GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_SECRET`, `SMTP_PASSWORD`, `WAZUH_API_PASSWORD` in plaintext. The backup download endpoint allows any admin-authenticated user to download the full archive.
- **Gap:** Backup archives are an unencrypted, admin-downloadable package of all platform secrets.
- **Remediation:**
  1. Encrypt backup archives with AES-256-GCM using a `BACKUP_ENCRYPTION_KEY` from Vault.
  2. Add a `_filter_secrets()` step to strip known secret keys from `.env` files before archiving — or omit `.env` files entirely.
  3. Require explicit re-authentication before download via the backup download endpoint.
- **Priority:** High

---

**GAP-S-6: No Penetration Testing Record or SAST/DAST in CI/CD**
- **Requirement:** SOC 2 CC4.1
- **Current state:** No penetration test reports, vulnerability scan results, or CVE tracking for platform components exist in the repository. `deploy.yml` CI/CD pipeline does not include a SAST/DAST step.
- **Gap:** SOC 2 auditors require evidence of periodic security testing and a documented remediation process.
- **Remediation:**
  1. Add a Semgrep SAST step to `deploy.yml` to scan Python and JavaScript on every push.
  2. Add `pip audit` and `npm audit` to the CI/CD pipeline.
  3. Schedule an annual third-party penetration test and store findings in the GRC evidence store.
  4. Document a vulnerability management policy in `docs/VULNERABILITY_MANAGEMENT.md`.
- **Priority:** High

---

**GAP-S-7: No Formal Incident Response Plan**
- **Requirement:** SOC 2 CC2.3, CC7.3, CC7.4
- **Current state:** The platform has technical incident detection (SIEM, UEBA, correlation rules) and CyIRIS integration. However, no documented incident response plan (IRP) defines roles, escalation procedures, customer notification SLAs, or post-incident review requirements.
- **Remediation:**
  1. Create `docs/INCIDENT_RESPONSE_PLAN.md` defining: detection, triage, containment, eradication, recovery, and post-mortem procedures.
  2. Include a GDPR Article 33/34 data breach notification procedure (72-hour supervisory authority notification).
  3. Add `POST /api/audit/incident-declare` endpoint that creates a formal incident record with severity level and assigned owner.
- **Priority:** High

---

**GAP-S-8: No Periodic Access Review Process**
- **Requirement:** SOC 2 CC6.2
- **Current state:** `GET /api/rbac/users` provides a user list and `GET /api/audit/logs` provides authentication history, but there is no automated mechanism for generating an access review report, flagging dormant accounts, or enforcing periodic re-certification of roles.
- **Remediation:**
  1. Add `last_login_at` column to `cy_users` (updated on successful authentication in `auth_event()`).
  2. Add `GET /api/rbac/access-review` endpoint returning users sorted by `last_login_at`, flagging accounts inactive for 90+ days, with CSV export.
  3. Add a scheduler job to email admins a monthly access review report.
- **Priority:** Medium

---

## 3. EU AI Act Readiness

### 3.1 Risk Classification

| AI Component | Classification | Justification |
|-------------|---------------|---------------|
| SIEM Correlation Engine (35 deterministic rules, `correlator.py`) | **Minimal Risk** | Rule-based; fully transparent, human-reviewable, overridable |
| UEBA Rule Engine (`ueba.py`) | **Limited Risk** | Behavioural anomaly flags influence incident severity; outputs are advisory |
| UEBA ML Layer — Isolation Forest (`ueba_ml.py`) | **Limited to High Risk** | Unsupervised ML profiling of named employees; currently shadow mode; outputs influence decisions about individuals |
| LLM Narrative Generation (`llm_enricher.py`) | **Limited Risk** | Generates analyst-facing summaries; human must review; no autonomous decisions |
| AI Risk Analysis for GRC | **Limited Risk** | Compliance analysis text; advisory only |
| ASM AI Enrichment | **Minimal Risk** | Attack surface risk scoring; infrastructure-focused, not individual-focused |

**Overall: Limited Risk with High-Risk characteristics for UEBA ML profiling** when deployed to monitor employees in an employment context (EU AI Act Annex III, point 4 — AI systems used in employment and workers management). Operators must conduct a conformity assessment before deploying UEBA ML in such contexts.

---

### 3.2 What is Compliant Today

**PASS-A-1: Analyst Verdict System — Human Oversight of AI Outputs**
- **Requirement:** EU AI Act Article 14 (human oversight)
- **Evidence:** `CorrelationFeedback` model in `cysiemstack/correlation_engine/models.py` allows analysts to submit verdicts (`true_positive`, `false_positive`, `benign`) on every AI-generated incident. `apply_feedback_adjustments()` in `feedback_store.py` uses these verdicts to reduce rule confidence scores for rules with sustained high FP rates — a documented, code-enforced feedback loop. Analysts retain the ability to override any AI-generated severity or finding.
- **Status:** PASS

---

**PASS-A-2: ML Shadow Mode Default — Safe Deployment Gate**
- **Requirement:** EU AI Act Article 9 (risk management system)
- **Evidence:** `cysiemstack/correlation_engine/ueba_ml.py`: `SHADOW_MODE = os.getenv('UEBA_ML_SHADOW_MODE', 'true').lower() == 'true'`. The Isolation Forest ML model defaults to shadow mode — it logs anomalies via `log.info()` but does not create alert database records or affect risk scores. ML predictions only enter the decision pipeline when an operator explicitly sets `UEBA_ML_SHADOW_MODE=false`. This is a meaningful safety gate preventing unreviewed ML deployment.
- **Status:** PASS

---

**PASS-A-3: Risk Score Explainability with Component Breakdown**
- **Requirement:** EU AI Act Article 13 (transparency and provision of information)
- **Evidence:** `cysiemstack/correlation_engine/risk_scorer.py` stores a `score_breakdown` JSONB column in the `risk_scores` table containing per-component contributions: `alert_severity`, `incident_severity`, `ueba_anomalies`, `misp_ioc_hits`, `asset_criticality`. Each score is individually attributable — an analyst reviewing a risk score can see exactly which signals drove it.
- **Status:** PASS

---

**PASS-A-4: False-Positive Pattern Learning and Suppression**
- **Requirement:** EU AI Act Article 9 (risk management — error correction)
- **Evidence:** `FpPattern` model and `fp_pattern_store.py` record analyst-identified false-positive patterns (rule ID, hostname, username, source IP combinations). `check_fp_pattern()` is called before raising every alert — matching patterns suppress the alert before it enters the incident pipeline. This is a documented, auditable mechanism for correcting systematic AI errors.
- **Status:** PASS

---

**PASS-A-5: Automated Rule Accuracy Monitoring and Confidence Downgrade**
- **Requirement:** EU AI Act Article 9 (accuracy, robustness, and cybersecurity)
- **Evidence:** `apply_feedback_adjustments()` in `cysiemstack/correlation_engine/feedback_store.py` computes a 30-day FP rate per rule. Rules with FP rate >80% have their confidence score automatically reduced. `get_rule_accuracy()` returns per-rule accuracy metrics. This constitutes automated performance monitoring of the AI system's detection rules.
- **Status:** PASS

---

**PASS-A-6: Weekly AI Decision Audit Report**
- **Requirement:** EU AI Act Article 12 (record keeping / logging)
- **Evidence:** `cysiemstack/correlation_engine/audit_reporter.py` generates a weekly structured JSON report (`generate_auto_close_audit()`) of all automatically-closed false-positive incidents, grouped by rule, with per-rule FP counts and suppression actions. This creates a durable record of the AI system's autonomous actions for post-hoc review.
- **Status:** PASS

---

**PASS-A-7: Deterministic Correlation Engine as Primary Decision Layer**
- **Requirement:** EU AI Act Article 13 (transparency), Article 14 (human oversight)
- **Evidence:** The primary SIEM decision layer (`cysiemstack/correlation_engine/correlator.py`) uses 35 deterministic, human-authored correlation rules with explicit conditions, severity levels, and MITRE ATT&CK tags. Each rule's logic is fully inspectable, auditable, and modifiable by an admin. The ML and LLM layers are additive enrichments — they cannot override deterministic rule outcomes and are presented as advisory information to analysts.
- **Status:** PASS

---

**PASS-A-8: Minimum Training Data Guard**
- **Requirement:** EU AI Act Article 10 (data and data governance)
- **Evidence:** `cysiemstack/correlation_engine/ueba_ml.py` checks `MIN_TRAIN_ALERTS = 30` and `MIN_TRAIN_DAYS = 7` before attempting to train a model for any user. If insufficient data exists, training is skipped and the user has no ML model — preventing models trained on statistically insufficient data from making predictions. The per-user model architecture also prevents cross-user contamination.
- **Status:** PASS

---

### 3.3 Gaps and Remediation

---

**GAP-A-1: No EU AI Act Conformity Assessment or Technical Documentation**
- **Requirement:** EU AI Act Articles 9 (risk management), 11 (technical documentation), 13 (transparency), 53 (GPAI transparency)
- **Current state:** No documentation exists describing the AI system architecture, intended purpose, training data sources, performance metrics, known limitations, or risk mitigation measures meeting Article 11 requirements. The `docs/` folder contains operational guides but no Article 11 technical documentation.
- **Gap:** For Limited Risk systems, users must be informed when interacting with AI. For High Risk systems, Article 11 requires complete technical documentation.
- **Remediation:**
  1. Create `docs/AI_TECHNICAL_DOCUMENTATION.md` covering:
     - Intended purpose of each AI component
     - Input data types and sources
     - UEBA ML training data: alert data, lookback window (7 days minimum per `ueba_ml.py:MIN_TRAIN_DAYS`), Isolation Forest hyperparameters (`contamination=0.05, n_estimators=100, random_state=42`)
     - Known limitations: ML trained on ≥30 alerts per user; new users have no model; shadow mode default
     - Human oversight mechanisms: analyst verdict system, feedback adjustments, FP overrides
     - Performance monitoring: `get_rule_accuracy()` in `feedback_store.py`
  2. Add a UI notification badge when AI-generated content is displayed (see GAP-A-2).
- **Priority:** High

---

**GAP-A-2: LLM Outputs Not Labeled as AI-Generated in the UI**
- **Requirement:** EU AI Act Article 52 (transparency obligations)
- **Current state:** `llm_summary` and `llm_remediation` fields are stored in the `incidents` table and surfaced via `GET /api/siem/incidents`. The `llm_generated_at` timestamp is also stored. However, there is no visible indicator in the portal UI that a particular narrative was generated by an LLM rather than a human analyst.
- **Gap:** Article 52 requires that AI-generated content be labeled as such unless obvious. Incident narratives could be mistaken for expert human analysis.
- **Remediation:**
  1. In the incident detail view, when `llm_generated_at != null`, display a visible badge: "AI-generated summary — verify before acting."
  2. Add a `llm_provider` column to `incidents` table (e.g., `"anthropic"`, `"local"`) and display the provider name in the UI disclosure.
  3. Apply the same disclosure to GRC AI analysis outputs in `cy_comp_findings.ai_analysis` and `cy_comp_risks.ai_analysis`.
- **Priority:** High

---

**GAP-A-3: UEBA ML Models Stored as Unsafe Pickle Files**
- **Requirement:** EU AI Act Articles 9 (risk management), 12 (record keeping)
- **Current state:** `ueba_ml.py`: `pickle.dump(model, f)` and `model = pickle.load(f)`. Python pickle files execute arbitrary code on deserialization. ML model files are stored at `MODEL_DIR / f"{username.replace('/', '_')}.pkl"` using the username as filename. If an attacker can write to `MODEL_DIR`, they can inject arbitrary code that executes in the SIEM engine process.
- **Gap:** Pickle deserialization is a remote code execution vector. Also an AI system integrity concern under Article 9.
- **Remediation:**
  1. Replace `pickle` with `joblib.dump()` / `joblib.load()` plus a HMAC signature check, or use `skops` (scikit-learn secure serialization).
  2. Add a file integrity check before loading: compute SHA-256 of the model file and compare against a stored manifest.
  3. Sanitize username-based filenames more aggressively: `re.sub(r'[^a-zA-Z0-9_-]', '_', username)` instead of only replacing `/`.
- **Priority:** High

---

**GAP-A-4: No Human Override Gate for Automated Severity Escalation**
- **Requirement:** EU AI Act Article 14 (human oversight)
- **Current state:** In `cysiemstack/correlation_engine/correlator.py`, when a correlation rule fires, `incident.severity` is directly updated to the rule's severity level. This automatic escalation can trigger downstream automated actions — SOAR playbooks (`cysoar_connector.py`), CyIRIS case creation (`iris_connector.py`), and LLM enrichment — all without any analyst approval gate when UEBA flags are set.
- **Gap:** For incidents involving UEBA anomalies on named users, the automated severity escalation chain can proceed without a human in the loop, potentially triggering automated responses affecting the individual. Article 14 requires that humans can intervene, override, and stop AI systems.
- **Remediation:**
  1. Add a `requires_human_review` flag to `Incident`. Set it to `True` when `incident.ueba_flags` is non-empty and escalated severity is `high` or `critical`.
  2. When `requires_human_review = True`, pause downstream automated actions until an analyst explicitly approves via `POST /api/siem/incidents/<id>/approve-escalation`.
  3. Log the approver's identity via `AuditLog`.
- **Priority:** High

---

**GAP-A-5: UEBA ML Training Data Has No Bias Testing or Fairness Assessment**
- **Requirement:** EU AI Act Articles 9, 10 (data and data governance)
- **Current state:** `ueba_ml.py` trains an Isolation Forest per user using raw alert features with `contamination=0.05` (assumes 5% of all behavior is anomalous). No bias testing, disparate impact analysis, or fairness evaluation is performed. Users with naturally varied schedules (shift workers, international travelers) may be systematically flagged.
- **Gap:** Article 10 requires examination of training data for potential biases.
- **Remediation:**
  1. Add a `MIN_DISTINCT_HOURS` threshold check before training — only train if historical data covers at least 3 distinct hour bins.
  2. Document known bias risks and mitigations in `docs/AI_TECHNICAL_DOCUMENTATION.md`.
  3. Add a `contamination` tuning endpoint: `PUT /api/siem/ueba/ml-config` for admins to adjust per deployment context.
  4. Log model training metrics (training data size, date range, contamination setting) to `engine_stats` table for audit purposes.
- **Priority:** Medium

---

## 4. Summary Tables

### 4.1 Passed Checks

| Pass ID | Framework | Title | Article / TSC |
|---------|-----------|-------|--------------|
| PASS-G-1 | GDPR | Minimal-purpose user schema (`cy_users`) | Art. 5(1)(c) |
| PASS-G-2 | GDPR | User account deletion implemented and audited | Art. 17 (partial) |
| PASS-G-3 | GDPR | Passwords hashed with bcrypt rounds=12 | Art. 32 |
| PASS-G-4 | GDPR | Secure session cookies (HttpOnly, Secure, 1-day TTL) | Art. 32 |
| PASS-G-5 | GDPR | Structured auth and application audit trail | Art. 5(2), 32 |
| PASS-G-6 | GDPR | Secrets loaded from Vault — not hardcoded; masked in API | Art. 32 |
| PASS-G-7 | GDPR | SSO approval gate — data protection by design | Art. 25 |
| PASS-G-8 | GDPR | GRC module includes GDPR questionnaire (Arts. 13–22) | Art. 5, 13–22 |
| PASS-S-1 | SOC 2 | RBAC with 5 roles and principle of least privilege | CC5.2, CC6.3 |
| PASS-S-2 | SOC 2 | Real-time session revocation via nginx auth gate | CC6.2, CC6.8 |
| PASS-S-3 | SOC 2 | OIDC/OAuth SSO with RS256 JWTs and CSRF protection | CC6.1 |
| PASS-S-4 | SOC 2 | Paginated, filterable, exportable audit log | CC4.1, CC7.2 |
| PASS-S-5 | SOC 2 | Weekly automated audit report generation | CC4.2, CC7.4 |
| PASS-S-6 | SOC 2 | Vault-backed secrets with response masking | CC6.1, CC6.7 |
| PASS-S-7 | SOC 2 | CI/CD with versioned releases and concurrency guard | CC8.1 |
| PASS-S-8 | SOC 2 | Backup/restore with safety snapshot and path traversal protection | A1.2, CC7.5 |
| PASS-S-9 | SOC 2 | Health endpoint and scheduler watchdog | A1.1 |
| PASS-S-10 | SOC 2 | False-positive suppression and rule confidence management | PI1.2 |
| PASS-A-1 | EU AI Act | Analyst verdict system — human oversight of AI outputs | Art. 14 |
| PASS-A-2 | EU AI Act | ML shadow mode default — safe deployment gate | Art. 9 |
| PASS-A-3 | EU AI Act | Risk score explainability with component breakdown | Art. 13 |
| PASS-A-4 | EU AI Act | False-positive pattern learning and suppression | Art. 9 |
| PASS-A-5 | EU AI Act | Automated rule accuracy monitoring and confidence downgrade | Art. 9 |
| PASS-A-6 | EU AI Act | Weekly AI decision audit report | Art. 12 |
| PASS-A-7 | EU AI Act | Deterministic correlation engine as primary decision layer | Art. 13, 14 |
| PASS-A-8 | EU AI Act | Minimum training data guard (30 alerts / 7 days) | Art. 10 |

---

### 4.2 Gaps

| Gap ID | Framework | Title | Priority | Effort |
|--------|-----------|-------|----------|--------|
| GAP-G-7 | GDPR | Default insecure SECRET_KEY | Critical | Low |
| GAP-G-1 | GDPR | No privacy notice, ROPA, or lawful basis documentation | Critical | Medium |
| GAP-G-3 | GDPR | PII sent to external LLMs without DPA / anonymisation | Critical | Medium |
| GAP-G-2 | GDPR | UEBA profiling without Article 22 disclosure or oversight | Critical | High |
| GAP-S-1 | SOC 2 | No MFA enforcement for local accounts | Critical | High |
| GAP-S-2 | SOC 2 | No account lockout / brute-force protection | Critical | Medium |
| GAP-G-4 | GDPR | No data retention policy or automated deletion | High | Medium |
| GAP-G-5 | GDPR | No encryption at rest for PII | High | High |
| GAP-G-6 | GDPR | No DSAR endpoints (access, portability, erasure) | High | Medium |
| GAP-G-8 | GDPR | Auth logs readable by viewer-role users | High | Low |
| GAP-S-3 | SOC 2 | In-memory OIDC token store — unbounded + multi-worker | High | Medium |
| GAP-S-5 | SOC 2 | Backup archives contain plaintext secrets | High | Medium |
| GAP-S-6 | SOC 2 | No penetration testing or SAST/DAST in CI/CD | High | Medium |
| GAP-S-7 | SOC 2 | No incident response plan | High | Medium |
| GAP-A-1 | EU AI Act | No AI conformity documentation or technical specification | High | Medium |
| GAP-A-2 | EU AI Act | LLM outputs not labeled as AI-generated in UI | High | Low |
| GAP-A-3 | EU AI Act | UEBA ML models stored as unsafe pickle files | High | Low-Medium |
| GAP-A-4 | EU AI Act | No human override gate for automated severity escalation | High | Medium |
| GAP-S-4 | SOC 2 | Dynamic SQL construction (structural injection risk) | Medium | Medium |
| GAP-S-8 | SOC 2 | No periodic access review process | Medium | Medium |
| GAP-A-5 | EU AI Act | UEBA ML training data has no bias testing | Medium | Medium |

---

## 5. Recommended Implementation Sequence

> Sequence is ordered by severity of legal/security risk, then ease of implementation.

### Sprint 1 — Critical Security Fixes (Days 1–14)

1. **GAP-G-7** — Add startup assertion in `core/config.py` that raises `RuntimeError` if `SECRET_KEY` equals the default string. Add `SECRET_KEY` to `FLASK_KV_MAP` in `core/kv_secrets.py`. One-hour fix with potentially catastrophic impact if left unfixed.
2. **GAP-G-8** — Add role check to `auth_logs()` in `blueprints/auth/oauth.py` — restrict to `admin`/`analyst`. Five-line code change.
3. **GAP-G-3 (partial)** — Add `_anonymise_for_cloud()` helper in `llm_enricher.py` that replaces usernames with hashed identifiers when `provider` is not `cymind` or `local`. Reduces immediate GDPR exposure while DPAs are executed.
4. **GAP-S-2** — Add `failed_login_count` and `lockout_until` to `cy_users` and enforce lockout in `auth_local()`.
5. **GAP-A-3** — Replace `pickle.dump`/`pickle.load` in `ueba_ml.py` with `joblib` + HMAC integrity check.

### Sprint 2 — Legal Framework and Documentation (Days 15–45)

6. **GAP-G-1** — Draft and publish ROPA, privacy notice, and DPA register. Execute DPAs with Anthropic, Google, and DeepSeek.
7. **GAP-G-2 (partial)** — Add `ueba_profiling_notice_shown` config flag and surface disclosure in platform setup wizard.
8. **GAP-G-4** — Implement data retention scheduler job and cascade delete on user erasure.
9. **GAP-A-1** — Write `docs/AI_TECHNICAL_DOCUMENTATION.md`.
10. **GAP-S-7** — Write `docs/INCIDENT_RESPONSE_PLAN.md` including GDPR 72-hour breach notification procedure.

### Sprint 3 — SOC 2 Controls (Days 46–90)

11. **GAP-S-1** — Implement TOTP-based MFA for local accounts using `pyotp`.
12. **GAP-S-3** — Replace in-memory OIDC token dicts in `blueprints/oidc/provider.py` with Redis-backed storage.
13. **GAP-S-5** — Implement backup archive encryption with AES-256-GCM.
14. **GAP-G-6** — Implement DSAR endpoints: `GET/DELETE/PATCH /api/auth/me` (and `/api/auth/me/data`).
15. **GAP-S-6** — Add Semgrep and `pip audit`/`npm audit` to `deploy.yml`. Schedule first penetration test.
16. **GAP-A-2** — Add "AI-generated" badge in incident detail UI when `llm_generated_at` is set. Add `llm_provider` column to `incidents`.

### Sprint 4 — Hardening and Compliance Maturity (Days 91–180)

17. **GAP-G-5** — Enable PostgreSQL TDE or column-level encryption for `cy_users.email`, `cy_users.name`.
18. **GAP-A-4** — Implement `requires_human_review` flag and analyst approval gate for UEBA-flagged escalations in `correlator.py`.
19. **GAP-S-4** — Migrate `comp/routes.py` UPDATE queries to SQLAlchemy ORM pattern.
20. **GAP-S-8** — Add `last_login_at` to `cy_users` and build access review reporting endpoint.
21. **GAP-G-2 (complete)** — Implement `GET /api/ueba/profile/<username>` for DSAR responses.
22. **GAP-A-5** — Add UEBA ML training guards and document bias risks in AI technical documentation.

---

*Generated by compliance review on 2026-05-25. Review annually or after any significant architecture change.*
