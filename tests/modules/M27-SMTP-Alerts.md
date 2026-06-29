# M27 — SMTP Alerting Service
**File:** `backend/smtp_service.py`
**Run Date:** 2026-06-29

---

## Module Scope

Email alerting service. Sends notifications for: high-severity SIEM incidents, compliance score drops, license expiry warnings, integration health failures, and scheduled scan completion. Configured via `ai_settings.json` `smtp.*` block.

**Config Keys:**
- `smtp.host`, `smtp.port`, `smtp.user`, `smtp.password`
- `smtp.from_address`, `smtp.to_addresses` (list)
- `smtp.tls` — Use TLS (bool)

---

## AI-Executable Tests (Automated)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `smtp_service.py` AST syntax | ✅ PASS | Compiles cleanly |
| A1.02 | No hardcoded SMTP credentials | ✅ PASS | Reads from ai_settings.json |
| A1.03 | SMTP password not logged | ✅ PASS | Static scan — password not in log calls |
| A1.04 | `send_alert()` handles SMTP failure gracefully | ✅ PASS | Try/except present — no crash on failure |
| A1.05 | Email addresses validated before send | ✅ PASS | Format validation present |

---

## Manual Test Suite

### M-SMTP-01: SMTP Configuration
**Steps:**
1. Navigate to Settings → Notifications → Email
2. Configure SMTP: host, port, user, password, from, to
3. Click "Test Email"
4. Verify test email arrives at destination

### M-SMTP-02: Incident Alert
**Steps:**
1. Configure notification trigger: severity=critical
2. Trigger a critical SIEM incident
3. Verify email arrives within 2 minutes
4. Verify email contains: incident ID, severity, title, SIEM link

### M-SMTP-03: Compliance Drop Alert
**Steps:**
1. Set compliance alert threshold: score_drop > 10%
2. Mark several controls as not-implemented
3. Verify email sent when score drops below threshold

### M-SMTP-04: License Expiry Warning
**Steps:**
1. Configure license within 30 days of expiry
2. Verify email sent: "Your CyCentra 360 license expires in X days"

### M-SMTP-05: SMTP TLS/SSL
**Steps:**
1. Configure SMTP with TLS enabled (port 587 STARTTLS)
2. Send test email
3. Verify TLS handshake in server logs
4. Verify email delivered without falling back to plaintext
