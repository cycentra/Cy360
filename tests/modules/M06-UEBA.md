# M06 — User & Entity Behavior Analytics (UEBA)
**File:** `backend/cysiemstack/correlation_engine/ueba.py`
**Run Date:** 2026-06-29

---

## Module Scope

Stateful behavioral baseline engine. Maintains per-user and per-host baselines in Redis/memory. Runs 17 user detectors and 3 host detectors on every normalised alert. Returns scored risk contributions that feed into the SIEM risk scorer.

**User Detectors (D-01 through D-17):**
- D-01 `off_hours_login` — Login at unusual hour vs. baseline
- D-02 `high_auth_fail_rate` — Auth failure rate spike
- D-03 `new_agent_access` — First login from unknown host
- D-04 `multi_host_burst` — Login to 4+ hosts in 10 minutes
- D-05 `svc_account_interactive` — Service account interactive login
- D-06 `privilege_escalation` — Privesc with corroborating context
- D-07 `impossible_travel` — Logins from different agents within 2 min
- D-08 `dormant_account_login` — Login after 90+ day inactivity
- D-09 `concurrent_session` — Same user, different agents within 30s
- D-10 `activity_volume_spike` — Event burst vs. hourly baseline
- D-11 `suspicious_process` — Known malware process names
- D-12 `repeated_privesc_attempt` — 3+ privesc + auth fail
- D-13 `mfa_fatigue` — 8+ MFA prompts, same user
- D-14 `data_staging` — Archive + FIM activity
- D-15 `wmi_execution` — WMI-based execution
- D-16 `token_theft` — Pass-the-cookie / 5+ IPs
- D-17 `crypto_miner` — Mining process/protocol signatures

**Host Detectors:**
- HOST-01 `multi_host_burst` — 4+ peer agents in 10 min
- HOST-02 `impossible_travel` — IP change within 2 min
- HOST-03 `c2_beaconing` — Regular-interval outbound (CV < 0.25)

---

## AI-Executable Tests (89 tests — ALL PASSED)

### A1 — RISK_CONTRIBUTIONS Completeness

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | All 17 types in RISK_CONTRIBUTIONS | ✅ PASS | |
| A1.02 | All scores 1-100 | ✅ PASS | |
| A1.03 | `impossible_travel` ≥ 50 | ✅ PASS | High-risk detector |
| A1.04 | `svc_account_interactive` ≥ 50 | ✅ PASS | |
| A1.05 | AUTH_SUCCESS_IDS / AUTH_FAIL_IDS / PRIVESC_IDS non-empty | ✅ PASS | |

### A2 — Detector Tests (all 89 PASSED)

| Detector | Tests | Result |
|----------|-------|--------|
| D-01 off_hours_login | 6 | ✅ ALL PASS |
| D-02 high_auth_fail_rate | 4 | ✅ ALL PASS |
| D-03 new_agent_access | 4 | ✅ ALL PASS |
| D-04 multi_host_burst | 3 | ✅ ALL PASS |
| D-05 svc_account_interactive | 5 | ✅ ALL PASS |
| D-06 privilege_escalation | 5 | ✅ ALL PASS |
| D-07 impossible_travel | 4 | ✅ ALL PASS |
| D-08 dormant_account_login | 4 | ✅ ALL PASS |
| D-09 concurrent_session | 3 | ✅ ALL PASS |
| D-10 activity_volume_spike | 4 | ✅ ALL PASS |
| D-11 suspicious_process | 7 | ✅ ALL PASS |
| D-12 repeated_privesc_attempt | 3 | ✅ ALL PASS |
| D-13 mfa_fatigue | 4 | ✅ ALL PASS |
| D-14 data_staging | 5 | ✅ ALL PASS |
| D-15 wmi_execution | 4 | ✅ ALL PASS |
| D-16 token_theft (threshold=5 IPs) | 5 | ✅ ALL PASS |
| D-17 crypto_miner | 4 | ✅ ALL PASS |
| HOST-01 multi_host_burst | 2 | ✅ ALL PASS |
| HOST-02 impossible_travel | 3 | ✅ ALL PASS |
| HOST-03 c2_beaconing | 3 | ✅ ALL PASS |
| ROUTE routing correctness | 2 | ✅ ALL PASS |

**Key known-behavior anchors (all validated):**
- D-16 threshold = 5 IPs (NOT 3) — raised to avoid VPN false positives ✅
- D-06 only fires with corroborating context (service acct OR off-hours OR prior fail) ✅
- D-10 spike_ratio = recent / max(baseline/24, 1) ✅

---

## Manual Test Suite

### M-UEBA-01: Baseline Establishment
**Steps:**
1. Simulate 2 weeks of normal login activity for a user
2. Verify UEBA risk score stabilises near 0 for expected patterns
3. Simulate an off-hours login at 3 AM
4. Verify D-01 fires and risk score jumps

### M-UEBA-02: Impossible Travel Alert
**Steps:**
1. Generate login event from Agent-A (London)
2. Within 90 seconds, generate login event from Agent-B (New York)
3. Verify D-07 impossible_travel fires
4. Verify incident created with both agent names in `key_alert_ids`

### M-UEBA-03: MFA Fatigue Detection
**Steps:**
1. Simulate 8 MFA push requests within 10 minutes for same user
2. Verify D-13 fires
3. Verify alert contains user identity and push count

### M-UEBA-04: Service Account Interactive Session
**Steps:**
1. Simulate interactive login with account matching `svc_` prefix
2. Verify D-05 fires immediately
3. Verify analyst is alerted

### M-UEBA-05: Risk Score Dashboard
**Steps:**
1. Navigate to SIEM → UEBA → Risk Scores
2. Verify user list with risk scores displayed
3. Click a high-risk user — verify contributing detector breakdown shown
4. Verify historical risk trend chart renders
