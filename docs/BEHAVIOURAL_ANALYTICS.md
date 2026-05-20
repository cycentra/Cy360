# CySIEM Behavioural Analytics — Full Reference

_Last updated: 2026-05-20 | Source: `backend/cysiemstack/correlation_engine/`_

---

## 1. Overview

The CySIEM behavioural analytics stack operates across three layers:

| Layer | Engine | File |
|-------|--------|------|
| UEBA Rule-Based | 12 user-behaviour detectors + 3 host-behaviour detectors | `ueba.py` |
| UEBA ML-Based | Unsupervised IsolationForest per-user (shadow mode by default) | `ueba_ml.py` |
| Temporal Correlation | 35 MITRE ATT&CK-aligned correlation rules | `correlator.py` |

All three layers feed into the risk scorer (`risk_scorer.py`), which produces a 0–100 composite score per entity. The auto-close and ticket logic (`iris_connector.py`) then acts on that score.

---

## 2. UEBA Behavioural Rules — User-Based (12 detectors)

Each detector runs on every alert that has a `username` field. Baselines per user are maintained in the `ueba_baselines` table and updated incrementally (EWMA) on every alert.

### Risk Contribution Scores

| Anomaly Type | Risk Points |
|---|---|
| `suspicious_process` | 65 |
| `impossible_travel` | 60 |
| `concurrent_session` | 50 |
| `svc_account_interactive` | 55 |
| `dormant_account_login` | 55 |
| `repeated_privesc_attempt` | 50 |
| `multi_host_burst` | 45 |
| `activity_volume_spike` | 45 |
| `high_auth_fail_rate` | 40 |
| `privilege_escalation` | 40 |
| `off_hours_login` | 35 |
| `new_agent_access` | 25 |

---

### UEBA-U-01: Off-Hours Login

**Trigger:** Successful authentication (rule IDs 5715, 5718) outside 07:00–19:00, AND the login hour is not in the user's established `typical_hours` baseline, AND at least 5 typical-hour observations exist.

**Logic:** Guards against late-night or weekend logins by accounts that never normally work those hours. Requires baseline maturity (≥5 known hours) to avoid noise for new accounts.

**Risk:** 35 pts

---

### UEBA-U-02: High Auth Failure Rate

**Trigger:** Current alert is an auth failure (rule IDs 5710, 5711, 5716, 5719, 5720, 2502). The failure rate in the 2-hour window is ≥ `max(0.15, baseline_fail_rate × 3)` AND there are ≥5 failures.

**Logic:** Dynamic threshold — adapts to users whose jobs naturally generate moderate auth failures (e.g. scripts). A user who normally has 5% failure rate triggers at 15%; one with 0% triggers at 15% (floor). Requires ≥5 failures to suppress single-event noise.

**Risk:** 40 pts

---

### UEBA-U-03: New Agent Access

**Trigger:** Successful authentication to a host (`agent_id`) that is not in the user's `typical_agents` baseline, when the baseline already contains at least one known host.

**Logic:** A user accessing a host they have never touched before — lateral movement indicator. Only fires once the user has an established host profile to compare against.

**Risk:** 25 pts

---

### UEBA-U-04: Multi-Host Burst

**Trigger:** The user has successful or auth-related activity across 4 or more distinct `agent_id` values within any rolling 10-minute window.

**Logic:** Spreading across many hosts rapidly is characteristic of automated lateral movement, worm propagation, or compromised credential reuse.

**Risk:** 45 pts

---

### UEBA-U-05: Service Account Interactive

**Trigger:** A username matching service-account naming patterns (`svc_`, `svc-`, `daemon`, `service`, `system`, `_svc`, `-svc`, `admin`) performs an interactive authentication (rule IDs 5715, 5718, 5501, 5502).

**Logic:** Service accounts should authenticate only programmatically. An interactive login by a service account strongly suggests credential theft or operator error.

**Risk:** 55 pts

---

### UEBA-U-06: Privilege Escalation

**Trigger:** Any alert with a privilege-escalation rule ID (5400, 5402, 5501, 18101, 18104) is associated with a named user.

**Logic:** Every sudo/su event is flagged unconditionally when tied to a user identity. Feeds directly into kill-chain tracking.

**Risk:** 40 pts

---

### UEBA-U-07: Impossible Travel

**Trigger:** The same user authenticates successfully (rule IDs 5715, 5718) to two different hosts (`agent_id`) within a 2-minute window.

**Logic:** Physical impossibility — a human cannot authenticate to two separate systems in under 2 minutes unless credentials are stolen and being used simultaneously from different sessions.

**Risk:** 60 pts

---

### UEBA-U-08: Dormant Account Rebirth

**Trigger:** Successful authentication by a user whose baseline `updated_at` is ≥90 days in the past AND who has a non-zero `avg_daily_events` baseline (i.e. was previously active).

**Logic:** A long-dormant account suddenly logging in signals a potentially compromised or forgotten account being exploited. The 90-day threshold aligns with CR-018.

**Risk:** 55 pts

---

### UEBA-U-09: Concurrent Sessions from Different Agents

**Trigger:** Successful authentication on the current host AND another successful authentication by the same user on a different host within the same 30-second window.

**Logic:** Near-simultaneous logins from two different machines are a strong session-hijack or stolen-credential indicator — more precise and shorter-window than impossible travel.

**Risk:** 50 pts

---

### UEBA-U-10: Activity Volume Spike

**Trigger:** The number of events for this user in the 2-hour context window is ≥10× their hourly baseline average AND total recent events ≥20.

**Logic:** Sudden massive activity increase (data hoarding, automated exfiltration precursor, compromised session running a script). Requires both the spike ratio AND an absolute floor to avoid firing on users with very low baselines (e.g. 1 event/day ÷ 10× = 10 events still fires without the floor).

**Risk:** 45 pts

---

### UEBA-U-11: First-Seen Suspicious Process

**Trigger:** A process name in the `malware` or `system` category that is NOT in the common-process allow-list AND matches known attack-tool names: `mimikatz`, `meterpreter`, `cobaltstrike`, `cobalt`, `empire`, `havoc`, `sliver`, `psexec`, `wce.exe`, `pwdump`, `procdump`, `sharpdump`, `rubeus`, `bloodhound`.

**Logic:** Exact-match on well-known post-exploitation tool process names. These are never legitimate on production systems.

**Risk:** 65 pts

---

### UEBA-U-12: Rapid Privilege Escalation Attempts

**Trigger:** Current alert is an auth failure AND ≥3 privilege-escalation rule IDs (5400, 5402, 5501, 18101, 18104) appear in the 2-hour recent context.

**Logic:** Auth failures co-occurring with repeated escalation attempts signal a user actively trying to gain higher permissions — either an attacker or a misconfigured automation that's being blocked.

**Risk:** 50 pts

---

## 3. UEBA Behavioural Rules — Host-Based (3 detectors)

These run when an alert has NO `username` (e.g. network events, system-level events from agents). The host entity identifier is `host:<agent_id>`.

---

### UEBA-H-01: Host Multi-Host Burst

**Trigger:** The same host (`agent_id`) is seen interacting with 4+ different peer agents in a rolling 10-minute window.

**Risk:** 45 pts

---

### UEBA-H-02: Host Impossible Travel (IP Shift)

**Trigger:** The same `agent_id` appears with two different source IPs (`src_ip`) within a 2-minute window.

**Logic:** An agent reporting from two IPs simultaneously may indicate IP spoofing, a NAT change under attack conditions, or a compromised host faking its identity.

**Risk:** 60 pts

---

### UEBA-H-03: C2 Beaconing Pattern

**Trigger:** ≥5 outbound network events (rule IDs ≥18100) from the same agent, with an average inter-arrival interval <600 seconds AND a coefficient of variation (CV) <0.25 (tight, regular spacing).

**Logic:** Malware C2 beacons call home at precise intervals. The CV filter separates legitimate polling applications (which have irregular timing) from beacon traffic (which is tightly scheduled).

**Risk:** Inherits the `c2_beaconing` type — see risk table addition needed (currently not in `RISK_CONTRIBUTIONS` dict; defaults to 20 pts — **identified gap**).

---

## 4. ML-Based UEBA (IsolationForest)

**File:** `ueba_ml.py`

**Status:** Shadow mode by default (`UEBA_ML_SHADOW_MODE=true`). In shadow mode, anomalies are logged but do not create `UEBAAnomaly` records or affect risk scores.

### Feature Vector (8 dimensions per alert)

| # | Feature | Description |
|---|---------|-------------|
| 1 | `hour` | Hour of day (0–23) |
| 2 | `rule_level` | Wazuh rule severity level |
| 3 | `base_score` | Alert base risk score |
| 4 | `recent_fails` | Count of auth failures (rule IDs 5710, 5711, 5716) in 2-hour window |
| 5 | `recent_agents` | Count of unique agents in the 2-hour window |
| 6 | `recent_count` | Total events in the 2-hour window |
| 7 | `has_src_ip` | Binary: 1 if alert has an external `src_ip` |
| 8 | `is_success_login` | Binary: 1 if rule ID is 5715 or 5718 |

### Training

- Per-user IsolationForest model trained weekly from last 7 days of data
- Minimum 30 alerts required to train; minimum 20 valid feature vectors to fit
- `contamination=0.05` (expects ~5% of traffic to be anomalous)
- `n_estimators=100`, `random_state=42`
- Models stored in `/app/ml_models/<username>.pkl` with in-memory mtime cache

### Live Mode Behaviour

When `UEBA_ML_SHADOW_MODE=false`, a detected anomaly creates a `UEBAAnomaly` record with `risk_contribution=15`. Intentionally low — ML is advisory and supplements the rule-based detectors, not replaces them.

---

## 5. Temporal Correlation Rules (35 rules)

Each rule has a **time window** — only alerts within that window relative to the newest alert are considered. Rules fire once per incident (deduplicated by `rule_id`). When a rule fires it may escalate incident severity.

### CR-001: SSH Brute Force → Login
**Window:** 15 min | **Severity:** High | **Tactics:** Credential Access, Initial Access

≥5 SSH failures (5710, 5711, 5716) followed by a successful login (5715, 5718).

---

### CR-002: Login → Privilege Escalation
**Window:** 30 min | **Severity:** High | **Tactics:** Privilege Escalation

Successful login (5715, 5718) on the same agent followed by a sudo/su event (5400, 5402, 18101, 18104).

---

### CR-003: Full Compromise Chain
**Window:** 90 min | **Severity:** Critical | **Tactics:** Initial Access, Privilege Escalation, Execution, Impact

Auth + PrivEsc + FIM/Malware all on the same host. Confidence: 1.0.

---

### CR-004: Web Exploit → File Modification
**Window:** 30 min | **Severity:** High | **Tactics:** Initial Access, Persistence

Web attack alert (keywords: attack, exploit, traversal, injection, rce, shell) followed by a FIM event on the same agent.

---

### CR-005: Lateral Movement
**Window:** 360 min | **Severity:** High | **Tactics:** Lateral Movement

Same source IP authenticates successfully to 3+ different hosts.

---

### CR-006: Host Takeover
**Window:** 60 min | **Severity:** Critical | **Tactics:** Defense Evasion, Persistence

Rootkit alert (rule IDs 510–535) + FIM activity on the same host.

---

### CR-007: Account Creation → Login
**Window:** 120 min | **Severity:** Medium | **Tactics:** Persistence

New account created (5902, 5903) and the same username authenticates afterwards.

---

### CR-008: Port Scan → Exploitation
**Window:** 30 min | **Severity:** High | **Tactics:** Reconnaissance

Category `scan` alert followed by an alert with exploit/attack/injection/overflow/rce in the description.

---

### CR-009: Data Exfiltration Indicators
**Window:** 60 min | **Severity:** High | **Tactics:** Exfiltration

FIM activity + network transfer keywords (outbound, upload, curl, wget, scp, rsync).

---

### CR-010: Service Account Anomaly
**Window:** 30 min | **Severity:** Medium | **Tactics:** Defense Evasion, Privilege Escalation

Service-account-named user (patterns: `svc_`, `daemon`, `service`, etc.) generating ≥2 interactive or auth events.

---

### CR-011: Event Log Cleared
**Window:** 20 min | **Severity:** High | **Tactics:** Defense Evasion

Windows event log clear events (18101, 18104, 60101, 60102). Single event is sufficient. Confidence: 0.95.

---

### CR-012: DNS Tunnelling Indicator
**Window:** 10 min | **Severity:** Medium | **Tactics:** Exfiltration, Command and Control

≥20 DNS-related alerts from a single host within the window (rule IDs 82200–82202 or "dns" in description).

---

### CR-013: Credential Dumping
**Window:** 30 min | **Severity:** Critical | **Tactics:** Credential Access

LSASS/mimikatz/ntds keywords in alert description followed by a login with a source IP.

---

### CR-014: Ransomware Indicators
**Window:** 20 min | **Severity:** Critical | **Tactics:** Impact

Mass FIM (≥30 changes) OR FIM alerts with ransomware file extensions (.encrypted, .locked, .ransom, .crypt, .enc, .pay2decrypt) PLUS outbound network activity.

---

### CR-015: C2 Beacon Pattern
**Window:** 120 min | **Severity:** High | **Tactics:** Command and Control

≥5 outbound connections to the same destination IP at regular intervals — average gap >30s AND variance < (30% of avg)².

---

### CR-016: Password Spraying
**Window:** 5 min | **Severity:** High | **Tactics:** Credential Access, Initial Access

1 failed login across ≥20 different usernames from the same source IP within 5 minutes.

---

### CR-017: Windows Brute Force → Login
**Window:** 15 min | **Severity:** High | **Tactics:** Credential Access, Initial Access

≥5 Windows EventID 4625 failures (rule IDs 60122, 60123, 60204) followed by a 4624 success (60106, 60137, 60138).

---

### CR-018: Dormant Account Rebirth
**Window:** 60 min | **Severity:** High | **Tactics:** Initial Access, Persistence

Login for a username with no prior activity in the current observation window (uses window-scoped data). Confidence: 0.65.

---

### CR-019: Privileged Group Membership Change
**Window:** 60 min | **Severity:** Critical | **Tactics:** Privilege Escalation, Persistence

Windows EventID 4732 group change (rule IDs 60148–60272) involving Domain Admins, Administrators, Enterprise Admins, Schema Admins, Backup Operators.

---

### CR-020: Kerberos Ticket Anomaly
**Window:** 30 min | **Severity:** Critical | **Tactics:** Credential Access, Lateral Movement

Kerberos TGS rule IDs (60210–60213) or keywords: rc4-hmac, golden ticket, kerberoast, pass-the-ticket, etc.

---

### CR-021: Registry Persistence
**Window:** 30 min | **Severity:** High | **Tactics:** Persistence

FIM alert on autorun registry keys: `CurrentVersion\Run`, `RunOnce`, `RunServices`, `Winlogon\Userinit`, `Policies\Explorer\Run`.

---

### CR-022: Scheduled Task Abuse
**Window:** 30 min | **Severity:** High | **Tactics:** Persistence, Execution

Scheduled task creation/modification (EventID 4698/4702 via rule IDs 60280–60282) pointing to suspicious paths: `\Temp\`, `\AppData\`, `\Public\`, `/tmp/`, `/var/tmp/`.

---

### CR-023: Process Injection Indicator
**Window:** 15 min | **Severity:** High | **Tactics:** Defense Evasion, Execution

Browser or Office parent process (chrome.exe, msedge.exe, winword.exe, excel.exe, outlook.exe, etc.) spawning a shell/system child (cmd.exe, powershell.exe, mshta.exe, rundll32.exe, etc.).

---

### CR-024: Encoded/Obfuscated Command Execution
**Window:** 20 min | **Severity:** High | **Tactics:** Execution, Defense Evasion

PowerShell or script interpreter with LOLBin keywords: `-EncodedCommand`, `-enc`, `FromBase64String`, `IEX(`, `Invoke-Expression`, `DownloadString`, `-Hidden -w`, `Bypass`.

---

### CR-025: Web Shell Execution
**Window:** 20 min | **Severity:** Critical | **Tactics:** Initial Access, Execution, Persistence

Web server process (w3wp.exe, httpd, apache2, nginx, php-fpm, tomcat) spawning a shell (cmd.exe, powershell.exe, bash, python, perl, ruby). Confidence: 0.95.

---

### CR-026: Security Tool Disabled
**Window:** 15 min | **Severity:** Critical | **Tactics:** Defense Evasion

Known AV/EDR/firewall service name (Windows Defender, CrowdStrike, Sophos, Kaspersky, ufw, firewalld, iptables, etc.) stopped or disabled. Confidence: 0.95.

---

### CR-027: Unusual Outbound Port
**Window:** 30 min | **Severity:** High | **Tactics:** Command and Control

Outbound connection on classic malware/C2/RAT ports: 4444, 1234, 6667, 6666, 9001, 9002, 31337, 1337, 8888, 2222.

---

### CR-028: RDP to External Host
**Window:** 30 min | **Severity:** High | **Tactics:** Lateral Movement, Exfiltration

Internal host making an outbound connection on port 3389 (RDP).

---

### CR-029: Internal Subnet Scan
**Window:** 10 min | **Severity:** Medium | **Tactics:** Discovery, Reconnaissance

Single host generating ≥20 scan-category alerts (port scan, host scan, arp scan, ping sweep) in 10 minutes.

---

### CR-030: Large Upload to Cloud Storage
**Window:** 30 min | **Severity:** High | **Tactics:** Exfiltration

≥3 connections from the same host to known cloud storage/file-sharing services: mega.nz, dropbox.com, drive.google.com, onedrive.live.com, box.com, wetransfer.com, gofile.io, transfer.sh, anonfiles.com, filebin.net, mediafire.com.

---

### CR-031: Cloud Console Login without MFA
**Window:** 30 min | **Severity:** High | **Tactics:** Initial Access

AWS or Azure console login event with `mfaUsed: No` or equivalent keywords. Confidence: 0.90.

---

### CR-032: Privileged Cloud IAM Change
**Window:** 60 min | **Severity:** Critical | **Tactics:** Privilege Escalation, Persistence

AWS AdminPolicy attachment or Azure global-admin role assignment keywords: `AdministratorAccess`, `CreateUser`, `AttachUserPolicy`, `Global Administrator`, `Owner role assigned`.

---

### CR-033: Mass Cloud Resource Deletion
**Window:** 10 min | **Severity:** Critical | **Tactics:** Impact

≥5 cloud resource deletion events (S3 bucket delete, blob delete, storage account delete, instance termination) within 10 minutes.

---

### CR-034: Suspicious Mail Forwarding Rule
**Window:** 60 min | **Severity:** High | **Tactics:** Collection, Exfiltration

O365/Exchange inbox rule creation with forwarding/redirect keywords: `New-InboxRule`, `ForwardTo`, `RedirectTo`, `auto-forward`. BEC indicator. Confidence: 0.88.

---

### CR-035: Suspicious OAuth App Consent
**Window:** 60 min | **Severity:** High | **Tactics:** Collection, Initial Access

User grants 3rd-party app broad permissions to mail, files, or contacts: `Mail.Read`, `Files.ReadWrite`, `Contacts.Read`, `consent to application`. OAuth phishing indicator. Confidence: 0.85.

---

## 6. Risk Scoring Model

**File:** `risk_scorer.py` | Composite 0–100 per entity (host, user, cloud service)

| Component | Max Points | Method |
|-----------|-----------|--------|
| Alert severity | 35 | Log-scale sum of `base_score` values: `min(log1p(total) × 3.5, 35)` |
| Incident severity | 30 | Weighted by severity level (critical=4, high=3, medium=2, low=1) × (1 + sum of rule confidences) |
| UEBA anomalies | 25 | Sum of `risk_contribution` values for unresolved anomalies |
| MISP IOC hits | 10 | 2.5 pts per confirmed IOC match, capped at 10 |
| Asset criticality | 20 bonus | Tier 1 (crown jewel) +20 pts; Tier 2 (business-critical) +10 pts |

**Time decay:** Linear to 0 over `RISK_DECAY_HOURS` with no new activity.

**Trend:** rising / stable / falling — based on ±5 pt delta from previous score.

### FP Probability Score (0–100, high = likely false positive)

Computed by `compute_fp_score()` in `risk_scorer.py`:

1. **Base:** `(1 − avg_rule_confidence) × 100`
2. **UEBA penalty:** each anomaly reduces FP probability by 8 pts (cap 30) — anomalies are evidence of real threat
3. **MISP IOC hit:** multiply base by 0.6; floor at 5 if any hit
4. **Kill-chain cap/floor:** exfiltration/C2 stages cap FP at 30; recon/weaponization floor at 65
5. **Asset criticality cap/floor:** tier 1 caps FP at 20; tier 3 floors at 40

---

## 7. Auto-Status Logic (Current State)

**File:** `iris_connector.py` → `advance_incident_status()`

| FP Score Band | Action |
|---|---|
| ≥ `fpThreshold` (UI slider) | Auto-closed — no ticket, audit entry: `auto_close` |
| 40 – < `fpThreshold` | Stays `investigating` |
| < 40 + enrichment complete | Advanced to `in_review` + IRIS ticket (if severity high/critical + ≥3 alerts) |

The threshold is read live from `ai_settings.json` on every alert — slider changes take effect immediately without restart.

---

## 8. Analyst Feedback Loop (Current State)

**File:** `feedback_store.py`

Analyst verdicts (`true_positive` / `false_positive` / `benign`) are stored in `correlation_feedback`. A **nightly job** (`apply_feedback_adjustments`) tunes rule confidence:

- If a rule's FP rate > 80% over 30 days with ≥5 feedback entries: reduce confidence by 0.1 (floor 0.1) and suppress the rule for 24 hours.
- True positives trigger MISP sighting push (IOC enrichment back to MISP).

---

## 9. Identified Gaps

### GAP-1: No AI Recommendation in the Incident View

The system computes an `llm_summary` and `llm_remediation` (stored on the `Incident` model) but these are currently only included in the IRIS ticket description (`iris_connector.py:create_iris_case`). **The portal incident detail view does not surface the AI-generated remediation steps as actionable analyst guidance.** There is no "What to do next" panel driven by the LLM output.

**Impact:** Analysts who handle incidents outside of IRIS never see the AI-generated recommendations.

---

### GAP-2: Auto-Close Is Purely Threshold-Based — No Pattern Memory

The current FP auto-close mechanism uses a continuous score (`fp_probability`) against a static threshold slider. It has no memory of "this specific type of alert content was closed as FP by analysts N times." 

Every occurrence of a known-benign event (e.g. the cycentra-setup.sh sudo command below) must exceed the global FP threshold to be dismissed — there is no per-pattern auto-suppression based on repeat analyst closures.

**Canonical example of a known-benign incident that analysts close every time:**
```
root : PWD=/usr/local/lib/python3.12/dist-packages ;
       USER=root ;
       COMMAND=/opt/cycentra/cycentra-setup.sh --update
```
This fires a sudo/privilege-escalation rule (UEBA-U-06 and possibly CR-002), generates a UEBA anomaly, and gets routed to `in_review`. An analyst closes it. It fires again next update. The analyst closes it again. The system never learns.

---

### GAP-3: c2_beaconing Risk Contribution Not in RISK_CONTRIBUTIONS Dict

`ueba.py` creates `UEBAAnomaly` records with `anomaly_type='c2_beaconing'` from the host path but `RISK_CONTRIBUTIONS` does not have an entry for it. It defaults to 20 pts (the `dict.get` default). This should be explicitly defined at ~60 pts given the severity of the detection.

---

## 10. Proposed: ML-Based Repeat FP Auto-Close

### Concept

After an analyst closes an incident N times (configurable, default **5**) where the key alert's normalized content matches a consistent fingerprint, future incidents matching that fingerprint should be **automatically closed** without analyst intervention. The system effectively learns "this is a known-benign administrative activity on this host."

### Fingerprint Design

A fingerprint is a hash of the normalized alert pattern. For sudo-based alerts the fingerprint captures:
- `agent_id` (host)
- `rule_id`
- Normalized `raw_log` with variable data stripped: usernames replaced with `USER=*`, paths normalized, timestamps removed

For the canonical example:
```
agent_id: <host>
rule_id:  5402 (or similar sudo rule)
pattern:  "USER=root ; COMMAND=/opt/cycentra/cycentra-setup.sh --update"
```

The fingerprint hash is: `SHA256(agent_id + ":" + rule_id + ":" + normalized_command)`.

### Database Table: `fp_patterns`

```sql
CREATE TABLE fp_patterns (
    id              BIGSERIAL PRIMARY KEY,
    fingerprint     TEXT NOT NULL UNIQUE,
    raw_sample      TEXT,              -- one example raw_log for human readability
    agent_id        TEXT,              -- NULL = any host
    rule_id         INTEGER,
    description     TEXT,              -- human-readable description of what was learned
    close_count     INTEGER DEFAULT 0, -- times analyst has closed a matching incident
    threshold       INTEGER DEFAULT 5, -- auto-close after this many manual closes
    auto_close      BOOLEAN DEFAULT false,  -- true once close_count >= threshold
    last_seen       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    created_by      TEXT               -- analyst email who first closed it
);
```

### Learning Flow

1. **Analyst closes incident as FP/benign** → `submit_feedback()` in `feedback_store.py` computes a fingerprint for the key alert in the incident.
2. The fingerprint is upserted into `fp_patterns`: if new, `close_count=1`; if existing, `close_count += 1`.
3. When `close_count >= threshold`, `auto_close` is set to `true`.
4. From that point, any new incident whose trigger alert matches the fingerprint is **immediately auto-closed** during ingestion — before UEBA, correlation, and risk scoring run.

### Matching in Ingestor

In `_do_process_alert()` in `ingestor.py`, after normalisation and before grouping:

```python
fp_match = await check_fp_pattern(db, alert)
if fp_match:
    # Skip the full pipeline — log and skip
    log.info("alert_suppressed_fp_pattern",
             fingerprint=fp_match.fingerprint,
             description=fp_match.description,
             agent_id=alert.get("agent_id"))
    await write_audit(db, "alert", alert.get("wazuh_id"),
                      action="auto_fp_suppressed",
                      actor="system",
                      comment=f"Suppressed: matched known FP pattern '{fp_match.description}'")
    await db.commit()
    return
```

### Portal UX

- **Incident Detail → Close as False Positive:** Existing close action now adds a "Remember this pattern" checkbox. When checked, the fingerprint is learned.
- **Settings → SIEM → Known-Benign Patterns:** Admin page listing all learned patterns with `close_count`, `auto_close` status, a toggle to disable/enable auto-close per pattern, and a "Forget" button.
- **Incident list:** Incidents that were auto-closed by a learned pattern show a "Pattern Match" badge with a tooltip showing the matched description.

### Scope of the Example Pattern

For the sudo command `COMMAND=/opt/cycentra/cycentra-setup.sh --update`:

```
Fingerprint description: "System update via cycentra-setup.sh on <host>"
Pattern:                  rule_id IN (5400, 5402) AND raw_log CONTAINS "cycentra-setup.sh --update"
Agent scope:              system-wide (any host) OR per-host (configurable)
Auto-close threshold:     5 manual closures (default)
Action when matched:      skip pipeline, close incident as "auto_fp", write audit entry
```

### Escalation Safety

A pattern match is **skipped and the incident proceeds normally** if any of the following are also true for the same incident:
- A MISP IOC hit is found for the same alert
- A critical-severity correlation rule (CR-003, CR-013, CR-014, CR-025, CR-026) fires alongside the matched alert
- The asset tier is 1 (crown jewel) — for high-value assets, human review is always required

This prevents the pattern suppressor from masking real threats that happen to share a benign-looking event.

---

## 11. Proposed: AI Enrichment in Incident View (Surfacing llm_remediation)

The `Incident` model already has `llm_summary` and `llm_remediation` fields populated by `llm_enricher.py` for critical/high incidents. The gap is portal display.

**Proposed additions to the incident detail panel:**

1. **AI Analyst Summary** (from `llm_summary`): Narrative explanation of what happened and why it's suspicious.
2. **Recommended Next Steps** (from `llm_remediation`): Structured action list — e.g. "Isolate host X", "Rotate credential Y", "Check lateral movement from Z".
3. **Confidence Indicator**: Show `fp_probability` as a plain-language label: "Low confidence — likely legitimate activity" vs "High confidence — real threat".
4. **Trigger AI Analysis Button**: For incidents where `llm_summary` is NULL (medium/low incidents that didn't auto-trigger), allow analysts to manually request LLM enrichment.

These are already fully generated by the backend — this is a portal-only change to surface what already exists.

---

_Document covers: `ueba.py`, `ueba_ml.py`, `correlator.py`, `risk_scorer.py`, `feedback_store.py`, `iris_connector.py`, `ingestor.py`, `models.py`_
