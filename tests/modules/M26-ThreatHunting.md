# M26 — Threat Hunting
**File:** `backend/cysiemstack/threat_hunter/hunter.py`, `portal/src/siem/ThreatHuntingPage.jsx`
**Run Date:** 2026-06-29

---

## Module Scope

Interactive threat hunting module. Allows analysts to write and execute hunting queries (SQL/DSL) against the SIEM alert database. Supports YARA-based hunting, hypothesis-driven hunting, and custom query templates. Results feed into case creation.

**Components:**
- `hunter.py` — Query engine and result processor
- `ThreatHuntingPage.jsx` — Hunt query builder UI
- Integration with MITRE ATT&CK matrix for technique-driven hunts

---

## AI-Executable Tests (Automated)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `hunter.py` AST syntax | ✅ PASS | Compiles cleanly |
| A1.02 | `threat_hunter` package importable | ✅ PASS | |
| A1.03 | Hunt queries are parameterized (no SQL injection) | ✅ PASS | Static analysis — no string concatenation in queries |
| A1.04 | Unauthenticated → 401 | ✅ PASS | |
| A1.05 | Viewer cannot execute hunts → 403 | ✅ PASS | Analyst+ required |

---

## Manual Test Suite

### M-HUNT-01: MITRE-Driven Hunt
**Steps:**
1. Navigate to SIEM → Threat Hunting
2. Select MITRE technique T1059.001 (PowerShell)
3. Execute pre-built hunt template
4. Verify results: all alerts matching PowerShell execution patterns

### M-HUNT-02: Custom Query Hunt
**Steps:**
1. Write custom hunt: `rule_id IN (60122, 60106) AND agent_name LIKE 'server%'`
2. Execute query
3. Verify results table: agent_name, timestamp, description, confidence
4. Export results as CSV

### M-HUNT-03: YARA Hunt
**Steps:**
1. Upload custom YARA rule for known malware pattern
2. Execute YARA hunt against recent process events
3. Verify any matches returned with matching evidence

### M-HUNT-04: Hunt to Case
**Steps:**
1. Identify suspicious pattern in hunt results
2. Click "Open Case" from hunt results
3. Verify case created with hunt query and results as evidence
4. Verify hunt evidence attached to case

### M-HUNT-05: Hunt Templates
**Steps:**
1. Navigate to Threat Hunting → Templates
2. Verify pre-built templates: Brute Force, Lateral Movement, Data Exfiltration, etc.
3. Run "Lateral Movement" template
4. Verify results surface any host-hopping behavior
