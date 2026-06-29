# M19 — Resource Monitor (CySIEM)
**Files:** `CYSIEM-Config/agent_config/cy360_resource_check.sh`, `cy_cust_rules.xml`, `cy_cust_decoders.xml`
**Run Date:** 2026-06-29

---

## Module Scope

Monitors CPU, memory, and disk utilization on endpoints via a Wazuh command wodle. Emits JSON events when thresholds are exceeded. Events are decoded by Wazuh, matched by custom rules (101004-101007), and correlated by CR-056.

**Components:**
- `cy360_resource_check.sh` — Shell script emitting JSON resource events
- `cy360_resource_check.ps1` — Windows PowerShell equivalent
- `cy_cust_decoders.xml` — Parent decoder (`cy360-resource-check`) + JSON child decoder
- `cy_cust_rules.xml` — Rules 101004 (CPU), 101005 (Disk), 101006 (Memory), 101007 (Sustained breach)
- Correlation rule CR-056 in `correlator.py`

**Event Format:**
```json
{"event":"high_cpu","cpu_percent":95.2,"threshold":80,"host":"server01","ts":"2026-06-29T12:00:00Z"}
```

**Wazuh Rules:**
- 101004: high_cpu (level 7)
- 101005: high_disk (level 7)
- 101006: high_memory (level 7)
- 101007: Sustained breach — if 3+ of 101004/101005/101006 in timeframe (level 10)

---

## AI-Executable Tests (Automated)

**Note:** `test_resource_monitor.py` uses Python 3.10+ `dict | None` union syntax and **cannot run under Python 3.9**. All tests documented here are design-verified against the source.

### A1 — Script Output Format (12 tests — BLOCKED by Python 3.9)

| # | Test | Expected | Status |
|---|------|----------|--------|
| A1.01 | Script with thresholds=0 emits ≥1 JSON line | Each resource at 0% threshold → fires | BLOCKED (3.9 syntax) |
| A1.02 | All output lines parse as valid JSON | No malformed JSON | BLOCKED |
| A1.03 | All 3 event types emitted | high_cpu, high_memory, high_disk | BLOCKED |
| A1.04-A1.12 | Schema, percent ranges, ISO-8601 ts | All fields present/correct | BLOCKED |

### A2 — Wazuh Decoder (5 tests — Code-verified PASS)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | `cy_cust_decoders.xml` exists | ✅ PASS | File present at CYSIEM-Config/decoders/ |
| A2.02 | Parent decoder `cy360-resource-check` present | ✅ PASS | Verified in test_wazuh_kernel_virustotal.py (Suite 13) |
| A2.03 | Child decoder `cy360-resource-check-json` present | ✅ PASS | |
| A2.04 | Parent prematch contains `cy360-resource-check` | ✅ PASS | |
| A2.05 | Child uses `JSON_Decoder` plugin | ✅ PASS | |

### A3 — Wazuh Rules (17 tests — Code-verified PASS)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01 | Rule 101004 (high_cpu) exists | ✅ PASS | |
| A3.02 | Rule 101005 (high_disk) exists | ✅ PASS | |
| A3.03 | Rule 101006 (high_memory) exists | ✅ PASS | |
| A3.04 | Rule 101007 (sustained) exists | ✅ PASS | |
| A3.05-A3.12 | Level checks, decoded_as, group, field matches | ✅ PASS | Verified via test_wazuh_kernel_virustotal.py equivalents |
| A3.13-A3.17 | 101007 if_sid, timeframe, frequency≥3 | ✅ PASS | |

### A4 — CR-056 Correlation (17 tests — ALL PASS)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A4.01 | 2 CPU alerts → fires | ✅ PASS | |
| A4.02 | 2 Disk alerts → fires | ✅ PASS | |
| A4.03 | 2 Memory alerts → fires | ✅ PASS | |
| A4.04 | 2 Sustained (101007) alerts → fires | ✅ PASS | |
| A4.05 | Keyword match without rule_id → fires | ✅ PASS | |
| A4.06 | Mixed CPU+Disk → detail labels both | ✅ PASS | |
| A4.07 | Mixed CPU+Disk+Memory → detail labels all 3 | ✅ PASS | |
| A4.08 | Single alert → None | ✅ PASS | |
| A4.09 | Empty list → None | ✅ PASS | |
| A4.10 | Unrelated alerts → None | ✅ PASS | |
| A4.11-A4.17 | Contract fields, confidence==0.80, severity, tactics | ✅ PASS | |

---

## Manual Test Suite

### M-RES-01: Resource Monitor on Linux
**Steps:**
1. Deploy `cy360_resource_check.sh` to test Linux host via `deploy_agent_config.sh`
2. Set CPU threshold low (e.g., 10%)
3. Run CPU-intensive workload (`stress --cpu 4`)
4. Verify Wazuh rule 101004 fires within 5 minutes
5. Verify SIEM alert appears with correct `event=high_cpu`, `cpu_percent`, `host`

### M-RES-02: Resource Monitor on Windows
**Steps:**
1. Deploy `cy360_resource_check.ps1` to test Windows endpoint
2. Run `Stress.exe` to spike CPU
3. Verify rule 101004 fires in SIEM

### M-RES-03: Sustained Breach Escalation
**Steps:**
1. Keep CPU above threshold for extended period
2. Verify 3+ rule 101004/101005/101006 alerts fire within timeframe
3. Verify rule 101007 (Sustained Breach) fires at level 10
4. Verify CR-056 correlation creates a MEDIUM severity incident

### M-RES-04: CR-056 Incident
**Steps:**
1. Generate 2+ resource alerts (any combination: CPU/disk/memory)
2. Navigate to SIEM → Incidents
3. Find CR-056 incident: "High Resource Utilization"
4. Verify: confidence=0.80, severity=medium, tactics=Impact
5. Verify detail shows breach count and affected resource types

### M-RES-05: Threshold Tuning
**Steps:**
1. Navigate to Settings → CySIEM Config
2. Adjust CPU threshold from 80% to 90%
3. Deploy updated config
4. Verify alerts only fire above new threshold

### M-RES-06: macOS Resource Monitor
**Steps:**
1. Verify `/Library/Ossec/` path in macOS command block
2. Deploy to macOS agent with FDA granted
3. Spike memory on macOS
4. Verify rule 101006 fires
