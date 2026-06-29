# M18 — Agent Installer
**File:** `backend/blueprints/system/routes.py` (agent section)
**Run Date:** 2026-06-29

---

## Module Scope

Generates on-demand shell scripts (Bash for Linux/macOS, PowerShell for Windows) that install the CySIEM agent (Wazuh-based, branded as CyCentra agent). Handles install, upgrade, and uninstall. macOS section includes Full Disk Access guidance. Uses `_register_agent()` for duplicate detection.

**Agent Packages Directory:** `agent-packages/`
**Current Version:** `1.0.103`
**Platforms:** Linux (amd64/arm64/x86_64/aarch64), macOS (intel64/arm64), Windows (MSI)

---

## AI-Executable Tests (49 tests — 35 PASS, 7 FAIL, 7 ERROR)

### A1 — Shell Safety Checks

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `set -euo pipefail` present in SH template | ✅ PASS | Safety flags confirmed |
| A1.02 | No bare `clear` | ✅ PASS | Template clean |
| A1.03 | 3 format placeholders present (`{server_url}`, `{cysiem_manager}`, `{version}`) | ❌ FAIL | Test checks for `{wazuh_manager}` but template now uses `{cysiem_manager}` — test needs update |
| A1.04 | No Python format errors with special chars | ❌ FAIL | Template renders if placeholders match; fails when test uses wrong placeholder name |
| A1.05 | Template renders without error | ❌ ERROR | Fixture uses wrong placeholder names causing `KeyError` |
| A1.06 | Resolved template contains `server_url` | ❌ ERROR | Downstream from A1.05 error |
| A1.07 | Resolved template contains `manager_ip` | ❌ ERROR | Downstream from A1.05 error |
| A1.08 | Resolved template contains `version` | ❌ ERROR | Downstream from A1.05 error |

**Root cause:** Template was updated from `{wazuh_manager}` to `{cysiem_manager}` for rebranding. `test_agent_installer.py` still tests for `{wazuh_manager}`. Tests need update.

### A2 — `_register_agent()` Function

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | Function exists | ✅ PASS | |
| A2.02 | Captures output before RC check | ❌ FAIL | Output capture pattern changed in template |
| A2.03 | "Duplicate agent" detected | ✅ PASS | |
| A2.04 | Upgrade path uses `ok()` not `err()` | ✅ PASS | |
| A2.05 | No `${CTRL_BIN} restart` inside function body | ✅ PASS | |
| A2.06 | Port 1515 mentioned in error | ✅ PASS | |
| A2.07 | `err()` called for non-duplicate failures | ✅ PASS | |

### A3 — macOS FDA Notice

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01 | 'Full Disk Access' present | ✅ PASS | |
| A3.02 | `wazuh-agentd` listed in Darwin section | ❌ FAIL | Darwin section refactored — FDA notice now in `do_install_macos()` function, not inline |
| A3.03 | `wazuh-logcollector` listed | ✅ PASS | |
| A3.04 | `will not start` warning present | ❌ FAIL | Message text changed in template update |
| A3.05 | Both binaries in Darwin section | ❌ FAIL | `do_install_macos` refactor moved content |
| A3.06 | Both in same Darwin section | ✅ PASS | |

### A4 — Darwin Single Restart

| # | Test | Result | Detail |
|---|------|--------|--------|
| A4.01 | Restart follows MACEOF heredoc | ✅ PASS | |
| A4.02 | Exactly 1 `CTRL_BIN` restart in Darwin section | ❌ FAIL | Darwin section now calls `do_install_macos` — restart is inside that function, not in Darwin case label body |

### A5 — PowerShell Template

| # | Test | Result | Detail |
|---|------|--------|--------|
| A5.01 | `{server_url}` placeholder present | ✅ PASS | |
| A5.02 | `{wazuh_manager}` placeholder present | ❌ FAIL | Template now uses `{cysiem_manager}` — same rebrand as SH template |
| A5.03 | `{version}` present | ✅ PASS | |
| A5.04 | Renders without error | ❌ ERROR | `KeyError` on `{wazuh_manager}` |
| A5.05 | Rendered contains server_url | ❌ ERROR | Downstream |
| A5.06 | `$ErrorActionPreference = "Stop"` present | ✅ PASS | |
| A5.07 | `Tls12` present | ✅ PASS | |
| A5.08 | `agent-auth.exe` present | ✅ PASS | |
| A5.09 | CyCentra branding present | ✅ PASS | |

### A6 — Route Security

| # | Test | Result | Detail |
|---|------|--------|--------|
| A6.01 | `/api/system/agent-installer` route defined | ✅ PASS | |
| A6.02 | Session user_email check | ✅ PASS | |
| A6.03 | 401 without auth | ✅ PASS | |
| A6.04 | `text/x-shellscript` MIME for SH | ✅ PASS | |
| A6.05 | `text/plain` for PS1 | ✅ PASS | |
| A6.06 | Content-Disposition attachment | ✅ PASS | |
| A6.07 | X-Content-Type-Options: nosniff | ✅ PASS | |
| A6.08 | `format` param lowercased | ✅ PASS | |
| A6.09 | OPTIONS handler present | ✅ PASS | |

**Summary: 35/49 pass. 7 failures + 7 errors are all in the same root cause: test_agent_installer.py still checks for `{wazuh_manager}` but template was rebranded to `{cysiem_manager}`, and Darwin section was refactored to use helper function. Tests need ONE update to each failing assertion.**

---

## Manual Test Suite

### M-AGT-01: Linux Agent Install
**Steps:**
1. Navigate to EDR → Agent Installer; select Linux
2. Download generated script; verify Content-Type = text/x-shellscript
3. Run on a test Linux VM as root
4. Verify agent registers within 2 minutes
5. Verify `cy360_agent_tamper` audit key present in `/etc/audit/rules.d/`

### M-AGT-02: macOS Agent Install with FDA
**Steps:**
1. Download macOS installer script
2. Run on macOS test machine; follow FDA notice
3. Grant FDA to wazuh-agentd in System Settings → Privacy & Security
4. Verify agent connects and Apple ULS log events appear in SIEM

### M-AGT-03: Windows Agent Install (PS1)
**Steps:**
1. Download PS1 installer
2. Run in elevated PowerShell: `Set-ExecutionPolicy Bypass -Scope Process; .\agent-installer.ps1`
3. Verify agent service starts
4. Verify Windows Security events appear in SIEM

### M-AGT-04: Duplicate Agent Detection
**Steps:**
1. Run installer on host that already has the agent
2. Verify `_register_agent()` detects duplicate
3. Verify installer prompts for upgrade/uninstall rather than installing twice

### M-AGT-05: Agent Upgrade
**Steps:**
1. Install older agent version on test host
2. Run installer with `--upgrade` flag
3. Verify new version installed; old version cleaned up
4. Verify agent reconnects after upgrade
