#!/usr/bin/env bash
# CyCentra360 — Sysmon Integration Module
# Deploys supplemental Sysmon detection rules and Windows-side deployment scripts.
#
# NOTE: Sysmon event decoding is handled by Wazuh's built-in decoder
# (ruleset/decoders/0485-win-sysmon_decoders.xml). A custom sysmon decoder is
# NOT deployed here — it would override the built-in and suppress EventID 8/10/25
# detection required by kernel telemetry rules 101011-101013 in cy_cust_rules.xml.
#
# Primary detection rules for Sysmon events live in:
#   CYSIEM-Config/rules/cy_cust_rules.xml  (groups cycentra_rules, cycentra_kernel)
# and are deployed automatically by cycentra-setup.sh Step 18.

set -euo pipefail

SYSMON_RULES="/var/ossec/etc/rules/cycentra_sysmon_rules.xml"
SYSMON_PKG_DIR="/opt/cycentra/sysmon"

# Deploy supplemental Sysmon detection rule for parent-process chain (Office/Browser → shell)
# Rule 100303: complements cy_cust_rules.xml rule 100300 (PowerShell encoded) and
# 100302 (Office macro) by catching the process-spawn chain via Sysmon field data.
cat > "$SYSMON_RULES" << 'XML'
<!-- CyCentra360 supplemental Sysmon rules — Office/Browser process spawn chain -->
<!-- Primary Sysmon kernel rules (101011-101013) live in cy_cust_rules.xml     -->
<group name="cycentra,sysmon,windows,">
  <rule id="100303" level="12">
    <if_group>sysmon</if_group>
    <field name="data.win.eventdata.image" type="pcre2">(?i)(cmd|powershell|wscript|cscript|mshta)\.exe$</field>
    <field name="data.win.eventdata.parentImage" type="pcre2">(?i)(chrome|msedge|firefox|winword|excel|outlook)\.exe$</field>
    <description>Sysmon: Office/Browser spawned shell $(data.win.eventdata.image) on $(agent.name) — T1566.001</description>
    <mitre><id>T1566.001</id></mitre>
    <group>execution,initial_access,phishing,</group>
  </rule>
</group>
XML
chown root:wazuh "$SYSMON_RULES"; chmod 660 "$SYSMON_RULES"
echo "Sysmon supplemental rules deployed (rule 100303 → /var/ossec/etc/rules/cycentra_sysmon_rules.xml)"

# Deploy Windows-side Sysmon installation scripts
mkdir -p "$SYSMON_PKG_DIR"
cat > "$SYSMON_PKG_DIR/deploy_sysmon.ps1" << 'PS1'
# CyCentra360 — Sysmon Deployment
# Requirements: Sysmon64.exe from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
# Place Sysmon64.exe and cycentra_sysmon_config.xml alongside this script, then run as Administrator.
param(
    [string]$SysmonPath   = ".\Sysmon64.exe",
    [string]$ConfigPath   = ".\cycentra_sysmon_config.xml"
)
if (-not (Test-Path $SysmonPath))  { Write-Error "Sysmon64.exe not found."; exit 1 }
if (-not (Test-Path $ConfigPath))  { Write-Error "cycentra_sysmon_config.xml not found. Copy from /opt/cycentra/sysmon/ on the CyCentra server."; exit 1 }
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Updating Sysmon config..." -ForegroundColor Yellow
    & $SysmonPath -c $ConfigPath
} else {
    Write-Host "Installing Sysmon64..." -ForegroundColor Cyan
    & $SysmonPath -accepteula -i $ConfigPath
}
$s = Get-Service -Name "Sysmon64"
Write-Host "Sysmon status: $($s.Status)" -ForegroundColor $(if ($s.Status -eq "Running") {"Green"} else {"Red"})
Write-Host "Wazuh will receive events from: Microsoft-Windows-Sysmon/Operational"
PS1

cat > "$SYSMON_PKG_DIR/apply_audit_policy.ps1" << 'PS1'
# CyCentra360 — Advanced Audit Policy Setup
# Run on each Domain Controller as Domain Admin (PowerShell, Run as Administrator)
Write-Host "Applying Advanced Audit Policy for CyCentra360..." -ForegroundColor Cyan
$cmds = @(
  'auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable',
  'auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable',
  'auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable',
  'auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
  'auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable',
  'auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable',
  'auditpol /set /subcategory:"Security Group Management" /success:enable /failure:disable',
  'auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable',
  'auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable',
  'auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable',
  'auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:disable'
)
foreach ($cmd in $cmds) { Invoke-Expression $cmd; Write-Host "  OK: $cmd" -ForegroundColor Green }
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Write-Host "Done. Verify: auditpol /get /category:*" -ForegroundColor Cyan
PS1

# Deploy cycentra_sysmon_config.xml from repo (CYSIEM-Config/sysmon/)
# deploy_sysmon.ps1 expects it in the same directory when run on Windows endpoints.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_SYSMON_CFG="$SCRIPT_DIR/../CYSIEM-Config/sysmon/cycentra_sysmon_config.xml"
if [[ -f "$REPO_SYSMON_CFG" ]]; then
    cp "$REPO_SYSMON_CFG" "$SYSMON_PKG_DIR/cycentra_sysmon_config.xml"
    echo "cycentra_sysmon_config.xml deployed to $SYSMON_PKG_DIR"
else
    echo "WARN: $REPO_SYSMON_CFG not found — sysmon config not deployed"
fi

echo "Sysmon deployment package ready in $SYSMON_PKG_DIR:"
ls "$SYSMON_PKG_DIR/"
echo ""
echo "To deploy Sysmon on Windows endpoints:"
echo "  1. Copy all files from $SYSMON_PKG_DIR/ to the Windows host"
echo "  2. Download Sysmon64.exe from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
echo "  3. Place Sysmon64.exe in the same directory, then run: .\\deploy_sysmon.ps1"
