#!/usr/bin/env bash
# CyCentra360 — Sysmon / Windows Audit Policy Integration Module
#
# IMPORTANT (v1.0.5+ migration):
#   Sysmon installation is now handled by CyEDR — scripts/cyedr-install.ps1
#   Wazuh no longer reads Microsoft-Windows-Sysmon/Operational (removed from agent.conf).
#   This script now deploys only:
#     1. Domain Controller audit policy (apply_audit_policy.ps1) — unchanged
#     2. CyEDR Office/Browser spawn chain Wazuh rule (100303) — kept because
#        CyEDR telemetry also feeds back into the Wazuh SIEM pipeline via edr_bridge.py,
#        allowing this string-match rule to fire on CyEDR telemetry log entries.
#
# For Sysmon deployment on Windows endpoints, use:
#   .\cyedr-install.ps1 -Token <TOKEN> -Platform <URL>

set -euo pipefail

SYSMON_RULES="/var/ossec/etc/rules/cycentra_sysmon_rules.xml"
DC_AUDIT_DIR="/opt/cycentra/sysmon"

# Deploy supplemental rule 100303 — Office/Browser spawned shell detection.
# This rule fires on CyEDR telemetry events that flow through edr_bridge.py into
# the SIEM pipeline (matching the raw event text in CyEDR alerts).
cat > "$SYSMON_RULES" << 'XML'
<!-- CyCentra360 supplemental rules — Office/Browser process spawn chain -->
<!-- NOTE: Sysmon events now flow through CyEDR → edr_bridge.py → SIEM.  -->
<!-- Rule 100303 matches CyEDR telemetry text, not direct Sysmon events.  -->
<group name="cycentra,edr_telemetry,windows,">
  <rule id="100303" level="12">
    <if_sid>0</if_sid>
    <match>script_from_browser</match>
    <description>CyEDR: Office/Browser spawned shell on $(agent.name) — T1566.001</description>
    <mitre><id>T1566.001</id></mitre>
    <group>execution,initial_access,phishing,</group>
  </rule>
</group>
XML
chown root:wazuh "$SYSMON_RULES"; chmod 660 "$SYSMON_RULES"
echo "Supplemental rule 100303 deployed → $SYSMON_RULES"

# Deploy Domain Controller audit policy script (unchanged from original)
mkdir -p "$DC_AUDIT_DIR"
cat > "$DC_AUDIT_DIR/apply_audit_policy.ps1" << 'PS1'
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

echo ""
echo "Domain Controller audit policy script deployed → $DC_AUDIT_DIR/apply_audit_policy.ps1"
echo ""
echo "To apply audit policy on Domain Controllers:"
echo "  1. Copy $DC_AUDIT_DIR/apply_audit_policy.ps1 to the Domain Controller"
echo "  2. Run as Domain Admin in an elevated PowerShell: .\\apply_audit_policy.ps1"
echo ""
echo "To deploy CyEDR (Sysmon + CyEDR agent) on Windows endpoints:"
echo "  Use: .\\cyedr-install.ps1 -Token <TOKEN> -Platform <URL>"
echo "  Full docs: Cy360/scripts/cyedr-install.ps1"
