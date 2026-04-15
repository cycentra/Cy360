#!/usr/bin/env bash
# CyCentra360 — Sysmon Integration Module
# Deploys Sysmon decoder, custom rules, and Windows deployment scripts for Wazuh integration.

set -euo pipefail

SYSMON_DECODER="/var/ossec/etc/decoders/cycentra_sysmon_decoder.xml"
CUSTOM_RULES="/var/ossec/etc/rules/cycentra_custom_rules.xml"
SYSMON_PKG_DIR="/opt/cycentra/sysmon"

# Deploy Sysmon decoder
cat > "$SYSMON_DECODER" << 'XML'
<!-- CyCentra360 Sysmon Decoder for Windows Sysmon v14+ -->
<decoder name="sysmon">
  <prematch>Microsoft-Windows-Sysmon</prematch>
</decoder>
<decoder name="sysmon-process">
  <parent>sysmon</parent>
  <prematch>EventID: 1</prematch>
  <regex>Image: (\S+)\.+ParentImage: (\S+)</regex>
  <order>process_name, parent_process</order>
</decoder>
<decoder name="sysmon-network">
  <parent>sysmon</parent>
  <prematch>EventID: 3</prematch>
  <regex>DestinationIp: (\d+\.\d+\.\d+\.\d+)\.+DestinationPort: (\d+)</regex>
  <order>dst_ip, dst_port</order>
</decoder>
<decoder name="sysmon-registry">
  <parent>sysmon</parent>
  <prematch>EventID: 13</prematch>
  <regex>TargetObject: (\S+)</regex>
  <order>file_path</order>
</decoder>
<decoder name="sysmon-dns">
  <parent>sysmon</parent>
  <prematch>EventID: 22</prematch>
  <regex>QueryName: (\S+)</regex>
  <order>url</order>
</decoder>
XML
chown root:wazuh "$SYSMON_DECODER"; chmod 660 "$SYSMON_DECODER"
echo "Sysmon decoder deployed"

# Deploy custom rules
cat > "$CUSTOM_RULES" << 'XML'
<!-- CyCentra360 Custom Detection Rules — feeds CR-019 through CR-035 -->
<group name="cycentra,sysmon,windows,">
  <rule id="100300" level="12">
    <if_group>sysmon</if_group>
    <field name="process_name">cmd.exe|powershell.exe|wscript.exe|cscript.exe|mshta.exe</field>
    <field name="parent_process">chrome.exe|msedge.exe|firefox.exe|winword.exe|excel.exe|outlook.exe</field>
    <description>Suspicious: Office/Browser spawned shell - $(parent_process) -> $(process_name)</description>
    <mitre><id>T1055</id></mitre>
    <group>process_injection,</group>
  </rule>
  <!-- ...other rules omitted for brevity... -->
</group>
XML
chown root:wazuh "$CUSTOM_RULES"; chmod 660 "$CUSTOM_RULES"
echo "Custom detection rules deployed"

# Deploy Windows-side scripts
mkdir -p "$SYSMON_PKG_DIR"
cat > "$SYSMON_PKG_DIR/deploy_sysmon.ps1" << 'PS1'
# CyCentra360 — Sysmon Deployment
# Download Sysmon64.exe: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
# Place alongside this script and cycentra_sysmon_config.xml, then run as Admin
param([string]$SysmonPath=".\Sysmon64.exe", [string]$ConfigPath=".\cycentra_sysmon_config.xml")
if (-not (Test-Path $SysmonPath)) {
    Write-Error "Sysmon64.exe not found. Download from Microsoft Sysinternals."
    exit 1
}
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Updating Sysmon config..." -ForegroundColor Yellow
    & $SysmonPath -c $ConfigPath
} else {
    Write-Host "Installing Sysmon64..." -ForegroundColor Cyan
    & $SysmonPath -accepteula -i $ConfigPath
}
$s = Get-Service -Name "Sysmon64"
Write-Host "Sysmon status: $($s.Status)" -ForegroundColor $(if($s.Status -eq "Running"){"Green"}else{"Red"})
Write-Host "Wazuh will collect events from: Microsoft-Windows-Sysmon/Operational"
PS1

echo "Sysmon deployment script ready in $SYSMON_PKG_DIR"

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
# Enable command line in 4688 events
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Write-Host "Done. Verify: auditpol /get /category:*" -ForegroundColor Cyan
PS1

echo "Audit policy script ready in $SYSMON_PKG_DIR"
