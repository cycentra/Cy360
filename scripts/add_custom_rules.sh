#!/usr/bin/env bash
# CyCentra360 — Custom Rules Integration Module
# Deploys CyCentra custom detection rules for Wazuh.

set -euo pipefail

CUSTOM_RULES="/var/ossec/etc/rules/cycentra_custom_rules.xml"

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
