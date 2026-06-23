#!/usr/bin/env bash
# CyCentra360 — Custom Rules Integration Module
# Deploys supplemental custom detection rules alongside the core rule set.
#
# NOTE: The primary CyCentra detection rules (100100-101007) are in
#   CYSIEM-Config/rules/cy_cust_rules.xml
# and are deployed automatically by cycentra-setup.sh Step 18.
# This script only deploys supplemental rules that are NOT in that file.

set -euo pipefail

CUSTOM_RULES="/var/ossec/etc/rules/cycentra_custom_rules.xml"

cat > "$CUSTOM_RULES" << 'XML'
<!-- CyCentra360 supplemental custom detection rules -->
<!-- Core rules (100100-101007) are in cy_cust_rules.xml, deployed by setup.sh -->
<group name="cycentra,sysmon,windows,">
  <!-- Rule 100303: Office/Browser spawned shell via Sysmon field-level match -->
  <!-- Complements cy_cust_rules rule 100300 (PowerShell encoded) and 100302 (macro) -->
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
chown root:wazuh "$CUSTOM_RULES"; chmod 660 "$CUSTOM_RULES"
echo "Supplemental custom detection rules deployed (rule 100303 → $CUSTOM_RULES)"
