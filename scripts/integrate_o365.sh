#!/usr/bin/env bash
# CyCentra360 — O365 Integration Module
# Installs O365 wodle, decoders, and rules for Wazuh integration.

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
O365_DECODER="/var/ossec/etc/decoders/cycentra_o365_decoder.xml"
O365_RULES="/var/ossec/etc/rules/cycentra_o365_rules.xml"

# Inject O365 wodle block
inject_o365_wodle() {
    local marker='wodle name="o365"'
    if grep -q "$marker" "$OSSEC_CONF" 2>/dev/null; then
        echo "O365 wodle already present in ossec.conf"
        return
    fi
    python3 -c "\
src = open('$OSSEC_CONF').read()\nblk = '''
  <wodle name=\"o365\">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <tenant_id>YOUR_TENANT_ID</tenant_id>
    <client_id>YOUR_CLIENT_ID</client_id>
    <client_secret>YOUR_CLIENT_SECRET</client_secret>
    <only_logs_after>2024-01-01</only_logs_after>
  </wodle>\n'''\nsrc = src.replace('</ossec_config>', blk + '\n</ossec_config>') if '</ossec_config>' in src else src + '\n' + blk\nopen('$OSSEC_CONF', 'w').write(src)\
" && echo "O365 wodle block injected" || echo "Failed to inject O365 wodle"
}

# Deploy O365 decoder
cat > "$O365_DECODER" << 'XML'
<!-- CyCentra360 O365 Log Decoder -->
<decoder name="o365">
  <prematch>Office365|UserId|Operation</prematch>
</decoder>
<decoder name="o365-event">
  <parent>o365</parent>
  <use_own_name>true</use_own_name>
</decoder>
XML
chown root:wazuh "$O365_DECODER"; chmod 660 "$O365_DECODER"
echo "O365 decoder deployed"

# Deploy O365 rules
cat > "$O365_RULES" << 'XML'
<!-- CyCentra360 O365 Detection Rules -->
<group name="cycentra,o365,">
  <rule id="140001" level="10">
    <if_group>o365</if_group>
    <field name="Operation">UserLoggedIn</field>
    <description>O365: User login detected</description>
    <mitre><id>T1078</id></mitre>
    <group>o365_login,</group>
  </rule>
  <!-- ...other rules omitted for brevity... -->
</group>
XML
chown root:wazuh "$O365_RULES"; chmod 660 "$O365_RULES"
echo "O365 rules deployed"

# Inject wodle
inject_o365_wodle

echo "O365 integration complete. Edit ossec.conf to set your tenant/client details."
