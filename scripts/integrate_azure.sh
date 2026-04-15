#!/usr/bin/env bash
# CyCentra360 — Azure Integration Module
# Installs Azure wodle, decoders, and rules for Wazuh integration.

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
AZURE_DECODER="/var/ossec/etc/decoders/cycentra_azure_decoder.xml"
AZURE_RULES="/var/ossec/etc/rules/cycentra_azure_rules.xml"

# Inject Azure wodle block
inject_azure_wodle() {
    local marker='wodle name="azure-blob"'
    if grep -q "$marker" "$OSSEC_CONF" 2>/dev/null; then
        echo "Azure wodle already present in ossec.conf"
        return
    fi
    python3 -c "\
src = open('$OSSEC_CONF').read()\nblk = '''
  <wodle name=\"azure-blob\">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <container>YOUR_CONTAINER_NAME</container>
    <account_name>YOUR_ACCOUNT_NAME</account_name>
    <account_key>YOUR_ACCOUNT_KEY</account_key>
    <only_logs_after>2024-01-01</only_logs_after>
  </wodle>\n'''\nsrc = src.replace('</ossec_config>', blk + '\n</ossec_config>') if '</ossec_config>' in src else src + '\n' + blk\nopen('$OSSEC_CONF', 'w').write(src)\
" && echo "Azure wodle block injected" || echo "Failed to inject Azure wodle"
}

# Deploy Azure decoder
cat > "$AZURE_DECODER" << 'XML'
<!-- CyCentra360 Azure Log Decoder -->
<decoder name="azure">
  <prematch>AzureActivity|ResourceId|OperationName</prematch>
</decoder>
<decoder name="azure-event">
  <parent>azure</parent>
  <use_own_name>true</use_own_name>
</decoder>
XML
chown root:wazuh "$AZURE_DECODER"; chmod 660 "$AZURE_DECODER"
echo "Azure decoder deployed"

# Deploy Azure rules
cat > "$AZURE_RULES" << 'XML'
<!-- CyCentra360 Azure Detection Rules -->
<group name="cycentra,azure,">
  <rule id="130001" level="10">
    <if_group>azure</if_group>
    <field name="OperationName">Add member to group</field>
    <description>Azure: Group membership change detected</description>
    <mitre><id>T1098</id></mitre>
    <group>azure_group,</group>
  </rule>
  <!-- ...other rules omitted for brevity... -->
</group>
XML
chown root:wazuh "$AZURE_RULES"; chmod 660 "$AZURE_RULES"
echo "Azure rules deployed"

# Inject wodle
inject_azure_wodle

echo "Azure integration complete. Edit ossec.conf to set your container/account details."
