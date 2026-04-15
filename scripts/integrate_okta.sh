#!/usr/bin/env bash
# CyCentra360 — Okta Integration Module
# Installs Okta decoders and rules for Wazuh integration.

set -euo pipefail

OKTA_DECODER="/var/ossec/etc/decoders/cycentra_okta_decoder.xml"
OKTA_RULES="/var/ossec/etc/rules/cycentra_okta_rules.xml"

# Deploy Okta decoder
cat > "$OKTA_DECODER" << 'XML'
<!-- CyCentra360 Okta Log Decoder -->
<decoder name="okta">
  <prematch>{"actor":|"eventType":</prematch>
</decoder>
<decoder name="okta-event">
  <parent>okta</parent>
  <use_own_name>true</use_own_name>
</decoder>
XML
chown root:wazuh "$OKTA_DECODER"; chmod 660 "$OKTA_DECODER"
echo "Okta decoder deployed"

# Deploy Okta rules
cat > "$OKTA_RULES" << 'XML'
<!-- CyCentra360 Okta Detection Rules -->
<group name="cycentra,okta,">
  <rule id="120001" level="10">
    <if_group>okta</if_group>
    <field name="eventType">user.session.start</field>
    <description>Okta: User session started</description>
    <mitre><id>T1078</id></mitre>
    <group>okta_login,</group>
  </rule>
  <!-- ...other rules omitted for brevity... -->
</group>
XML
chown root:wazuh "$OKTA_RULES"; chmod 660 "$OKTA_RULES"
echo "Okta rules deployed"

echo "Okta integration complete. Configure Okta log forwarding to Wazuh."