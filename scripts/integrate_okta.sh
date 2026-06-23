#!/usr/bin/env bash
# CyCentra360 — Okta Integration Module
#
# DEPRECATION NOTICE: Use integrate_saas_auth.sh instead.
# That script covers Okta + Azure MFA + Duo in a single deployment and avoids
# the decoder-name conflict (both scripts define <decoder name="okta">) that
# causes wazuh-manager to fail decoder loading if both are run.
#
# This script is kept for reference only. Running BOTH this script and
# integrate_saas_auth.sh on the same host will produce duplicate decoder names
# and break Wazuh startup.

set -euo pipefail

echo "WARNING: integrate_okta.sh is deprecated. Use integrate_saas_auth.sh instead."
echo "See deprecation notice in this file for details."
echo ""
read -rp "Continue anyway? [y/N]: " _ans
[[ "$_ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

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
</group>
XML
chown root:wazuh "$OKTA_RULES"; chmod 660 "$OKTA_RULES"
echo "Okta rules deployed"

echo "Okta integration complete. Configure Okta log forwarding to Wazuh."
