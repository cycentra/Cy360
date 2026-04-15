#!/usr/bin/env bash
# CyCentra360 — SaaS Auth Integration Module
# Installs Okta, Azure MFA, and Duo decoders and rules for Wazuh integration.

set -euo pipefail

SAAS_DECODER="/var/ossec/etc/decoders/cycentra_saas_decoders.xml"
SAAS_RULES="/var/ossec/etc/rules/cycentra_saas_rules.xml"

# Deploy SaaS Auth decoders
cat > "$SAAS_DECODER" << 'XML'
<!-- CyCentra360 SaaS Auth Log Decoders -->
<decoder name="okta">
  <prematch>{"actor":|"eventType":</prematch>
</decoder>
<decoder name="okta-event">
  <parent>okta</parent>
  <use_own_name>true</use_own_name>
</decoder>
<decoder name="azure-mfa">
  <prematch>MicrosoftAuthenticator|ConditionalAccess</prematch>
</decoder>
<decoder name="azure-mfa-event">
  <parent>azure-mfa</parent>
  <prematch>ResultType|AuthenticationRequirement</prematch>
  <regex>ResultType: (\d+).+UserPrincipalName: (\S+)</regex>
  <order>id, user</order>
</decoder>
<decoder name="duo">
  <prematch>{"action":|duo_</prematch>
</decoder>
<decoder name="duo-event">
  <parent>duo</parent>
  <use_own_name>true</use_own_name>
</decoder>
XML
chown root:wazuh "$SAAS_DECODER"; chmod 660 "$SAAS_DECODER"
echo "SaaS auth decoders deployed (Okta / Azure MFA / Duo)"

# Deploy SaaS Auth rules
cat > "$SAAS_RULES" << 'XML'
<!-- CyCentra360 SaaS Auth Detection Rules -->
<group name="cycentra,saas,auth,">
  <rule id="150001" level="10">
    <if_group>okta</if_group>
    <field name="eventType">user.session.start</field>
    <description>Okta: User session started</description>
    <mitre><id>T1078</id></mitre>
    <group>okta_login,</group>
  </rule>
  <rule id="150002" level="10">
    <if_group>azure-mfa</if_group>
    <field name="ResultType">0</field>
    <description>Azure MFA: Successful authentication</description>
    <group>azure_mfa_success,</group>
  </rule>
  <rule id="150003" level="10">
    <if_group>duo</if_group>
    <field name="action">login</field>
    <description>Duo: User login detected</description>
    <group>duo_login,</group>
  </rule>
  <!-- ...other rules omitted for brevity... -->
</group>
XML
chown root:wazuh "$SAAS_RULES"; chmod 660 "$SAAS_RULES"
echo "SaaS auth rules deployed"

echo "SaaS Auth integration complete. Configure log forwarding for Okta, Azure MFA, and Duo."
