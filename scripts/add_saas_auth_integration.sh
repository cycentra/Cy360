#!/usr/bin/env bash
# CyCentra360 — SaaS Auth Integration Module
# Deploys Okta, Azure MFA, and Duo decoders for Wazuh.

set -euo pipefail

SAAS_DECODER="/var/ossec/etc/decoders/cycentra_saas_decoders.xml"

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
