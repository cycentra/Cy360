#!/usr/bin/env bash
# CyCentra360 — O365 Integration Module
# Configures Office 365 log collection via Wazuh's native <office365> module.
#
# PREFERRED PATH: Use the CyCentra portal (Settings → AI & Integrations → Office 365)
# or POST /api/system/o365config — the Flask API writes the <office365> block and
# restarts wazuh-manager automatically. Use THIS script only when the portal is
# unavailable (air-gapped setup or initial bootstrap before the backend is running).
#
# WARNING: Do NOT use the old <wodle name="o365"> format — it is deprecated in
# Wazuh 4.5+ and conflicts with the native <office365> module written by the portal.

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
O365_DECODER="/var/ossec/etc/decoders/cycentra_o365_decoder.xml"
O365_RULES="/var/ossec/etc/rules/cycentra_o365_rules.xml"

# ── Require credentials ────────────────────────────────────────────────────────
: "${O365_TENANT_ID:?Set O365_TENANT_ID before running this script}"
: "${O365_CLIENT_ID:?Set O365_CLIENT_ID before running this script}"
: "${O365_CLIENT_SECRET:?Set O365_CLIENT_SECRET before running this script}"

# ── Inject native <office365> module block into ossec.conf ────────────────────
inject_o365_module() {
    local marker='<office365>'
    if grep -q "$marker" "$OSSEC_CONF" 2>/dev/null; then
        echo "Office365 module already present in ossec.conf — updating credentials"
        python3 - "$OSSEC_CONF" "$O365_TENANT_ID" "$O365_CLIENT_ID" "$O365_CLIENT_SECRET" << 'PYEOF'
import sys, re
path, tenant, client_id, client_secret = sys.argv[1:5]
with open(path) as f: content = f.read()
content = re.sub(r'<tenant_id>[^<]*</tenant_id>',   f'<tenant_id>{tenant}</tenant_id>',         content)
content = re.sub(r'<client_id>[^<]*</client_id>',   f'<client_id>{client_id}</client_id>',       content)
content = re.sub(r'<client_secret>[^<]*</client_secret>', f'<client_secret>{client_secret}</client_secret>', content)
with open(path, 'w') as f: f.write(content)
PYEOF
        echo "Office365 credentials updated in ossec.conf"
        return
    fi
    python3 - "$OSSEC_CONF" "$O365_TENANT_ID" "$O365_CLIENT_ID" "$O365_CLIENT_SECRET" << 'PYEOF'
import sys
path, tenant, client_id, client_secret = sys.argv[1:5]
with open(path) as f: src = f.read()
blk = f"""
  <office365>
    <enabled>yes</enabled>
    <interval>10m</interval>
    <curl_max_size>1M</curl_max_size>
    <only_future_events>yes</only_future_events>
    <api_auth>
      <tenant_id>{tenant}</tenant_id>
      <client_id>{client_id}</client_id>
      <client_secret>{client_secret}</client_secret>
    </api_auth>
    <subscriptions>
      <subscription>Audit.AzureActiveDirectory</subscription>
      <subscription>Audit.Exchange</subscription>
      <subscription>Audit.SharePoint</subscription>
      <subscription>Audit.General</subscription>
    </subscriptions>
  </office365>"""
src = src.replace('</ossec_config>', blk + '\n</ossec_config>', 1)
with open(path, 'w') as f: f.write(src)
PYEOF
    echo "Office365 module block injected into ossec.conf"
}

# ── Deploy O365 decoder ───────────────────────────────────────────────────────
cat > "$O365_DECODER" << 'XML'
<!-- CyCentra360 O365 Log Decoder (native office365 module format) -->
<decoder name="office365">
  <prematch>office365</prematch>
</decoder>
<decoder name="office365-event">
  <parent>office365</parent>
  <use_own_name>true</use_own_name>
</decoder>
XML
chown root:wazuh "$O365_DECODER"; chmod 660 "$O365_DECODER"
echo "O365 decoder deployed"

# ── Deploy O365 detection rules ───────────────────────────────────────────────
cat > "$O365_RULES" << 'XML'
<!-- CyCentra360 O365 Detection Rules (native office365 module) -->
<group name="cycentra,office365,">
  <rule id="140001" level="10">
    <if_group>office365</if_group>
    <field name="data.office365.Operation">UserLoggedIn</field>
    <description>O365: User login — $(data.office365.UserId)</description>
    <mitre><id>T1078</id></mitre>
    <group>o365_login,</group>
  </rule>
  <rule id="140002" level="12">
    <if_group>office365</if_group>
    <field name="data.office365.Operation">Add member to role</field>
    <description>O365: Role membership change — $(data.office365.UserId) T1098</description>
    <mitre><id>T1098</id></mitre>
    <group>o365_privilege,</group>
  </rule>
  <rule id="140003" level="14">
    <if_group>office365</if_group>
    <field name="data.office365.Operation">Set-AdminAuditLogConfig</field>
    <description>O365: Audit log configuration changed — possible defense evasion T1562</description>
    <mitre><id>T1562</id></mitre>
    <group>defense_evasion,o365_admin,</group>
  </rule>
</group>
XML
chown root:wazuh "$O365_RULES"; chmod 660 "$O365_RULES"
echo "O365 rules deployed"

inject_o365_module

systemctl reload wazuh-manager 2>/dev/null || systemctl restart wazuh-manager 2>/dev/null || true
echo "O365 integration complete — wazuh-manager reloaded"
echo "Monitor collection: tail -f /var/ossec/logs/ossec.log | grep -i office365"
