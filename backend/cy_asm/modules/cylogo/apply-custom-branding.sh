#!/bin/bash
set -e

CONF_FILE="/etc/wazuh-dashboard/opensearch_dashboards.yml"

echo "[+] Applying UI Text Branding to $CONF_FILE..."

# 1. Remove any existing custom branding blocks to prevent duplicates
sudo sed -i '/# Custom Branding/,$d' "$CONF_FILE"

# 2. Append the new branding block
cat <<EOF | sudo tee -a "$CONF_FILE"

# Custom Branding
opensearch_security.basicauth.login.brandimage: "/ui/logos/icon_light.svg"
opensearchDashboards.branding:
  applicationTitle: "CySIEM"
  loadingLogo:
    defaultUrl: "/ui/logos/icon_light.svg"
    darkModeUrl: "/ui/logos/icon_light.svg"
# opensearch_security.basicauth.login.title: "CYCENTRA"
EOF

echo "[✓] UI Branding applied successfully."
