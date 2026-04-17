#!/bin/bash
set -e

WAZUH_CONF="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
SRC_DIR="/usr/local/lib/python3.12/dist-packages/cy_asm/cylogo/app-logos"
IMG_DIR="/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom/images"

echo "[+] Applying Wazuh Plugin internal branding..."

# 1. Ensure the image directory exists and move the logos
sudo mkdir -p "$IMG_DIR"
sudo cp "$SRC_DIR/app.svg" "$IMG_DIR/customization.logo.app.svg"
sudo cp "$SRC_DIR/healthcheck.svg" "$IMG_DIR/customization.logo.healthcheck.svg"
sudo cp "$SRC_DIR/reports.png" "$IMG_DIR/customization.logo.reports.png"
sudo chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom/

# 2. CLEAN UP: Remove any previous Custom Branding blocks to prevent duplicates
# This deletes everything from the first '# Custom Branding' line to the end of the file
sudo sed -i '/# Custom Branding/,$d' "$WAZUH_CONF"

# 3. INJECT: Append the clean branding block
cat <<EOF | sudo tee -a "$WAZUH_CONF"

# Custom Branding
customization.enabled: true
customization.logo.app: "custom/images/customization.logo.app.svg"
customization.logo.healthcheck: "custom/images/customization.logo.healthcheck.svg"
customization.logo.reports: "custom/images/customization.logo.reports.png"
EOF

# 4. Permissions check for the config file itself
sudo chown wazuh-dashboard:wazuh-dashboard "$WAZUH_CONF"
sudo chmod 660 "$WAZUH_CONF"

echo "[✓] Plugin branding injected into wazuh.yml successfully."
