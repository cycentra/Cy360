#!/bin/bash
set -e

CONF_FILE="/etc/wazuh-dashboard/opensearch_dashboards.yml"

echo "[+] Enabling Multi-tenancy in Wazuh Dashboard..."

# Check if the setting already exists
if grep -q "opensearch_security.multitenancy.enabled" "$CONF_FILE"; then
    # If it exists, make sure it is set to true
    sudo sed -i 's/opensearch_security.multitenancy.enabled: .*/opensearch_security.multitenancy.enabled: true/' "$CONF_FILE"
else
    # If it doesn't exist, append it to the end of the file
    echo "opensearch_security.multitenancy.enabled: true" | sudo tee -a "$CONF_FILE"
fi

# Set the default tenant to 'global' or 'private' (Optional but recommended)
if ! grep -q "opensearch_security.multitenancy.tenants.preferred" "$CONF_FILE"; then
    echo 'opensearch_security.multitenancy.tenants.preferred: ["Global", "Private"]' | sudo tee -a "$CONF_FILE"
fi

echo "[✓] Multi-tenancy configuration applied."
