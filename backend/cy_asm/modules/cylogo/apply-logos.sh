#!/bin/bash
set -e

SRC="/usr/local/lib/python3.12/dist-packages/cy_asm/modules/cylogo/logos"
DEST="/usr/share/wazuh-dashboard/src/core/server/core_app/assets/logos"

if [ ! -d "/usr/share/wazuh-dashboard" ]; then
  echo "[i] No local Wazuh Dashboard install found — skipping logo branding"
  exit 0
fi

FILES=(
  icon_dark.svg
  icon_light.svg
  spinner_on_dark.svg
  spinner_on_light.svg
  wazuh.svg
  wazuh_center_mark.svg
  wazuh_center_mark_on_dark.svg
  wazuh_center_mark_on_light.svg
  wazuh_dashboards.svg
  wazuh_dashboards_on_dark.svg
  wazuh_dashboards_on_light.svg
  wazuh_mark.svg
  wazuh_mark_on_dark.svg
  wazuh_mark_on_light.svg
  wazuh_on_dark.svg
  wazuh_on_light.svg
)

echo "[+] Applying Wazuh logos"

for file in "${FILES[@]}"; do
  src_file="$SRC/$file"
  dest_file="$DEST/$file"

  if [ ! -f "$src_file" ]; then
    echo "[ERROR] Missing source file: $src_file"
    exit 1
  fi

  if [ -f "$dest_file" ] && [ ! -f "$dest_file.backup" ]; then
    echo "Backing up $file"
    sudo mv "$dest_file" "$dest_file.backup"
  fi

  echo "Copying $file"
  sudo cp "$src_file" "$DEST/"
done

echo "[✓] Logos applied successfully"

