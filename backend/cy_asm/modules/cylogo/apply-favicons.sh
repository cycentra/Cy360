#!/bin/bash
set -e

SRC="/usr/local/lib/python3.12/dist-packages/cy_asm/modules/cylogo/favicons"
DEST="/usr/share/wazuh-dashboard/src/core/server/core_app/assets/favicons"

if [ ! -d "/usr/share/wazuh-dashboard" ]; then
  echo "[i] No local Wazuh Dashboard install found — skipping favicon branding"
  exit 0
fi

FILES=(
  android-chrome-192x192.png
  android-chrome-512x512.png
  apple-touch-icon.png
  favicon-16x16.png
  favicon-32x32.png
  favicon.ico
  mstile-70x70.png
  mstile-144x144.png
  mstile-150x150.png
  mstile-310x310.png
)

echo "[+] Applying Wazuh favicons"

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

echo "[✓] Favicons applied successfully"

