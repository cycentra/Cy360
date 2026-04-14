#!/bin/bash
# CyCentra 360 Uninstall Script (Comprehensive)
# This script will remove CyCentra 360 application, services, configs, Docker, users, and dependencies.
# Run as root: sudo bash cycentra-uninstall.sh

set -euo pipefail

echo "[1/8] Stopping and disabling services..."
systemctl stop cycentra-backend 2>/dev/null || true
systemctl disable cycentra-backend 2>/dev/null || true
systemctl stop cysiem-to-redis 2>/dev/null || true
systemctl disable cysiem-to-redis 2>/dev/null || true
systemctl stop cycentra-frontend 2>/dev/null || true
systemctl disable cycentra-frontend 2>/dev/null || true
systemctl stop cycentra-cymind 2>/dev/null || true
systemctl disable cycentra-cymind 2>/dev/null || true
systemctl stop cycentra-cysoar 2>/dev/null || true
systemctl disable cycentra-cysoar 2>/dev/null || true
systemctl stop cycentra-cyiris 2>/dev/null || true
systemctl disable cycentra-cyiris 2>/dev/null || true
systemctl stop redis-server 2>/dev/null || true
systemctl disable redis-server 2>/dev/null || true
systemctl stop postgresql 2>/dev/null || true
systemctl disable postgresql 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true
systemctl stop docker 2>/dev/null || true
systemctl disable docker 2>/dev/null || true

echo "[2/8] Removing application files, configs, and logs..."
# Remove immutable files if present
if [ -f /opt/cycentra/.demo_start ]; then
	chattr -i /opt/cycentra/.demo_start 2>/dev/null || true
fi

rm -rf /opt/cycentra
rm -rf /var/www/cycentra360
rm -rf /opt/cycentra-branding
rm -rf /var/log/cycentra
rm -rf /var/log/cycentra/cy-asm
rm -rf /tmp/cycentra*
rm -rf /etc/cycentra*
rm -rf /etc/nginx/sites-available/cycentra*
rm -rf /etc/nginx/sites-enabled/cycentra*
rm -rf /etc/systemd/system/cycentra-*.service
rm -rf /etc/systemd/system/cysiem-to-redis.service
rm -rf /etc/systemd/system/cymind*.service
rm -rf /etc/systemd/system/cysoar*.service
rm -rf /etc/systemd/system/cyiris*.service
rm -rf /etc/cron.d/cycentra*
rm -rf /etc/logrotate.d/cycentra*
rm -rf /etc/default/cycentra*
rm -rf /etc/profile.d/cycentra*
rm -rf /usr/local/bin/cycentra*
rm -rf /usr/local/bin/cysiem*
rm -rf /usr/local/bin/cymind*
rm -rf /usr/local/bin/cysoar*
rm -rf /usr/local/bin/cyiris*
rm -rf /var/lib/cycentra*
rm -rf /var/lib/postgresql/16/main
rm -rf /var/lib/redis
rm -rf /var/lib/docker
rm -rf /var/lib/nginx
rm -rf /var/cache/nginx
rm -rf /var/cache/cycentra*
rm -rf /var/tmp/cycentra*
rm -rf /var/spool/cycentra*
rm -rf /var/backups/cycentra*
rm -rf /var/run/cycentra*
rm -rf /var/run/cysiem*
rm -rf /var/run/cymind*
rm -rf /var/run/cysoar*
rm -rf /var/run/cyiris*

echo "[3/8] Removing systemd service files and reloading..."
systemctl daemon-reload

echo "[4/8] Removing users, groups, and crontab..."
deluser --remove-home cycentra 2>/dev/null || true
delgroup cycentra 2>/dev/null || true
crontab -r -u cycentra 2>/dev/null || true

echo "[5/8] Removing Docker containers, images, volumes, and networks..."
docker ps -a -q --filter "name=cycentra" | xargs -r docker rm -f 2>/dev/null || true
docker images -a | grep cycentra | awk '{print $3}' | xargs -r docker rmi -f 2>/dev/null || true
docker volume ls -q | grep cycentra | xargs -r docker volume rm 2>/dev/null || true
docker network ls -q | xargs -r docker network rm 2>/dev/null || true

echo "[6/8] Removing system packages (optional, may affect other apps)..."
apt-get remove --purge -y postgresql-16 postgresql redis-server nginx certbot python3 python3-pip docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin nodejs npm yarn || true
apt-get autoremove --purge -y || true
apt-get clean || true

echo "[7/8] Cleaning up any remaining temp/cache files..."
find /tmp -name 'cycentra*' -exec rm -rf {} +
find /var/tmp -name 'cycentra*' -exec rm -rf {} +

echo "[8/8] Final checks and message..."
echo "CyCentra 360 and all related components have been removed."
echo "Please review any remaining dependencies, files, or Docker artifacts manually if needed."
