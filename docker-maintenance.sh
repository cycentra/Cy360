#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# docker-maintenance.sh — Scheduled Docker housekeeping
# Removes stopped containers, unused networks, stale images (>14 days),
# build cache, and orphaned volumes.
#
# Runs automatically via cron every 15 days (added by the setup script).
# Safe to run manually at any time:
#   sudo bash docker-maintenance.sh
# ═══════════════════════════════════════════════════════════════════════════════

# Retention period: keep images pulled within the last 14 days
RETENTION="336h"

echo "---------------------------------------------------------"
echo "Starting Docker Maintenance: $(date)"
echo "---------------------------------------------------------"

# 1. Show disk usage BEFORE
echo "Current Space Usage:"
docker system df

echo -e "
Step 1: Removing stopped containers and unused networks..."
docker system prune -f

echo -e "
Step 2: Removing images older than $RETENTION..."
# Skips images currently in use by running containers
docker image prune -a -f --filter "until=$RETENTION"

echo -e "
Step 3: Cleaning up build cache..."
docker builder prune -f

echo -e "
Step 4: Clearing orphaned volumes..."
# Only removes volumes NOT attached to a container
docker volume prune -f

# 2. Show disk usage AFTER
echo -e "
Maintenance Complete! New Space Usage:"
docker system df
echo "---------------------------------------------------------"

