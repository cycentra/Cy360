#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CySOAR Server Cleanup Script
# Run this on your production server BEFORE reinstalling CySOAR via portal
# Removes old volumes/containers that cause 37/40 hang and logo issues
# ═══════════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BLUE}${BOLD}"
echo "══════════════════════════════════════════════════════════════"
echo "  CySOAR Server Cleanup"
echo "  Preparing for clean reinstall via cycentra360-portal"
echo "══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (or with sudo)${NC}" 
   echo -e "Usage: ${BLUE}sudo bash cysoar-server-cleanup.sh${NC}"
   exit 1
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker not found. Please install Docker first.${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/5] Current CySOAR status...${NC}"
CONTAINERS=$(docker ps -a --filter "name=cysoar" --format "{{.Names}}" 2>/dev/null || echo "")
if [ -n "$CONTAINERS" ]; then
    echo -e "  Found containers:"
    docker ps -a --filter "name=cysoar" --format "  - {{.Names}} ({{.Status}})"
else
    echo -e "  ${GREEN}✓${NC} No containers found"
fi

VOLUMES=$(docker volume ls --filter "name=cysoar" --format "{{.Name}}" 2>/dev/null || echo "")
if [ -n "$VOLUMES" ]; then
    echo -e "  Found volumes (these may have httpStatic misconfiguration):"
    echo "$VOLUMES" | sed 's/^/    - /'
else
    echo -e "  ${GREEN}✓${NC} No volumes found"
fi

IMAGES=$(docker images ghcr.io/cycentra/cysoar --format "{{.ID}}" 2>/dev/null || echo "")
if [ -n "$IMAGES" ]; then
    echo -e "  Found cached images:"
    docker images ghcr.io/cycentra/cysoar --format "  - {{.Repository}}:{{.Tag}} ({{.ID}}) - {{.CreatedAt}}"
else
    echo -e "  ${GREEN}✓${NC} No images cached"
fi

echo ""
echo -e "${YELLOW}[2/5] Stopping and removing CySOAR containers...${NC}"
if [ -n "$CONTAINERS" ]; then
    echo "$CONTAINERS" | xargs -r docker stop 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} Containers stopped"
    echo "$CONTAINERS" | xargs -r docker rm -f 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} Containers removed"
else
    echo -e "  ${GREEN}✓${NC} No containers to remove"
fi

echo ""
echo -e "${YELLOW}[3/5] Removing old data volumes (ROOT CAUSE OF LOGO ISSUES)...${NC}"
if [ -n "$VOLUMES" ]; then
    echo -e "  ${RED}${BOLD}⚠ WARNING:${NC} This will delete ALL CySOAR data!"
    echo -e "  Volumes contain httpStatic misconfiguration causing:"
    echo -e "    - Logo images not loading (404 errors)"
    echo -e "    - 37/40 hang in browser UI"
    echo -e "    - Support form not accessible"
    echo ""
    read -p "  Delete these volumes? (y/N): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "$VOLUMES" | xargs -r docker volume rm -f 2>/dev/null || true
        echo -e "  ${GREEN}✓${NC} Volumes deleted (fresh volume will be created on reinstall)"
    else
        echo -e "  ${YELLOW}⚠${NC}  Volumes kept - issues may persist"
        echo -e "     Run with: ${BLUE}echo 'y' | sudo bash cysoar-server-cleanup.sh${NC} to skip prompt"
    fi
else
    echo -e "  ${GREEN}✓${NC} No volumes to remove"
fi

echo ""
echo -e "${YELLOW}[4/5] Removing cached Docker images...${NC}"
if [ -n "$IMAGES" ]; then
    echo "$IMAGES" | xargs -r docker rmi -f 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} Old images removed (portal will pull fresh)"
else
    echo -e "  ${GREEN}✓${NC} No images to remove"
fi

echo ""
echo -e "${YELLOW}[5/5] Cleaning up deployment directory...${NC}"
if [ -d "/opt/cycentra/modules/cysoar" ]; then
    rm -rf /opt/cycentra/modules/cysoar
    echo -e "  ${GREEN}✓${NC} Deployment directory cleaned"
else
    echo -e "  ${GREEN}✓${NC} No deployment directory found"
fi

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✓ Cleanup Complete!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Next Steps:${NC}"
echo ""
echo -e "  ${BOLD}1. Ensure SMTP configuration in /opt/cycentra/.env${NC}"
echo -e "     ${BLUE}nano /opt/cycentra/.env${NC}"
echo -e "     Add these lines if missing:"
echo -e "       ${BLUE}SMTP_HOST=smtp.gmail.com${NC}"
echo -e "       ${BLUE}SMTP_PORT=587${NC}"
echo -e "       ${BLUE}SMTP_USER=your@email.com${NC}"
echo -e "       ${BLUE}SMTP_PASS=your-app-password${NC}"
echo -e "       ${BLUE}SUPPORT_EMAIL=support@cycentra.com${NC}"
echo ""
echo -e "  ${BOLD}2. Set custom image flag in .env${NC}"
echo -e "     ${BLUE}echo 'USE_CUSTOM_IMAGES=yes' >> /opt/cycentra/.env${NC}"
echo ""
echo -e "  ${BOLD}3. Restart backend to pick up new .env${NC}"
echo -e "     ${BLUE}systemctl restart cycentra-backend${NC}"
echo ""
echo -e "  ${BOLD}4. Pull latest backend code (includes volume cleanup fix)${NC}"
echo -e "     ${BLUE}cd /opt/cycentra/backend && git pull${NC}"
echo -e "     ${BLUE}systemctl restart cycentra-backend${NC}"
echo ""
echo -e "  ${BOLD}5. Install CySOAR via portal${NC}"
echo -e "     - Go to: ${BLUE}https://cy360.\${YOUR_DOMAIN}${NC}"
echo -e "     - Navigate to Platform Modules"
echo -e "     - Click ${GREEN}Install${NC} on CySOAR"
echo -e "     - Wait ~30-60 seconds for completion"
echo ""
echo -e "  ${BOLD}6. Verify installation${NC}"
echo -e "     ${BLUE}docker ps | grep cysoar${NC}  # Should show running"
echo -e "     ${BLUE}docker logs cysoar-cysoar-1 | tail -30${NC}"
echo -e "     ${BLUE}curl http://localhost:1880/red/images/node-red.svg | head -5${NC}"
echo ""
echo -e "${BOLD}Expected Results After Reinstall:${NC}"
echo -e "  ✓ Container starts in 8-10 seconds (no 37/40 hang)"
echo -e "  ✓ Log: '✅ CySOAR Support System initialized with email notifications'"
echo -e "  ✓ Log: 'Started flows' appears quickly"
echo -e "  ✓ NO 'HTTP Static : /data/custom' in logs"
echo -e "  ✓ Logo SVG shows: <linearGradient id=\"cyGradient\"> (blue gradient)"
echo -e "  ✓ Support form accessible at /cysoar/support"
echo ""
echo -e "${YELLOW}Troubleshooting:${NC}"
echo -e "  View installation logs:"
echo -e "    ${BLUE}tail -f /opt/cycentra/modules/cysoar/install.log${NC}"
echo ""
echo -e "  Check backend logs:"
echo -e "    ${BLUE}journalctl -u cycentra-backend -f${NC}"
echo ""
echo -e "  Manual image pull:"
echo -e "    ${BLUE}docker pull ghcr.io/cycentra/cysoar:latest${NC}"
echo ""
