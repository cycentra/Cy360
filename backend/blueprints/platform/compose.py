"""
blueprints/platform/compose.py
================================
Docker Compose YAML templates for each installable platform module.

This is pure data — no Flask, no imports, no logic.
Edit ONLY this file when updating a module's compose config,
image versions, environment variables, or ports.
"""

import os

# Image references (resolved from env at import time so hot-reload picks them up)
_CYSOAR_IMAGE     = os.environ.get("CYSOAR_IMAGE",     "ghcr.io/cycentra/cysoar:latest")


COMPOSE_TEMPLATES = {

    # ── CySOAR — Security Orchestration & Automation (Node-RED) ─────────────
    "cysoar": f"""
services:
  cysoar:
    image: {_CYSOAR_IMAGE}
    container_name: cysoar
    restart: unless-stopped
    ports:
      - "127.0.0.1:1880:1880"
    environment:
      # IAP mode: oauth2-proxy gates /cysoar/ via nginx auth_request.
      # No OIDC credentials needed here — authentication is handled upstream.
      - SESSION_SECRET=${{CYSOAR_SESSION_SECRET}}
      - WAZUH_URL=https://cysiem.${{BASE_DOMAIN}}
      - CYCENTRA_PORTAL_URL=${{CYCENTRA_PORTAL_URL}}
    volumes:
      - cysoar_data:/data

volumes:
  cysoar_data:
""",

    # ── CyMISP — Threat Intelligence Platform (MISP) ─────────────────────────
    "cymisp": """
services:
  cymisp:
    image: coolacid/misp-docker:latest
    container_name: cymisp
    restart: unless-stopped
    ports:
      - "127.0.0.1:8243:443"
    environment:
      MISP_ADMIN_EMAIL: "${MISP_ADMIN_EMAIL:-admin@admin.test}"
      MISP_ADMIN_PASSPHRASE: "${MISP_ADMIN_PASSPHRASE}"
      MYSQL_HOST: "cymisp-db"
      MYSQL_USER: "misp"
      MYSQL_PASSWORD: "${MISP_MYSQL_PASSWORD:-misp_db_pass}"
      MYSQL_DATABASE: "misp"
      REDIS_FQDN: "cymisp-redis"
      REDIS_PASSWORD: "${REDIS_PASSWORD:-redispassword}"
      NOREDIR: "true"
    volumes:
      - cymisp_data:/var/www/MISP/app/files
    depends_on:
      - cymisp-db
      - cymisp-redis

  cymisp-db:
    image: mariadb:10.11
    container_name: cymisp-db
    restart: unless-stopped
    environment:
      MYSQL_USER: "misp"
      MYSQL_PASSWORD: "${MISP_MYSQL_PASSWORD:-misp_db_pass}"
      MYSQL_DATABASE: "misp"
      MYSQL_ROOT_PASSWORD: "${MYSQL_ROOT_PASSWORD:-misp_root_pass}"
    volumes:
      - cymisp_db_data:/var/lib/mysql

  cymisp-redis:
    image: redis:7-alpine
    container_name: cymisp-redis
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD:-redispassword}
    volumes:
      - cymisp_redis_data:/data

volumes:
  cymisp_data:
  cymisp_db_data:
  cymisp_redis_data:
""",
}

# Derived from template keys — used for validation in routes.py
VALID_MODULES = set(COMPOSE_TEMPLATES.keys())
