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

}

# Derived from template keys — used for validation in routes.py
VALID_MODULES = set(COMPOSE_TEMPLATES.keys())
