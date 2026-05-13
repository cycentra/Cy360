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
_CYIRIS_IMAGE_APP = os.environ.get("CYIRIS_IMAGE_APP", "ghcr.io/cycentra/cyiris:latest")
_CYIRIS_IMAGE_DB  = os.environ.get("CYIRIS_IMAGE_DB",  "postgres:15-alpine")


COMPOSE_TEMPLATES = {

    # ── CyIRIS — Incident Response & Case Management ─────────────────────────
    "cyiris": f"""
services:
  cyiris-db:
    image: {_CYIRIS_IMAGE_DB}
    restart: always
    environment:
      POSTGRES_PASSWORD: "${{POSTGRES_PASSWORD:-iris_pg_pass}}"
      POSTGRES_USER: iris
      POSTGRES_DB: iris_db
    volumes:
      - cyiris_db_data:/var/lib/postgresql/data
      - cyiris_db_init:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U iris -d iris_db"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s

  cyiris:
    image: {_CYIRIS_IMAGE_APP}
    restart: always
    command: ["app"]
    depends_on:
      cyiris-db:
        condition: service_healthy
    ports:
      - "4433:8000"
    environment:
      POSTGRES_SERVER: cyiris-db
      POSTGRES_PORT: "5432"
      POSTGRES_USER: iris
      POSTGRES_DB: iris_db
      POSTGRES_PASSWORD: "${{POSTGRES_PASSWORD:-iris_pg_pass}}"
      POSTGRES_ADMIN_USER: iris
      POSTGRES_ADMIN_PASSWORD: "${{POSTGRES_PASSWORD:-iris_pg_pass}}"
      IRIS_SECRET_KEY: "${{IRIS_SECRET_KEY:-change_in_production}}"
      IRIS_ADM_EMAIL: "${{IRIS_ADM_EMAIL:-admin@cycentra.com}}"
      IRIS_ADM_PASSWORD: "${{IRIS_ADM_PASSWORD}}"
      BASE_DOMAIN: "${{BASE_DOMAIN}}"
      # IAP mode: oauth2-proxy gates the subdomain; CyIRIS trusts X-Email header (lazy verify)
      IRIS_AUTHENTICATION_TYPE: "oidc_proxy"
      OIDC_IRIS_TOKEN_VERIFY_MODE: "lazy"
      OIDC_IRIS_DISCOVERY_URL: "https://cyasm.${{BASE_DOMAIN}}/oidc/.well-known/openid-configuration"
      IRIS_AUTHENTICATION_CREATE_USER_IF_NOT_EXIST: "True"
      IRIS_AUTHENTICATION_LOCAL_FALLBACK: "False"
      IRIS_NEW_USERS_DEFAULT_GROUP: "Administrators"
      # TLS_ROOT_CA intentionally omitted — the system CA bundle inside the container
      # already trusts Let's Encrypt.  Pointing it at a server-cert path causes
      # requests.get() to fail at startup → exit(0) crash-loop (v1.0.197 rationale).
    volumes:
      - cyiris_app_data:/home/iris/iriswebapp/app/static/assets/files
      - cyiris_user_data:/home/iris/iriswebapp/user_data

volumes:
  cyiris_db_data:
  cyiris_db_init:
  cyiris_app_data:
  cyiris_user_data:
""",

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
      - IRIS_URL=https://cyiris.${{BASE_DOMAIN}}
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
