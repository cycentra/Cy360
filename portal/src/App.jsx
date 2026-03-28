import { useState, useEffect, useRef } from "react";
// ════════════════════════════════════════════════════════════════════════════
// MODULE 01 — CONSTANTS, PLATFORM REGISTRY, DATA ADAPTER
// CyCentra 360 v3 — Deploy first, all other modules import from here
// ════════════════════════════════════════════════════════════════════════════

// ── Dynamic domain resolution ────────────────────────────────────────────────
// setup.sh injects:  <script>window.__CYCENTRA_DOMAIN__='clientdomain.com';</script>
// into index.html so this SPA works for any customer without a rebuild.
// Falls back to the current hostname so development (localhost) still works.

import { SiemIncidentsPage } from "./siem/SiemIncidentsPage";
import { SiemRiskScoresPage } from "./siem/SiemRiskScoresPage";
import { SiemUebaPage }       from "./siem/SiemUebaPage";

const _BASE_DOMAIN = (
  window.__CYCENTRA_DOMAIN__ ||                     // injected by setup.sh
  window.location.hostname.replace(/^cy360\./, "")  // derive from current host
);

export const CYSCAN_URL    = `https://cyscan.${_BASE_DOMAIN}`;   // public backend — OAuth redirects, CLI
export const PORTAL_URL    = `https://cy360.${_BASE_DOMAIN}`;    // this SPA
export const PORTAL_ISSUER = `https://cy360.${_BASE_DOMAIN}`;    // OIDC issuer
export const SIEM_BASE_URL = `https://cysiem.${_BASE_DOMAIN}`;   // 
export const IRIS_BASE_URL = `https://cyiris.${_BASE_DOMAIN}`;   // 
export const MISP_BASE_URL = `https://cymisp.${_BASE_DOMAIN}`;   // 

// API_BASE is empty so all fetch() calls are same-origin relative URLs (/api/…).
// nginx on cy360.domain proxies /api/ /auth/ /oidc/ → 127.0.0.1:5252 (Flask).
// cyscan.domain remains fully reachable from the public internet independently.
export const API_BASE = "";

// ── SSO Token helpers ─────────────────────────────────────────────────────────
// The portal acts as the IdP. Uses localStorage so the session survives page
// refreshes (sessionStorage is wiped on refresh in some browsers/configs).
// A cy_user object is stored alongside so CyCentra360 can restore state on load.
function getSSOToken() {
  try {
    const t = localStorage.getItem("cy_sso_token");
    return t?.trim() || null;  // ← return null instead of "" so falsy check works on refresh
  } catch { return null; }
}
function setSSOToken(token) {
  try {
    if (token) localStorage.setItem("cy_sso_token", token);  // ← only save non-empty tokens
  } catch {}
}

function clearSSOToken() {
  try {
    localStorage.removeItem("cy_sso_token");
    localStorage.removeItem("cy_user");
  } catch {}
}
function getSavedUser() {
  try {
    const raw = localStorage.getItem("cy_user");
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function saveUser(u) {
  try { localStorage.setItem("cy_user", JSON.stringify(u)); } catch {}
}

// ── Module URL resolution ─────────────────────────────────────────────────────
// Modules can be accessed via path-based routes (cy360.domain/cysoar) or legacy
export const MODULE_DEFAULT_URLS = {
  cysiem:     SIEM_BASE_URL, // Resolves to https://cysiem.domain.com
  cyiris:     IRIS_BASE_URL, // Resolves to https://cyiris.domain.com
  cysoar:     `${PORTAL_URL}/cysoar`,     // Node-RED (CySOAR) at path-based route
  cymisp:     MISP_BASE_URL, // Resolves to https://cymisp.domain.com
};

function getModuleUrl(moduleId) {
  try {
    const saved = localStorage.getItem(`cycentra_url_${moduleId}`);
    if (saved?.trim()) return saved.trim().replace(/\/$/, "");
  } catch {}
  return MODULE_DEFAULT_URLS[moduleId] || CYSCAN_URL;
}

// ── Navigation: same-tab module navigation with history state ────────────────
// All module links use pushState so the Back button works correctly.
function navigateToModule(moduleId) {
  const url = getModuleUrl(moduleId);
  // Push a history entry so Back returns to the portal
  window.history.pushState({ moduleId, from: "portal" }, "", window.location.pathname);
  window.location.href = url;
}

// ── Risk & status display config ──────────────────────────────────────────────
export const RISK_CONFIG = {
  critical: { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)",  label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "rgba(255,140,0,0.12)",  label: "HIGH"     },
  medium:   { color: "#f5c518", bg: "rgba(245,197,24,0.12)", label: "MEDIUM"   },
  low:      { color: "#00e5a0", bg: "rgba(0,229,160,0.12)",  label: "LOW"      },
};
export const STATUS_CONFIG = {
  "open":      { color: "#ff3b3b", label: "OPEN"      },
  "in-review": { color: "#f5c518", label: "IN REVIEW" },
  "resolved":  { color: "#00e5a0", label: "RESOLVED"  },
};

// ── Platform Module Registry ──────────────────────────────────────────────────
// tier: "base"   = always installed, never removable (CySIEM, ASM)
// tier: "addon"  = user installs/uninstalls (CyIRIS, CySOAR)
export const PLATFORM_MODULES = {

  // ── BASE: CySIEM ─────────────────────────────────────────────────
  cysiem: {
    id: "cysiem", tier: "base",
    name: "CySIEM",
    fullName: "CySIEM — Endpoint & Log Intelligence",
    description: "Wazuh-based SIEM. Endpoint detection, log analysis, FIM, vulnerability scanning and alerting. Core Base 360 module — always active.",
    icon: "👁️", color: "#ff8c00",
    ram_gb: 8, disk_gb: 50, install_time: "N/A",
    port: 443, healthPath: "/api/status",
    image: "wazuh/wazuh-manager:4.7.0",
    // SSO: SAML/OIDC via OpenSearch Security plugin
    ssoProtocol: "SAML",
    ssoNotes: "Configure OpenSearch Security → SAML with PORTAL_URL as IdP. See SSO Config tab.",
    composeTemplate: `# CySIEM (Wazuh 4.7.0) — Base 360 Module
# SSO via SAML — configure opensearch_security plugin after first boot
version: "3.8"
services:
  cysiem-manager:
    image: wazuh/wazuh-manager:4.7.0
    hostname: cysiem-manager
    restart: unless-stopped
    ports: ["1514:1514/udp","1515:1515","514:514/udp","55000:55000"]
    environment:
      - INDEXER_URL=https://cysiem-indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=\${INDEXER_PASSWORD}
      - CYCENTRA_PORTAL_URL=\${CYCENTRA_PORTAL_URL}
      - CYCENTRA_SSO_TOKEN=\${CYCENTRA_SSO_TOKEN}
    volumes:
      - cysiem_api_configuration:/var/ossec/api/configuration
      - cysiem_etc:/var/ossec/etc
      - cysiem_logs:/var/ossec/logs
      - cysiem_queue:/var/ossec/queue
      - cysiem_integrations:/var/ossec/integrations
      - cysiem_active_response:/var/ossec/active-response/bin
      - filebeat_etc:/etc/filebeat
      - filebeat_var:/var/lib/filebeat

  cysiem-indexer:
    image: wazuh/wazuh-indexer:4.7.0
    hostname: cysiem-indexer
    restart: unless-stopped
    ports: ["9200:9200"]
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - bootstrap.memory_lock=true
      # SAML IdP metadata endpoint — portal must serve /.well-known/saml-metadata
      - plugins.security.authcz.admin_dn=CN=admin,DC=cycentra,DC=com
    volumes:
      - cysiem_indexer:/var/lib/wazuh-indexer

  cysiem-dashboard:
    image: wazuh/wazuh-dashboard:4.7.0
    hostname: cysiem-dashboard
    restart: unless-stopped
    ports: ["5601:5601"]
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=\${INDEXER_PASSWORD}
      - WAZUH_API_URL=https://cysiem-manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=\${DASHBOARD_PASSWORD}
      # SAML SSO settings
      - OPENSEARCH_SECURITY_AUTH_TYPE=saml
      - OPENSEARCH_SECURITY_SAML_IDP_METADATA_URL=\${CYCENTRA_PORTAL_URL}/.well-known/saml-metadata
      - OPENSEARCH_SECURITY_SAML_SP_ENTITY_ID=cysiem
      - OPENSEARCH_SECURITY_SAML_IDP_ENTITY_ID=cycentra360

volumes:
  cysiem_api_configuration: cysiem_etc: cysiem_logs: cysiem_queue:
  cysiem_integrations: cysiem_active_response: filebeat_etc: filebeat_var: cysiem_indexer:`,
    defaultConfig: {
      adminPassword:     "CySIEM@"   + Math.random().toString(36).slice(2,8).toUpperCase(),
      indexerPassword:   "Indexer@"  + Math.random().toString(36).slice(2,8).toUpperCase(),
      dashboardPassword: "Dash@"     + Math.random().toString(36).slice(2,8).toUpperCase(),
      retentionDays: 90, alertLevel: 7,
    },
    configFields: [
      { key: "adminPassword",   label: "Admin Password",        type: "password", help: "Wazuh API admin password" },
      { key: "retentionDays",   label: "Log Retention (days)",  type: "number",   help: "Index retention period" },
      { key: "alertLevel",      label: "Alert Threshold (1–15)",type: "number",   help: "Min rule level to forward to portal" },
    ],
    features: ["Endpoint monitoring","Log analysis","FIM","Vuln detection","Threat intelligence","Custom rules","SAML SSO"],
    githubRepo: "https://github.com/wazuh/wazuh-docker",
    docsUrl: "https://documentation.wazuh.com",
  },

  // ── ADD-ON: CyIRIS (Incident Response & Case Management) ─────────────────
  cyiris: {
    id: "cyiris", tier: "addon",
    name: "CyIRIS",
    fullName: "CyIRIS — Incident Response & Case Management",
    description: "DFIR IRIS-powered incident response platform, branded as CyIRIS. Track cases, IOCs, timelines and collaborate on security incidents. SSO via native OIDC.",
    icon: "🎫", color: "#b06eff",
    ram_gb: 3, disk_gb: 20, install_time: "4–6 minutes",
    port: 4433, healthPath: "/api/v2/ping",
    image: "ghcr.io/dfir-iris/iriswebapp_app:latest",
    ssoProtocol: "OIDC",
    ssoNotes: "CyIRIS uses DFIR IRIS native OIDC client. Point OIDC_PROVIDER_URL to the portal's /oidc endpoint. Client ID: cyiris, Client Secret: auto-generated.",
    composeTemplate: `# CyIRIS (DFIR IRIS) — Add-on Module
services:
  cyiris-db:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=iris_db
      - POSTGRES_USER=iris
      - POSTGRES_PASSWORD=\${DB_PASSWORD}
    volumes: [cyiris_db:/var/lib/postgresql/data]

  cyiris-rabbitmq:
    image: rabbitmq:3-alpine
    restart: unless-stopped
    environment:
      - RABBITMQ_DEFAULT_USER=iris
      - RABBITMQ_DEFAULT_PASS=\${RABBITMQ_PASSWORD}

  cyiris-worker:
    image: ghcr.io/dfir-iris/iriswebapp_app:latest
    restart: unless-stopped
    depends_on: [cyiris-db, cyiris-rabbitmq]
    environment:
      - IRIS_SECRET_KEY=\${SECRET_KEY}
      - IRIS_POSTGRES_SERVER=cyiris-db
      - IRIS_POSTGRES_USER=iris
      - IRIS_POSTGRES_PASSWORD=\${DB_PASSWORD}
      - IRIS_POSTGRES_DB=iris_db
      - CELERY_BROKER=amqp://iris:\${RABBITMQ_PASSWORD}@cyiris-rabbitmq

  cyiris-app:
    image: ghcr.io/cycentra/cyiris:latest
    restart: unless-stopped
    depends_on: [cyiris-db, cyiris-rabbitmq, cyiris-worker]
    ports: ["4433:8000"]
    environment:
      - IRIS_SECRET_KEY=\${SECRET_KEY}
      - IRIS_POSTGRES_SERVER=cyiris-db
      - IRIS_POSTGRES_USER=iris
      - IRIS_POSTGRES_PASSWORD=\${DB_PASSWORD}
      - IRIS_POSTGRES_DB=iris_db
      - CELERY_BROKER=amqp://iris:\${RABBITMQ_PASSWORD}@cyiris-rabbitmq
      - IRIS_ADMIN_PASSWORD=\${ADMIN_PASSWORD}
      - IRIS_ADMIN_EMAIL=\${ADMIN_EMAIL}
      - IRIS_OIDC_ENABLED=true
      - IRIS_OIDC_PROVIDER_URL=\${CYCENTRA_PORTAL_URL}/oidc
      - IRIS_OIDC_CLIENT_ID=cyiris
      - IRIS_OIDC_CLIENT_SECRET=\${CYIRIS_OIDC_SECRET}
      - IRIS_OIDC_REDIRECT_URI=https://cyiris.\${BASE_DOMAIN}/auth/oidc/callback

volumes:
  cyiris_db:`,
    defaultConfig: {
      IRIS_ADM_PASSWORD:      "CyIRIS@" + Math.random().toString(36).slice(2,8).toUpperCase(),
      dbPassword:             "DB@"      + Math.random().toString(36).slice(2,8).toUpperCase(),
      rabbitmqPassword:       "RMQ@"     + Math.random().toString(36).slice(2,8).toUpperCase(),
      secretKey:              Array.from({length:32}, () => Math.random().toString(36)[2]).join(""),
      cyirisOidcSecret:       Array.from({length:24}, () => Math.random().toString(36)[2]).join(""),
    },
    configFields: [
      { key: "IRIS_ADM_PASSWORD", label: "Admin Password", type: "password", help: "Fallback admin password" },
    ],
    features: ["Case management","IOC tracking","Timeline analysis","MISP integration","VirusTotal enrichment","Team collaboration","OIDC SSO"],
    githubRepo: "https://github.com/cycentra/cyiris",
    docsUrl: "https://cycentra.com/docs/cyiris",
  },

  // ── ADD-ON: CySOAR (Security Orchestration, Automation & Response) ───────
  cysoar: {
    id: "cysoar", tier: "addon",
    name: "CySOAR",
    fullName: "CySOAR — Security Orchestration, Automation & Response",
    description: "Visual SOAR engine built on Node-RED. Pre-loaded with SOC use cases — alert triage, IOC enrichment, brute-force response, malware isolation, threat summaries and more. OIDC SSO built-in.",
    icon: "🛡️", color: "#4d9eff", embedded: true, embeddedPath: "/cysoar/",
    ram_gb: 2, disk_gb: 10, install_time: "3–5 minutes",
    port: 1880, healthPath: "/health",
    image: "nodered/node-red:latest",
    ssoProtocol: "OIDC",
    ssoNotes: "CySOAR uses passport-openidconnect. Point OIDC_ISSUER to the portal. Client ID: cysoar. After install, register the client in the portal OIDC config.",
    composeTemplate: `# CySOAR (Node-RED SOAR) — Add-on Module
services:
  cysoar:
    image: nodered/node-red:latest
    container_name: cysoar
    restart: unless-stopped
    ports: ["1880:1880"]
    environment:
      - OIDC_ISSUER=\${CYCENTRA_PORTAL_URL}/oidc
      - OIDC_CLIENT_ID=cysoar
      - OIDC_CLIENT_SECRET=\${CYSOAR_OIDC_SECRET}
      - OIDC_REDIRECT_URI=https://cysoar.\${BASE_DOMAIN}/auth/callback
      - SESSION_SECRET=\${CYSOAR_SESSION_SECRET}
      - IRIS_URL=https://cyiris.\${BASE_DOMAIN}
      - WAZUH_URL=https://cysiem.\${BASE_DOMAIN}
      - CYCENTRA_PORTAL_URL=\${CYCENTRA_PORTAL_URL}
    volumes: [cysoar_data:/data]

volumes:
  cysoar_data:`,
    defaultConfig: {
      cysoarOidcSecret:    Array.from({length:24}, () => Math.random().toString(36)[2]).join(""),
      cysoarSessionSecret: Array.from({length:32}, () => Math.random().toString(36)[2]).join(""),
    },
    configFields: [],
    features: ["Alert triage","IOC enrichment","Brute-force response","Malware isolation","Threat summaries","Phishing response","OIDC SSO","CyIRIS integration","CySIEM integration"],
    githubRepo: "https://github.com/cycentra/cysoar",
    docsUrl: "https://cycentra.org/docs/",
  },
// ── ADD-ON: CyMISP (Threat Intelligence Platform) ────────────────────────
  cymisp: {
    id: "cymisp", tier: "addon",
    name: "CyMISP",
    fullName: "CyMISP — Threat Intelligence Platform",
    description: "MISP open-source threat intelligence platform. Manage and correlate indicators of compromise, track threat actors, and enrich CySIEM incidents automatically.",
    icon: "🔍", color: "#e8a020", embedded: false, embeddedPath: null,
    ram_gb: 4, disk_gb: 10, install_time: "8–12 minutes",
    port: 8243, healthPath: "/users/login",
    image: "ghcr.io/misp/misp-docker/misp-core:latest",
    ssoProtocol: "None",
    ssoNotes: "MISP uses its own local accounts. OIDC SSO can be configured later via MISP administration settings.",
    composeTemplate: `services:
  cymisp-db:
    image: mysql:8.0
    container_name: cymisp-db
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: \${MISP_MYSQL_PASSWORD}
      MYSQL_ROOT_PASSWORD: \${MISP_MYSQL_ROOT_PASSWORD}
    volumes:
      - cymisp_db_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

  cymisp-redis:
    image: redis:7-alpine
    container_name: cymisp-redis
    restart: unless-stopped
    command: redis-server --requirepass \${REDIS_PASSWORD}

  cymisp:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    container_name: cymisp
    restart: unless-stopped
    ports:
      - "127.0.0.1:8200:80"
      - "127.0.0.1:8243:443"
    environment:
      - MISP_BASEURL=https://cymisp.\${BASE_DOMAIN}
      - MISP_EXTERNAL_BASEURL=https://cymisp.\${BASE_DOMAIN}
      - MISP_ADMIN_EMAIL=\${MISP_ADMIN_EMAIL}
      - MISP_ADMIN_PASSPHRASE=\${MISP_ADMIN_PASSPHRASE}
      - MYSQL_HOST=cymisp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=\${MISP_MYSQL_PASSWORD}
      - REDIS_HOST=cymisp-redis
      - REDIS_PORT=6379
      - REDIS_PASSWORD=\${REDIS_PASSWORD}
      - PHP_SESSIONS_IN_REDIS=true
    depends_on:
      cymisp-db:
        condition: service_healthy
      cymisp-redis:
        condition: service_started
    volumes:
      - cymisp_data:/var/www/MISP
      - ./misp-config.php:/var/www/MISP/app/Config/config.php

volumes:
  cymisp_db_data:
  cymisp_data:`,

    defaultConfig: {
      MISP_ADMIN_EMAIL:         "admin@cycentra.local",
      MISP_ADMIN_PASSPHRASE:    "CyAdmin_MISP1234!",
      MISP_MYSQL_PASSWORD:      "Cycentra_SQL_" + Math.random().toString(36).slice(2,10),
      MISP_MYSQL_ROOT_PASSWORD: "Cycentra_SQL_root_" + Math.random().toString(36).slice(2,10),
      REDIS_PASSWORD:           "CyRedis_" + Math.random().toString(36).slice(2,10),
      BASE_DOMAIN:              window.__CYCENTRA_DOMAIN__ || "cycentra.com",
    },
    configFields: [
      { key: "MISP_ADMIN_EMAIL",         label: "Admin Email",          type: "text",     help: "MISP administrator email" },
      { key: "MISP_ADMIN_PASSPHRASE",    label: "Admin Password",       type: "password", help: "MISP administrator password" },
    ],
    features: ["IOC management and sharing","Threat actor tracking","Automated indicator enrichment","STIX/TAXII support","CySIEM correlation integration","Event correlation","Feeds and galaxies"],
    githubRepo: "https://github.com/MISP/MISP",
    docsUrl: "https://www.misp-project.org/documentation/",
    postInstallNote: "CyMISP is ready. Login with the email and password you set during installation. If login fails, use admin@admin.test / admin as fallback. Change your password after first login.",
  },
};

// ── AI Provider Registry ──────────────────────────────────────────────────────
export const AI_PROVIDERS = {
  local: {
    id: "local", name: "Local LLM", icon: "🖥️", color: "#00e5a0",
    description: "Self-hosted LLM (Ollama, LM Studio). Air-gapped — data never leaves your network.",
    fields: [
      { key: "baseUrl", label: "LLM Server URL", placeholder: "http://192.168.1.100:11434", type: "text" },
      { key: "model",   label: "Model Name",     placeholder: "mistral:7b or llama3:8b",   type: "text" },
    ],
    apiKeyRequired: false, badge: "AIR-GAPPED",
  },
  openai: {
    id: "openai", name: "OpenAI", icon: "🤖", color: "#10a37f",
    description: "GPT-4o, GPT-4 Turbo. Best for complex reasoning and code analysis.",
    fields: [
      { key: "apiKey", label: "API Key", placeholder: "sk-...",  type: "password" },
      { key: "model",  label: "Model",   placeholder: "gpt-4o",  type: "text"     },
    ],
    apiKeyRequired: true, badge: "CLOUD",
    models: ["gpt-4o","gpt-4-turbo","gpt-4","gpt-3.5-turbo"],
  },
  anthropic: {
    id: "anthropic", name: "Claude (Anthropic)", icon: "⬡", color: "#d97706",
    description: "Claude Sonnet 4 & Opus. Excellent for security analysis and nuanced reasoning.",
    fields: [
      { key: "apiKey", label: "API Key", placeholder: "sk-ant-...",                type: "password" },
      { key: "model",  label: "Model",   placeholder: "claude-sonnet-4-6",         type: "text"     },
    ],
    apiKeyRequired: true, badge: "CLOUD",
    models: ["claude-opus-4-6","claude-sonnet-4-6","claude-haiku-4-5-20251001"],
  },
  gemini: {
    id: "gemini", name: "Google Gemini", icon: "✦", color: "#4285f4",
    description: "Gemini 1.5 Pro & Flash. Large context, strong multimodal.",
    fields: [
      { key: "apiKey", label: "API Key", placeholder: "AIza...",          type: "password" },
      { key: "model",  label: "Model",   placeholder: "gemini-1.5-pro",   type: "text"     },
    ],
    apiKeyRequired: true, badge: "CLOUD",
    models: ["gemini-1.5-pro","gemini-1.5-flash","gemini-pro"],
  },
  deepseek: {
    id: "deepseek", name: "DeepSeek", icon: "🔭", color: "#06b6d4",
    description: "DeepSeek R1 & V3. High performance, cost-effective, strong at code.",
    fields: [
      { key: "apiKey", label: "API Key", placeholder: "sk-...",        type: "password" },
      { key: "model",  label: "Model",   placeholder: "deepseek-chat", type: "text"     },
    ],
    apiKeyRequired: true, badge: "CLOUD",
    models: ["deepseek-chat","deepseek-reasoner"],
  },
};

// ── Default AI Prompts ─────────────────────────────────────────────────────────
export const DEFAULT_PROMPTS = {
  system: `You are CyCentra AI, an expert security analyst assistant embedded in the CyCentra 360 Attack Surface Management platform. You have access to real-time scan data, vulnerability findings, asset information and security context.

Your role:
- Analyse attack surface findings and prioritise risks clearly
- Explain vulnerabilities in plain language with actionable remediation steps
- Correlate findings across assets to identify patterns and systemic risks
- Generate executive-ready summaries and technical deep-dives as needed
- Always cite specific assets, CVEs or findings when making recommendations

Tone: Professional, direct and concise. Avoid unnecessary caveats. Lead with the most important information.`,

  asm_context: `When analysing ASM scan results, structure your response as:
1. CRITICAL ACTIONS (must fix immediately)
2. HIGH PRIORITY (fix within 7 days)
3. MEDIUM TERM (fix within 30 days)
4. OBSERVATIONS (informational)

Always include specific asset hostnames and estimated remediation effort.`,

  vuln_analysis: `When explaining a vulnerability:
1. What it is (1 sentence, plain language)
2. Why it matters for this specific asset
3. Step-by-step remediation
4. Verification steps after fixing`,
};

// ── JSON Adapter ───────────────────────────────────────────────────────────────
function adaptCyCentraJSON(raw) {
  if (!raw?.assets) return null;
  const sevMap = { Critical:"critical", High:"high", Medium:"medium", Low:"low", Informational:"low" };
  const allAssets = [];

  raw.assets.forEach(a => {
    const vulns = a.vulnerabilities || [];
    const topSev = vulns.reduce((acc, v) => {
      const order = { critical:0, high:1, medium:2, low:3 };
      const mapped = sevMap[v.severity] || "low";
      return order[mapped] < order[acc] ? mapped : acc;
    }, "low");

    const ports      = a.raw_results?.web?.results?.ports || [];
    const certInfo   = a.raw_results?.crypto?.results?.ssl?.cert_info || a.raw_results?.web?.results?.ssl?.cert_info || null;
    const certExpiry = certInfo?.days_to_expiry != null ? (() => {
      const d = new Date(); d.setDate(d.getDate() + certInfo.days_to_expiry);
      return d.toISOString().split("T")[0];
    })() : null;

    const cySiemAlerts = vulns.filter(v => v.severity==="Critical"||v.severity==="High")
      .map((v,i) => ({ rule_id:`CC-${100000+i}`, level: v.severity==="Critical"?12:8,
        description: v.vulnerability, asset: a.host,
        ts: raw.meta?.last_scan || new Date().toISOString(), module: v.module }));

    const subRaw = a.raw_results?.subdomains?.results || [];
    const subdomains = [...new Set(subRaw.flatMap(s =>
      typeof s==="string" ? s.split("\n").map(d=>d.trim()).filter(Boolean) : []))];

    // ── Email security data ──
    const emailSec = a.raw_results?.email_sec?.results || null;
    // ── Cloud / infra data — task key in cycentra_scan.py is "cloud" not "cloud_infra"
    const cloudData = a.raw_results?.cloud?.results || null;
    // ── Supply chain data ──
    const supplyChain = a.raw_results?.supply_chain?.results || null;
    // ── Dark web / brand ──
    const darkWeb = a.raw_results?.dark_web?.results || null;
    // No "brand" module — typosquat data lives in dns.results.typos (populated separately below)
    const brandData = a.raw_results?.dns?.results?.typos || null;

    allAssets.push({
      id: a.id, host: a.host,
      ip: a.raw_results?.dns?.results?.ips?.[0]?.ip || "—",
      type: (() => {
        const b = a.raw_results?.web?.results?.fingerprints?.["80"]?.banner || "";
        if (b.includes("LiteSpeed")) return "Web Server (LiteSpeed)";
        if (b.includes("nginx"))     return "Web Server (Nginx)";
        if (b.includes("Apache"))    return "Web Server (Apache)";
        return "Web Asset";
      })(),
      ports, risk: topSev, risk_score: a.risk_score || 0,
      cves: vulns.map(v=>v.vulnerability), vulnerabilities: vulns,
      cert_expiry: certExpiry, cert_days: certInfo?.days_to_expiry??null,
      owner: raw.meta?.org||"Unknown", status:"open",
      first_seen: raw.meta?.last_scan?.split("T")[0]||"—",
      last_seen:  raw.meta?.last_scan?.split("T")[0]||"—",
      tags: ["external","primary"], subdomains,
      exposed_paths: a.raw_results?.web?.results?.exposed_paths || [],
      email_sec: emailSec, cloud_data: cloudData,
      supply_chain: supplyChain, dark_web: darkWeb, brand_data: brandData,
      dns_raw: a.raw_results?.dns?.results || null,
      registrar: a.raw_results?.whois?.results?.whois?.registrar || null,
      summary: a.summary, cySiemAlerts,
    });

    subdomains.forEach((sub,i) => {
      if (sub===a.host) return;
      allAssets.push({ id:`${a.id}-sub-${i}`, host:sub, ip:"—", type:"Subdomain",
        ports:[], risk:"low", risk_score:2, cves:[], vulnerabilities:[], cert_expiry:null, cert_days:null,
        owner:raw.meta?.org||"Unknown", status:"open",
        first_seen:raw.meta?.last_scan?.split("T")[0]||"—", last_seen:raw.meta?.last_scan?.split("T")[0]||"—",
        tags:["external","subdomain"], subdomains:[], exposed_paths:[],
        summary:`Subdomain of ${a.host}`, cySiemAlerts:[] });
    });

    (a.raw_results?.dns?.results?.ips || []).forEach((ipObj,i) => {
      if (i===0) return;
      allAssets.push({ id:`${a.id}-ip-${i}`, host:ipObj.ip, ip:ipObj.ip, type:`IP (${ipObj.org||"Unknown"})`,
        ports:[], risk:"low", risk_score:1, cves:[], vulnerabilities:[], cert_expiry:null, cert_days:null,
        owner:ipObj.org||raw.meta?.org||"Unknown", status:"open",
        first_seen:raw.meta?.last_scan?.split("T")[0]||"—", last_seen:raw.meta?.last_scan?.split("T")[0]||"—",
        tags:["external","ip"], subdomains:[], exposed_paths:[],
        summary:`IP address: ${ipObj.ip} (${ipObj.country||"?"})`, cySiemAlerts:[] });
    });

    (a.raw_results?.dns?.results?.typos?.registered || []).forEach((typo,i) => {
      allAssets.push({ id:`${a.id}-typo-${i}`, host:typo, ip:"—", type:"Typosquat (Registered)",
        ports:[], risk:"high", risk_score:7, cves:[],
        vulnerabilities:[{ vulnerability:"Registered Typosquat Domain", severity:"High", risk_score:7,
          description:`${typo} is registered and could be used for phishing or brand abuse.`,
          recommendation:"Investigate ownership. If malicious, file abuse report or acquire the domain.", module:"DNS" }],
        cert_expiry:null, cert_days:null, owner:"Unknown (3rd party)", status:"open",
        first_seen:raw.meta?.last_scan?.split("T")[0]||"—", last_seen:raw.meta?.last_scan?.split("T")[0]||"—",
        tags:["external","typosquat"], subdomains:[], exposed_paths:[],
        summary:`Typosquat domain registered: ${typo}`, cySiemAlerts:[] });
    });
  });

  return { meta: raw.meta, assets: allAssets, cysiemAlerts: allAssets.flatMap(a=>a.cySiemAlerts) };
}

// ── Utility helpers ───────────────────────────────────────────────────────────
function daysUntil(dateStr) {
  if (!dateStr) return null;
  return Math.ceil((new Date(dateStr) - new Date()) / 86400000);
}
function formatDate(dateStr) {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", { month:"short", day:"numeric", year:"numeric" });
}
// ════════════════════════════════════════════════════════════════════════════
// MODULE 02 — SHARED UI PRIMITIVES
// Badge, StatCard, AnimCounter, RiskDonut, CertTimeline, AssetModal, ImportModal
// ════════════════════════════════════════════════════════════════════════════

// ── Animated Counter ──────────────────────────────────────────────────────────
function AnimCounter({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = Math.max(1, Math.ceil(value / (duration / 16)));
    const timer = setInterval(() => {
      start += step;
      if (start >= value) { setDisplay(value); clearInterval(timer); }
      else setDisplay(start);
    }, 16);
    return () => clearInterval(timer);
  }, [value]);
  return <>{display}</>;
}

// ── Risk Badge ────────────────────────────────────────────────────────────────
function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return (
    <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`,
      fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace",
      padding: "2px 8px", borderRadius: "2px", whiteSpace:"nowrap" }}>{cfg.label}</span>
  );
}

// ── Status Badge ──────────────────────────────────────────────────────────────
function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.open;
  return (
    <span style={{ color: cfg.color, fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px",
      fontFamily: "monospace", display: "flex", alignItems: "center", gap: 5 }}>
      <span style={{ width:6, height:6, borderRadius:"50%", background:cfg.color, display:"inline-block",
        boxShadow:`0 0 6px ${cfg.color}` }} />
      {cfg.label}
    </span>
  );
}

// ── Stat Card ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, accent, sub, onClick }) {
  return (
    <div onClick={onClick}
      style={{ background: "rgba(255,255,255,0.03)", border:`1px solid rgba(255,255,255,0.07)`,
        borderTop:`2px solid ${accent}`, padding:"18px 22px", borderRadius:"4px", flex:1, minWidth:130,
        cursor: onClick ? "pointer" : "default" }}>
      <div style={{ color:accent, fontSize:30, fontWeight:800, fontFamily:"'Space Mono',monospace", lineHeight:1 }}>
        <AnimCounter value={value} />
      </div>
      <div style={{ color:"rgba(255,255,255,0.45)", fontSize:10, letterSpacing:"1.5px", marginTop:5, textTransform:"uppercase" }}>{label}</div>
      {sub && <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, marginTop:2 }}>{sub}</div>}
    </div>
  );
}

// ── Risk Donut — counts VULNERABILITIES by severity (not assets) ──────────────
function RiskDonut({ assets, onSevClick }) {
  const counts = { critical:0, high:0, medium:0, low:0 };
  assets.forEach(a => {
    (a.vulnerabilities||[]).forEach(v => {
      const sev = v.severity?.toLowerCase();
      if (counts[sev]!==undefined) counts[sev]++;
    });
  });
  const total = Object.values(counts).reduce((a,b)=>a+b,0) || 1;
  const colors = ["#ff3b3b","#ff8c00","#f5c518","#00e5a0"];
  const keys   = ["critical","high","medium","low"];
  let cumulative = 0;
  const segments = keys.map((k,i) => {
    const pct = counts[k] / total;
    const startAngle = cumulative * 360;
    const endAngle   = (cumulative+pct)*360;
    cumulative += pct;
    const r=60, cx=80, cy=80;
    const toRad = deg => (deg-90)*Math.PI/180;
    const x1=cx+r*Math.cos(toRad(startAngle)); const y1=cy+r*Math.sin(toRad(startAngle));
    const x2=cx+r*Math.cos(toRad(endAngle));   const y2=cy+r*Math.sin(toRad(endAngle));
    const largeArc = pct>0.5?1:0;
    const d = pct===0 ? "" : `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2} Z`;
    return { d, color:colors[i], key:k, count:counts[k] };
  });
  const totalVulns = Object.values(counts).reduce((a,b)=>a+b,0);

  return (
    <div style={{ display:"flex", alignItems:"center", gap:20 }}>
      <svg width="160" height="160" style={{ flexShrink:0, cursor: onSevClick?"pointer":"default" }}
        onClick={onSevClick}>
        {segments.map(s => s.d && <path key={s.key} d={s.d} fill={s.color} opacity={0.85}/>)}
        <circle cx="80" cy="80" r="38" fill="#0d0f14"/>
        <text x="80" y="76" textAnchor="middle" fill="white" fontSize="18" fontWeight="800" fontFamily="monospace">{totalVulns}</text>
        <text x="80" y="90" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="8" letterSpacing="1" fontFamily="monospace">VULNS</text>
      </svg>
      <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
        {segments.map(s => (
          <div key={s.key} onClick={()=>onSevClick?.(s.key)}
            style={{ display:"flex", alignItems:"center", gap:8, cursor:onSevClick?"pointer":"default",
              padding:"2px 4px", borderRadius:3, transition:"background 0.15s" }}
            onMouseEnter={e=>onSevClick&&(e.currentTarget.style.background="rgba(255,255,255,0.04)")}
            onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
            <span style={{ width:9, height:9, borderRadius:2, background:s.color, display:"inline-block", flexShrink:0 }}/>
            <span style={{ color:"rgba(255,255,255,0.55)", fontSize:10, textTransform:"uppercase", letterSpacing:1, fontFamily:"monospace", width:65 }}>{s.key}</span>
            <span style={{ color:s.color, fontSize:13, fontWeight:700, fontFamily:"monospace" }}>{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Cert Expiry Timeline — top 7 ──────────────────────────────────────────────
function CertTimeline({ assets, onViewAll }) {
  const withCerts = assets.filter(a => a.cert_expiry||a.cert_days!=null)
    .map(a => ({ ...a, days: a.cert_days ?? daysUntil(a.cert_expiry) }))
    .sort((x,y) => (x.days??999)-(y.days??999));
  const shown = withCerts.slice(0,7);
  const rest  = withCerts.length - shown.length;

  if (!withCerts.length) return (
    <div style={{ color:"rgba(255,255,255,0.3)", fontSize:12, fontFamily:"monospace" }}>No certificate data</div>
  );

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {shown.map(a => {
        const days  = a.days ?? 0;
        const color = days<0 ? "#ff3b3b" : days<30 ? "#ff3b3b" : days<90 ? "#ff8c00" : "#00e5a0";
        const label = days<0 ? "EXPIRED" : days<30 ? "CRITICAL" : days<90 ? "WARNING" : "OK";
        const pct   = Math.min(100, Math.max(2, (Math.max(0,days)/365)*100));
        return (
          <div key={a.id}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:3 }}>
              <span style={{ color:"rgba(255,255,255,0.65)", fontSize:10, fontFamily:"monospace", maxWidth:130, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{a.host}</span>
              <div style={{ display:"flex", gap:6, alignItems:"center" }}>
                <span style={{ color, fontSize:9, fontFamily:"monospace", fontWeight:700 }}>{label}</span>
                <span style={{ color, fontSize:10, fontFamily:"monospace" }}>{days<0?"EXPIRED":`${days}d`}</span>
              </div>
            </div>
            <div style={{ height:3, background:"rgba(255,255,255,0.07)", borderRadius:2 }}>
              <div style={{ height:"100%", width:`${pct}%`, background:color, borderRadius:2, boxShadow:`0 0 4px ${color}60`, transition:"width 1s ease" }}/>
            </div>
          </div>
        );
      })}
      {rest>0 && onViewAll && (
        <button onClick={onViewAll} style={{ background:"none", border:"none", color:"rgba(0,229,160,0.6)",
          fontSize:10, fontFamily:"monospace", cursor:"pointer", textAlign:"left", padding:"2px 0" }}>
          + {rest} more certificate{rest>1?"s":""} → View all
        </button>
      )}
    </div>
  );
}

// ── Cert Modal — full list ────────────────────────────────────────────────────
function CertModal({ assets, onClose }) {
  const withCerts = assets.filter(a => a.cert_expiry||a.cert_days!=null)
    .map(a => ({ ...a, days: a.cert_days ?? daysUntil(a.cert_expiry) }))
    .sort((x,y) => (x.days??999)-(y.days??999));

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.85)", display:"flex",
      alignItems:"center", justifyContent:"center", zIndex:200, backdropFilter:"blur(4px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:"1px solid rgba(0,229,160,0.2)", borderTop:"2px solid #00e5a0",
        borderRadius:6, padding:28, width:"min(600px,95vw)", maxHeight:"80vh", display:"flex", flexDirection:"column" }}
        onClick={e=>e.stopPropagation()}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:20 }}>
          <span style={{ color:"white", fontFamily:"monospace", fontSize:14, fontWeight:700 }}>
            SSL CERTIFICATE STATUS <span style={{ color:"#00e5a0" }}>({withCerts.length})</span>
          </span>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:20 }}>×</button>
        </div>
        <div style={{ overflowY:"auto", display:"flex", flexDirection:"column", gap:8 }}>
          {withCerts.map(a => {
            const days  = a.days ?? 0;
            const color = days<0?"#ff3b3b":days<30?"#ff3b3b":days<90?"#ff8c00":"#00e5a0";
            const label = days<0?"EXPIRED":days<30?"CRITICAL":days<90?"WARNING":"OK";
            const pct   = Math.min(100, Math.max(2, (Math.max(0,days)/365)*100));
            return (
              <div key={a.id} style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:3, padding:"12px 16px" }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                  <span style={{ color:"rgba(255,255,255,0.8)", fontSize:12, fontFamily:"monospace" }}>{a.host}</span>
                  <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                    <span style={{ background:`${color}20`, color, border:`1px solid ${color}40`, fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, fontWeight:700 }}>{label}</span>
                    <span style={{ color, fontSize:11, fontFamily:"monospace", fontWeight:700 }}>{days<0?"EXPIRED":`${days}d`}</span>
                  </div>
                </div>
                <div style={{ height:3, background:"rgba(255,255,255,0.07)", borderRadius:2 }}>
                  <div style={{ height:"100%", width:`${pct}%`, background:color, borderRadius:2, boxShadow:`0 0 4px ${color}60` }}/>
                </div>
                <div style={{ display:"flex", justifyContent:"space-between", marginTop:6 }}>
                  <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>{a.type}</span>
                  {a.cert_expiry && <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>Expires {formatDate(a.cert_expiry)}</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── CySIEM Alert Feed ─────────────────────────────────────────────────────────
function CySIEMFeed({ alerts }) {
  if (!alerts?.length) return (
    <div style={{ color:"rgba(255,255,255,0.3)", fontSize:12, fontFamily:"monospace" }}>No alerts forwarded</div>
  );
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {alerts.map((a,i) => {
        const lvlColor = a.level>=12?"#ff3b3b":a.level>=8?"#ff8c00":"#f5c518";
        return (
          <div key={i} style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)",
            borderLeft:`3px solid ${lvlColor}`, padding:"10px 14px", borderRadius:"2px" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:4 }}>
              <span style={{ color:lvlColor, fontSize:10, fontFamily:"monospace", fontWeight:700 }}>
                LEVEL {a.level} · {a.rule_id}
              </span>
              <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>
                {new Date(a.ts).toLocaleTimeString()}
              </span>
            </div>
            <div style={{ color:"rgba(255,255,255,0.8)", fontSize:12 }}>{a.description}</div>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:4 }}>→ {a.asset}</div>
          </div>
        );
      })}
    </div>
  );
}

// ── Asset Detail Modal ────────────────────────────────────────────────────────
function AssetModal({ asset, onClose, onStatusChange }) {
  if (!asset) return null;
  const cfg  = RISK_CONFIG[asset.risk] || RISK_CONFIG.low;
  const days = asset.cert_days ?? daysUntil(asset.cert_expiry);

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.85)", display:"flex",
      alignItems:"center", justifyContent:"center", zIndex:100, backdropFilter:"blur(4px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:`1px solid ${cfg.color}40`,
        borderTop:`2px solid ${cfg.color}`, borderRadius:6, padding:32,
        width:"min(680px,95vw)", maxHeight:"88vh", overflowY:"auto",
        boxShadow:`0 0 60px ${cfg.color}20` }} onClick={e=>e.stopPropagation()}>

        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div>
            <div style={{ color:"white", fontSize:18, fontWeight:700, fontFamily:"'Space Mono',monospace" }}>{asset.host}</div>
            <div style={{ color:"rgba(255,255,255,0.4)", fontSize:12, fontFamily:"monospace", marginTop:4 }}>{asset.ip} · {asset.type}</div>
            {asset.summary && <div style={{ color:"rgba(255,255,255,0.3)", fontSize:11, marginTop:6, maxWidth:500 }}>{asset.summary}</div>}
          </div>
          <div style={{ display:"flex", gap:10, alignItems:"center" }}>
            <Badge risk={asset.risk}/>
            <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:20 }}>×</button>
          </div>
        </div>

        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:20 }}>
          {[
            ["Owner / Org",  asset.owner],
            ["Status",       <StatusBadge status={asset.status}/>],
            ["Registrar",    asset.registrar||"—"],
            ["Last Seen",    formatDate(asset.last_seen)],
            ["Cert Expiry",  days!=null?`${days}d remaining`:"N/A"],
            ["Risk Score",   <span style={{color:cfg.color,fontWeight:700}}>{asset.risk_score}/10</span>],
          ].map(([k,v]) => (
            <div key={k} style={{ background:"rgba(255,255,255,0.03)", padding:"12px 14px", borderRadius:3 }}>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1px", textTransform:"uppercase", marginBottom:4, fontFamily:"monospace" }}>{k}</div>
              <div style={{ color:"rgba(255,255,255,0.8)", fontSize:13, fontFamily:"monospace" }}>{v}</div>
            </div>
          ))}
        </div>

        {asset.ports?.length>0 && (
          <div style={{ marginBottom:16 }}>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1px", textTransform:"uppercase", marginBottom:8, fontFamily:"monospace" }}>Exposed Ports</div>
            <div style={{ display:"flex", gap:6, flexWrap:"wrap" }}>
              {asset.ports.map(p => (
                <span key={p} style={{ background:"rgba(255,255,255,0.06)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.2)", padding:"3px 10px", borderRadius:2, fontSize:12, fontFamily:"monospace" }}>:{p}</span>
              ))}
            </div>
          </div>
        )}

        {asset.subdomains?.length>0 && (
          <div style={{ marginBottom:16 }}>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1px", textTransform:"uppercase", marginBottom:8, fontFamily:"monospace" }}>Subdomains ({asset.subdomains.length})</div>
            <div style={{ display:"flex", gap:6, flexWrap:"wrap", maxHeight:80, overflowY:"auto" }}>
              {asset.subdomains.map(s => (
                <span key={s} style={{ background:"rgba(0,229,160,0.06)", color:"rgba(0,229,160,0.7)", border:"1px solid rgba(0,229,160,0.15)", padding:"2px 8px", borderRadius:2, fontSize:10, fontFamily:"monospace" }}>{s}</span>
              ))}
            </div>
          </div>
        )}

        {asset.vulnerabilities?.length>0 && (
          <div style={{ marginBottom:20 }}>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1px", textTransform:"uppercase", marginBottom:10, fontFamily:"monospace" }}>Vulnerabilities ({asset.vulnerabilities.length})</div>
            <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
              {asset.vulnerabilities.map((v,i) => {
                const vc = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.low;
                return (
                  <div key={i} style={{ background:"rgba(255,255,255,0.02)", border:`1px solid ${vc.color}20`, borderLeft:`3px solid ${vc.color}`, padding:"10px 14px", borderRadius:2 }}>
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
                      <span style={{ color:"white", fontSize:12, fontWeight:600 }}>{v.vulnerability}</span>
                      <Badge risk={v.severity?.toLowerCase()}/>
                    </div>
                    <div style={{ color:"rgba(255,255,255,0.5)", fontSize:11, marginBottom:6 }}>{v.description}</div>
                    <div style={{ color:"#00e5a0", fontSize:11 }}>✓ {v.recommendation}</div>
                    {v.module && <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace", marginTop:4 }}>Module: {v.module}</div>}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {asset.exposed_paths?.length>0 && (
          <div style={{ marginBottom:20 }}>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1px", textTransform:"uppercase", marginBottom:8, fontFamily:"monospace" }}>Exposed Paths ({asset.exposed_paths.length})</div>
            <div style={{ maxHeight:100, overflowY:"auto", display:"flex", flexDirection:"column", gap:4 }}>
              {asset.exposed_paths.slice(0,10).map((p,i) => (
                <div key={i} style={{ display:"flex", gap:10, alignItems:"center" }}>
                  <Badge risk={p.severity?.toLowerCase()||"medium"}/><span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, fontFamily:"monospace" }}>{p.path}</span>
                </div>
              ))}
              {asset.exposed_paths.length>10 && <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace" }}>+{asset.exposed_paths.length-10} more paths</div>}
            </div>
          </div>
        )}

        <div>
          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1px", textTransform:"uppercase", marginBottom:10, fontFamily:"monospace" }}>Update Status</div>
          <div style={{ display:"flex", gap:8 }}>
            {["open","in-review","resolved"].map(s => (
              <button key={s} onClick={() => { onStatusChange(asset.id,s); onClose(); }}
                style={{ padding:"8px 16px", borderRadius:3, border:`1px solid ${STATUS_CONFIG[s].color}40`,
                  background: asset.status===s?`${STATUS_CONFIG[s].color}20`:"transparent",
                  color: STATUS_CONFIG[s].color, fontFamily:"monospace", fontSize:11,
                  letterSpacing:"1px", cursor:"pointer", textTransform:"uppercase",
                  fontWeight: asset.status===s?700:400 }}>{s}</button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Import Modal ──────────────────────────────────────────────────────────────
function ImportModal({ onClose, onImport }) {
  const [text, setText] = useState("");
  const [err,  setErr]  = useState("");
  const handle = () => {
    try { onImport(JSON.parse(text)); onClose(); }
    catch(e) { setErr("Invalid JSON: " + e.message); }
  };
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.85)", display:"flex",
      alignItems:"center", justifyContent:"center", zIndex:100, backdropFilter:"blur(4px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:"1px solid rgba(0,229,160,0.2)", borderTop:"2px solid #00e5a0",
        borderRadius:6, padding:32, width:"min(560px,95vw)" }} onClick={e=>e.stopPropagation()}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
          <span style={{ color:"white", fontFamily:"monospace", fontSize:14, fontWeight:700 }}>IMPORT SCAN JSON</span>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:20 }}>×</button>
        </div>
        <div style={{ color:"rgba(255,255,255,0.4)", fontSize:11, marginBottom:12 }}>
          Paste output from <code style={{ color:"#00e5a0" }}>cycentra_scan.py</code>
        </div>
        <textarea value={text} onChange={e=>{setText(e.target.value);setErr("");}}
          placeholder="Paste your CyCentra scan JSON here..."
          style={{ width:"100%", height:220, background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.1)",
            color:"#00e5a0", fontFamily:"monospace", fontSize:12, padding:14, borderRadius:3,
            outline:"none", resize:"vertical", boxSizing:"border-box" }}/>
        {err && <div style={{ color:"#ff3b3b", fontSize:11, fontFamily:"monospace", marginTop:8 }}>{err}</div>}
        <div style={{ display:"flex", gap:10, marginTop:16 }}>
          <button onClick={handle}
            style={{ background:"#00e5a0", color:"#0d0f14", fontFamily:"monospace", fontWeight:700,
              fontSize:12, letterSpacing:"1px", padding:"10px 24px", border:"none", borderRadius:3, cursor:"pointer", textTransform:"uppercase" }}>
            Import & Apply
          </button>
          <button onClick={onClose}
            style={{ background:"transparent", color:"rgba(255,255,255,0.4)", fontFamily:"monospace",
              fontSize:12, padding:"10px 20px", border:"1px solid rgba(255,255,255,0.1)", borderRadius:3, cursor:"pointer" }}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
// ════════════════════════════════════════════════════════════════════════════
// MODULE 03 — DASHBOARD (8 ASM WIDGETS) + USE CASES MARKETPLACE
// ════════════════════════════════════════════════════════════════════════════

// ── Use Cases data ────────────────────────────────────────────────────────────
const USE_CASES = [
  {
    id: "phishing-response",
    title: "Phishing Response",
    icon: "🎣",
    color: "#ff3b3b",
    category: "Incident Response",
    description: "Auto-triage phishing emails. Extract IOCs, create a CyIRIS case, block sender domain in CySIEM, and notify the SOC team — all in under 60 seconds.",
    steps: ["Email received → CySOAR webhook trigger","Extract headers, links, attachments","VirusTotal/URLScan enrichment","Auto-create CyIRIS case","Block domain in CySIEM active response","Alert SOC via Slack/Teams"],
    modules: ["CySOAR","CyIRIS","CySIEM"],
    difficulty: "Beginner", time: "~45 min to deploy",
    cysoarFlow: "phishing_response.py",
  },
  {
    id: "block-ip",
    title: "Block IP",
    icon: "🚫",
    color: "#ff8c00",
    category: "Active Response",
    description: "Instantly block a malicious IP across all agents via CySIEM active response. Triggered by alert level, CyIRIS case or manual override from the portal.",
    steps: ["Trigger: alert level ≥12 OR manual from portal","Resolve IP reputation via AbuseIPDB","Push block to all CySIEM agents","Log action to CyIRIS case","Schedule unblock review in 24h"],
    modules: ["CySOAR","CySIEM","CyIRIS"],
    difficulty: "Beginner", time: "~30 min to deploy",
    cysoarFlow: "block_ip.py",
  },
  {
    id: "block-country",
    title: "Block Country",
    icon: "🌍",
    color: "#f5c518",
    category: "Network Policy",
    description: "Geo-block a country across all CySIEM agents using IPset rules. Useful for compliance, incident containment or reducing attack surface from high-risk regions.",
    steps: ["Input: country code (e.g. RU, CN, KP)","Fetch CIDR ranges from ip-ranges.io","Generate IPset rule file","Push via CySIEM active response to all agents","Create audit trail in CyIRIS","Notify team"],
    modules: ["CySOAR","CySIEM"],
    difficulty: "Intermediate", time: "~1 hour to deploy",
    cysoarFlow: "block_country.py",
  },
  {
    id: "brute-force-defense",
    title: "Brute-Force Defense",
    icon: "🛡️",
    color: "#b06eff",
    category: "Active Response",
    description: "Auto-detect and neutralise SSH/RDP/web brute-force attacks. Triggered by CySIEM rule 5712/5763, auto-blocks the source IP and logs to CyIRIS.",
    steps: ["CySIEM detects brute-force (rule 5712/5763+)","Webhook fires to CySOAR","Rate-limit check (avoid blocking scan tools)","Block source IP via active response","Create/update CyIRIS case","Re-evaluate block after 1h cooldown"],
    modules: ["CySOAR","CySIEM","CyIRIS"],
    difficulty: "Beginner", time: "~20 min to deploy",
    cysoarFlow: "brute_force_defense.py",
  },
  {
    id: "drift-correction",
    title: "Drift Correction",
    icon: "⚖️",
    color: "#4d9eff",
    category: "Compliance",
    description: "Detect configuration drift on monitored hosts. When CySIEM FIM detects an unexpected change, CySOAR validates against the golden config and reverts or alerts.",
    steps: ["CySIEM FIM alert fires","CySOAR fetches changed file/config","Compare against git golden baseline","If minor: auto-revert and log","If major: create P1 CyIRIS case + page on-call","Generate drift report"],
    modules: ["CySOAR","CySIEM","CyIRIS"],
    difficulty: "Advanced", time: "~2 hours to deploy",
    cysoarFlow: "drift_correction.py",
  },
  {
    id: "zombie-killer",
    title: "Zombie Killer",
    icon: "🧟",
    color: "#00e5a0",
    category: "Process Hygiene",
    description: "Process reaper that hunts and kills zombie/orphan processes and rogue binaries detected by CySIEM. Useful for crypto-miner containment and malware cleanup.",
    steps: ["CySIEM detects suspicious process (rule group: malware)","CySOAR queries process details via CySIEM API","Validate against allow-list","Kill process via active response","Quarantine binary","Create forensic case in CyIRIS"],
    modules: ["CySOAR","CySIEM","CyIRIS"],
    difficulty: "Intermediate", time: "~45 min to deploy",
    cysoarFlow: "zombie_killer.py",
  },
  {
    id: "asm-report",
    title: "ASM Report Generation",
    icon: "📊",
    color: "#10a37f",
    category: "Reporting",
    description: "Scheduled weekly ASM report. Runs cycentra_scan.py, enriches findings with AI analysis, generates an executive PDF, and delivers it by email and CyIRIS case.",
    steps: ["Cron: every Monday 06:00","Run cycentra_scan.py for all tracked domains","AI enrichment via configured LLM","Generate PDF report","Email to stakeholders","Create weekly review case in CyIRIS"],
    modules: ["CySOAR","CyIRIS"],
    difficulty: "Intermediate", time: "~1 hour to deploy",
    cysoarFlow: "asm_report_generator.py",
  },
];

// ── Use Case Card ─────────────────────────────────────────────────────────────
function UseCaseCard({ uc, onExpand }) {
  const diffColor = { Beginner:"#00e5a0", Intermediate:"#f5c518", Advanced:"#ff8c00" }[uc.difficulty] || "#00e5a0";
  return (
    <div onClick={()=>onExpand(uc)}
      style={{ background:"rgba(255,255,255,0.02)", border:`1px solid rgba(255,255,255,0.07)`,
        borderTop:`2px solid ${uc.color}`, borderRadius:6, padding:"20px 22px", cursor:"pointer",
        transition:"all 0.2s" }}
      onMouseEnter={e=>{ e.currentTarget.style.background="rgba(255,255,255,0.04)"; e.currentTarget.style.borderColor=`${uc.color}50`; }}
      onMouseLeave={e=>{ e.currentTarget.style.background="rgba(255,255,255,0.02)"; e.currentTarget.style.borderColor="rgba(255,255,255,0.07)"; }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:12 }}>
        <span style={{ fontSize:28 }}>{uc.icon}</span>
        <span style={{ background:`${diffColor}18`, color:diffColor, border:`1px solid ${diffColor}30`,
          fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, fontWeight:700, letterSpacing:"1px" }}>
          {uc.difficulty.toUpperCase()}
        </span>
      </div>
      <div style={{ color:"white", fontSize:15, fontWeight:700, marginBottom:6 }}>{uc.title}</div>
      <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", letterSpacing:"1px", textTransform:"uppercase", marginBottom:10 }}>{uc.category}</div>
      <div style={{ color:"rgba(255,255,255,0.55)", fontSize:12, lineHeight:1.6, marginBottom:14 }}>{uc.description}</div>
      <div style={{ display:"flex", flexWrap:"wrap", gap:5, marginBottom:14 }}>
        {uc.modules.map(m => (
          <span key={m} style={{ background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.5)",
            border:"1px solid rgba(255,255,255,0.1)", fontSize:9, fontFamily:"monospace",
            padding:"2px 8px", borderRadius:2 }}>{m}</span>
        ))}
      </div>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <span style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace" }}>{uc.time}</span>
        <span style={{ color:uc.color, fontSize:11, fontFamily:"monospace" }}>View details →</span>
      </div>
    </div>
  );
}

// ── Use Case Detail Modal ─────────────────────────────────────────────────────
function UseCaseModal({ uc, onClose }) {
  if (!uc) return null;
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.88)", display:"flex",
      alignItems:"center", justifyContent:"center", zIndex:150, backdropFilter:"blur(6px)" }} onClick={onClose}>
      <div style={{ background:"#0d0f14", border:`1px solid ${uc.color}40`, borderTop:`2px solid ${uc.color}`,
        borderRadius:8, padding:36, width:"min(640px,95vw)", maxHeight:"85vh", overflowY:"auto",
        boxShadow:`0 0 80px ${uc.color}15` }} onClick={e=>e.stopPropagation()}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:24 }}>
          <div style={{ display:"flex", alignItems:"center", gap:14 }}>
            <span style={{ fontSize:36 }}>{uc.icon}</span>
            <div>
              <div style={{ color:"white", fontSize:20, fontWeight:700 }}>{uc.title}</div>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace", marginTop:3 }}>{uc.category} · {uc.time}</div>
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"rgba(255,255,255,0.4)", cursor:"pointer", fontSize:22 }}>×</button>
        </div>

        <div style={{ color:"rgba(255,255,255,0.6)", fontSize:13, lineHeight:1.7, marginBottom:24 }}>{uc.description}</div>

        <div style={{ marginBottom:24 }}>
          <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:12 }}>Automation Steps</div>
          {uc.steps.map((step,i) => (
            <div key={i} style={{ display:"flex", gap:12, alignItems:"flex-start", marginBottom:10 }}>
              <div style={{ width:22, height:22, borderRadius:"50%", background:`${uc.color}20`, border:`1px solid ${uc.color}40`,
                display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, marginTop:1 }}>
                <span style={{ color:uc.color, fontSize:10, fontWeight:700, fontFamily:"monospace" }}>{i+1}</span>
              </div>
              <span style={{ color:"rgba(255,255,255,0.65)", fontSize:13, lineHeight:1.5, paddingTop:2 }}>{step}</span>
            </div>
          ))}
        </div>

        <div style={{ display:"flex", gap:8, flexWrap:"wrap", marginBottom:24 }}>
          {uc.modules.map(m => (
            <span key={m} style={{ background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.6)",
              border:"1px solid rgba(255,255,255,0.12)", fontSize:11, fontFamily:"monospace",
              padding:"4px 12px", borderRadius:3 }}>Requires: {m}</span>
          ))}
        </div>

        <div style={{ background:"rgba(0,0,0,0.4)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:4, padding:"14px 18px", marginBottom:20 }}>
          <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", marginBottom:6 }}>CYSOAR FLOW</div>
          <code style={{ color:"#00e5a0", fontSize:12, fontFamily:"monospace" }}>
            cysoar import-flow {uc.cysoarFlow} --workspace cycentra
          </code>
        </div>

        <div style={{ display:"flex", gap:10 }}>
          <button onClick={onClose}
            style={{ flex:1, background:uc.color, color:"#0d0f14", border:"none", borderRadius:4,
              padding:"12px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:"pointer",
              letterSpacing:"1px", textTransform:"uppercase" }}>
            Download Template
          </button>
          <button onClick={onClose}
            style={{ padding:"12px 20px", background:"transparent", color:"rgba(255,255,255,0.4)",
              border:"1px solid rgba(255,255,255,0.12)", borderRadius:4, fontFamily:"monospace",
              fontSize:12, cursor:"pointer" }}>Close</button>
        </div>
      </div>
    </div>
  );
}

// ── Use Cases Page ────────────────────────────────────────────────────────────
function UseCasesPage() {
  const [expanded, setExpanded] = useState(null);
  const [catFilter, setCatFilter] = useState("all");
  const categories = ["all", ...new Set(USE_CASES.map(u=>u.category))];
  const filtered = catFilter==="all" ? USE_CASES : USE_CASES.filter(u=>u.category===catFilter);

  return (
    <div>
      <div style={{ marginBottom:28 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:8 }}>
          <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Use Case Marketplace</h1>
          <span style={{ background:"rgba(0,229,160,0.12)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)",
            fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px" }}>
            {USE_CASES.length} TEMPLATES
          </span>
        </div>
        <p style={{ color:"rgba(255,255,255,0.4)", fontSize:13 }}>
          Pre-built CySOAR automation playbooks. One-click deploy integrates CySOAR, CyIRIS and CySIEM into battle-tested response workflows.
        </p>
      </div>

      {/* Category filter */}
      <div style={{ display:"flex", gap:6, marginBottom:24, flexWrap:"wrap" }}>
        {categories.map(cat => (
          <button key={cat} onClick={()=>setCatFilter(cat)}
            style={{ background: catFilter===cat?"rgba(0,229,160,0.12)":"rgba(255,255,255,0.04)",
              color: catFilter===cat?"#00e5a0":"rgba(255,255,255,0.45)",
              border: `1px solid ${catFilter===cat?"rgba(0,229,160,0.3)":"rgba(255,255,255,0.08)"}`,
              borderRadius:20, padding:"6px 14px", fontSize:11, fontFamily:"monospace",
              cursor:"pointer", letterSpacing:"0.5px", textTransform:"capitalize" }}>
            {cat}
          </button>
        ))}
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(300px, 1fr))", gap:16 }}>
        {filtered.map(uc => <UseCaseCard key={uc.id} uc={uc} onExpand={setExpanded}/>)}
      </div>

      {/* CySOAR integration note */}
      <div style={{ marginTop:28, background:"rgba(77,158,255,0.04)", border:"1px solid rgba(77,158,255,0.15)",
        borderRadius:6, padding:"20px 24px" }}>
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
          <span style={{ fontSize:20 }}>⚡</span>
          <span style={{ color:"rgba(255,255,255,0.7)", fontSize:14, fontWeight:600 }}>CySOAR Integration</span>
        </div>
        <div style={{ color:"rgba(255,255,255,0.4)", fontSize:12, lineHeight:1.8 }}>
          All templates are CySOAR-native Python/TypeScript scripts with built-in secret management, retry logic and webhook endpoints.
          Deploy via <code style={{color:"#4d9eff"}}>cysoar CLI</code> or drag-and-drop into your CySOAR workspace.
          OIDC SSO means no separate login — your CyCentra 360 session carries through automatically.
        </div>
      </div>

      {expanded && <UseCaseModal uc={expanded} onClose={()=>setExpanded(null)}/>}
    </div>
  );
}

// ── 8-Widget ASM Dashboard ────────────────────────────────────────────────────
function ASMWidget({ title, children, accent="#00e5a0", onViewAll, badge }) {
  return (
    <div style={{ background:"rgba(255,255,255,0.025)", border:"1px solid rgba(255,255,255,0.07)",
      borderTop:`2px solid ${accent}`, borderRadius:5, padding:"18px 22px" }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
        <div style={{ color:"rgba(255,255,255,0.45)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace" }}>{title}</div>
        <div style={{ display:"flex", gap:8, alignItems:"center" }}>
          {badge!=null && <span style={{ background:`${accent}18`, color:accent, fontSize:10, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, fontWeight:700 }}>{badge}</span>}
          {onViewAll && <button onClick={onViewAll} style={{ background:"none", border:"none", color:accent, fontSize:10, fontFamily:"monospace", cursor:"pointer", opacity:0.7 }}>View All ↗</button>}
        </div>
      </div>
      {children}
    </div>
  );
}

// helper — email security sub-row
function ESecRow({ label, value, pass }) {
  const color = pass===null?"rgba(255,255,255,0.35)":pass?"#00e5a0":"#ff3b3b";
  const icon  = pass===null?"—":pass?"✓":"✗";
  return (
    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"6px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color:"rgba(255,255,255,0.5)", fontSize:12, fontFamily:"monospace" }}>{label}</span>
      <div style={{ display:"flex", gap:8, alignItems:"center" }}>
        <span style={{ color:"rgba(255,255,255,0.35)", fontSize:10, maxWidth:180, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{value||"—"}</span>
        <span style={{ color, fontWeight:700, fontSize:12 }}>{icon}</span>
      </div>
    </div>
  );
}

// widget data extractors from assets
function getEmailSecData(assets) {
  const primary = assets.find(a=>a.tags?.includes("primary") && a.email_sec);
  const e = primary?.email_sec;
  if (!e) return null;
  // Field names match email_security.py gather_email_security() actual JSON:
  //   spf:           { present, record, note }
  //   dkim:          [ { selector, record, valid } ]  ← array
  //   dmarc:         { present, record, policy, note }
  //   elite_checks:  { bimi: { status, record }, mta_sts: { status, mode, policy } }
  return {
    spf:    { value: e.spf?.record   || null, pass: e.spf?.present   ?? null },
    dkim:   { value: e.dkim?.[0]?.selector || null, pass: e.dkim?.[0]?.valid ?? null },
    dmarc:  { value: e.dmarc?.policy || null, pass: e.dmarc?.present ?? null },
    bimi:   { value: e.elite_checks?.bimi?.record    || null, pass: e.elite_checks?.bimi?.status    === "pass" },
    mta_sts:{ value: e.elite_checks?.mta_sts?.policy || null, pass: e.elite_checks?.mta_sts?.status === "pass" },
  };
}

function getWebSecStats(assets) {
  const allVulns = assets.flatMap(a=>(a.vulnerabilities||[]).filter(v=>v.module==="Web"||v.module==="Crypto"));
  const exposedPaths = assets.reduce((acc,a)=>acc+(a.exposed_paths?.length||0),0);
  return { vulns: allVulns.length, paths: exposedPaths };
}

function getInfraStats(assets) {
  const ips    = assets.filter(a=>a.type?.startsWith("IP")).length;
  const ports  = [...new Set(assets.flatMap(a=>a.ports||[]))].length;
  const cloud  = assets.filter(a=>a.cloud_data).length;
  return { ips, ports, cloud };
}

function getSupplyChainRisk(assets) {
  // supply_chain.py now returns results: { scripts, risks, count, high }
  // assets[].supply_chain is mapped from raw_results.supply_chain.results
  const primary = assets.find(a=>a.tags?.includes("primary"));
  const sc = primary?.supply_chain;
  if (!sc) return { count:0, high:0 };
  // New structured format
  if (sc.risks !== undefined) {
    return {
      count: sc.count  ?? sc.scripts?.length ?? 0,
      high:  sc.high   ?? sc.risks?.filter(r=>r.severity==="High"||r.severity==="Critical").length ?? 0,
    };
  }
  // Legacy flat array of script URL strings
  if (Array.isArray(sc)) return { count: sc.length, high: 0 };
  return { count:0, high:0 };
}

function getBrandData(assets) {
  const typos   = assets.filter(a=>a.type==="Typosquat (Registered)");
  // dark_web.py returns results: { ahmia:[...], hibp:[...], summary }
  const darkweb = assets.flatMap(a=>[
    ...(a.dark_web?.ahmia || []),
    ...(a.dark_web?.hibp  || []),
  ]);
  return { typos: typos.length, darkweb: darkweb.length };
}

function getSSLData(assets) {
  const withCerts = assets.filter(a=>a.cert_days!=null);
  const expired   = withCerts.filter(a=>a.cert_days<0).length;
  const critical  = withCerts.filter(a=>a.cert_days>=0&&a.cert_days<30).length;
  const tls10     = assets.filter(a=>(a.vulnerabilities||[]).some(v=>v.vulnerability?.includes("TLS 1.0")||v.vulnerability?.includes("TLS1.0"))).length;
  return { total: withCerts.length, expired, critical, weakTLS: tls10 };
}

function DashboardTab({ assets, data, stats, installedModules, setActiveTab, setSelectedAsset, setShowImport }) {
  const [showCertModal, setShowCertModal] = useState(false);

  const critHighVulns = assets.flatMap(a =>
    (a.vulnerabilities||[]).filter(v=>v.severity==="Critical"||v.severity==="High")
      .map(v=>({...v, asset:a.host, assetId:a.id, assetObj:a}))
  ).sort((a,b)=>(a.severity==="Critical"?0:1)-(b.severity==="Critical"?0:1));

  const emailSec  = getEmailSecData(assets);
  const webSec    = getWebSecStats(assets);
  const infra     = getInfraStats(assets);
  const supply    = getSupplyChainRisk(assets);
  const brand     = getBrandData(assets);
  const sslData   = getSSLData(assets);
  const installedAddons = Object.entries(installedModules).filter(([id])=>PLATFORM_MODULES[id]?.tier==="addon");

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom:22 }}>
        <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Attack Surface Overview</h1>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>
          {data?.meta?.domain||data?.meta?.org||"No scan loaded"} · Scan ID: {data?.meta?.scan_id||"—"}
        </p>
      </div>

      {/* Top stat row */}
      <div style={{ display:"flex", gap:10, marginBottom:20, flexWrap:"wrap" }}>
        <StatCard label="Assets"         value={stats.total}     accent="#00e5a0"/>
        <StatCard label="Open Issues"    value={stats.open}      accent="#ff3b3b"  sub="Requires remediation"/>
        <StatCard label="Findings"       value={stats.totalVulns}accent="#ff8c00"  sub="Across all modules"/>
        <StatCard label="Exposed Paths"  value={stats.exposedPaths}accent="#f5c518" sub="Web surface"/>
        <StatCard label="Add-ons Active" value={installedAddons.length} accent="#b06eff" sub="Optional modules"/>
      </div>

      {/* ── ROW 1: Risk Overview + SSL/Crypto + Infrastructure ── */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14, marginBottom:14 }}>

        {/* 1. Overall Risk Overview */}
        <ASMWidget title="1. Overall Risk Overview" accent="#ff3b3b" onViewAll={()=>setActiveTab("vulns")}>
          <RiskDonut assets={assets} onSevClick={()=>setActiveTab("vulns")}/>
        </ASMWidget>

        {/* 2. SSL / Crypto Health */}
        <ASMWidget title="2. SSL / Crypto Health" accent="#f5c518" onViewAll={()=>setShowCertModal(true)}
          badge={sslData.expired>0?`${sslData.expired} EXPIRED`:null}>
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {[
              { label:"Certs Monitored",  val:sslData.total,     color:"rgba(255,255,255,0.7)" },
              { label:"Expired",          val:sslData.expired,    color:sslData.expired>0?"#ff3b3b":"#00e5a0" },
              { label:"Expiring <30d",    val:sslData.critical,   color:sslData.critical>0?"#ff8c00":"#00e5a0" },
              { label:"Weak TLS (≤1.0)",  val:sslData.weakTLS,    color:sslData.weakTLS>0?"#f5c518":"#00e5a0" },
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
                <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.val}</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop:12 }}>
            <CertTimeline assets={assets} onViewAll={()=>setShowCertModal(true)}/>
          </div>
        </ASMWidget>

        {/* 3. Infrastructure & Cloud */}
        <ASMWidget title="3. Infrastructure & Cloud" accent="#4d9eff">
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {[
              { label:"IP Addresses",   val:infra.ips,   color:"#4d9eff" },
              { label:"Open Ports",     val:infra.ports, color:"#ff8c00" },
              { label:"Cloud Assets",   val:infra.cloud, color:"#00e5a0" },
              { label:"Subdomains",     val:assets.filter(a=>a.type==="Subdomain").length, color:"rgba(255,255,255,0.6)" },
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
                <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.val}</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop:14 }}>
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginBottom:6 }}>PORT EXPOSURE</div>
            <div style={{ display:"flex", gap:5, flexWrap:"wrap" }}>
              {[...new Set(assets.flatMap(a=>a.ports||[]))].slice(0,12).map(p=>(
                <span key={p} style={{ background:"rgba(77,158,255,0.1)", color:"#4d9eff", border:"1px solid rgba(77,158,255,0.2)",
                  padding:"2px 8px", borderRadius:2, fontSize:10, fontFamily:"monospace" }}>:{p}</span>
              ))}
            </div>
          </div>
        </ASMWidget>
      </div>

      {/* ── ROW 2: Email Security + Web Security + Attack Surface Inventory ── */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14, marginBottom:14 }}>

        {/* 4. Email Security */}
        <ASMWidget title="4. Email Security" accent="#b06eff">
          {emailSec ? (
            <div style={{ display:"flex", flexDirection:"column" }}>
              <ESecRow label="SPF"     value={emailSec.spf.value}    pass={emailSec.spf.pass}/>
              <ESecRow label="DKIM"    value={emailSec.dkim.value}   pass={emailSec.dkim.pass}/>
              <ESecRow label="DMARC"   value={emailSec.dmarc.value}  pass={emailSec.dmarc.pass}/>
              <ESecRow label="BIMI"    value={emailSec.bimi.value}   pass={emailSec.bimi.pass}/>
              <ESecRow label="MTA-STS" value={emailSec.mta_sts.value}pass={emailSec.mta_sts.pass}/>
            </div>
          ) : (
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:12, fontFamily:"monospace", padding:"16px 0" }}>
              No email security data in scan.<br/>Run a scan with the Email Security module enabled.
            </div>
          )}
        </ASMWidget>

        {/* 5. Web Security */}
        <ASMWidget title="5. Web Security" accent="#ff8c00" onViewAll={()=>setActiveTab("vulns")}>
          <div style={{ display:"flex", flexDirection:"column", gap:8, marginBottom:12 }}>
            {[
              { label:"Web Vulnerabilities", val:webSec.vulns,  color:webSec.vulns>0?"#ff8c00":"#00e5a0" },
              { label:"Exposed Paths",       val:webSec.paths,  color:webSec.paths>0?"#f5c518":"#00e5a0" },
              { label:"Assets Scanned",      val:assets.filter(a=>a.type?.startsWith("Web")).length, color:"rgba(255,255,255,0.6)" },
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
                <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.val}</span>
              </div>
            ))}
          </div>
          {/* Top web vulns preview */}
          <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
            {assets.flatMap(a=>(a.vulnerabilities||[]).filter(v=>v.module==="Web"||v.module==="Crypto")).slice(0,3).map((v,i)=>{
              const cfg = RISK_CONFIG[v.severity?.toLowerCase()]||RISK_CONFIG.low;
              return (
                <div key={i} style={{ display:"flex", gap:8, alignItems:"center" }}>
                  <span style={{ width:6, height:6, borderRadius:"50%", background:cfg.color, flexShrink:0 }}/>
                  <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.vulnerability}</span>
                </div>
              );
            })}
          </div>
        </ASMWidget>

        {/* 6. Attack Surface Inventory */}
        <ASMWidget title="6. Attack Surface Inventory" accent="#00e5a0" onViewAll={()=>setActiveTab("assets")}>
          <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
            {[
              { label:"Primary Domains",  count:assets.filter(a=>a.tags?.includes("primary")).length,  color:"#00e5a0" },
              { label:"Subdomains",       count:assets.filter(a=>a.type==="Subdomain").length,          color:"rgba(0,229,160,0.6)" },
              { label:"IP Addresses",     count:assets.filter(a=>a.tags?.includes("ip")).length,         color:"#4d9eff" },
              { label:"Typosquats",       count:assets.filter(a=>a.type?.includes("Typosquat")).length,  color:"#ff8c00" },
              { label:"Critical Risk",    count:assets.filter(a=>a.risk==="critical").length,            color:"#ff3b3b" },
              { label:"High Risk",        count:assets.filter(a=>a.risk==="high").length,                color:"#ff8c00" },
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"4px 0" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
                <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.count}</span>
              </div>
            ))}
          </div>
        </ASMWidget>
      </div>

      {/* ── ROW 3: Supply Chain + Brand/External + CySIEM Alerts ── */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14, marginBottom:14 }}>

        {/* 7. Supply Chain Risk */}
        <ASMWidget title="7. Supply Chain Risk" accent="#f5c518"
          badge={supply.high>0?`${supply.high} HIGH`:null}>
          {supply.count>0 ? (
            <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
              <div style={{ display:"flex", justifyContent:"space-between", padding:"5px 0" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>Total Risks</span>
                <span style={{ color:"#f5c518", fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{supply.count}</span>
              </div>
              <div style={{ display:"flex", justifyContent:"space-between", padding:"5px 0" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>Critical/High</span>
                <span style={{ color:"#ff3b3b", fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{supply.high}</span>
              </div>
            </div>
          ) : (
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:12, fontFamily:"monospace", padding:"16px 0" }}>
              No supply chain data.<br/>Enable Supply Chain module in scanner config.
            </div>
          )}
          <div style={{ marginTop:12, background:"rgba(245,197,24,0.05)", border:"1px solid rgba(245,197,24,0.12)", borderRadius:3, padding:"10px 12px" }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", lineHeight:1.7 }}>
              Supply chain analysis scans JS dependencies, CDN sources, third-party APIs and external scripts for compromise indicators.
            </div>
          </div>
        </ASMWidget>

        {/* 8. Brand & External Exposure */}
        <ASMWidget title="8. Brand & External Exposure" accent="#ff3b3b"
          badge={brand.typos>0?`${brand.typos} TYPOSQUATS`:null}>
          <div style={{ display:"flex", flexDirection:"column", gap:7, marginBottom:12 }}>
            {[
              { label:"Registered Typosquats", val:brand.typos,   color:brand.typos>0?"#ff3b3b":"#00e5a0" },
              { label:"Dark Web Mentions",     val:brand.darkweb, color:brand.darkweb>0?"#ff8c00":"#00e5a0" },
            ].map(r=>(
              <div key={r.label} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ color:"rgba(255,255,255,0.45)", fontSize:12 }}>{r.label}</span>
                <span style={{ color:r.color, fontFamily:"monospace", fontSize:13, fontWeight:700 }}>{r.val}</span>
              </div>
            ))}
          </div>
          {brand.typos>0 && (
            <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginBottom:4 }}>REGISTERED TYPOSQUATS</div>
              {assets.filter(a=>a.type?.includes("Typosquat")).slice(0,3).map(a=>(
                <div key={a.id} style={{ display:"flex", gap:8, alignItems:"center" }}>
                  <span style={{ color:"#ff3b3b", fontSize:10 }}>⚠</span>
                  <span style={{ color:"rgba(255,255,255,0.5)", fontSize:11, fontFamily:"monospace" }}>{a.host}</span>
                </div>
              ))}
            </div>
          )}
        </ASMWidget>

        {/* CySIEM Alerts (sidebar to the 8 widgets) */}
        <ASMWidget title="CySIEM Alerts" accent="#ff3b3b" onViewAll={()=>setActiveTab("cysiemfeed")}
          badge={`${data?.cysiemAlerts?.length||0} FORWARDED`}>
          <CySIEMFeed alerts={data?.cysiemAlerts?.slice(0,3)||[]}/>
        </ASMWidget>
      </div>

      {/* Add-on modules strip */}
      {installedAddons.length>0 && (
        <div style={{ background:"rgba(176,110,255,0.04)", border:"1px solid rgba(176,110,255,0.15)", borderRadius:4, padding:"14px 22px", marginBottom:14 }}>
          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:10 }}>Add-on Modules</div>
          <div style={{ display:"flex", gap:10 }}>
            {installedAddons.map(([id])=>{
              const def=PLATFORM_MODULES[id]; if(!def) return null;
              return (
                <button key={id} onClick={()=>{ window.history.pushState({from:"portal"},"",window.location.pathname); window.location.href=getModuleUrl(id); }}
                  style={{ display:"flex", alignItems:"center", gap:8, background:"rgba(255,255,255,0.03)",
                    border:`1px solid ${def.color}30`, borderRadius:4, padding:"10px 14px", flex:1,
                    cursor:"pointer", textAlign:"left" }}>
                  <span style={{ fontSize:18 }}>{def.icon}</span>
                  <div>
                    <div style={{ color:def.color, fontSize:12, fontWeight:700, fontFamily:"monospace" }}>{def.name}</div>
                    <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>Click to open</div>
                  </div>
                  <span style={{ marginLeft:"auto", width:5, height:5, borderRadius:"50%", background:"#00e5a0", animation:"pulse 2s infinite" }}/>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Critical & High priority vulns */}
      <div style={{ background:"rgba(255,255,255,0.025)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:4, padding:"18px 22px" }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
          <div style={{ color:"rgba(255,255,255,0.45)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace" }}>Critical & High Vulnerabilities</div>
          <button onClick={()=>setActiveTab("vulns")} style={{ background:"none", border:"none", color:"#00e5a0", fontSize:10, fontFamily:"monospace", cursor:"pointer" }}>
            View All ({critHighVulns.length}) ↗
          </button>
        </div>
        {assets.length===0 ? (
          <div style={{ color:"rgba(255,255,255,0.2)", fontSize:13, textAlign:"center", padding:"20px 0" }}>
            No scan data. <button onClick={()=>setShowImport(true)} style={{ background:"none", border:"none", color:"#00e5a0", cursor:"pointer", fontSize:13 }}>Import a scan</button> or <button onClick={()=>setActiveTab("scan")} style={{ background:"none", border:"none", color:"#00e5a0", cursor:"pointer", fontSize:13 }}>start a new scan</button>.
          </div>
        ) : critHighVulns.length===0 ? (
          <div style={{ color:"rgba(0,229,160,0.6)", fontSize:13, textAlign:"center", padding:"20px 0", fontFamily:"monospace" }}>✓ No critical or high vulnerabilities found</div>
        ) : (
          <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
            {critHighVulns.slice(0,10).map((v,i) => {
              const cfg=RISK_CONFIG[v.severity?.toLowerCase()]||RISK_CONFIG.high;
              return (
                <div key={i} className="asset-row" onClick={()=>setSelectedAsset(v.assetObj)}
                  style={{ display:"flex", alignItems:"center", gap:10, padding:"9px 12px",
                    background:"rgba(255,255,255,0.02)", borderRadius:3, border:`1px solid ${cfg.color}12`,
                    borderLeft:`3px solid ${cfg.color}`, cursor:"pointer" }}>
                  <Badge risk={v.severity?.toLowerCase()}/>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ color:"white", fontSize:12, fontWeight:600, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.vulnerability}</div>
                    <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.description}</div>
                  </div>
                  <div style={{ flexShrink:0, textAlign:"right" }}>
                    <div style={{ color:cfg.color, fontSize:11, fontFamily:"monospace", fontWeight:700 }}>{v.asset}</div>
                    {v.module && <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>{v.module}</div>}
                  </div>
                  <span style={{ color:"rgba(255,255,255,0.2)", fontSize:11 }}>↗</span>
                </div>
              );
            })}
            {critHighVulns.length>10 && (
              <button onClick={()=>setActiveTab("vulns")} style={{ background:"none", border:"none", color:"#00e5a0", fontSize:11, fontFamily:"monospace", cursor:"pointer", textAlign:"left", padding:"5px 0" }}>
                + {critHighVulns.length-10} more → View all in Vulnerability Explorer
              </button>
            )}
          </div>
        )}
      </div>

      {showCertModal && <CertModal assets={assets} onClose={()=>setShowCertModal(false)}/>}
    </div>
  );
}
// ════════════════════════════════════════════════════════════════════════════
// MODULE 04 — PLATFORM PAGE (BASE MODULES + SELECTIVE ADD-ONS + SSO CONFIG)
// ════════════════════════════════════════════════════════════════════════════

// ── Module Status Indicator ───────────────────────────────────────────────────
function StatusPill({ status, tier }) {
  if (tier === "base") return (
    <span style={{ background:"rgba(0,229,160,0.12)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.3)",
      fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px" }}>
      BASE 360 · ALWAYS ON
    </span>
  );
  const cfg = {
    running: { color:"#00e5a0", label:"RUNNING" },
    installing: { color:"#f5c518", label:"INSTALLING" },
    failed:   { color:"#ff3b3b", label:"FAILED" },
    stopped:  { color:"rgba(255,255,255,0.3)", label:"STOPPED" },
  }[status] || { color:"rgba(255,255,255,0.2)", label:"NOT INSTALLED" };
  return (
    <span style={{ background:`${cfg.color}15`, color:cfg.color, border:`1px solid ${cfg.color}30`,
      fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px",
      display:"flex", alignItems:"center", gap:5 }}>
      {status==="running" && <span style={{ width:5, height:5, borderRadius:"50%", background:cfg.color, animation:"pulse 2s infinite" }}/>}
      {cfg.label}
    </span>
  );
}

// ── Install Form ──────────────────────────────────────────────────────────────
function InstallForm({ mod, onInstall, onCancel }) {
  const [config, setConfig] = useState(mod.defaultConfig || {});
  const [stage, setStage]   = useState("config"); // config | installing | done | error
  const [log,   setLog]     = useState([]);
  const [progress, setProgress] = useState(0);
  const logRef = useRef(null);

  const update = (k, v) => setConfig(prev => ({...prev, [k]:v}));

  const startInstall = async () => {
    setStage("installing");
    setLog(["Preparing installation..."]);
    setProgress(5);

    try {
      const res = await fetch(`${API_BASE}/api/platform/install`, {
        method:"POST", headers:{"Content-Type":"application/json"}, credentials:"include",
        body: JSON.stringify({ module:mod.id, config, compose_yaml: mod.composeTemplate }),
      });

      if (!res.ok) { const e=await res.json(); setLog(prev=>[...prev,`ERROR: ${e.error||"Install failed"}`]); setStage("error"); return; }

      // Poll log lines + status every 3s — fixes stuck-at-5% issue
      const pollInterval = setInterval(async () => {
        try {
          // Fetch log lines from correct endpoint
          const lr = await fetch(`${API_BASE}/api/platform/logs/${mod.id}`, { credentials:"include" });
          if (lr.ok) {
            const l = await lr.json();
            if (l.lines && l.lines.length) {
              setLog(l.lines);
              const last = l.lines[l.lines.length - 1].toLowerCase();
              if (last.includes("pulling"))                  setProgress(15);
              else if (last.includes("starting containers")) setProgress(40);
              else if (last.includes("waiting for misp"))    setProgress(50);
              else if (last.includes("misp is live"))        setProgress(85);
              else if (last.includes("baseurl patched"))     setProgress(90);
              else if (last.includes("config.php saved"))    setProgress(93);
              else if (last.includes("nginx block"))         setProgress(96);
              else if (last.includes("ssl cert"))            setProgress(98);
              else if (last.includes("done — status"))      setProgress(100);
              else if (last.includes("pulled"))              setProgress(60);
              else if (last.includes("health check"))        setProgress(75);
              else if (last.includes("complete"))            setProgress(100);
            }
          }
          // Check actual container status
          const sr = await fetch(`${API_BASE}/api/platform/status`, { credentials:"include" });
          if (!sr.ok) return;
          const all = await sr.json();
          const s = all[mod.id];
          if (!s) return;
          if (s.status === "running") {
            clearInterval(pollInterval);
            setStage("done"); setProgress(100); onInstall(mod.id, config);
          } else if (s.status === "failed") {
            clearInterval(pollInterval); setStage("error");
          }
        } catch {}
      }, 3000);
    } catch (e) {
      setLog(prev=>[...prev, `Network error: ${e.message}`]);
      setStage("error");
    }
  };

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [log]);

  if (stage === "config") return (
    <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.08)", borderRadius:4, padding:"20px 24px", marginTop:16 }}>
      <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:16 }}>Configure {mod.name}</div>
      {(mod.configFields||[]).map(f => (
        <div key={f.key} style={{ marginBottom:14 }}>
          <label style={{ color:"rgba(255,255,255,0.45)", fontSize:10, fontFamily:"monospace", letterSpacing:"1px", textTransform:"uppercase", display:"block", marginBottom:6 }}>{f.label}</label>
          <input type={f.type||"text"} value={config[f.key]||""} onChange={e=>update(f.key,e.target.value)}
            style={{ width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)",
              color:"white", padding:"10px 14px", borderRadius:4, fontSize:13, fontFamily:"monospace", outline:"none", boxSizing:"border-box" }}/>
          {f.help && <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, marginTop:4 }}>{f.help}</div>}
        </div>
      ))}
      <div style={{ display:"flex", gap:10, marginTop:20 }}>
        <button onClick={startInstall}
          style={{ background:`${mod.color}`, color:"#0d0f14", border:"none", borderRadius:4,
            padding:"10px 24px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:"pointer", letterSpacing:"1px" }}>
          Install {mod.name} →
        </button>
        <button onClick={onCancel}
          style={{ background:"transparent", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.1)",
            borderRadius:4, padding:"10px 18px", fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>Cancel</button>
      </div>
    </div>
  );

  return (
    <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.08)", borderRadius:4, padding:"20px 24px", marginTop:16 }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:12 }}>
        <span style={{ color:"rgba(255,255,255,0.5)", fontSize:12, fontFamily:"monospace" }}>
          {stage==="installing"?"Installing…":stage==="done"?"✓ Complete":stage==="error"?"✗ Failed":""}
        </span>
        <span style={{ color: stage==="done"?"#00e5a0":stage==="error"?"#ff3b3b":"#f5c518", fontFamily:"monospace", fontSize:12, fontWeight:700 }}>{progress}%</span>
      </div>
      <div style={{ height:4, background:"rgba(255,255,255,0.06)", borderRadius:2, marginBottom:14 }}>
        <div style={{ height:"100%", width:`${progress}%`, background:stage==="error"?"#ff3b3b":"#00e5a0", borderRadius:2, transition:"width 0.5s ease" }}/>
      </div>
      <div ref={logRef}
        style={{ background:"rgba(0,0,0,0.4)", borderRadius:3, padding:"12px 14px", fontFamily:"monospace",
          fontSize:11, color:"rgba(0,229,160,0.7)", lineHeight:1.8, maxHeight:160, overflowY:"auto" }}>
        {log.map((l,i) => <div key={i}>{l}</div>)}
      </div>
      {(stage==="done"||stage==="error") && (
        <div>
          {stage==="done" && mod.postInstallNote && (
            <div style={{ marginTop:12, padding:"10px 14px",
              background:"rgba(0,229,160,0.08)", border:"1px solid rgba(0,229,160,0.2)",
              borderRadius:4, color:"rgba(0,229,160,0.8)", fontSize:11,
              fontFamily:"monospace", lineHeight:1.6 }}>
              ✓ {mod.postInstallNote}
            </div>
          )}
          <div style={{ display:"flex", gap:10, marginTop:12 }}>
            {stage==="done" && mod.id==="cymisp" && (
              <button
                onClick={()=> window.open(`https://cymisp.${_BASE_DOMAIN}`, '_blank')}
                style={{ background:"#e8a020", color:"#0d0f14", border:"none", borderRadius:4,
                  padding:"10px 24px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:"pointer" }}>
                Open CyMISP →
              </button>
            )}
            <button onClick={onCancel}
              style={{ background:stage==="done"?"rgba(255,255,255,0.08)":"rgba(255,59,59,0.2)",
                color:stage==="done"?"rgba(255,255,255,0.6)":"#ff3b3b",
                border:"1px solid rgba(255,255,255,0.1)",
                borderRadius:4, padding:"10px 24px", fontFamily:"monospace",
                fontSize:12, fontWeight:700, cursor:"pointer" }}>
              {stage==="done"?"Done":"Close"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── SSO Configuration Panel ───────────────────────────────────────────────────
function SSOConfigPanel() {
  const [expanded, setExpanded] = useState(null);

  const ssoGuides = [
    {
      id: "cyiris",
      name: "CyIRIS (DFIR IRIS)",
      protocol: "OIDC",
      color: "#b06eff",
      icon: "🔍",
      steps: [
        "Install CyIRIS module (creates the DFIR IRIS instance)",
        `In IRIS → Settings → Authentication → Enable OpenID Connect`,
        `Set OIDC Discovery URL: ${PORTAL_URL}/oidc/.well-known/openid-configuration`,
        "Client ID: cyiris",
        "Client Secret: use the CYIRIS_OIDC_SECRET from your install config",
        `Redirect URI: https://cyiris.${_BASE_DOMAIN}/auth/oidc/callback`,
        "Save and restart CyIRIS. Users will see 'Login with CyCentra 360' button.",
      ],
      apiHardening: [
        "Create a dedicated CySOAR service account in CyIRIS (not admin)",
        "Generate a long-lived API key: CyIRIS → Settings → API Keys → New Key (no expiry)",
        "Store key as CySOAR secret: CYIRIS_API_KEY",
        "Use key for all CySOAR → CyIRIS orchestration calls",
        "Restrict service account to: Case Create/Update, Alert Acknowledge only",
      ],
    },
    {
      id: "cysoar",
      name: "CySOAR (Node-RED SOAR)",
      protocol: "OIDC",
      color: "#4d9eff",
      icon: "⚡",
      steps: [
        "Install CySOAR module (creates the Node-RED instance)",
        `In CySOAR → Manage Palette → install node-red-contrib-oidc`,
        `Configure OIDC: Discovery URL: ${PORTAL_URL}/oidc/.well-known/openid-configuration`,
        "Client ID: cysoar",
        "Client Secret: use the CYSOAR_OIDC_SECRET from your install config",
        `Redirect URI: https://cysoar.${_BASE_DOMAIN}/auth/callback`,
        "Enable SSO in Node-RED settings.js. Restart CySOAR.",
      ],
      apiHardening: [
        "Create a CySOAR service account token with 365-day expiry (rotate annually)",
        "Store as env var: CYSOAR_TOKEN on the worker",
        "For CySIEM → CySOAR webhooks: use per-flow webhook tokens, not the global token",
        "Enable IP allowlist in CySOAR: only allow requests from cysiem-manager IP",
        "For CyIRIS → CySOAR triggers: use HMAC-signed webhook payloads",
      ],
    },
    {
      id: "cysiem",
      name: "CySIEM (Wazuh)",
      protocol: "SAML",
      color: "#ff8c00",
      icon: "👁️",
      steps: [
        "CySIEM runs Wazuh with OpenSearch. SSO uses OpenSearch Security → SAML.",
        `In CySIEM Dashboard → Security → Authentication: set method = SAML`,
        `IdP Metadata URL: ${PORTAL_URL}/.well-known/saml-metadata`,
        "SP Entity ID: cysiem",
        "IdP Entity ID: cycentra360",
        "Roles Mapping: map 'analyst' group to 'readall', 'admin' group to 'all_access'",
        "Restart OpenSearch Security plugin. Users log in via CyCentra 360.",
      ],
      apiHardening: [
        "For CySOAR → CySIEM API: use a dedicated CySIEM API user (not wazuh-wui)",
        "Generate token: POST /security/user/authenticate with service account creds",
        "Tokens expire in 900s by default — use CySOAR's HTTP node to auto-refresh",
        "Or: set auth_token_exp_timeout=86400 in /var/ossec/api/configuration/api.yaml",
        "Restrict service account role to: agent:read, syscheck:read, active-response:command",
        "Webhook endpoint for active response: POST /active-response — whitelist CySOAR IP",
      ],
    },
  ];

  return (
    <div style={{ marginTop:32 }}>
      <div style={{ marginBottom:20 }}>
        <h2 style={{ fontSize:18, fontWeight:700, color:"white", marginBottom:6 }}>Centralized SSO Configuration</h2>
        <p style={{ color:"rgba(255,255,255,0.4)", fontSize:13 }}>
          CyCentra 360 acts as the Identity Provider (IdP). Once configured, users authenticated in the portal access all modules without a second login prompt — <strong style={{color:"rgba(255,255,255,0.6)"}}>silent auth</strong>.
        </p>
      </div>

      {/* Architecture diagram */}
      <div style={{ background:"rgba(0,229,160,0.03)", border:"1px solid rgba(0,229,160,0.12)", borderRadius:4, padding:"18px 24px", marginBottom:24 }}>
        <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:14 }}>SSO Architecture</div>
        <div style={{ display:"flex", alignItems:"center", gap:0, flexWrap:"wrap", gap:8 }}>
          {[
            { label:"Google / Microsoft", sub:"External IdP", color:"#4285f4" },
            { label:"→", sub:"" },
            { label:"CyCentra 360 Portal", sub:"Central IdP · OIDC + SAML", color:"#00e5a0" },
            { label:"→", sub:"" },
            { label:"CyIRIS", sub:"OIDC client", color:"#b06eff" },
            { label:"→", sub:"" },
            { label:"CySOAR", sub:"OIDC client", color:"#4d9eff" },
            { label:"→", sub:"" },
            { label:"CySIEM", sub:"SAML SP", color:"#ff8c00" },
          ].map((item,i) => item.label==="→" ? (
            <div key={i} style={{ color:"rgba(255,255,255,0.2)", fontSize:16, fontFamily:"monospace" }}>→</div>
          ) : (
            <div key={i} style={{ background:"rgba(255,255,255,0.03)", border:`1px solid ${item.color}30`, borderTop:`2px solid ${item.color}`,
              padding:"10px 16px", borderRadius:3, textAlign:"center" }}>
              <div style={{ color:item.color, fontFamily:"monospace", fontSize:11, fontWeight:700 }}>{item.label}</div>
              {item.sub && <div style={{ color:"rgba(255,255,255,0.3)", fontSize:9, marginTop:3 }}>{item.sub}</div>}
            </div>
          ))}
        </div>
        <div style={{ marginTop:14, color:"rgba(255,255,255,0.25)", fontSize:11, lineHeight:1.7 }}>
          <strong style={{color:"rgba(255,255,255,0.4)"}}>Silent Auth:</strong> After portal login, sub-apps receive an OIDC ID token via redirect. No second login prompt if the token is valid. 
          Navigation uses <code style={{color:"#00e5a0"}}>window.history.pushState</code> — the Back button returns to the portal, not a blank page.
        </div>
      </div>

      {/* Per-module guides */}
      {ssoGuides.map(guide => (
        <div key={guide.id} style={{ marginBottom:12 }}>
          <div onClick={()=>setExpanded(expanded===guide.id?null:guide.id)}
            style={{ display:"flex", alignItems:"center", gap:12, padding:"14px 18px",
              background:"rgba(255,255,255,0.02)", border:`1px solid ${expanded===guide.id?guide.color+"40":"rgba(255,255,255,0.07)"}`,
              borderLeft:`3px solid ${guide.color}`, borderRadius:4, cursor:"pointer", transition:"all 0.2s" }}>
            <span style={{ fontSize:20 }}>{guide.icon}</span>
            <div style={{ flex:1 }}>
              <div style={{ color:"white", fontSize:14, fontWeight:600 }}>{guide.name}</div>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, fontFamily:"monospace" }}>Protocol: {guide.protocol}</div>
            </div>
            <span style={{ background:`${guide.color}20`, color:guide.color, border:`1px solid ${guide.color}30`,
              fontSize:9, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700 }}>{guide.protocol}</span>
            <span style={{ color:"rgba(255,255,255,0.3)", fontSize:14 }}>{expanded===guide.id?"▲":"▼"}</span>
          </div>

          {expanded===guide.id && (
            <div style={{ background:"rgba(255,255,255,0.015)", border:`1px solid ${guide.color}20`,
              borderTop:"none", borderRadius:"0 0 4px 4px", padding:"20px 22px" }}>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
                <div>
                  <div style={{ color:guide.color, fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:12 }}>SSO Setup Steps</div>
                  {guide.steps.map((step,i) => (
                    <div key={i} style={{ display:"flex", gap:10, marginBottom:10 }}>
                      <span style={{ color:guide.color, fontSize:10, fontFamily:"monospace", fontWeight:700, flexShrink:0, marginTop:1 }}>{String(i+1).padStart(2,"0")}</span>
                      <span style={{ color:"rgba(255,255,255,0.6)", fontSize:12, lineHeight:1.5 }}>{step}</span>
                    </div>
                  ))}
                </div>
                <div>
                  <div style={{ color:"#f5c518", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:12 }}>API Hardening (for CySOAR orchestration)</div>
                  {guide.apiHardening.map((step,i) => (
                    <div key={i} style={{ display:"flex", gap:10, marginBottom:10 }}>
                      <span style={{ color:"#f5c518", fontSize:10, fontFamily:"monospace", fontWeight:700, flexShrink:0, marginTop:1 }}>⚡</span>
                      <span style={{ color:"rgba(255,255,255,0.6)", fontSize:12, lineHeight:1.5 }}>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      ))}

      {/* Performance note */}
      <div style={{ marginTop:20, background:"rgba(0,0,0,0.3)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:4, padding:"16px 20px" }}>
        <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:10 }}>Performance — State Management</div>
        <div style={{ color:"rgba(255,255,255,0.45)", fontSize:12, lineHeight:1.8 }}>
          The portal uses React Context (no Redux) with a single top-level data store. Switching between Dashboard, CyIRIS and CySOAR tabs does <strong style={{color:"rgba(255,255,255,0.7)"}}>not</strong> trigger redundant API fetches — scan data, installed module state and AI config are all held in memory and hydrated once on login. Sub-app navigation (to CyIRIS/CySOAR URLs) preserves portal state via <code style={{color:"#00e5a0"}}>localStorage</code>. On Back, the portal SPA restores from in-memory state.
        </div>
      </div>
    </div>
  );
}

// ── Platform Page ─────────────────────────────────────────────────────────────
function PlatformPage({ installedModules, onInstall, onUninstall }) {
  const [installing,   setInstalling]   = useState(null);
  const [confirmUnins, setConfirmUnins] = useState(null);
  const [activeSection, setActiveSection] = useState("modules");

  const baseModules  = Object.values(PLATFORM_MODULES).filter(m=>m.tier==="base");
  const addonModules = Object.values(PLATFORM_MODULES).filter(m=>m.tier==="addon");

  const handleInstall = (moduleId, config) => {
    onInstall(moduleId, config);
    setInstalling(null);
  };

  // Auto-refresh module status every 5s so cards update without page reload
  useEffect(() => {
    const refresh = async () => {
      try {
        const r = await fetch(`${API_BASE}/api/platform/status`, { credentials:"include" });
        if (!r.ok) return;
        const data = await r.json();
        Object.entries(data).forEach(([id, s]) => {
          if (s.status === "running" && installedModules[id]?.status !== "running") {
            onInstall(id, installedModules[id]?.config || {});
          }
        });
      } catch {}
    };
    const timer = setInterval(refresh, 5000);
    refresh(); // immediate first check
    return () => clearInterval(timer);
  }, []);

  return (
    <div>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-end", marginBottom:24 }}>
        <div>
          <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Platform</h1>
          <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>Manage modules and centralized SSO configuration</p>
        </div>
        <div style={{ display:"flex", gap:6 }}>
          {[["modules","Modules"],["sso","SSO Config"]].map(([id,label])=>(
            <button key={id} onClick={()=>setActiveSection(id)}
              style={{ background:activeSection===id?"rgba(0,229,160,0.12)":"rgba(255,255,255,0.04)",
                color:activeSection===id?"#00e5a0":"rgba(255,255,255,0.5)",
                border:`1px solid ${activeSection===id?"rgba(0,229,160,0.3)":"rgba(255,255,255,0.08)"}`,
                borderRadius:4, padding:"8px 18px", fontFamily:"monospace", fontSize:11, cursor:"pointer", fontWeight:700 }}>{label}</button>
          ))}
        </div>
      </div>

      {activeSection==="modules" && (
        <div>
          {/* ── BASE 360 MODULES ── */}
          <div style={{ marginBottom:32 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:14 }}>
              <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace" }}>Base 360 — Always Installed</div>
              <span style={{ background:"rgba(0,229,160,0.1)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.2)",
                fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2, fontWeight:700 }}>CORE · NO INSTALL REQUIRED</span>
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
              {baseModules.map(mod => (
                <div key={mod.id} style={{ background:"rgba(255,255,255,0.025)", border:`1px solid ${mod.color}20`,
                  borderTop:`2px solid ${mod.color}`, borderRadius:5, padding:"22px 24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}>
                    <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                      <span style={{ fontSize:26 }}>{mod.icon}</span>
                      <div>
                        <div style={{ color:"white", fontSize:16, fontWeight:700 }}>{mod.name}</div>
                        <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:2 }}>{mod.fullName.split("—")[1]?.trim()}</div>
                      </div>
                    </div>
                    <StatusPill tier="base"/>
                  </div>
                  <div style={{ color:"rgba(255,255,255,0.5)", fontSize:12, lineHeight:1.6, marginBottom:14 }}>{mod.description}</div>
                  <div style={{ display:"flex", gap:5, flexWrap:"wrap", marginBottom:14 }}>
                    {(mod.features||[]).map(f=>(
                      <span key={f} style={{ background:"rgba(255,255,255,0.05)", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.08)",
                        fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2 }}>{f}</span>
                    ))}
                  </div>
                  <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                    <span style={{ color:"rgba(255,255,255,0.3)", fontSize:11, fontFamily:"monospace" }}>SSO: {mod.ssoProtocol}</span>
                    <span style={{ color:"rgba(255,255,255,0.15)", fontSize:11 }}>·</span>
                    <a href={mod.docsUrl} onClick={e=>{e.preventDefault(); window.history.pushState({from:"portal"},"",window.location.pathname); window.location.href=mod.docsUrl;}}
                      style={{ color:"rgba(255,255,255,0.35)", fontSize:11, textDecoration:"none" }}>Docs ↗</a>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* ── ADD-ON MODULES ── */}
          <div>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:14 }}>Add-on Modules — Optional</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
              {addonModules.map(mod => {
                const installed = installedModules[mod.id];
                const isInstalling = installing===mod.id;

                return (
                  <div key={mod.id} style={{ background:"rgba(255,255,255,0.025)", border:`1px solid ${mod.color}20`,
                    borderTop:`2px solid ${mod.color}`, borderRadius:5, padding:"22px 24px" }}>
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}>
                      <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                        <span style={{ fontSize:26 }}>{mod.icon}</span>
                        <div>
                          <div style={{ color:"white", fontSize:16, fontWeight:700 }}>{mod.name}</div>
                          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:2 }}>{mod.fullName.split("—")[1]?.trim()}</div>
                        </div>
                      </div>
                      <StatusPill status={installed?.status} tier={mod.tier}/>
                    </div>

                    <div style={{ color:"rgba(255,255,255,0.5)", fontSize:12, lineHeight:1.6, marginBottom:14 }}>{mod.description}</div>

                    {/* Resource info */}
                    <div style={{ display:"flex", gap:16, marginBottom:14 }}>
                      {[
                        { label:"RAM",  val:`${mod.ram_gb} GB` },
                        { label:"Disk", val:`${mod.disk_gb} GB` },
                        { label:"Time", val:mod.install_time },
                        { label:"SSO",  val:mod.ssoProtocol },
                      ].map(r=>(
                        <div key={r.label}>
                          <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace", letterSpacing:"1px" }}>{r.label}</div>
                          <div style={{ color:"rgba(255,255,255,0.6)", fontSize:12, fontFamily:"monospace" }}>{r.val}</div>
                        </div>
                      ))}
                    </div>

                    <div style={{ display:"flex", gap:5, flexWrap:"wrap", marginBottom:14 }}>
                      {(mod.features||[]).map(f=>(
                        <span key={f} style={{ background:"rgba(255,255,255,0.05)", color:"rgba(255,255,255,0.4)", border:"1px solid rgba(255,255,255,0.08)",
                          fontSize:9, fontFamily:"monospace", padding:"2px 8px", borderRadius:2 }}>{f}</span>
                      ))}
                    </div>

                    {/* Action buttons */}
                    {!installed && !isInstalling && (
                      <button onClick={()=>setInstalling(mod.id)}
                        style={{ background:`${mod.color}20`, color:mod.color, border:`1px solid ${mod.color}40`,
                          borderRadius:4, padding:"9px 20px", fontFamily:"monospace", fontSize:11,
                          fontWeight:700, cursor:"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
                        Install {mod.name}
                      </button>
                    )}

                    {installed && (
                      <div style={{ display:"flex", gap:10 }}>
                        <button onClick={()=>{ window.history.pushState({from:"portal"},"",window.location.pathname); window.location.href=mod.port?`http://${window.location.hostname}:${mod.port}`:`https://auto.cycentra.com`; }}
                          style={{ background:`${mod.color}20`, color:mod.color, border:`1px solid ${mod.color}40`,
                            borderRadius:4, padding:"9px 20px", fontFamily:"monospace", fontSize:11, fontWeight:700, cursor:"pointer" }}>
                          Open {mod.name}
                        </button>
                        {confirmUnins===mod.id ? (
                          <div style={{ display:"flex", gap:6 }}>
                            <button onClick={()=>{onUninstall(mod.id);setConfirmUnins(null);}}
                              style={{ background:"rgba(255,59,59,0.15)", color:"#ff3b3b", border:"1px solid rgba(255,59,59,0.3)",
                                borderRadius:4, padding:"9px 16px", fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>Confirm Remove</button>
                            <button onClick={()=>setConfirmUnins(null)}
                              style={{ background:"transparent", color:"rgba(255,255,255,0.35)", border:"1px solid rgba(255,255,255,0.1)",
                                borderRadius:4, padding:"9px 12px", fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>Cancel</button>
                          </div>
                        ) : (
                          <button onClick={()=>setConfirmUnins(mod.id)}
                            style={{ background:"transparent", color:"rgba(255,59,59,0.5)", border:"1px solid rgba(255,59,59,0.2)",
                              borderRadius:4, padding:"9px 16px", fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>Uninstall</button>
                        )}
                      </div>
                    )}

                    {isInstalling && (
                      <InstallForm mod={mod} onInstall={handleInstall} onCancel={()=>setInstalling(null)}/>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {activeSection==="sso" && <SSOConfigPanel/>}
    </div>
  );
}
// ════════════════════════════════════════════════════════════════════════════
// MODULE 05 — MAIN APP (ENTRY POINT)
// Wires all modules. SSO login, sidebar, routing.
// In a modular deployment: import this file as App.jsx
// Single-file build — all modules defined above, no sub-imports needed.
// ════════════════════════════════════════════════════════════════════════════

// ── Global CSS injected once ──────────────────────────────────────────────────
const GLOBAL_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  ::-webkit-scrollbar { width: 3px; } ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(0,229,160,0.2); border-radius: 2px; }
  @keyframes pulse    { 0%,100%{opacity:1;} 50%{opacity:0.4;} }
  @keyframes fadeIn   { from{opacity:0;transform:translateY(6px);} to{opacity:1;transform:translateY(0);} }
  @keyframes spin     { to{transform:rotate(360deg);} }
  @keyframes hexPulse { 0%,100%{opacity:0.5;transform:scale(1);} 50%{opacity:1;transform:scale(1.05);} }
  .asset-row:hover    { background:rgba(255,255,255,0.04) !important; cursor:pointer; }
  .side-item          { transition: background 0.15s, color 0.15s; cursor: pointer; }
  .side-item:hover    { background: rgba(255,255,255,0.05) !important; }
  input::placeholder  { color: rgba(255,255,255,0.2); }
  input:focus         { outline:none; border-color:rgba(0,229,160,0.4) !important; }
  textarea::placeholder { color: rgba(255,255,255,0.2); }
  select:focus        { outline:none; }
  button:hover        { opacity:0.88; }
`;

// ── SSO Login Screen ──────────────────────────────────────────────────────────
function LoginScreen() {
  const [loading, setLoading] = useState(null);

  const handleSSO = (provider) => {
    setLoading(provider);
    window.location.href = `${CYSCAN_URL}/auth/${provider}?redirect=${encodeURIComponent(window.location.origin)}`;
  };

  return (
    <div style={{ minHeight:"100vh", background:"#090b10", display:"flex",
      fontFamily:"'Barlow',sans-serif",
      backgroundImage:"radial-gradient(ellipse at 15% 50%, rgba(0,229,160,0.06) 0%, transparent 55%), radial-gradient(ellipse at 85% 20%, rgba(0,120,255,0.05) 0%, transparent 55%)" }}>
      <style>{GLOBAL_CSS}{`@keyframes fadeUp{from{opacity:0;transform:translateY(16px);}to{opacity:1;transform:translateY(0);}}`}</style>

      {/* Left panel — branding */}
      <div style={{ flex:"1 1 55%", display:"flex", flexDirection:"column", justifyContent:"center",
        padding:"60px 64px", borderRight:"1px solid rgba(255,255,255,0.05)" }}>
        <div style={{ animation:"fadeUp 0.5s ease", maxWidth:520 }}>
          {/* Logo */}
          <div style={{ display:"flex", alignItems:"center", gap:14, marginBottom:48 }}>
            <svg width="44" height="44" viewBox="0 0 24 24" style={{ animation:"hexPulse 3s ease-in-out infinite", flexShrink:0 }}>
              <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
              <polygon points="12,6 18,10 18,14 12,18 6,14 6,10" fill="rgba(0,229,160,0.15)" stroke="#00e5a0" strokeWidth="0.75"/>
              <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
            </svg>
            <div>
              <div style={{ color:"white", fontFamily:"'Space Mono',monospace", fontSize:26, fontWeight:700, letterSpacing:"2px", lineHeight:1 }}>
                CY<span style={{color:"#00e5a0"}}>CENTRA</span>
              </div>
              <div style={{ color:"#00e5a0", fontFamily:"'Space Mono',monospace", fontSize:11, letterSpacing:"4px", opacity:0.7 }}>360°</div>
            </div>
          </div>

          <h1 style={{ color:"white", fontSize:36, fontWeight:800, lineHeight:1.2, marginBottom:18 }}>
            Attack Surface<br/>
            <span style={{ color:"#00e5a0" }}>Intelligence Platform</span>
          </h1>
          <p style={{ color:"rgba(255,255,255,0.4)", fontSize:15, lineHeight:1.8, maxWidth:420, marginBottom:48 }}>
            Unified external ASM, incident response, SIEM and SOAR — one login to access your entire security stack.
          </p>

          {/* Feature pills */}
          <div style={{ display:"flex", flexWrap:"wrap", gap:10 }}>
            {[
              { icon:"👁️", label:"CySIEM", desc:"Always active" },
              { icon:"🎫", label:"CyIRIS", desc:"Case management" },
              { icon:"🛡️", label:"CySOAR", desc:"Automation & response" },
              { icon:"🔍", label:"ASM Scan", desc:"External exposure" },
            ].map(f => (
              <div key={f.label} style={{ display:"flex", alignItems:"center", gap:8,
                background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.08)",
                borderRadius:8, padding:"10px 14px" }}>
                <span style={{ fontSize:16 }}>{f.icon}</span>
                <div>
                  <div style={{ color:"rgba(255,255,255,0.8)", fontSize:12, fontWeight:600 }}>{f.label}</div>
                  <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10 }}>{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right panel — sign-in form */}
      <div style={{ flex:"1 1 45%", display:"flex", alignItems:"center", justifyContent:"center",
        padding:"40px 48px" }}>
        <div style={{ width:"min(420px,100%)", animation:"fadeUp 0.6s ease 0.1s both" }}>
          <div style={{ marginBottom:32, display:"inline-flex", gap:6, alignItems:"center",
            background:"rgba(0,229,160,0.08)", border:"1px solid rgba(0,229,160,0.15)",
            borderRadius:20, padding:"5px 14px" }}>
            <span style={{ width:5, height:5, borderRadius:"50%", background:"#00e5a0", display:"inline-block", animation:"pulse 2s infinite" }}/>
            <span style={{ color:"rgba(0,229,160,0.8)", fontSize:10, fontFamily:"monospace", letterSpacing:"1px" }}>CENTRAL SSO GATEWAY</span>
          </div>

          <h2 style={{ color:"white", fontSize:22, fontWeight:700, marginBottom:6 }}>Sign in to your workspace</h2>
          <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginBottom:32 }}>One login. Portal, CySIEM, CyIRIS and CySOAR.</p>

          <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.08)", borderRadius:10, padding:"32px 28px" }}>
            {/* Google */}
            <button onClick={()=>handleSSO("google")} disabled={!!loading}
              style={{ width:"100%", display:"flex", alignItems:"center", justifyContent:"center", gap:12,
                background:loading==="google"?"rgba(255,255,255,0.08)":"rgba(255,255,255,0.06)",
                border:"1px solid rgba(255,255,255,0.12)", borderRadius:8, padding:"14px 20px",
                color:"white", fontFamily:"'Barlow',sans-serif", fontSize:14, fontWeight:600,
                cursor:loading?"not-allowed":"pointer", marginBottom:12, transition:"all 0.2s" }}>
              {loading==="google"
                ? <div style={{ width:18, height:18, border:"2px solid rgba(255,255,255,0.2)", borderTopColor:"#00e5a0", borderRadius:"50%", animation:"spin 0.8s linear infinite" }}/>
                : <svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
              }
              {loading==="google" ? "Connecting…" : "Continue with Google"}
            </button>

            {/* Microsoft */}
            <button onClick={()=>handleSSO("microsoft")} disabled={!!loading}
              style={{ width:"100%", display:"flex", alignItems:"center", justifyContent:"center", gap:12,
                background:loading==="microsoft"?"rgba(255,255,255,0.08)":"rgba(255,255,255,0.06)",
                border:"1px solid rgba(255,255,255,0.12)", borderRadius:8, padding:"14px 20px",
                color:"white", fontFamily:"'Barlow',sans-serif", fontSize:14, fontWeight:600,
                cursor:loading?"not-allowed":"pointer", marginBottom:28, transition:"all 0.2s" }}>
              {loading==="microsoft"
                ? <div style={{ width:18, height:18, border:"2px solid rgba(255,255,255,0.2)", borderTopColor:"#00b4f0", borderRadius:"50%", animation:"spin 0.8s linear infinite" }}/>
                : <svg width="18" height="18" viewBox="0 0 21 21"><rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>
              }
              {loading==="microsoft" ? "Connecting…" : "Continue with Microsoft"}
            </button>

            <div style={{ borderTop:"1px solid rgba(255,255,255,0.06)", paddingTop:20, color:"rgba(255,255,255,0.2)", fontSize:11, textAlign:"center", lineHeight:1.6 }}>
              Single sign-on gateway · All modules share this session<br/>
              CySIEM · CyIRIS · CySOAR — one login to rule them all
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Scan Page ─────────────────────────────────────────────────────────────────
function ScanPage({ user, onScanComplete }) {
  const [domain, setDomain]               = useState("");
  const [email,  setEmail]                = useState(user?.email||"");
  const [scanType, setScanType]           = useState("standard");
  const [includeSubdomains, setIncludeSub]= useState(true);
  const [scanState, setScanState]         = useState("idle");
  const [progress, setProgress]           = useState(0);
  const [currentModule, setCurrentModule] = useState("");
  const [elapsed, setElapsed]             = useState(0);
  const [lastLog, setLastLog]             = useState("");
  const timerRef = useRef(null); const pollRef = useRef(null);

  const MODULES = ["DNS Reconnaissance","Subdomain Enumeration","Web Analysis","Crypto & SSL Audit",
    "Email Security Check","WHOIS & History","OSINT Gathering","Cloud Infrastructure",
    "Dark Web Monitoring","Supply Chain Analysis","AI Risk Enrichment","Generating Report"];

  const pollStatus = () => {
    let noProgressCount = 0;
    let pollCount = 0;
    pollRef.current = setInterval(async () => {
      try {
        pollCount++;
        const res = await fetch(`${API_BASE}/api/scan/status`, { credentials:"include" });
        if (!res.ok) {
          console.warn("[Scan] status poll failed:", res.status);
          return; // backend hiccup — keep polling, don't abort
        }
        const s = await res.json();
        console.log("[Scan] status poll #" + pollCount + ":", s);

        if (s.progress != null && s.progress > 0)  setProgress(s.progress);
        if (s.current_module)    setCurrentModule(s.current_module);
        if (s.last_log)          setLastLog(s.last_log);

        const logText = (s.last_log||"").toLowerCase();
        const isDone  = (!s.running && s.progress >= 98) ||
                        logText.includes("portal json saved") ||
                        logText.includes("ndjson report saved") ||
                        logText.includes("all done") ||
                        logText.includes("scan complete");

        if (isDone) {
          clearInterval(pollRef.current); clearInterval(timerRef.current);
          setProgress(100); setCurrentModule("Complete"); setScanState("done");
          try {
            const r2 = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user?.id||"")}`, { credentials:"include" });
            if (r2.ok) onScanComplete(await r2.json());
          } catch {}
          return;
        }

        // Grace period: for first 8 polls (24s) don't count stalls — engine may be starting
        if (pollCount > 8 && s.running === false && (s.progress||0) < 5) {
          noProgressCount++;
          if (noProgressCount >= 4) {
            // Check if results exist — scan may have completed without updating log
            try {
              const r2 = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user?.id||"")}`, { credentials:"include" });
              if (r2.ok) {
                const raw = await r2.json();
                if (raw?.assets?.length) {
                  clearInterval(pollRef.current); clearInterval(timerRef.current);
                  setProgress(100); setScanState("done"); onScanComplete(raw);
                } else {
                  // Truly stuck — show error
                  clearInterval(pollRef.current); clearInterval(timerRef.current);
                  setLastLog("Scan engine not responding. Check backend logs at /var/log/cycentra/cy-asm/logs/");
                  setScanState("error");
                }
              }
            } catch {}
          }
        } else if (s.running === true || s.progress > 0) {
          noProgressCount = 0;
        }
      } catch(e) {
        console.warn("[Scan] poll error:", e.message);
      } // network error during poll — silent, keep trying
    }, 3000);
  };

  const startScan = async () => {
    if (!domain) return;
    setScanState("running"); setProgress(2); setElapsed(0);
    setLastLog("Connecting to scan engine…"); setCurrentModule("Initialising...");
    let secs=0; timerRef.current = setInterval(()=>{ secs++; setElapsed(secs); }, 1000);
    try {
      const res = await fetch(`${API_BASE}/api/scan/trigger`, {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        credentials:"include",   // ← required: Flask session cookie
        body: JSON.stringify({ domain, scan_type:scanType, notify_email:email,
                               include_subdomains:includeSubdomains, uid:user?.id||"anonymous" }),
      });
      const body = await res.json().catch(()=>({}));
      console.log("[Scan] trigger response:", res.status, body);
      if (res.status === 503) {
        // Engine not found — warn but keep running; maybe engine is starting
        setLastLog(body.error || "Scan engine not found — check /opt/cycentra/backend/cy-asm/cycentra_scan.py");
        setCurrentModule("Waiting for scan engine...");
      } else if (!res.ok) {
        // Any other HTTP error (400 bad domain, 500 crash) → abort
        setLastLog(`Error: ${body.error || res.statusText}`);
        setScanState("error"); clearInterval(timerRef.current); return;
      } else {
        setLastLog(`Scan started for ${domain} — polling for progress…`);
        setCurrentModule("DNS Reconnaissance");
        setProgress(5);
      }
      // 200 or 503 — start polling
    } catch(e) {
      // Only abort on true network failure (CORS, no route, etc.)
      setLastLog(`Cannot reach backend: ${e.message} — is the backend running?`);
      setScanState("error"); clearInterval(timerRef.current); return;
    }
    pollStatus();
  };

  const resetScan = () => {
    clearInterval(timerRef.current); clearInterval(pollRef.current);
    setScanState("idle"); setProgress(0); setElapsed(0); setCurrentModule(""); setLastLog("");
  };

  const viewReport = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user?.id||"")}`);
      if (res.ok) onScanComplete(await res.json());
    } catch {}
  };

  const fmt = s => `${String(Math.floor(s/60)).padStart(2,"0")}:${String(s%60).padStart(2,"0")}`;
  const circumference = 2*Math.PI*54;
  const strokeDash    = circumference-(progress/100)*circumference;

  return (
    <div>
      <div style={{ marginBottom:28 }}>
        <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>Initiate ASM Scan</h1>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>Launch automated reconnaissance & exposure assessment</p>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 360px", gap:24, alignItems:"start" }}>
        {/* Form */}
        <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, padding:28 }}>
          {[["Target Domain *","domain","text","example.com",domain,e=>setDomain(e.target.value)],
            ["Notify Email","email","email","security@company.com",email,e=>setEmail(e.target.value)]].map(([label,name,type,ph,val,onChange])=>(
            <div key={name} style={{ marginBottom:18 }}>
              <label style={{ color:"rgba(255,255,255,0.5)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", display:"block", marginBottom:8 }}>{label}</label>
              <input type={type} value={val} onChange={onChange} placeholder={ph} disabled={scanState==="running"}
                style={{ width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)",
                  color:"white", padding:"12px 16px", borderRadius:4, fontSize:14, fontFamily:"monospace",
                  outline:"none", boxSizing:"border-box", opacity:scanState==="running"?0.5:1 }}/>
            </div>
          ))}

          <div style={{ marginBottom:18 }}>
            <label style={{ color:"rgba(255,255,255,0.5)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", display:"block", marginBottom:10 }}>Scan Type</label>
            {[{id:"standard",label:"Standard (Recommended)",desc:"DNS,Web,Crypto,Email,OSINT — ~45s"},
              {id:"deep",label:"Deep Scan",desc:"Full suite + AI enrichment — ~90s"},
              {id:"passive",label:"Passive Scan",desc:"Read-only, no active probing — ~20s"}].map(t=>(
              <div key={t.id} onClick={()=>scanState!=="running"&&setScanType(t.id)}
                style={{ display:"flex", alignItems:"flex-start", gap:12, padding:"12px 14px", marginBottom:6,
                  background:scanType===t.id?"rgba(0,229,160,0.08)":"rgba(255,255,255,0.02)",
                  border:`1px solid ${scanType===t.id?"rgba(0,229,160,0.3)":"rgba(255,255,255,0.06)"}`,
                  borderRadius:4, cursor:scanState==="running"?"not-allowed":"pointer" }}>
                <div style={{ width:16, height:16, borderRadius:"50%", flexShrink:0, marginTop:2,
                  border:`2px solid ${scanType===t.id?"#00e5a0":"rgba(255,255,255,0.2)"}`,
                  background:scanType===t.id?"#00e5a0":"transparent",
                  boxShadow:scanType===t.id?"0 0 8px #00e5a0":"none" }}/>
                <div>
                  <div style={{ color:scanType===t.id?"#00e5a0":"rgba(255,255,255,0.8)", fontSize:13, fontWeight:600 }}>{t.label}</div>
                  <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:2 }}>{t.desc}</div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:22 }}>
            <div onClick={()=>scanState!=="running"&&setIncludeSub(v=>!v)}
              style={{ width:18, height:18, borderRadius:3, cursor:"pointer", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0,
                border:`2px solid ${includeSubdomains?"#00e5a0":"rgba(255,255,255,0.2)"}`,
                background:includeSubdomains?"#00e5a0":"transparent" }}>
              {includeSubdomains && <span style={{ color:"#0d0f14", fontSize:11, fontWeight:900 }}>✓</span>}
            </div>
            <span style={{ color:"rgba(255,255,255,0.7)", fontSize:13 }}>Include Subdomain Enumeration</span>
          </div>

          {scanState==="idle" && (
            <button onClick={startScan} disabled={!domain}
              style={{ width:"100%", background:domain?"#00e5a0":"rgba(0,229,160,0.3)", color:"#0d0f14",
                fontFamily:"'Space Mono',monospace", fontWeight:700, fontSize:13, letterSpacing:"1px",
                padding:"14px 24px", border:"none", borderRadius:4, cursor:domain?"pointer":"not-allowed", textTransform:"uppercase" }}>
              Launch ASM Scan →
            </button>
          )}
          {scanState==="done" && (
            <div style={{ display:"flex", gap:10 }}>
              <button onClick={resetScan} style={{ flex:1, background:"transparent", color:"rgba(255,255,255,0.5)", border:"1px solid rgba(255,255,255,0.15)", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>New Scan</button>
              <button onClick={viewReport} style={{ flex:1, background:"#00e5a0", color:"#0d0f14", border:"none", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, fontWeight:700, cursor:"pointer" }}>View Report →</button>
            </div>
          )}
          {scanState==="error" && (
            <div style={{ display:"flex", gap:10 }}>
              <button onClick={resetScan} style={{ flex:1, background:"rgba(255,59,59,0.15)", color:"#ff3b3b", border:"1px solid rgba(255,59,59,0.3)", borderRadius:4, padding:"12px", fontFamily:"monospace", fontSize:12, cursor:"pointer" }}>← Try Again</button>
            </div>
          )}

          <div style={{ marginTop:14, background:"rgba(0,0,0,0.3)", border:"1px solid rgba(255,255,255,0.05)", borderRadius:4, padding:"10px 14px" }}>
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", marginBottom:4 }}>CLI EQUIVALENT</div>
            <code style={{ color:"#00e5a0", fontSize:11 }}>python3 cycentra_scan.py {domain||"<domain>"} {user?.id||"<uid>"}</code>
          </div>
        </div>

        {/* Progress panel */}
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
          <div style={{ background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, padding:24, textAlign:"center" }}>
            <div style={{ position:"relative", display:"inline-flex", alignItems:"center", justifyContent:"center", marginBottom:16 }}>
              <svg width="128" height="128" style={{ transform:"rotate(-90deg)" }}>
                <circle cx="64" cy="64" r="54" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8"/>
                <circle cx="64" cy="64" r="54" fill="none"
                  stroke={scanState==="error"?"#ff3b3b":scanState!=="idle"?"#00e5a0":"rgba(0,229,160,0.2)"}
                  strokeWidth="8" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={strokeDash}
                  style={{ transition:"stroke-dashoffset 1s ease", filter:scanState!=="idle"?"drop-shadow(0 0 8px #00e5a060)":"none" }}/>
              </svg>
              <div style={{ position:"absolute", textAlign:"center" }}>
                <div style={{ color:scanState==="error"?"#ff3b3b":"#00e5a0", fontSize:26, fontFamily:"'Space Mono',monospace", fontWeight:700 }}>
                  {scanState==="idle"?"--:--":fmt(elapsed)}
                </div>
                <div style={{ color:"rgba(255,255,255,0.3)", fontSize:9, letterSpacing:"1.5px", fontFamily:"monospace", marginTop:2 }}>
                  {scanState==="idle"?"READY":scanState==="done"?"COMPLETE":scanState==="error"?"FAILED":"ELAPSED"}
                </div>
              </div>
            </div>
            {scanState==="running" && <div style={{ color:"#00e5a0", fontSize:12, fontFamily:"monospace", marginBottom:10 }}>{currentModule}…</div>}
            {scanState==="done"    && <div style={{ color:"#00e5a0", fontSize:14, fontWeight:700, marginBottom:6 }}>✓ Scan Complete</div>}
            {scanState==="error"   && <div style={{ color:"#ff3b3b", fontSize:13, marginBottom:6 }}>✗ Could not reach backend</div>}
            <div style={{ height:4, background:"rgba(255,255,255,0.06)", borderRadius:2 }}>
              <div style={{ height:"100%", width:`${progress}%`, background:scanState==="error"?"#ff3b3b":"#00e5a0", borderRadius:2, transition:"width 1s ease" }}/>
            </div>
            <div style={{ display:"flex", justifyContent:"space-between", marginTop:5 }}>
              <span style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>0%</span>
              <span style={{ color:progress>0?"#00e5a0":"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace", fontWeight:700 }}>{Math.round(progress)}%</span>
              <span style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>100%</span>
            </div>
            {lastLog && (
              <div style={{ marginTop:8, background:"rgba(0,0,0,0.3)", borderRadius:3, padding:"5px 10px",
                color: scanState==="error" ? "#ff6b6b" : "rgba(0,229,160,0.5)",
                fontSize:10, fontFamily:"monospace", whiteSpace:"normal", overflow:"hidden",
                wordBreak:"break-word", lineHeight:1.5 }}>
                {lastLog}
              </div>
            )}
          </div>
          {/* Module checklist */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:6, padding:18 }}>
            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:10 }}>Scan Modules</div>
            <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
              {MODULES.map((m,i)=>{
                const modIdx=Math.min(MODULES.length-1,Math.floor((progress/100)*MODULES.length));
                const done=progress>0&&i<modIdx; const active=i===modIdx&&scanState==="running";
                return (
                  <div key={m} style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <div style={{ width:13, height:13, borderRadius:"50%", flexShrink:0,
                      background:done?"#00e5a0":active?"rgba(0,229,160,0.2)":"rgba(255,255,255,0.05)",
                      border:active?"1.5px solid #00e5a0":"none",
                      display:"flex", alignItems:"center", justifyContent:"center" }}>
                      {done && <span style={{ fontSize:7, color:"#0d0f14", fontWeight:900 }}>✓</span>}
                      {active && <div style={{ width:5, height:5, borderRadius:"50%", background:"#00e5a0", animation:"pulse 1s infinite" }}/>}
                    </div>
                    <span style={{ fontSize:11, fontFamily:"monospace", color:done?"rgba(255,255,255,0.7)":active?"#00e5a0":"rgba(255,255,255,0.25)" }}>{m}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Vulnerability Explorer ────────────────────────────────────────────────────
function VulnerabilityPage({ assets }) {
  const [sevFilter, setSevFilter] = useState("all");
  const [modFilter, setModFilter] = useState("all");
  const allVulns  = assets.flatMap(a=>(a.vulnerabilities||[]).map(v=>({...v,asset:a.host,assetId:a.id})));
  const modules   = [...new Set(allVulns.map(v=>v.module).filter(Boolean))];
  const filtered  = allVulns.filter(v=>
    (sevFilter==="all"||v.severity?.toLowerCase()===sevFilter) &&
    (modFilter==="all"||v.module===modFilter)
  );
  return (
    <div>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-end", marginBottom:22 }}>
        <div>
          <h1 style={{ fontSize:22, fontWeight:700 }}>Vulnerability Explorer</h1>
          <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>{filtered.length} of {allVulns.length} findings</p>
        </div>
        <div style={{ display:"flex", gap:8 }}>
          {[["sevFilter",sevFilter,setSevFilter,[["all","All Severities"],["critical","Critical"],["high","High"],["medium","Medium"],["low","Low"]]],
            ["modFilter",modFilter,setModFilter,[["all","All Modules"],...modules.map(m=>[m,m])]]].map(([key,val,setter,opts])=>(
            <select key={key} value={val} onChange={e=>setter(e.target.value)}
              style={{ background:"#0d0f14", border:"1px solid rgba(255,255,255,0.1)", color:"rgba(255,255,255,0.6)",
                padding:"8px 12px", borderRadius:3, fontSize:12, fontFamily:"monospace", cursor:"pointer" }}>
              {opts.map(([v,l])=><option key={v} value={v}>{l}</option>)}
            </select>
          ))}
        </div>
      </div>
      {filtered.length===0 ? (
        <div style={{ textAlign:"center", padding:"60px 0", color:"rgba(255,255,255,0.2)", fontFamily:"monospace" }}>No vulnerabilities matching filters</div>
      ) : (
        <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
          {filtered.map((v,i)=>{
            const cfg=({critical:{color:"#ff3b3b"},high:{color:"#ff8c00"},medium:{color:"#f5c518"},low:{color:"#00e5a0"}})[v.severity?.toLowerCase()]||{color:"#00e5a0"};
            return (
              <div key={i} style={{ background:"rgba(255,255,255,0.02)", border:`1px solid ${cfg.color}15`,
                borderLeft:`4px solid ${cfg.color}`, borderRadius:4, padding:"16px 20px" }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:8 }}>
                  <div style={{ flex:1, paddingRight:16 }}>
                    <div style={{ color:"white", fontSize:14, fontWeight:600, marginBottom:4 }}>{v.vulnerability}</div>
                    <div style={{ color:"rgba(255,255,255,0.45)", fontSize:12, lineHeight:1.5 }}>{v.description}</div>
                  </div>
                  <div style={{ display:"flex", flexDirection:"column", alignItems:"flex-end", gap:6, flexShrink:0 }}>
                    <Badge risk={v.severity?.toLowerCase()}/>
                    <span style={{ color:cfg.color, fontFamily:"monospace", fontSize:11, fontWeight:700 }}>Risk {v.risk_score}/10</span>
                  </div>
                </div>
                <div style={{ background:"rgba(0,229,160,0.05)", border:"1px solid rgba(0,229,160,0.1)", borderRadius:3, padding:"8px 12px", marginBottom:8 }}>
                  <span style={{ color:"rgba(0,229,160,0.7)", fontSize:11 }}>✓ Recommendation: </span>
                  <span style={{ color:"rgba(255,255,255,0.6)", fontSize:11 }}>{v.recommendation}</span>
                </div>
                <div style={{ display:"flex", gap:12 }}>
                  <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>Asset: {v.asset}</span>
                  {v.module && <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>Module: {v.module}</span>}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── AI Settings Page ──────────────────────────────────────────────────────────
function AISettingsPage({ aiConfig, onSave }) {
  const [provider, setProvider]           = useState(aiConfig?.provider||"local");
  const [fields,   setFields]             = useState(aiConfig?.fields||{});
  const [prompts,  setPrompts]            = useState(aiConfig?.prompts||DEFAULT_PROMPTS);
  const [activePromptTab, setActivePTab]  = useState("system");
  const [testStatus, setTestStatus]       = useState(null);
  const [testMsg,    setTestMsg]          = useState("");
  const [saved,      setSaved]            = useState(false);
  const [moduleUrls, setModuleUrls]       = useState(()=>{
    try { return { cyiris:localStorage.getItem("cycentra_url_cyiris")||"", cysoar:localStorage.getItem("cycentra_url_cysoar")||"", cysiem:localStorage.getItem("cycentra_url_cysiem")||"" }; }
    catch { return { cyiris:"", cysoar:"", cysiem:"" }; }
  });

  const currentProvider = AI_PROVIDERS[provider];
  const updateField  = (k,v) => setFields(prev=>({...prev,[k]:v}));
  const updatePrompt = (k,v) => setPrompts(prev=>({...prev,[k]:v}));
  const resetPrompt  = (k)   => setPrompts(prev=>({...prev,[k]:DEFAULT_PROMPTS[k]}));

  const testConnection = async () => {
    setTestStatus("testing"); setTestMsg("");
    if (provider==="local"&&!fields.baseUrl) { setTestStatus("fail"); setTestMsg("Server URL is required"); return; }
    if (provider!=="local"&&!fields.apiKey)  { setTestStatus("fail"); setTestMsg("API key is required"); return; }
    try {
      const res=await fetch(`${API_BASE}/api/ai/test`,{method:"POST",headers:{"Content-Type":"application/json"},credentials:"include",body:JSON.stringify({provider,fields})});
      const d=await res.json();
      if (d.ok) { setTestStatus("ok"); setTestMsg(d.message||"Connected"); }
      else      { setTestStatus("fail"); setTestMsg(d.error||"Connection failed"); }
    } catch { setTestStatus("fail"); setTestMsg(`Cannot reach backend at ${CYSCAN_URL}`); }
  };

  const handleSave = () => {
    onSave({provider,fields,prompts});
    try {
      Object.entries(moduleUrls).forEach(([id,url])=>localStorage.setItem(`cycentra_url_${id}`,url));
    } catch {}
    setSaved(true); setTimeout(()=>setSaved(false),2000);
  };

  return (
    <div>
      <div style={{ marginBottom:28 }}>
        <h1 style={{ fontSize:22, fontWeight:700, color:"white" }}>AI Settings</h1>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>Configure AI provider and customise how CyCentra AI interprets security findings.</p>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:24, alignItems:"start" }}>
        {/* Provider selection */}
        <div>
          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:14 }}>AI Provider</div>
          <div style={{ display:"flex", flexDirection:"column", gap:8, marginBottom:22 }}>
            {Object.values(AI_PROVIDERS).map(p=>(
              <div key={p.id} onClick={()=>{setProvider(p.id);setFields({});setTestStatus(null);}}
                style={{ display:"flex", alignItems:"center", gap:12, padding:"12px 16px",
                  background:provider===p.id?"rgba(255,255,255,0.04)":"rgba(255,255,255,0.02)",
                  border:`1px solid ${provider===p.id?p.color+"50":"rgba(255,255,255,0.07)"}`,
                  borderLeft:`3px solid ${provider===p.id?p.color:"transparent"}`,
                  borderRadius:4, cursor:"pointer" }}>
                <span style={{ fontSize:18 }}>{p.icon}</span>
                <div style={{ flex:1 }}>
                  <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                    <span style={{ color:provider===p.id?"white":"rgba(255,255,255,0.7)", fontSize:13, fontWeight:600 }}>{p.name}</span>
                    <span style={{ background:`${p.color}20`, color:p.color, border:`1px solid ${p.color}30`, fontSize:8, fontFamily:"monospace", padding:"1px 6px", borderRadius:2, fontWeight:700 }}>{p.badge}</span>
                  </div>
                  <div style={{ color:"rgba(255,255,255,0.35)", fontSize:11, marginTop:2 }}>{p.description}</div>
                </div>
                <div style={{ width:15, height:15, borderRadius:"50%", border:`2px solid ${provider===p.id?p.color:"rgba(255,255,255,0.2)"}`, background:provider===p.id?p.color:"transparent", flexShrink:0 }}/>
              </div>
            ))}
          </div>
          {/* Fields */}
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, padding:"18px 20px" }}>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:12 }}>{currentProvider.name} Configuration</div>
            {currentProvider.fields.map(f=>(
              <div key={f.key} style={{ marginBottom:12 }}>
                <label style={{ color:"rgba(255,255,255,0.45)", fontSize:10, fontFamily:"monospace", letterSpacing:"1px", textTransform:"uppercase", display:"block", marginBottom:6 }}>{f.label}</label>
                <input type={f.type} value={fields[f.key]||""} onChange={e=>updateField(f.key,e.target.value)} placeholder={f.placeholder}
                  style={{ width:"100%", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", color:"white",
                    padding:"10px 14px", borderRadius:4, fontSize:13, fontFamily:"monospace", outline:"none", boxSizing:"border-box" }}/>
              </div>
            ))}
            {currentProvider.models && (
              <div style={{ marginBottom:12 }}>
                <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace", marginBottom:8 }}>QUICK SELECT</div>
                <div style={{ display:"flex", gap:5, flexWrap:"wrap" }}>
                  {currentProvider.models.map(m=>(
                    <button key={m} onClick={()=>updateField("model",m)}
                      style={{ background:fields.model===m?`${currentProvider.color}20`:"rgba(255,255,255,0.04)",
                        color:fields.model===m?currentProvider.color:"rgba(255,255,255,0.4)",
                        border:`1px solid ${fields.model===m?currentProvider.color+"40":"rgba(255,255,255,0.08)"}`,
                        borderRadius:3, padding:"4px 10px", fontSize:10, fontFamily:"monospace", cursor:"pointer" }}>{m}</button>
                  ))}
                </div>
              </div>
            )}
            <div style={{ display:"flex", gap:8, alignItems:"center" }}>
              <button onClick={testConnection} disabled={testStatus==="testing"}
                style={{ background:"rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.7)", border:"1px solid rgba(255,255,255,0.12)",
                  borderRadius:4, padding:"8px 16px", fontFamily:"monospace", fontSize:11, cursor:"pointer" }}>
                {testStatus==="testing"?"Testing…":"Test Connection"}
              </button>
              {testStatus==="ok"   && <span style={{ color:"#00e5a0", fontSize:11, fontFamily:"monospace" }}>✓ {testMsg}</span>}
              {testStatus==="fail" && <span style={{ color:"#ff3b3b", fontSize:11, fontFamily:"monospace" }}>✗ {testMsg}</span>}
            </div>
          </div>

          {/* Module URL overrides */}
          <div style={{ marginTop:16, background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, padding:"18px 20px" }}>
            <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:12 }}>Module URL Overrides</div>
            {[{id:"cyiris",label:"CyIRIS URL"},{id:"cysoar",label:"CySOAR URL"},{id:"cysiem",label:"CySIEM URL"}].map(({id,label})=>(
              <div key={id} style={{ display:"flex", gap:8, alignItems:"center", marginBottom:10 }}>
                <label style={{ color:"rgba(255,255,255,0.4)", fontSize:11, fontFamily:"monospace", width:110, flexShrink:0 }}>{label}</label>
                <input value={moduleUrls[id]||""} onChange={e=>setModuleUrls(prev=>({...prev,[id]:e.target.value}))}
                  placeholder={`https://${id}.${_BASE_DOMAIN}`}
                  style={{ flex:1, background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)",
                    color:"white", padding:"8px 12px", borderRadius:4, fontSize:12, fontFamily:"monospace", outline:"none" }}/>
              </div>
            ))}
          </div>
        </div>

        {/* Prompt config */}
        <div>
          <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace", marginBottom:14 }}>Prompt Configuration</div>
          <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:6, overflow:"hidden" }}>
            <div style={{ display:"flex", borderBottom:"1px solid rgba(255,255,255,0.07)" }}>
              {[{id:"system",label:"System"},{id:"asm_context",label:"ASM Context"},{id:"vuln_analysis",label:"Vuln Analysis"}].map(t=>(
                <button key={t.id} onClick={()=>setActivePTab(t.id)}
                  style={{ flex:1, background:activePromptTab===t.id?"rgba(0,229,160,0.08)":"transparent",
                    color:activePromptTab===t.id?"#00e5a0":"rgba(255,255,255,0.4)",
                    border:"none", borderBottom:`2px solid ${activePromptTab===t.id?"#00e5a0":"transparent"}`,
                    padding:"10px 0", fontFamily:"monospace", fontSize:10, letterSpacing:"1px", cursor:"pointer" }}>{t.label}</button>
              ))}
            </div>
            <div style={{ padding:16 }}>
              <textarea value={prompts[activePromptTab]||""} onChange={e=>updatePrompt(activePromptTab,e.target.value)} rows={14}
                style={{ width:"100%", background:"rgba(0,0,0,0.3)", border:"1px solid rgba(255,255,255,0.08)",
                  color:"rgba(255,255,255,0.8)", fontFamily:"monospace", fontSize:11, padding:12, borderRadius:4,
                  outline:"none", resize:"vertical", lineHeight:1.7, boxSizing:"border-box" }}/>
              <div style={{ display:"flex", justifyContent:"space-between", marginTop:8 }}>
                <span style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>{(prompts[activePromptTab]||"").length} chars</span>
                <button onClick={()=>resetPrompt(activePromptTab)}
                  style={{ background:"none", color:"rgba(255,255,255,0.3)", border:"1px solid rgba(255,255,255,0.1)",
                    borderRadius:3, padding:"4px 12px", fontSize:10, fontFamily:"monospace", cursor:"pointer" }}>Reset</button>
              </div>
            </div>
          </div>
          <div style={{ background:"rgba(0,0,0,0.3)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:4, padding:"12px 16px", marginTop:12 }}>
            <div style={{ color:"rgba(255,255,255,0.25)", fontSize:10, fontFamily:"monospace", lineHeight:1.8 }}>
              <strong style={{color:"rgba(255,255,255,0.4)"}}>Available variables:</strong><br/>
              <code style={{color:"#00e5a0"}}>{"{{asset_host}}"}</code> · <code style={{color:"#00e5a0"}}>{"{{asset_risk}}"}</code> · <code style={{color:"#00e5a0"}}>{"{{vuln_count}}"}</code> · <code style={{color:"#00e5a0"}}>{"{{scan_date}}"}</code>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display:"flex", gap:12, marginTop:28, alignItems:"center" }}>
        <button onClick={handleSave}
          style={{ background:"#00e5a0", color:"#0d0f14", border:"none", borderRadius:4,
            padding:"12px 32px", fontFamily:"monospace", fontSize:13, fontWeight:700,
            cursor:"pointer", letterSpacing:"1px", textTransform:"uppercase" }}>
          Save AI Configuration
        </button>
        {saved && <span style={{ color:"#00e5a0", fontSize:12, fontFamily:"monospace" }}>✓ Saved</span>}
        <div style={{ flex:1 }}/>
        <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:4, padding:"8px 14px" }}>
          <span style={{ color:"rgba(255,255,255,0.3)", fontSize:11, fontFamily:"monospace" }}>Active: </span>
          <span style={{ color:currentProvider.color, fontSize:11, fontFamily:"monospace", fontWeight:700 }}>
            {currentProvider.icon} {currentProvider.name} {fields.model?`· ${fields.model}`:""}
          </span>
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// ── MAIN APP ──────────────────────────────────────────────────────────────────
function CyCentra360() {
  const [user,           setUser]           = useState(null);
  const [authReady,      setAuthReady]      = useState(false);   // ← ADD
  const [data,           setData]           = useState(null);
  const [assets,         setAssets]         = useState([]);
  const [activeTab,      setActiveTab]      = useState(() => sessionStorage.getItem("cycentra_tab") || "dashboard");
  const [selectedAsset,  setSelectedAsset]  = useState(null);
  const [showImport,     setShowImport]     = useState(false);
  const [installedModules, setInstalledModules] = useState({});
  const [aiConfig,       setAiConfig]       = useState({ provider:"local", fields:{ baseUrl:"", model:"mistral:7b" }, prompts:DEFAULT_PROMPTS });

  // ── Persist active tab across page refreshes ────────────────────────────
  useEffect(() => { sessionStorage.setItem("cycentra_tab", activeTab); }, [activeTab]);

  // ── OAuth callback & session restore ────────────────────────────────────
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("auth")==="success") {
      console.log("[Auth] OAuth callback detected");
      const name  = decodeURIComponent(params.get("name")||"");
      const email = decodeURIComponent(params.get("email")||"");
      const uid   = params.get("uid") || `user_${Math.random().toString(36).slice(2,8)}`;
      const provider = params.get("provider")||"google";
      const avatar   = name.split(" ").map(w=>w[0]).join("").slice(0,2).toUpperCase();
      
      const ssoToken = params.get("sso_token") || "";
      console.log("[Auth] SSO Token received:", ssoToken ? "Yes" : "No");
      if (ssoToken) {
        setSSOToken(ssoToken);
      } else {
        console.warn("[Auth] No SSO token in OAuth callback!");
      }
      
      const u = { id:uid, name, email, avatar, provider };
      console.log("[Auth] Saving user:", u);
      saveUser(u);
      setUser(u);
      setAuthReady(true);
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (params.get("logged_out")==="1") {
      console.log("[Auth] Logout detected");
      clearSSOToken();
      setUser(null); setData(null); setAssets([]);
      setAuthReady(true);
      window.history.replaceState({}, document.title, window.location.pathname);
    } else {
      // Page refresh — restore session from localStorage if user data exists
      const savedU = getSavedUser();
      console.log("[Auth] Page refresh detected. Saved user:", savedU);
      if (savedU) {
        console.log("[Auth] Restoring user session:", savedU.email);
        setUser(savedU);
      } else {
        console.log("[Auth] No saved user found in localStorage");
      }
      setAuthReady(true);
    }
  }, []);

  // ── Load saved state ─────────────────────────────────────────────────────
  useEffect(() => {
    try {
      const saved = localStorage.getItem("cycentra_ai_config");
      if (saved) setAiConfig(JSON.parse(saved));
      const mods = localStorage.getItem("cycentra_modules");
      if (mods)  setInstalledModules(JSON.parse(mods));
    } catch {}
  }, []);

  // ── Load latest scan on login ────────────────────────────────────────────
  useEffect(() => {
    if (user && !data) {
      fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user.id||"")}`, { credentials:"include" })
        .then(res=>res.ok?res.json():null)
        .then(raw=>{ if (raw?.assets) { const a=adaptCyCentraJSON(raw); if(a){setData(a);setAssets(a.assets);}} })
        .catch(()=>{});
    }
  }, [user, data]);

  const handleImport = (raw) => {
    const adapted = adaptCyCentraJSON(raw);
    if (adapted) { setData(adapted); setAssets(adapted.assets); }
  };

  const handleStatusChange = (id, status) => setAssets(prev=>prev.map(a=>a.id===id?{...a,status}:a));

  const handleInstallModule = (moduleId, config) => {
    const updated = { ...installedModules, [moduleId]:{ status:"running", config, installedAt:new Date().toISOString() } };
    setInstalledModules(updated);
    try { localStorage.setItem("cycentra_modules", JSON.stringify(updated)); } catch {}
  };

  const handleUninstallModule = (moduleId) => {
    const updated = {...installedModules}; delete updated[moduleId];
    setInstalledModules(updated);
    try { localStorage.setItem("cycentra_modules", JSON.stringify(updated)); } catch {}
    fetch(`${API_BASE}/api/platform/uninstall`, { method:"POST", headers:{"Content-Type":"application/json"}, credentials:"include", body:JSON.stringify({module:moduleId}) }).catch(()=>{});
  };

  const handleSaveAIConfig = (config) => {
    setAiConfig(config);
    try { localStorage.setItem("cycentra_ai_config", JSON.stringify(config)); } catch {}
  };
  
  console.log("[Auth] Render - authReady:", authReady, "user:", user?.email || null);
  if (!authReady) return null;
  if (!user) return <LoginScreen/>;

  const stats = {
    total:      assets.length,
    critical:   assets.filter(a=>a.risk==="critical").length,
    high:       assets.filter(a=>a.risk==="high").length,
    open:       assets.filter(a=>a.status==="open").length,
    totalVulns: assets.reduce((acc,a)=>acc+(a.vulnerabilities?.length||0),0),
    exposedPaths:assets.reduce((acc,a)=>acc+(a.exposed_paths?.length||0),0),
  };

  const scanTime = data?.meta?.last_scan ? new Date(data.meta.last_scan).toLocaleString() : "—";
  const addonInstalled = Object.entries(installedModules).filter(([id])=>PLATFORM_MODULES[id]?.tier==="addon");

  // ── Sidebar nav ───────────────────────────────────────────────────────────
  const SvgDash  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>;
  const SvgAsset = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>;
  const SvgVuln  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg>;
  const SvgSIEM  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>;
  const SvgScan  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35M11 8v6M8 11h6"/></svg>;
  const SvgUC    = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M4 6h16M4 10h16M4 14h10M4 18h6"/></svg>;
  const SvgMods  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>;
  const SvgAI    = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>;

  const NAV_SECTIONS = [
    {
      section: "MONITOR",
      items: [
        { id:"dashboard",  label:"Dashboard",       icon:SvgDash },
        { id:"assets",     label:"Assets",          icon:SvgAsset },
        { id:"vulns",      label:"Vulnerabilities", icon:SvgVuln },
        { id:"cysiemfeed", label:"CySIEM Feed",     icon:SvgSIEM, badge:data?.cysiemAlerts?.length||0 },
        { id:"siem-incidents", label:"Incidents",   icon:<span style={{fontSize:13}}>🔥</span>, accent:"#ff3b3b" },
        { id:"siem-risk",      label:"Risk Scores", icon:<span style={{fontSize:13}}>⚡</span>, accent:"#ff8c00" },
        { id:"siem-ueba",      label:"UEBA",        icon:<span style={{fontSize:13}}>👤</span>, accent:"#b06eff" },
      ]
    },
    {
      section: "ACTIONS",
      items: [
        { id:"scan",       label:"New Scan",        icon:SvgScan, accent:"#00e5a0" },
        { id:"usecases",   label:"Use Cases",       icon:SvgUC,   accent:"#4d9eff" },
      ]
    },
    {
      section: "PLATFORM",
      items: [
        { id:"platform",   label:"Modules",         icon:SvgMods, badge:addonInstalled.length||0, accent:"#b06eff" },
        { id:"ai-settings",label:"AI Settings",     icon:SvgAI,   accent:"#4d9eff" },
      ]
    },
    // OPEN section — CySIEM (always-on base module) + any installed add-ons
    {
      section: "OPEN",
      items: [
        // CySIEM is always active as a base module
        { id:"open-cysiem", label:"CySIEM", icon:<span style={{fontSize:14}}>👁️</span>,
          accent:"#ff8c00", externalUrl:getModuleUrl("cysiem") },
        // Installed add-on modules — embedded ones open in same tab at their path, others navigate to subdomain
        ...addonInstalled.map(([id]) => {
          const mod = PLATFORM_MODULES[id];
          return {
            id: `open-${id}`,
            label: mod?.name,
            icon: <span style={{fontSize:14}}>{mod?.icon}</span>,
            accent: mod?.color,
            externalUrl: mod?.embeddedPath || getModuleUrl(id),
          };
        })
      ]
    },
  ];

  return (
    <div style={{ height:"100vh", background:"#090b10", fontFamily:"'Barlow',sans-serif", color:"white", display:"flex", flexDirection:"column" }}>
      <style>{GLOBAL_CSS}</style>

      {/* ── Top bar ── */}
      <div style={{ height:52, background:"rgba(10,12,18,0.98)", borderBottom:"1px solid rgba(255,255,255,0.06)",
        display:"flex", alignItems:"center", justifyContent:"space-between",
        padding:"0 20px 0 0", position:"sticky", top:0, zIndex:60, backdropFilter:"blur(16px)", flexShrink:0 }}>

        {/* Logo */}
        <div style={{ width:220, display:"flex", alignItems:"center", gap:10, padding:"0 20px", flexShrink:0 }}>
          <svg width="22" height="22" viewBox="0 0 24 24" style={{ animation:"hexPulse 4s ease-in-out infinite", flexShrink:0 }}>
            <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
            <polygon points="12,6 18,10 18,14 12,18 6,14 6,10" fill="rgba(0,229,160,0.12)" stroke="#00e5a0" strokeWidth="0.75"/>
            <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
          </svg>
          <div>
            <div style={{ color:"white", fontFamily:"'Space Mono',monospace", fontSize:13, fontWeight:700, letterSpacing:"2px", lineHeight:1.1 }}>CY<span style={{color:"#00e5a0"}}>CENTRA</span></div>
            <div style={{ color:"#00e5a0", fontFamily:"'Space Mono',monospace", fontSize:8, letterSpacing:"4px", opacity:0.6, marginTop:1 }}>360°</div>
          </div>
        </div>

        {/* Right: AI chip, scan indicator, import, user */}
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ display:"flex", alignItems:"center", gap:5, padding:"3px 9px",
            background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:20 }}>
            <span style={{ fontSize:11 }}>{AI_PROVIDERS[aiConfig.provider]?.icon}</span>
            <span style={{ color:AI_PROVIDERS[aiConfig.provider]?.color, fontSize:10, fontFamily:"monospace", fontWeight:700 }}>
              {AI_PROVIDERS[aiConfig.provider]?.name}
            </span>
          </div>

          {data && (
            <div style={{ display:"flex", alignItems:"center", gap:5 }}>
              <span style={{ width:5, height:5, borderRadius:"50%", background:"#00e5a0", display:"inline-block", animation:"pulse 2s infinite", boxShadow:"0 0 6px #00e5a0" }}/>
              <span style={{ color:"rgba(255,255,255,0.3)", fontSize:10, fontFamily:"monospace" }}>{data.meta?.domain?.toUpperCase()}</span>
            </div>
          )}

          <button onClick={()=>setShowImport(true)}
            style={{ background:"rgba(0,229,160,0.08)", color:"#00e5a0", border:"1px solid rgba(0,229,160,0.25)",
              padding:"5px 12px", borderRadius:20, fontSize:11, fontFamily:"monospace",
              cursor:"pointer", fontWeight:700, display:"flex", alignItems:"center", gap:5 }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Import
          </button>

          <div style={{ width:1, height:24, background:"rgba(255,255,255,0.08)" }}/>

          {/* User */}
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:28, height:28, borderRadius:"50%", background:"rgba(0,229,160,0.12)", border:"1.5px solid rgba(0,229,160,0.3)",
              display:"flex", alignItems:"center", justifyContent:"center", color:"#00e5a0", fontSize:10, fontWeight:700, fontFamily:"monospace" }}>
              {user.avatar}
            </div>
            <div style={{ lineHeight:1.3 }}>
              <div style={{ color:"rgba(255,255,255,0.75)", fontSize:12, fontWeight:600 }}>{user.name}</div>
              <div style={{ color:"rgba(255,255,255,0.25)", fontSize:9, fontFamily:"monospace" }}>{user.provider?.toUpperCase()} SSO</div>
            </div>
            <button onClick={()=>{ clearSSOToken(); window.location.href=`${CYSCAN_URL}/auth/logout?provider=${encodeURIComponent(user.provider||"google")}`; }}
              style={{ background:"transparent", color:"rgba(255,255,255,0.25)", border:"none", padding:"4px 6px", borderRadius:3, fontSize:10, fontFamily:"monospace", cursor:"pointer" }}
              title="Sign out">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            </button>
          </div>
        </div>
      </div>

      {/* ── Body ── */}
      <div style={{ display:"flex", flex:1, overflow:"hidden" }}>

        {/* Sidebar */}
        <div style={{ width:220, background:"rgba(10,12,18,0.95)", borderRight:"1px solid rgba(255,255,255,0.06)",
          display:"flex", flexDirection:"column", position:"sticky", top:52,
          height:"calc(100vh - 52px)", overflowY:"auto", flexShrink:0 }}>
          <div style={{ flex:1, padding:"16px 10px" }}>
            {NAV_SECTIONS.map((sec,si) => (
              <div key={si} style={{ marginBottom:22 }}>
                <div style={{ color:"rgba(255,255,255,0.2)", fontSize:9, fontFamily:"monospace", letterSpacing:"1.8px", fontWeight:700, padding:"0 10px", marginBottom:4 }}>{sec.section}</div>
                {sec.items.map(item => {
                  const active = activeTab===item.id;
                  const accent = item.accent||"#00e5a0";
                  // External: navigate same-tab with pushState
                  if (item.externalUrl) return (
                    <button key={item.id} className="side-item"
                      onClick={()=>{ window.history.pushState({from:"portal"},"",window.location.pathname); window.location.href=item.externalUrl; }}
                      style={{ width:"100%", display:"flex", alignItems:"center", gap:10, padding:"9px 10px", borderRadius:6, marginBottom:2,
                        border:"none", background:"transparent", color:"rgba(255,255,255,0.5)", cursor:"pointer", textAlign:"left" }}>
                      <span style={{ flexShrink:0, opacity:0.7 }}>{item.icon}</span>
                      <span style={{ fontSize:13, fontWeight:500, flex:1 }}>{item.label}</span>
                      <svg style={{ opacity:0.3 }} width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                    </button>
                  );
                  return (
                    <button key={item.id} className="side-item" onClick={()=>setActiveTab(item.id)}
                      style={{ width:"100%", display:"flex", alignItems:"center", gap:10, padding:"9px 10px",
                        borderRadius:6, marginBottom:2, border:"none",
                        background:active?`${accent}14`:"transparent",
                        color:active?accent:"rgba(255,255,255,0.5)",
                        cursor:"pointer", textAlign:"left",
                        boxShadow:active?`inset 2px 0 0 ${accent}`:"none" }}>
                      <span style={{ flexShrink:0, color:active?accent:"rgba(255,255,255,0.35)" }}>{item.icon}</span>
                      <span style={{ fontSize:13, fontWeight:active?600:400, flex:1 }}>{item.label}</span>
                      {item.badge>0 && (
                        <span style={{ background:active?accent:"rgba(255,255,255,0.1)", color:active?"#0d0f14":"rgba(255,255,255,0.5)",
                          fontSize:9, fontWeight:700, fontFamily:"monospace", padding:"1px 6px", borderRadius:10, flexShrink:0 }}>
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>

          {/* Sidebar footer */}
          <div style={{ padding:"12px 16px", borderTop:"1px solid rgba(255,255,255,0.05)" }}>
            {data ? (
              <div>
                <div style={{ color:"rgba(255,255,255,0.2)", fontSize:9, fontFamily:"monospace", letterSpacing:"1px", marginBottom:3 }}>LAST SCAN</div>
                <div style={{ color:"rgba(255,255,255,0.45)", fontSize:10, fontFamily:"monospace" }}>{data.meta?.domain}</div>
                <div style={{ color:"rgba(255,255,255,0.2)", fontSize:9, marginTop:2 }}>{scanTime}</div>
              </div>
            ) : <div style={{ color:"rgba(255,255,255,0.2)", fontSize:10, fontFamily:"monospace" }}>No scan loaded</div>}
          </div>
        </div>

        {/* ── Main Content ── */}
        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden", background:"#090b10",
          backgroundImage:"radial-gradient(ellipse at 20% 30%, rgba(0,229,160,0.025) 0%, transparent 50%), radial-gradient(ellipse at 80% 10%, rgba(0,120,255,0.03) 0%, transparent 50%)" }}>
          {/* ── Page content ── */}
          <div style={{ flex:1, overflowY:"auto" }}>
            <div style={{ padding:"28px 32px", animation:"fadeIn 0.35s ease", maxWidth:1300, margin:"0 auto" }}>

                {activeTab==="scan" && (
                  <ScanPage user={user} onScanComplete={(raw)=>{ const a=adaptCyCentraJSON(raw); if(a){setData(a);setAssets(a.assets);setActiveTab("dashboard");} }}/>
                )}
                {activeTab==="dashboard" && (
                  <DashboardTab assets={assets} data={data} stats={stats}
                    installedModules={installedModules} setActiveTab={setActiveTab}
                    setSelectedAsset={setSelectedAsset} setShowImport={setShowImport}/>
                )}
                {activeTab==="assets" && (
                  <div>
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:20 }}>
                      <div>
                        <h1 style={{ fontSize:22, fontWeight:700 }}>Asset Inventory</h1>
                        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13, marginTop:4 }}>{assets.length} asset{assets.length!==1?"s":""}</p>
                      </div>
                    </div>
                    <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:4, overflow:"hidden" }}>
                      <div style={{ display:"grid", gridTemplateColumns:"110px 1fr 120px 160px 140px 90px 110px", padding:"10px 20px", borderBottom:"1px solid rgba(255,255,255,0.06)", color:"rgba(255,255,255,0.3)", fontSize:10, letterSpacing:"1.2px", textTransform:"uppercase", fontFamily:"monospace" }}>
                        <span>Risk</span><span>Host</span><span>IP</span><span>Type</span><span>Ports</span><span>Findings</span><span>Status</span>
                      </div>
                      {assets.length===0 && <div style={{ padding:"32px 20px", textAlign:"center", color:"rgba(255,255,255,0.2)", fontFamily:"monospace" }}>No assets — import a scan or launch a new one</div>}
                      {assets.map((a,i) => (
                        <div key={a.id} className="asset-row" onClick={()=>setSelectedAsset(a)}
                          style={{ display:"grid", gridTemplateColumns:"110px 1fr 120px 160px 140px 90px 110px", padding:"13px 20px",
                            borderBottom:"1px solid rgba(255,255,255,0.04)",
                            background:i%2===0?"transparent":"rgba(255,255,255,0.01)", alignItems:"center" }}>
                          <span><Badge risk={a.risk}/></span>
                          <div>
                            <div style={{ color:"white", fontFamily:"monospace", fontSize:12 }}>{a.host}</div>
                            <div style={{ color:"rgba(255,255,255,0.3)", fontSize:10, marginTop:2 }}>{a.owner}</div>
                            {a.subdomains?.length>0 && <div style={{ color:"rgba(0,229,160,0.4)", fontSize:10, marginTop:1 }}>{a.subdomains.length} subdomains</div>}
                          </div>
                          <span style={{ color:"rgba(255,255,255,0.5)", fontFamily:"monospace", fontSize:11 }}>{a.ip}</span>
                          <span style={{ color:"rgba(255,255,255,0.6)", fontSize:12 }}>{a.type}</span>
                          <div style={{ display:"flex", gap:4, flexWrap:"wrap" }}>
                            {(a.ports||[]).slice(0,4).map(p=><span key={p} style={{color:"#00e5a0",fontSize:10,fontFamily:"monospace"}}>:{p}</span>)}
                            {(a.ports?.length||0)>4 && <span style={{color:"rgba(0,229,160,0.4)",fontSize:10,fontFamily:"monospace"}}>+{a.ports.length-4}</span>}
                            {(!a.ports||a.ports.length===0) && <span style={{color:"rgba(255,255,255,0.2)",fontFamily:"monospace",fontSize:11}}>—</span>}
                          </div>
                          <span style={{ color:(a.vulnerabilities?.length||0)>0?"#ff3b3b":"rgba(255,255,255,0.25)", fontFamily:"monospace", fontSize:12, fontWeight:(a.vulnerabilities?.length||0)>0?700:400 }}>
                            {(a.vulnerabilities?.length||0)>0?`▲ ${a.vulnerabilities.length}`:"—"}
                          </span>
                          <StatusBadge status={a.status}/>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {activeTab==="vulns"      && <VulnerabilityPage assets={assets}/>}
                {activeTab==="cysiemfeed" && <CySIEMFeedPage data={data} installedModules={installedModules}/>}
                {activeTab==="siem-incidents" && <SiemIncidentsPage />}
                {activeTab==="siem-risk"      && <SiemRiskScoresPage />}
                {activeTab==="siem-ueba"      && <SiemUebaPage />}
                {activeTab==="usecases"   && <UseCasesPage/>}
                {activeTab==="platform"   && <PlatformPage installedModules={installedModules} onInstall={handleInstallModule} onUninstall={handleUninstallModule}/>}
                {activeTab==="ai-settings"&& <AISettingsPage aiConfig={aiConfig} onSave={handleSaveAIConfig}/>}
              </div>
            </div>
        </div>
      </div>

      {/* Modals */}
      {selectedAsset && <AssetModal asset={selectedAsset} onClose={()=>setSelectedAsset(null)} onStatusChange={handleStatusChange}/>}
      {showImport && <ImportModal onClose={()=>setShowImport(false)} onImport={handleImport}/>}
    </div>
  );
}

// ── CySIEM Feed Page (inline — small enough) ──────────────────────────────────
function CySIEMFeedPage({ data, installedModules }) {
  return (
    <div>
      <div style={{ marginBottom:22 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:8 }}>
          <h1 style={{ fontSize:22, fontWeight:700 }}>CySIEM Integration Feed</h1>
          <span style={{ background:"rgba(255,59,59,0.12)", color:"#ff3b3b", fontSize:10, fontFamily:"monospace", padding:"3px 10px", borderRadius:2, fontWeight:700, letterSpacing:"1px" }}>LIVE BRIDGE</span>
        </div>
        <p style={{ color:"rgba(255,255,255,0.35)", fontSize:13 }}>Critical/High CyCentra findings forwarded to CySIEM as custom rules.</p>
      </div>

      {/* Architecture */}
      <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:4, padding:"20px 24px", marginBottom:22 }}>
        <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", marginBottom:16, fontFamily:"monospace" }}>Integration Architecture</div>
        <div style={{ display:"flex", alignItems:"center", flexWrap:"wrap", gap:8 }}>
          {[
            { label:"cycentra_scan.py", sub:"Python Scanner", color:"#00e5a0" }, null,
            { label:"CyCentra 360", sub:"This Portal", color:"#00e5a0" }, null,
            { label:"NDJSON / Syslog", sub:"Critical+High only", color:"#f5c518" }, null,
            { label:"CySIEM", sub:"Alerts + Correlation", color:"#ff8c00" }, null,
            { label:"CySOAR", sub:"Auto-response", color:"#4d9eff" }, null,
            { label:"SOC Analyst", sub:"Unified triage", color:"rgba(255,255,255,0.5)" },
          ].map((item,i) => item===null
            ? <div key={i} style={{ color:"rgba(255,255,255,0.2)", fontSize:14, fontFamily:"monospace" }}>→</div>
            : <div key={i} style={{ background:"rgba(255,255,255,0.03)", border:`1px solid ${item.color}30`, borderTop:`2px solid ${item.color}`, padding:"10px 16px", borderRadius:3, textAlign:"center" }}>
                <div style={{ color:item.color, fontFamily:"monospace", fontSize:11, fontWeight:700 }}>{item.label}</div>
                <div style={{ color:"rgba(255,255,255,0.3)", fontSize:9, marginTop:3 }}>{item.sub}</div>
              </div>
          )}
        </div>
      </div>

      <div style={{ marginBottom:16, color:"rgba(255,255,255,0.45)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", fontFamily:"monospace" }}>
        Forwarded Alerts ({data?.cysiemAlerts?.length||0})
      </div>
      <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
        {(data?.cysiemAlerts||[]).map((a,i)=>{
          const lvlColor=a.level>=12?"#ff3b3b":a.level>=8?"#ff8c00":"#f5c518";
          return (
            <div key={i} style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.07)",
              borderLeft:`4px solid ${lvlColor}`, padding:"16px 20px", borderRadius:3,
              display:"grid", gridTemplateColumns:"80px 1fr 1fr 180px", gap:14, alignItems:"center" }}>
              <div>
                <div style={{ color:lvlColor, fontSize:20, fontFamily:"monospace", fontWeight:800 }}>{a.level}</div>
                <div style={{ color:"rgba(255,255,255,0.3)", fontSize:9, fontFamily:"monospace" }}>SIEM LEVEL</div>
              </div>
              <div>
                <div style={{ color:"rgba(255,255,255,0.7)", fontSize:13 }}>{a.description}</div>
                <div style={{ color:"rgba(255,255,255,0.3)", fontSize:11, fontFamily:"monospace", marginTop:4 }}>Rule: {a.rule_id}</div>
              </div>
              <div style={{ color:"rgba(255,255,255,0.5)", fontFamily:"monospace", fontSize:12 }}>{a.asset}</div>
              <div style={{ color:"rgba(255,255,255,0.3)", fontFamily:"monospace", fontSize:11 }}>{new Date(a.ts).toLocaleString()}</div>
            </div>
          );
        })}
        {!data?.cysiemAlerts?.length && <div style={{ textAlign:"center", padding:"40px 0", color:"rgba(255,255,255,0.2)", fontFamily:"monospace" }}>No alerts — import a scan to populate</div>}
      </div>

      <div style={{ marginTop:24, background:"rgba(0,0,0,0.4)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:4, padding:"18px 22px" }}>
        <div style={{ color:"rgba(255,255,255,0.35)", fontSize:10, letterSpacing:"1.5px", textTransform:"uppercase", marginBottom:12, fontFamily:"monospace" }}>CySIEM Custom Rule Example</div>
        <pre style={{ color:"#00e5a0", fontSize:11, fontFamily:"monospace", overflowX:"auto", lineHeight:1.7 }}>{`<rule id="100001" level="12">
  <decoded_as>json</decoded_as>
  <field name="asm.risk">critical</field>
  <description>CyCentra 360: Critical risk asset detected</description>
</rule>

<rule id="100002" level="10">
  <decoded_as>json</decoded_as>
  <field name="ssl.days_to_expiry">^[0-2]?[0-9]$</field>
  <description>CyCentra 360: Certificate expiring within 30 days</description>
</rule>`}</pre>
      </div>
    </div>
  );
}

export default CyCentra360;