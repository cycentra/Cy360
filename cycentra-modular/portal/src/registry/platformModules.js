/**
 * src/registry/platformModules.js
 * ================================
 * Platform module registry — metadata, compose templates, SSO config.
 * This is the single file to edit when adding or updating a module.
 *
 * Replaces PLATFORM_MODULES in App.jsx AND merges with
 * the now-deleted portal/src/config/constants.js MODULES dict.
 */

import { _BASE_DOMAIN } from '../core/constants.js';

export const PLATFORM_MODULES = {

  // ── BASE: CySIEM ──────────────────────────────────────────────────────────
  cysiem: {
    id: "cysiem", tier: "base",
    name: "CySIEM",
    fullName: "CySIEM — Endpoint & Log Intelligence",
    description: "Wazuh-based SIEM. Endpoint detection, log analysis, FIM, vulnerability scanning and alerting. Core Base 360 module — always active.",
    icon: "👁️", color: "#ff8c00",
    ram_gb: 8, disk_gb: 50, install_time: "N/A",
    port: 443, healthPath: "/api/status",
    ssoProtocol: "SAML",
    ssoNotes: "Configure OpenSearch Security → SAML with PORTAL_URL as IdP.",
    features: ["Endpoint monitoring","Log analysis","FIM","Vuln detection","Threat intelligence","Custom rules","SAML SSO"],
    docsUrl: "https://documentation.wazuh.com",
    embeddedPath: null,
    // Path-based routing alias (used in navConfig for sidebar link)
    modulePath: `/cysiem/`,
  },

  // ── ADD-ON: CyIRIS ────────────────────────────────────────────────────────
  cyiris: {
    id: "cyiris", tier: "addon",
    name: "CyIRIS",
    fullName: "CyIRIS — Incident Response & Case Management",
    description: "DFIR IRIS-powered incident response platform. Track cases, IOCs, timelines and collaborate on security incidents. SSO via native OIDC.",
    icon: "🎫", color: "#b06eff",
    ram_gb: 3, disk_gb: 20, install_time: "4–6 minutes",
    port: 4433, healthPath: "/api/v2/ping",
    ssoProtocol: "OIDC",
    ssoNotes: "Point OIDC_PROVIDER_URL to the portal /oidc endpoint. Client ID: cyiris.",
    features: ["Case management","IOC tracking","Evidence chain","Timeline analysis","OIDC SSO","CySOAR integration"],
    docsUrl: "https://cycentra.org/docs/cyiris",
    embeddedPath: null,
    modulePath: `/cyiris/`,
    configFields: [
      { key: "IRIS_ADM_EMAIL",    label: "Admin Email",    type: "text",     help: "Initial admin email" },
      { key: "IRIS_ADM_PASSWORD", label: "Admin Password", type: "password", help: "Initial admin password" },
    ],
    defaultConfig: {
      IRIS_ADM_EMAIL:    "",
      IRIS_ADM_PASSWORD: "",
    },
  },

  // ── ADD-ON: CySOAR ────────────────────────────────────────────────────────
  cysoar: {
    id: "cysoar", tier: "addon",
    name: "CySOAR",
    fullName: "CySOAR — Security Orchestration & Automation",
    description: "Node-RED SOAR engine. Pre-loaded with SOC use cases — alert triage, IOC enrichment, brute-force response, malware isolation and more.",
    icon: "🛡️", color: "#4d9eff",
    embedded: true, embeddedPath: "/cysoar/",
    ram_gb: 2, disk_gb: 10, install_time: "3–5 minutes",
    port: 1880, healthPath: "/health",
    ssoProtocol: "OIDC",
    ssoNotes: "Client ID: cysoar. After install, register the client in the portal OIDC config.",
    features: ["Alert triage","IOC enrichment","Brute-force response","Malware isolation","Phishing response","OIDC SSO","CyIRIS integration"],
    docsUrl: "https://cycentra.org/docs/cysoar",
    modulePath: `/cysoar/`,
    configFields: [],
    defaultConfig: {
      cysoarOidcSecret:    Array.from({ length: 24 }, () => Math.random().toString(36)[2]).join(""),
      cysoarSessionSecret: Array.from({ length: 32 }, () => Math.random().toString(36)[2]).join(""),
    },
  },

  // ── ADD-ON: CyMISP ────────────────────────────────────────────────────────
  cymisp: {
    id: "cymisp", tier: "addon",
    name: "CyMISP",
    fullName: "CyMISP — Threat Intelligence Platform",
    description: "MISP open-source threat intelligence platform. Manage and correlate indicators of compromise, track threat actors, and enrich CySIEM incidents automatically.",
    icon: "🔍", color: "#e8a020",
    embedded: false, embeddedPath: null,
    ram_gb: 4, disk_gb: 10, install_time: "8–12 minutes",
    port: 8243, healthPath: "/users/login",
    ssoProtocol: "None",
    ssoNotes: "MISP uses its own local accounts. OIDC SSO can be configured later via MISP admin settings.",
    features: ["IOC management","Threat actor tracking","Galaxy clusters","STIX/TAXII","CySIEM enrichment","API integration"],
    docsUrl: "https://www.misp-project.org/documentation/",
    modulePath: `https://cymisp.${_BASE_DOMAIN}`,
    configFields: [
      { key: "MISP_ADMIN_EMAIL",      label: "Admin Email",       type: "text",     help: "MISP admin account email" },
      { key: "MISP_ADMIN_PASSPHRASE", label: "Admin Passphrase",  type: "password", help: "MISP admin password" },
      { key: "REDIS_PASSWORD",        label: "Redis Password",     type: "password", help: "Internal Redis password" },
    ],
    defaultConfig: {
      MISP_ADMIN_EMAIL:      "",
      MISP_ADMIN_PASSPHRASE: `MISP@${Math.random().toString(36).slice(2, 8).toUpperCase()}`,
      REDIS_PASSWORD:        Array.from({ length: 20 }, () => Math.random().toString(36)[2]).join(""),
    },
  },
};
