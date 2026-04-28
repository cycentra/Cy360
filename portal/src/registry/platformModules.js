/**
 * src/registry/platformModules.js
 *
 * CyIRIS  — only asks for password (username is always 'administrator')
 * CyMISP  — only asks for admin email + passphrase (redis auto-generated)
 * CySOAR  — no config fields (all auto-generated)
 */

import { _BASE_DOMAIN } from '../core/constants.js';

export const PLATFORM_MODULES = {

  cysiem: {
    id: "cysiem", tier: "base",
    name: "CySIEM",
    fullName: "CySIEM — Endpoint & Log Intelligence",
    description: "Powered by Wazuh, CySIEM Engine. Endpoint detection, log analysis, FIM, vulnerability scanning and alerting. Core Base 360 module — always active.",
    icon: "👁️", color: "#ff8c00",
    ram_gb: 8, disk_gb: 50, install_time: "N/A",
    port: 443, healthPath: "/api/status",
    ssoProtocol: "proxy",
    features: ["Endpoint monitoring","Log analysis","FIM","Vuln detection","Threat intelligence","Custom rules","SAML SSO"],
    docsUrl: "https://documentation.wazuh.com",
    embeddedPath: null,
    modulePath: `/cysiem/`,
  },

  cyiris: {
    id: "cyiris", tier: "addon",
    name: "CyIRIS",
    fullName: "CyIRIS — Incident Response & Case Management",
    description: "DFIR IRIS-powered incident response platform. Track cases, IOCs, timelines and collaborate on security incidents.",
    icon: "🎫", color: "#b06eff",
    ram_gb: 3, disk_gb: 20, install_time: "4–6 minutes",
    port: 4433, healthPath: "/api/v2/ping",
    ssoProtocol: "OIDC",
    features: ["Case management","IOC tracking","Evidence chain","Timeline analysis","OIDC SSO"],
    docsUrl: "https://cycentra.org/docs/cyiris",
    embeddedPath: null,
    modulePath: `/cyiris/`,
    // Username is always 'administrator' — only ask for password
    configFields: [
      { key: "IRIS_ADM_PASSWORD", label: "Admin Password", type: "password",
        help: "Password for the 'administrator' account. Username is always: administrator" },
    ],
    defaultConfig: { IRIS_ADM_PASSWORD: "" },
  },

  cysoar: {
    id: "cysoar", tier: "addon",
    name: "CySOAR",
    fullName: "CySOAR — Security Orchestration & Automation",
    description: "Powered by Node-RED, CySOAR engine. Pre-loaded with SOC use cases — alert triage, IOC enrichment, brute-force response and more.",
    icon: "🛡️", color: "#4d9eff",
    embedded: true, embeddedPath: "/cysoar/",
    ram_gb: 2, disk_gb: 10, install_time: "3–5 minutes",
    port: 1880, healthPath: "/health",
    ssoProtocol: "OIDC",
    features: ["Alert triage","IOC enrichment","Brute-force response","Phishing response","OIDC SSO"],
    docsUrl: "https://cycentra.org/docs/cysoar",
    modulePath: `/cysoar/`,
    configFields: [],   // all secrets auto-generated
    defaultConfig: {
      cysoarOidcSecret:    Array.from({ length: 24 }, () => Math.random().toString(36)[2]).join(""),
      cysoarSessionSecret: Array.from({ length: 32 }, () => Math.random().toString(36)[2]).join(""),
    },
  },
};
