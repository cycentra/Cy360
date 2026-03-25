/**
 * CyCentra 360 Module Configuration
 * Path-based routing for internal traffic (zero DNS lookups)
 */

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE URLs - Path-based routing on cy360.domain.com
// ═══════════════════════════════════════════════════════════════════════════════

export const MODULE_URLS = {
  cysoar: '/cysoar/',    // Security Orchestration & Automation (Node-RED)
  cyiris: '/cyiris/',    // Incident Response & Investigation (DFIR-IRIS)
  cysiem: '/cysiem/'     // Security Information & Event Management (Wazuh)
};

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE METADATA
// ═══════════════════════════════════════════════════════════════════════════════

export const MODULES = {
  cysoar: {
    id: 'cysoar',
    name: 'CySOAR',
    title: 'Security Orchestration & Automation',
    description: 'Automate security workflows with Node-RED',
    icon: '🔄',
    color: '#10b981',
    url: MODULE_URLS.cysoar,
    features: [
      'Visual workflow automation',
      'Integration with security tools',
      'Custom playbook development',
      'Real-time event processing'
    ]
  },
  cyiris: {
    id: 'cyiris',
    name: 'CyIRIS',
    title: 'Incident Response & Investigation',
    description: 'DFIR-IRIS collaborative case management platform',
    icon: '🔍',
    color: '#f59e0b',
    url: MODULE_URLS.cyiris,
    features: [
      'Collaborative case management',
      'Evidence tracking',
      'Timeline reconstruction',
      'IOC management'
    ]
  },
  cysiem: {
    id: 'cysiem',
    name: 'CySIEM',
    title: 'Security Information & Event Management',
    description: 'Wazuh SIEM for threat detection and compliance',
    icon: '🛡️',
    color: '#3b82f6',
    url: MODULE_URLS.cysiem,
    features: [
      'Real-time threat detection',
      'Log analysis and correlation',
      'Compliance monitoring',
      'Vulnerability detection'
    ]
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get API backend URL from injected domain or fallback
 * @returns {string} Backend API URL
 */
export const getApiUrl = () => {
  const domain = window.__CYCENTRA_DOMAIN__ || 'cycentra.com';
  return `https://cyscan.${domain}`;
};

/**
 * Get portal base URL
 * @returns {string} Portal URL
 */
export const getPortalUrl = () => {
  const domain = window.__CYCENTRA_DOMAIN__ || 'cycentra.com';
  return `https://cy360.${domain}`;
};

/**
 * Get full absolute URL for a module (for external links)
 * @param {string} moduleId - Module identifier (cysoar, cyiris, cysiem)
 * @returns {string|null} Absolute module URL or null if invalid
 */
export const getModuleUrl = (moduleId) => {
  const portalUrl = getPortalUrl();
  const relativePath = MODULE_URLS[moduleId];
  return relativePath ? `${portalUrl}${relativePath}` : null;
};

/**
 * Get legacy subdomain URL (for fallback/direct bookmarked access)
 * @param {string} moduleId - Module identifier
 * @returns {string|null} Subdomain URL or null if invalid
 */
export const getSubdomainUrl = (moduleId) => {
  const domain = window.__CYCENTRA_DOMAIN__ || 'cycentra.com';
  const subdomains = {
    cysoar: `https://cysoar.${domain}`,
    cyiris: `https://cyiris.${domain}`,
    cysiem: `https://cysiem.${domain}`
  };
  return subdomains[moduleId] || null;
};

/**
 * Get module metadata by ID
 * @param {string} moduleId - Module identifier
 * @returns {object|null} Module metadata or null if invalid
 */
export const getModule = (moduleId) => {
  return MODULES[moduleId] || null;
};

/**
 * Get all module IDs
 * @returns {string[]} Array of module IDs
 */
export const getModuleIds = () => {
  return Object.keys(MODULES);
};

/**
 * Check if a module ID is valid
 * @param {string} moduleId - Module identifier
 * @returns {boolean} True if valid
 */
export const isValidModule = (moduleId) => {
  return moduleId in MODULES;
};

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORT DEFAULT
// ═══════════════════════════════════════════════════════════════════════════════

export default {
  MODULE_URLS,
  MODULES,
  getApiUrl,
  getPortalUrl,
  getModuleUrl,
  getSubdomainUrl,
  getModule,
  getModuleIds,
  isValidModule
};
