/**
 * src/sidebar/navConfig.js
 * =========================
 * Sidebar navigation sections and items.
 * To add a new nav item: add one entry to the relevant section below.
 * No other file needs to change.
 */

import { getModuleUrl } from '../core/constants.js';
import { PLATFORM_MODULES } from '../registry/platformModules.js';

// SVG icon helpers (inline so sidebar has no external icon dependency)
const SvgDash  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>;
const SvgComp  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>;
const SvgRisk  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
const SvgReport = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>;
const SvgDoc   = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>;
const SvgAsset = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>;
const SvgVuln  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg>;
const SvgSIEM  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>;
const SvgHost  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/><circle cx="12" cy="10" r="2"/><path d="M8 10h1M15 10h1"/></svg>;
const SvgScan  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35M11 8v6M8 11h6"/></svg>;
const SvgHist  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/><path d="M3.05 11a9 9 0 1 1 .5 4"/><polyline points="1 12 3 10 5 12"/></svg>;
const SvgMkt   = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/></svg>;
const SvgAudit = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>;
const SvgMods  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>;
const SvgBench = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>;
const SvgAI    = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>;
const SvgGear  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>;
const SvgPulse = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>;
const SvgEDR   = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M8 10h.01M8 14h.01M12 10h4M12 14h4"/><path d="M2 8h20"/></svg>;

/**
 * Build the sidebar nav sections.
 * Called with live state so badges and OPERATIONS module links stay current.
 *
 * Navigation hierarchy:
 *   SECURITY POSTURE     — Posture Benchmark (primary entry)
 *   EXTERNAL EXPOSURE    — Attack Surface · Asset Inventory · Vulnerabilities · Scan Operations
 *   INTERNAL EXPOSURE    — Active Incidents · Entity Risk · Behavioral Analytics
 *   OPERATIONS           — Audit Trail · Active module launch links (CySIEM always, addons when enabled)
 *   MARKETPLACE          — Marketplace (integrations, playbooks, platform extensions)
 *   PLATFORM CONFIGURATION — Settings, Extensions, Audit Trail
 *
 * @param {object} opts
 * @param {object} opts.installedModules - current installedModules state
 * @param {object|null} opts.data        - current scan data (unused, kept for API compat)
 */
export function buildNavSections({ installedModules = {}, data = null }) {
  const addonInstalled = Object.entries(installedModules)
    .filter(([id]) => PLATFORM_MODULES[id]?.tier === "addon");

  return [
    {
      section: "SECURITY POSTURE",
      items: [
        { id: "benchmark", label: "Posture Benchmark", icon: SvgBench, accent: "#00e5a0" },
      ],
    },
    {
      section: "EXTERNAL EXPOSURE",
      items: [
        { id: "dashboard", label: "External Attack Posture",  icon: SvgDash  },
        { id: "assets",    label: "Asset Inventory", icon: SvgAsset },
        { id: "vulns",     label: "Vulnerabilities", icon: SvgVuln  },
        { id: "scan",      label: "Scan Operations", icon: SvgScan, accent: "#00e5a0" },
      ],
    },
    {
      section: "INTERNAL EXPOSURE",
      items: [
        { id: "internal-dashboard", label: "Internal Attack Posture", icon: <span style={{ fontSize: 13 }}>🛡️</span>, accent: "#4d9eff" },
        { id: "host-inventory",     label: "Host Intelligence",       icon: SvgHost,                                  accent: "#00e5a0" },
        { id: "siem-incidents",     label: "Active Incidents",        icon: <span style={{ fontSize: 13 }}>🔥</span>, accent: "#ff3b3b" },
        { id: "siem-ueba",          label: "Behavioral Analytics",    icon: <span style={{ fontSize: 13 }}>👤</span>, accent: "#b06eff" },
        { id: "threat-hunting",     label: "Threat Hunting",          icon: <span style={{ fontSize: 13 }}>🎯</span>, accent: "#ff8c00" },
        { id: "cases",              label: "Case Management",         icon: <span style={{ fontSize: 13 }}>🗂️</span>, accent: "#b06eff" },
      ],
    },
    {
      section: "ENDPOINT DEFENSE",
      items: [
        { id: "edr-fleet",      label: "Endpoint Fleet",      icon: SvgEDR,                                           accent: "#00e5a0" },
        { id: "edr-detections", label: "EDR Detections",      icon: <span style={{ fontSize: 13 }}>🛡️</span>,         accent: "#ff3b3b" },
        { id: "edr-response",   label: "Response Console",    icon: <span style={{ fontSize: 13 }}>⚡</span>,          accent: "#ff8c00" },
        { id: "edr-policies",   label: "Policies",            icon: <span style={{ fontSize: 13 }}>📋</span>,          accent: "#b06eff" },
        { id: "edr-cyscan-rules", label: "Custom Threat Hunting", icon: <span style={{ fontSize: 13 }}>🎯</span>,       accent: "#00e5a0" },
        { id: "edr-installer",  label: "Agent Installer",     icon: <span style={{ fontSize: 13 }}>📥</span>,          accent: "#4d9eff" },
      ],
    },
    {
      section: "ASSET MANAGEMENT",
      items: [
        { id: "itam-coverage",  label: "Asset Coverage",    icon: <span style={{ fontSize: 13 }}>🖥️</span>,  accent: "#00e5a0" },
        { id: "itam-iot",       label: "IoT Registry",      icon: <span style={{ fontSize: 13 }}>📡</span>,  accent: "#f5c518" },
        { id: "itam-shadow-ai", label: "Shadow AI Monitor", icon: <span style={{ fontSize: 13 }}>🤖</span>,  accent: "#ff8c00" },
      ],
    },
    {
      section: "SECURITY COMPLIANCE",
      items: [
        { id: "comp-dashboard",  label: "GRC Posture",          icon: SvgComp,   accent: "#00e5a0" },
        { id: "comp-assessment", label: "Assessments",          icon: <span style={{ fontSize: 13 }}>📋</span>, accent: "#6378ff" },
        { id: "comp-findings",   label: "Findings & Alerts",    icon: SvgRisk,   accent: "#ff3b3b" },
        { id: "comp-risks",      label: "Risk Management",      icon: SvgRisk,   accent: "#ff8c00" },
        { id: "comp-reports",    label: "Reports",              icon: SvgReport, accent: "#b06eff" },
      ],
    },
    {
      section: "MARKETPLACE",
      items: [
        { id: "marketplace", label: "Marketplace", icon: SvgMkt, accent: "#4d9eff" },
      ],
    },
    {
      section: "PLATFORM CONFIGURATION",
      items: [
        { id: "system-settings",      label: "Settings",          icon: SvgGear,  accent: "#00e5a0" },
        { id: "platform-extensions",  label: "Extensions",        icon: SvgMods,  accent: "#b06eff" },
        { id: "audit-trail",          label: "Audit Trail",       icon: SvgAudit, accent: "#b06eff" },
        { id: "integration-health",   label: "Integration Health", icon: SvgPulse, accent: "#f5c518" },
      ],
    },
    {
      section: "OPERATIONS",
      items: [
        ...addonInstalled.map(([id]) => {
          const mod = PLATFORM_MODULES[id];
          return {
            id:          `open-${id}`,
            label:       mod?.name,
            icon:        <span style={{ fontSize: 14 }}>{mod?.icon}</span>,
            accent:      mod?.color,
            externalUrl: mod?.embeddedPath || getModuleUrl(id),
          };
        }),
      ],
    },
  ];
}
