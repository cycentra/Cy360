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
const SvgAsset = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>;
const SvgVuln  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg>;
const SvgSIEM  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>;
const SvgScan  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35M11 8v6M8 11h6"/></svg>;
const SvgUC    = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M4 6h16M4 10h16M4 14h10M4 18h6"/></svg>;
const SvgMods  = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>;
const SvgAI    = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>;

/**
 * Build the sidebar nav sections.
 * Called with live state so badges and OPEN module links stay current.
 *
 * @param {object} opts
 * @param {object} opts.installedModules - current installedModules state
 * @param {object|null} opts.data        - current scan data (for SIEM badge)
 */
export function buildNavSections({ installedModules = {}, data = null }) {
  const addonInstalled = Object.entries(installedModules)
    .filter(([id]) => PLATFORM_MODULES[id]?.tier === "addon");

  return [
    {
      section: "MONITOR",
      items: [
        { id: "dashboard",      label: "Dashboard",       icon: SvgDash  },
        { id: "assets",         label: "Assets",          icon: SvgAsset },
        { id: "vulns",          label: "Vulnerabilities", icon: SvgVuln  },
        { id: "cysiemfeed",     label: "CySIEM Feed",     icon: SvgSIEM, badge: data?.cysiemAlerts?.length || 0 },
        { id: "siem-incidents", label: "Incidents",       icon: <span style={{ fontSize: 13 }}>🔥</span>, accent: "#ff3b3b" },
        { id: "siem-risk",      label: "Risk Scores",     icon: <span style={{ fontSize: 13 }}>⚡</span>, accent: "#ff8c00" },
        { id: "siem-ueba",      label: "UEBA",            icon: <span style={{ fontSize: 13 }}>👤</span>, accent: "#b06eff" },
      ],
    },
    {
      section: "ACTIONS",
      items: [
        { id: "scan",      label: "New Scan",   icon: SvgScan, accent: "#00e5a0" },
        { id: "usecases",  label: "Use Cases",  icon: SvgUC,   accent: "#4d9eff" },
      ],
    },
    {
      section: "PLATFORM",
      items: [
        { id: "platform",    label: "Modules",     icon: SvgMods, badge: addonInstalled.length || 0, accent: "#b06eff" },
        { id: "ai-settings", label: "AI Settings", icon: SvgAI,   accent: "#4d9eff" },
      ],
    },
    {
      section: "OPEN",
      items: [
        {
          id:          "open-cysiem",
          label:       "CySIEM",
          icon:        <span style={{ fontSize: 14 }}>👁️</span>,
          accent:      "#ff8c00",
          externalUrl: getModuleUrl("cysiem"),
        },
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
