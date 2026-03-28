/**
 * src/hooks/useAppState.js
 * =========================
 * Central state hook. Owns all top-level useState, OAuth callback
 * parsing, session restore, and module/AI config persistence.
 *
 * Returns everything App.jsx needs — pages receive only the slice they use.
 */

import { useState, useEffect } from "react";
import { getSavedUser, saveUser, clearSSOToken, setSSOToken } from '../core/auth.js';
import { adaptCyCentraJSON } from '../core/adapter.js';
import { DEFAULT_PROMPTS } from '../registry/aiProviders.js';
import { API_BASE, CYSCAN_URL } from '../core/constants.js';

export function useAppState() {
  const [user,             setUser]             = useState(null);
  const [authReady,        setAuthReady]        = useState(false);
  const [data,             setData]             = useState(null);
  const [assets,           setAssets]           = useState([]);
  const [activeTab,        setActiveTabRaw]     = useState(
    () => sessionStorage.getItem("cycentra_tab") || "dashboard"
  );
  const [selectedAsset,    setSelectedAsset]    = useState(null);
  const [showImport,       setShowImport]       = useState(false);
  const [installedModules, setInstalledModules] = useState({});
  const [aiConfig,         setAiConfig]         = useState({
    provider: "local",
    fields:   { baseUrl: "", model: "mistral:7b" },
    prompts:  DEFAULT_PROMPTS,
  });

  // Persist active tab across refreshes
  function setActiveTab(tab) {
    setActiveTabRaw(tab);
    sessionStorage.setItem("cycentra_tab", tab);
  }

  // ── OAuth callback & session restore ────────────────────────────────────────
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);

    if (params.get("auth") === "success") {
      const name     = decodeURIComponent(params.get("name")  || "");
      const email    = decodeURIComponent(params.get("email") || "");
      const uid      = params.get("uid")      || `user_${Math.random().toString(36).slice(2, 8)}`;
      const provider = params.get("provider") || "google";
      const avatar   = name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();
      const ssoToken = params.get("sso_token") || "";

      if (ssoToken) setSSOToken(ssoToken);

      const u = { id: uid, name, email, avatar, provider };
      saveUser(u);
      setUser(u);
      setAuthReady(true);
      window.history.replaceState({}, document.title, window.location.pathname);

    } else if (params.get("logged_out") === "1") {
      clearSSOToken();
      setUser(null); setData(null); setAssets([]);
      setAuthReady(true);
      window.history.replaceState({}, document.title, window.location.pathname);

    } else {
      const savedU = getSavedUser();
      if (savedU) setUser(savedU);
      setAuthReady(true);
    }
  }, []);

  // ── Restore persisted config on mount ───────────────────────────────────────
  useEffect(() => {
    try {
      const saved = localStorage.getItem("cycentra_ai_config");
      if (saved) setAiConfig(JSON.parse(saved));
    } catch {}
    try {
      const mods = localStorage.getItem("cycentra_modules");
      if (mods) setInstalledModules(JSON.parse(mods));
    } catch {}
  }, []);

  // ── Auto-load latest scan on login ──────────────────────────────────────────
  useEffect(() => {
    if (!user || data) return;
    fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user.id || "")}`, {
      credentials: "include",
    })
      .then(res => res.ok ? res.json() : null)
      .then(raw => {
        if (raw?.assets) {
          const adapted = adaptCyCentraJSON(raw);
          if (adapted) { setData(adapted); setAssets(adapted.assets); }
        }
      })
      .catch(() => {});
  }, [user, data]);

  // ── Action handlers ─────────────────────────────────────────────────────────

  function handleImport(raw) {
    const adapted = adaptCyCentraJSON(raw);
    if (adapted) { setData(adapted); setAssets(adapted.assets); }
  }

  function handleStatusChange(id, status) {
    setAssets(prev => prev.map(a => a.id === id ? { ...a, status } : a));
  }

  function handleInstallModule(moduleId, config) {
    const updated = {
      ...installedModules,
      [moduleId]: { status: "running", config, installedAt: new Date().toISOString() },
    };
    setInstalledModules(updated);
    try { localStorage.setItem("cycentra_modules", JSON.stringify(updated)); } catch {}
  }

  function handleUninstallModule(moduleId) {
    const updated = { ...installedModules };
    delete updated[moduleId];
    setInstalledModules(updated);
    try { localStorage.setItem("cycentra_modules", JSON.stringify(updated)); } catch {}
    fetch(`${API_BASE}/api/platform/uninstall`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ module: moduleId }),
    }).catch(() => {});
  }

  function handleSaveAIConfig(config) {
    setAiConfig(config);
    try { localStorage.setItem("cycentra_ai_config", JSON.stringify(config)); } catch {}
  }

  function handleScanComplete(raw) {
    const adapted = adaptCyCentraJSON(raw);
    if (adapted) {
      setData(adapted);
      setAssets(adapted.assets);
      setActiveTab("dashboard");
    }
  }

  // ── Derived stats ────────────────────────────────────────────────────────────
  const stats = {
    total:       assets.length,
    critical:    assets.filter(a => a.risk === "critical").length,
    high:        assets.filter(a => a.risk === "high").length,
    open:        assets.filter(a => a.status === "open").length,
    totalVulns:  assets.reduce((acc, a) => acc + (a.vulnerabilities?.length || 0), 0),
    exposedPaths:assets.reduce((acc, a) => acc + (a.exposed_paths?.length  || 0), 0),
  };

  const scanTime = data?.meta?.last_scan
    ? new Date(data.meta.last_scan).toLocaleString()
    : "—";

  return {
    // State
    user, authReady, data, assets, activeTab, selectedAsset, showImport,
    installedModules, aiConfig, stats, scanTime,
    // Setters
    setUser, setData, setAssets, setActiveTab,
    setSelectedAsset, setShowImport,
    // Handlers
    handleImport, handleStatusChange, handleInstallModule,
    handleUninstallModule, handleSaveAIConfig, handleScanComplete,
  };
}
