/**
 * src/hooks/useAppState.js
 * =========================
 * Central state hook. Owns all top-level useState, OAuth callback
 * parsing, session restore, and module/AI config persistence.
 *
 * v2: Adds scanHistory[] + selectedScanId for the scan timeline dropdown.
 *     handleScanSelect(scanId) loads any historical scan by ID.
 *
 * Returns everything App.jsx needs — pages receive only the slice they use.
 */

import { useState, useEffect } from "react";
import { getSavedUser, saveUser, clearSSOToken, setSSOToken, validateStorage } from '../core/auth.js';
import { adaptCyCentraJSON } from '../core/adapter.js';
import { DEFAULT_PROMPTS } from '../registry/aiProviders.js';
import { API_BASE } from '../core/constants.js';

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

  // ── Scan history ─────────────────────────────────────────────────────────────
  const [scanHistory,    setScanHistory]    = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [allowedPages,   setAllowedPages]   = useState(null); // null = unrestricted

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

      const role = decodeURIComponent(params.get("role") || "viewer");
      const u = { id: uid, name, email, avatar, provider, role };
      saveUser(u);
      setUser(u);
      setAuthReady(true);
      window.history.replaceState({}, document.title, window.location.pathname);

    } else if (params.get("logged_out") === "1") {
      clearSSOToken();
      setUser(null); setData(null); setAssets([]); setScanHistory([]);
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
    // Validate + repair all localStorage keys before restoring state.
    // If corrupt data is found it is cleared automatically.
    validateStorage();

    try {
      const saved = localStorage.getItem("cycentra_ai_config");
      if (saved) setAiConfig(JSON.parse(saved));
    } catch {
      try { localStorage.removeItem("cycentra_ai_config"); } catch {}
    }
    try {
      const mods = localStorage.getItem("cycentra_modules");
      if (mods) setInstalledModules(JSON.parse(mods));
    } catch {
      try { localStorage.removeItem("cycentra_modules"); } catch {}
    }
  }, []);

  // ── Fetch page permissions when user is known ────────────────────────────────
  useEffect(() => {
    if (!user) { setAllowedPages(null); return; }
    fetch(`${API_BASE}/api/rbac/my-permissions`, { credentials: "include" })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d && "allowed_pages" in d) setAllowedPages(d.allowed_pages); })
      .catch(() => {}); // keep null (unrestricted) on network failure
  }, [user]);

  // ── Auto-load latest scan + history on login ─────────────────────────────────
  useEffect(() => {
    if (!user || data) return;

    // Load latest scan
    fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(user.id || "")}`, {
      credentials: "include",
    })
      .then(res => res.ok ? res.json() : null)
      .then(raw => {
        if (raw?.assets) {
          const adapted = adaptCyCentraJSON(raw);
          if (adapted) {
            setData(adapted);
            setSelectedScanId(adapted.meta?.scan_id || null);
            setAssets(_mergeStatuses(adapted.assets));
          }
        }
      })
      .catch(() => {});

    // Load scan history list
    _fetchHistory(user.id || "");
  }, [user, data]);

  function _fetchHistory(uid) {
    setHistoryLoading(true);
    fetch(`${API_BASE}/api/scans/list?uid=${encodeURIComponent(uid)}&limit=15`, {
      credentials: "include",
    })
      .then(res => res.ok ? res.json() : [])
      .then(list => { setScanHistory(Array.isArray(list) ? list : []); })
      .catch(() => setScanHistory([]))
      .finally(() => setHistoryLoading(false));
  }

  // ── Action handlers ─────────────────────────────────────────────────────────

  function _mergeStatuses(newAssets) {
    // Asset states are now server-side (loaded per user from /api/asm/asset-states).
    // The scan JSON already carries asset_state for each asset. No localStorage merge needed.
    return newAssets;
  }

  // Load a specific historical scan by scan_id
  async function handleScanSelect(scanId) {
    if (scanId === selectedScanId) return;
    try {
      const res = await fetch(
        `${API_BASE}/api/scans/${encodeURIComponent(scanId)}?uid=${encodeURIComponent(user?.id || "")}`,
        { credentials: "include" }
      );
      if (!res.ok) return;
      const raw = await res.json();
      if (raw?.assets) {
        const adapted = adaptCyCentraJSON(raw);
        if (adapted) {
          setData(adapted);
          setSelectedScanId(scanId);
          setAssets(_mergeStatuses(adapted.assets));
        }
      }
    } catch {}
  }

  function handleImport(raw) {
    const adapted = adaptCyCentraJSON(raw);
    if (adapted) {
      setData(adapted);
      setAssets(_mergeStatuses(adapted.assets));
    }
  }

  function handleStatusChange(id, state) {
    setAssets(prev => prev.map(a => a.id === id ? { ...a, asset_state: state } : a));
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

  async function handleSaveAIConfig(config) {
    setAiConfig(config);
    try { localStorage.setItem("cycentra_ai_config", JSON.stringify(config)); } catch {}
    const res = await fetch(`${API_BASE}/api/ai/settings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(config),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server returned ${res.status}`);
    }
  }

  function handleScanComplete(raw) {
    const adapted = adaptCyCentraJSON(raw);
    if (adapted) {
      setData(adapted);
      setSelectedScanId(adapted.meta?.scan_id || null);
      setAssets(_mergeStatuses(adapted.assets));
      setActiveTab("dashboard");
      // Refresh history list so new scan appears in dropdown
      if (user) _fetchHistory(user.id || "");
    }
  }

  // ── Derived stats ────────────────────────────────────────────────────────────
  const stats = {
    total:       assets.length,
    critical:    assets.filter(a => a.risk === "critical").length,
    high:        assets.filter(a => a.risk === "high").length,
    open:        assets.filter(a => a.asset_state === "new").length,
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
    scanHistory, selectedScanId, historyLoading,
    allowedPages,
    // Setters
    setUser, setData, setAssets, setActiveTab,
    setSelectedAsset, setShowImport,
    // Handlers
    handleImport, handleStatusChange, handleInstallModule,
    handleUninstallModule, handleSaveAIConfig, handleScanComplete,
    handleScanSelect,
  };
}
