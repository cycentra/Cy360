import { useCallback, useEffect, useRef, useState } from "react";
import { API_BASE } from "../../core/constants.js";

const STATUS_COLOR = {
  ok:       "#00e5a0",
  degraded: "#f5c518",
  down:     "#ff3b3b",
  unknown:  "#888888",
  skipped:  "#4d9eff",
};

const STATUS_LABEL = {
  ok:       "OK",
  degraded: "DEGRADED",
  down:     "DOWN",
  unknown:  "UNKNOWN",
  skipped:  "SKIPPED",
};

const SvgPulse = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </svg>
);
const SvgRefresh = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <polyline points="23 4 23 10 17 10" />
    <polyline points="1 20 1 14 7 14" />
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
  </svg>
);
const SvgLink = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
    <polyline points="15 3 21 3 21 9" />
    <line x1="10" y1="14" x2="21" y2="3" />
  </svg>
);

function StatusBadge({ status }) {
  const color = STATUS_COLOR[status] || "#888";
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 10px", borderRadius: 12,
      background: `${color}18`, border: `1px solid ${color}44`,
      color, fontSize: 11, fontWeight: 700, letterSpacing: "0.06em",
    }}>
      <span style={{
        width: 6, height: 6, borderRadius: "50%", background: color,
        boxShadow: status !== "ok" && status !== "skipped" ? `0 0 6px ${color}` : "none",
        display: "inline-block",
      }} />
      {STATUS_LABEL[status] || status.toUpperCase()}
    </span>
  );
}

function IntegrationCard({ intg, onViewCase }) {
  const lastChecked = intg.last_checked
    ? new Date(intg.last_checked).toLocaleString()
    : "Never";
  const lastOk = intg.last_ok
    ? new Date(intg.last_ok).toLocaleTimeString()
    : "—";

  return (
    <div style={{
      background: "rgba(255,255,255,0.03)",
      border: `1px solid ${intg.status === "ok" ? "rgba(255,255,255,0.07)" : STATUS_COLOR[intg.status] + "44"}`,
      borderRadius: 10, padding: "16px 20px",
      display: "flex", flexDirection: "column", gap: 10,
      transition: "border-color 0.2s",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 14, color: "#fff", marginBottom: 4 }}>
            {intg.display_name || intg.integration_name}
          </div>
          <div style={{ fontSize: 11, color: "#888" }}>
            Last checked: {lastChecked}
            {intg.status === "ok" && <span style={{ marginLeft: 12, color: "#888" }}>Last OK: {lastOk}</span>}
          </div>
        </div>
        <StatusBadge status={intg.status} />
      </div>

      {intg.error_message && intg.status !== "ok" && (
        <div style={{
          background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.18)",
          borderRadius: 6, padding: "8px 12px",
          fontSize: 12, color: "#ffaaaa", fontFamily: "monospace",
          wordBreak: "break-word",
        }}>
          {intg.error_message}
        </div>
      )}

      {intg.ingest_gap_minutes != null && (
        <div style={{ fontSize: 12, color: "#f5c518" }}>
          No events for <strong>{intg.ingest_gap_minutes} min</strong>
        </div>
      )}

      {intg.consecutive_failures > 0 && (
        <div style={{ fontSize: 11, color: "#888" }}>
          Consecutive failures: <span style={{ color: "#ff8c00" }}>{intg.consecutive_failures}</span>
        </div>
      )}

      {intg.incident_id && (
        <button
          onClick={() => onViewCase(intg.incident_id)}
          style={{
            alignSelf: "flex-start", display: "inline-flex", alignItems: "center", gap: 5,
            padding: "4px 10px", borderRadius: 6,
            background: "rgba(255,59,59,0.1)", border: "1px solid rgba(255,59,59,0.3)",
            color: "#ff8c8c", fontSize: 11, cursor: "pointer",
          }}
        >
          {SvgLink} Open incident: {intg.incident_id}
        </button>
      )}
    </div>
  );
}

function SummaryBar({ integrations }) {
  const counts = integrations.reduce((acc, i) => {
    acc[i.status] = (acc[i.status] || 0) + 1;
    return acc;
  }, {});
  return (
    <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 24 }}>
      {Object.entries(counts).map(([s, n]) => (
        <div key={s} style={{
          display: "flex", alignItems: "center", gap: 8,
          padding: "8px 16px", borderRadius: 8,
          background: `${STATUS_COLOR[s] || "#888"}12`,
          border: `1px solid ${STATUS_COLOR[s] || "#888"}33`,
        }}>
          <span style={{ fontSize: 20, fontWeight: 700, color: STATUS_COLOR[s] || "#888" }}>{n}</span>
          <span style={{ fontSize: 11, color: "#aaa", textTransform: "uppercase", letterSpacing: "0.05em" }}>{s}</span>
        </div>
      ))}
    </div>
  );
}

export default function IntegrationHealthPage({ onNavigate }) {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading]           = useState(true);
  const [checking, setChecking]         = useState(false);
  const [error, setError]               = useState(null);
  const [lastRefresh, setLastRefresh]   = useState(null);
  const intervalRef = useRef(null);

  const fetchHealth = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/integrations/health`, { credentials: "include" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      setIntegrations(data.integrations || []);
      setLastRefresh(new Date());
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    intervalRef.current = setInterval(fetchHealth, 60_000);
    return () => clearInterval(intervalRef.current);
  }, [fetchHealth]);

  const triggerCheck = async () => {
    setChecking(true);
    try {
      const r = await fetch(`${API_BASE}/api/integrations/health/check`, {
        method: "POST", credentials: "include",
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      await fetchHealth();
    } catch (e) {
      setError(e.message);
    } finally {
      setChecking(false);
    }
  };

  const handleViewCase = (incidentId) => {
    if (onNavigate) onNavigate("cases", { incidentId });
  };

  const anyUnhealthy = integrations.some(i => i.status === "down" || i.status === "degraded");

  return (
    <div style={{ padding: "28px 32px", maxWidth: 1100, margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 10 }}>
            {SvgPulse} Integration Health
          </h1>
          <p style={{ margin: "6px 0 0", fontSize: 13, color: "#888" }}>
            Real-time status of all CyCentra 360 integrations. Checks run every 5 minutes automatically.
            {lastRefresh && (
              <span style={{ marginLeft: 12, color: "#666" }}>
                UI refreshed: {lastRefresh.toLocaleTimeString()}
              </span>
            )}
          </p>
        </div>
        <button
          onClick={triggerCheck}
          disabled={checking}
          style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            padding: "8px 16px", borderRadius: 8,
            background: checking ? "rgba(255,255,255,0.05)" : "rgba(0,229,160,0.1)",
            border: `1px solid ${checking ? "rgba(255,255,255,0.1)" : "rgba(0,229,160,0.3)"}`,
            color: checking ? "#666" : "#00e5a0", fontSize: 13, cursor: checking ? "not-allowed" : "pointer",
            fontWeight: 600,
          }}
        >
          <span style={{ display: "inline-block", animation: checking ? "spin 1s linear infinite" : "none" }}>
            {SvgRefresh}
          </span>
          {checking ? "Checking…" : "Check Now"}
        </button>
      </div>

      {anyUnhealthy && (
        <div style={{
          background: "rgba(255,59,59,0.07)", border: "1px solid rgba(255,59,59,0.25)",
          borderRadius: 8, padding: "10px 16px", marginBottom: 20,
          fontSize: 13, color: "#ff9999", display: "flex", alignItems: "center", gap: 8,
        }}>
          <span style={{ fontSize: 16 }}>⚠</span>
          One or more integrations are unhealthy. Incidents have been auto-created in Case Management.
        </div>
      )}

      {error && (
        <div style={{
          background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.2)",
          borderRadius: 8, padding: "10px 16px", marginBottom: 20, fontSize: 13, color: "#ff8c8c",
        }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: "center", padding: 60, color: "#666", fontSize: 14 }}>
          Loading integration statuses…
        </div>
      ) : integrations.length === 0 ? (
        <div style={{
          textAlign: "center", padding: 60,
          background: "rgba(255,255,255,0.02)", borderRadius: 10,
          border: "1px solid rgba(255,255,255,0.06)", color: "#666", fontSize: 14,
        }}>
          No integration health data yet. Click <strong style={{ color: "#00e5a0" }}>Check Now</strong> to run the first check.
        </div>
      ) : (
        <>
          <SummaryBar integrations={integrations} />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: 16 }}>
            {integrations.map(i => (
              <IntegrationCard key={i.integration_name} intg={i} onViewCase={handleViewCase} />
            ))}
          </div>
        </>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
