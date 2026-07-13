/**
 * pages/connectors/index.jsx — CyDataLake SIEM Connectors
 *
 * CRUD + test/pull UI for /api/connectors/* (Phase 3 of the CyDataLake
 * initiative — see docs/CYDATALAKE_MIGRATION_PLAN.md §7). Secrets are
 * masked as "•STORED•" by the backend and never round-tripped back.
 */
import React, { useEffect, useState, useCallback } from "react";

const CARD_BG = "rgba(255,255,255,0.03)";
const BORDER  = "1px solid rgba(255,255,255,0.07)";
const ACCENT  = "#00e5a0";

const VENDOR_LABELS = {
  wazuh:       "Wazuh (indexer pull)",
  splunk:      "Splunk",
  qradar:      "IBM QRadar",
  sentinelone: "SentinelOne",
  paloalto:    "Palo Alto Cortex XDR/XSIAM",
  office365:   "Office 365 (Management Activity)",
  azure:       "Azure AD / Entra ID",
  aws:         "AWS CloudTrail",
  gcp:         "GCP Cloud Audit Logs",
};

const VENDOR_FIELDS = {
  wazuh:       [["username", "text", "Indexer username"], ["password", "password", "Indexer password"],
                ["index_pattern", "text", "Index pattern (default wazuh-alerts-*)"]],
  splunk:      [["api_token", "password", "API token"], ["search_query", "text", "SPL query (default: search index=notable)"]],
  qradar:      [["sec_token", "password", "SEC token"], ["api_version", "text", "API version (default 20.0)"]],
  sentinelone: [["api_token", "password", "API token"]],
  paloalto:    [["api_key_id", "text", "API Key ID"], ["api_key", "password", "API Key secret"]],
  office365:   [["tenant_id", "text", "Azure AD Tenant ID"], ["client_id", "text", "App Client ID"],
                ["client_secret", "password", "App Client Secret"],
                ["content_types", "text", "Content types (blank = all: Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All)"]],
  azure:       [["tenant_id", "text", "Azure AD Tenant ID"], ["client_id", "text", "App Client ID"],
                ["client_secret", "password", "App Client Secret"]],
  aws:         [["access_key_id", "text", "AWS Access Key ID"], ["secret_access_key", "password", "AWS Secret Access Key"],
                ["region", "text", "AWS Region (default us-east-1)"]],
  gcp:         [["project_id", "text", "GCP Project ID"], ["service_account_json", "password", "Service Account JSON (paste full key file contents)"]],
};

const STATUS_COLOR = { ok: ACCENT, error: "#ff3b3b", never_run: "#555" };

function StatusDot({ status }) {
  const color = STATUS_COLOR[status] || "#555";
  return <div style={{ width: 8, height: 8, borderRadius: "50%", background: color, boxShadow: `0 0 6px ${color}`, display: "inline-block", marginRight: 6 }} />;
}

function ConnectorForm({ initial, onSave, onCancel }) {
  const [vendor, setVendor]     = useState(initial?.vendor || "wazuh");
  const [name, setName]         = useState(initial?.name || "");
  const [baseUrl, setBaseUrl]   = useState(initial?.config?.base_url || "");
  const [interval, setInterval_] = useState(initial?.poll_interval_sec || 300);
  const [fields, setFields]     = useState(initial?.config || {});
  const [saving, setSaving]     = useState(false);

  const setField = (k, v) => setFields((f) => ({ ...f, [k]: v }));

  const submit = async () => {
    setSaving(true);
    const config = { ...fields, base_url: baseUrl };
    await onSave({ vendor, name, config, poll_interval_sec: Number(interval), enabled: true });
    setSaving(false);
  };

  return (
    <div style={{ background: CARD_BG, border: BORDER, borderRadius: 10, padding: 20, marginBottom: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <label style={{ fontSize: 12, color: "#999" }}>
          Vendor
          <select value={vendor} disabled={!!initial} onChange={(e) => setVendor(e.target.value)}
            style={{ display: "block", width: "100%", marginTop: 4, padding: 8, background: "#111", color: "#fff", border: BORDER, borderRadius: 6 }}>
            {Object.entries(VENDOR_LABELS).map(([v, label]) => <option key={v} value={v}>{label}</option>)}
          </select>
        </label>
        <label style={{ fontSize: 12, color: "#999" }}>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Primary Splunk ES"
            style={{ display: "block", width: "100%", marginTop: 4, padding: 8, background: "#111", color: "#fff", border: BORDER, borderRadius: 6 }} />
        </label>
        <label style={{ fontSize: 12, color: "#999" }}>
          Base URL
          <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://..."
            style={{ display: "block", width: "100%", marginTop: 4, padding: 8, background: "#111", color: "#fff", border: BORDER, borderRadius: 6 }} />
        </label>
        <label style={{ fontSize: 12, color: "#999" }}>
          Poll interval (seconds)
          <input type="number" value={interval} onChange={(e) => setInterval_(e.target.value)}
            style={{ display: "block", width: "100%", marginTop: 4, padding: 8, background: "#111", color: "#fff", border: BORDER, borderRadius: 6 }} />
        </label>
        {(VENDOR_FIELDS[vendor] || []).map(([key, type, placeholder]) => (
          <label key={key} style={{ fontSize: 12, color: "#999" }}>
            {placeholder}
            <input type={type} value={fields[key] || ""} onChange={(e) => setField(key, e.target.value)}
              placeholder={fields[key] === "•STORED•" ? "•STORED• (leave blank to keep)" : ""}
              style={{ display: "block", width: "100%", marginTop: 4, padding: 8, background: "#111", color: "#fff", border: BORDER, borderRadius: 6 }} />
          </label>
        ))}
      </div>
      <div style={{ marginTop: 16, display: "flex", gap: 8 }}>
        <button onClick={submit} disabled={saving || !name}
          style={{ background: ACCENT, color: "#000", border: "none", borderRadius: 6, padding: "8px 16px", fontWeight: 700, cursor: "pointer" }}>
          {saving ? "Saving…" : "Save"}
        </button>
        <button onClick={onCancel}
          style={{ background: "transparent", color: "#999", border: BORDER, borderRadius: 6, padding: "8px 16px", cursor: "pointer" }}>
          Cancel
        </button>
      </div>
    </div>
  );
}

export default function ConnectorsPage() {
  const [connectors, setConnectors] = useState([]);
  const [loading, setLoading]       = useState(true);
  const [showForm, setShowForm]     = useState(false);
  const [editing, setEditing]       = useState(null);
  const [busyId, setBusyId]         = useState(null);
  const [messages, setMessages]     = useState({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/connectors");
      const d = await r.json();
      setConnectors(d.connectors || []);
    } catch { /* network error — leave list as-is */ }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async (payload) => {
    const url = editing ? `/api/connectors/${editing.id}` : "/api/connectors";
    const method = editing ? "PUT" : "POST";
    await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    setShowForm(false);
    setEditing(null);
    load();
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this connector?")) return;
    await fetch(`/api/connectors/${id}`, { method: "DELETE" });
    load();
  };

  const test = async (id) => {
    setBusyId(id);
    const r = await fetch(`/api/connectors/${id}/test`, { method: "POST" });
    const d = await r.json();
    setMessages((m) => ({ ...m, [id]: d.ok ? `✅ ${d.message}` : `❌ ${d.message}` }));
    setBusyId(null);
  };

  const pullNow = async (id) => {
    setBusyId(id);
    const r = await fetch(`/api/connectors/${id}/pull`, { method: "POST" });
    const d = await r.json();
    setMessages((m) => ({ ...m, [id]: d.status === "ok" ? `✅ Pulled ${d.events_pushed} event(s)` : `❌ ${d.error}` }));
    setBusyId(null);
    load();
  };

  const toggleEnabled = async (c) => {
    await fetch(`/api/connectors/${c.id}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !c.enabled }) });
    load();
  };

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, color: "#fff" }}>CyDataLake — SIEM Connectors</h2>
          <div style={{ fontSize: 12, color: "#777", marginTop: 4 }}>
            Aggregate Wazuh, Splunk, QRadar, SentinelOne, and Palo Alto Cortex into Cy360.
          </div>
        </div>
        <button onClick={() => { setEditing(null); setShowForm(true); }}
          style={{ background: ACCENT, color: "#000", border: "none", borderRadius: 6, padding: "10px 18px", fontWeight: 700, cursor: "pointer" }}>
          + Add Connector
        </button>
      </div>

      {showForm && (
        <ConnectorForm initial={editing} onSave={save} onCancel={() => { setShowForm(false); setEditing(null); }} />
      )}

      <div style={{ background: CARD_BG, border: BORDER, borderRadius: 10, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: "left", color: "#777", fontSize: 11 }}>
              <th style={{ padding: 12 }}>Status</th>
              <th style={{ padding: 12 }}>Name</th>
              <th style={{ padding: 12 }}>Vendor</th>
              <th style={{ padding: 12 }}>Enabled</th>
              <th style={{ padding: 12 }}>Last Pull</th>
              <th style={{ padding: 12 }}>Events Pulled</th>
              <th style={{ padding: 12 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={7} style={{ padding: 20, textAlign: "center", color: "#777" }}>Loading…</td></tr>}
            {!loading && connectors.length === 0 && (
              <tr><td colSpan={7} style={{ padding: 20, textAlign: "center", color: "#777" }}>No connectors configured yet.</td></tr>
            )}
            {connectors.map((c) => (
              <tr key={c.id} style={{ borderTop: BORDER }}>
                <td style={{ padding: 12 }}><StatusDot status={c.last_status} /></td>
                <td style={{ padding: 12, color: "#fff" }}>{c.name}</td>
                <td style={{ padding: 12, color: "#999" }}>{VENDOR_LABELS[c.vendor] || c.vendor}</td>
                <td style={{ padding: 12 }}>
                  <input type="checkbox" checked={!!c.enabled} onChange={() => toggleEnabled(c)} />
                </td>
                <td style={{ padding: 12, color: "#999" }}>{c.last_pull_at ? new Date(c.last_pull_at).toLocaleString() : "never"}</td>
                <td style={{ padding: 12, color: "#999" }}>{c.events_pulled || 0}</td>
                <td style={{ padding: 12 }}>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <button disabled={busyId === c.id} onClick={() => test(c.id)}
                      style={{ fontSize: 11, background: "transparent", color: ACCENT, border: `1px solid ${ACCENT}`, borderRadius: 4, padding: "4px 8px", cursor: "pointer" }}>Test</button>
                    <button disabled={busyId === c.id} onClick={() => pullNow(c.id)}
                      style={{ fontSize: 11, background: "transparent", color: "#4d9eff", border: "1px solid #4d9eff", borderRadius: 4, padding: "4px 8px", cursor: "pointer" }}>Pull Now</button>
                    <button onClick={() => { setEditing(c); setShowForm(true); }}
                      style={{ fontSize: 11, background: "transparent", color: "#999", border: BORDER, borderRadius: 4, padding: "4px 8px", cursor: "pointer" }}>Edit</button>
                    <button onClick={() => remove(c.id)}
                      style={{ fontSize: 11, background: "transparent", color: "#ff3b3b", border: "1px solid #ff3b3b", borderRadius: 4, padding: "4px 8px", cursor: "pointer" }}>Delete</button>
                  </div>
                  {messages[c.id] && <div style={{ fontSize: 11, color: "#999", marginTop: 4 }}>{messages[c.id]}</div>}
                  {c.last_error && !messages[c.id] && <div style={{ fontSize: 11, color: "#ff3b3b", marginTop: 4 }}>{c.last_error}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
