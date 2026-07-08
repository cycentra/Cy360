/**
 * ExposureRegisterPage.jsx — Exposure Register (#10 full UI)
 * ============================================================
 * Full exposure register: all tracked attack-surface and compliance exposure items.
 * Tabs: All | Vulnerabilities | Supply Chain | Other
 * Actions: create, update status, import from ASM, sync from SIEM.
 */

import { useState, useEffect, useCallback } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};
const CARD = {
  background: "rgba(255,255,255,0.02)", border: `1px solid ${C.border}`,
  borderRadius: 8, padding: "20px 24px",
};

const SEV_COLORS = { critical: C.red, high: C.orange, medium: C.blue, low: C.muted };
const SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3 };

const TABS = [
  { id: "all",          label: "All" },
  { id: "vulnerability", label: "Vulnerabilities" },
  { id: "supply_chain", label: "Supply Chain" },
  { id: "other",        label: "Other" },
];

function SevBadge({ sev }) {
  const color = SEV_COLORS[sev] || C.muted;
  return (
    <span style={{
      background: `${color}22`, color, border: `1px solid ${color}44`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 600,
      textTransform: "uppercase", letterSpacing: 1,
    }}>{sev || "—"}</span>
  );
}

function TypeBadge({ type }) {
  const map = {
    vulnerability: { label: "Vulnerability", color: C.blue },
    supply_chain:  { label: "Supply Chain",  color: C.orange },
    configuration: { label: "Config",        color: C.purple },
    manual:        { label: "Manual",        color: C.muted },
  };
  const m = map[type] || { label: type || "Other", color: C.muted };
  return (
    <span style={{ color: m.color, fontSize: 11, fontFamily: "monospace" }}>{m.label}</span>
  );
}

function StatCard({ label, value, color, sub }) {
  return (
    <div style={{ ...CARD, textAlign: "center", minWidth: 100 }}>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || C.text, fontFamily: "monospace" }}>
        {value ?? "—"}
      </div>
      <div style={{ fontSize: 11, color: C.muted, marginTop: 3, textTransform: "uppercase", letterSpacing: 0.8 }}>
        {label}
      </div>
      {sub && <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function CreateModal({ onClose, onCreate }) {
  const [form, setForm] = useState({
    asset: "", asset_type: "host", exposure_type: "vulnerability",
    severity: "medium", title: "", description: "", cvss_score: "",
  });
  const [saving, setSaving] = useState(false);
  const [err, setErr]       = useState(null);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const submit = async () => {
    if (!form.asset || !form.title) { setErr("Asset and title are required."); return; }
    setSaving(true); setErr(null);
    try {
      const body = { ...form };
      if (form.cvss_score) body.cvss_score = parseFloat(form.cvss_score);
      else delete body.cvss_score;
      const r = await fetch(`${API_BASE}/api/comp/exposure`,
        { method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Create failed");
      onCreate(d.exposure);
      onClose();
    } catch (e) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 999 }}>
      <div style={{ background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: 10, padding: 28, width: 480, maxHeight: "80vh", overflowY: "auto" }}>
        <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 20 }}>Add Exposure Item</div>
        {err && <div style={{ color: C.red, fontSize: 12, marginBottom: 12 }}>{err}</div>}

        {[
          { key: "asset",       label: "Asset / Library",     type: "text",   placeholder: "e.g. acme.example.com" },
          { key: "title",       label: "Title",               type: "text",   placeholder: "Short description of the risk" },
          { key: "description", label: "Description",         type: "textarea" },
          { key: "cvss_score",  label: "CVSS Score (optional)", type: "number", placeholder: "0.0 – 10.0" },
        ].map(f => (
          <div key={f.key} style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.7 }}>{f.label}</div>
            {f.type === "textarea" ? (
              <textarea value={form[f.key]} onChange={e => set(f.key, e.target.value)} rows={3}
                style={{ width: "100%", background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                  borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13, resize: "vertical",
                  boxSizing: "border-box", outline: "none" }} />
            ) : (
              <input type={f.type || "text"} placeholder={f.placeholder} value={form[f.key]}
                onChange={e => set(f.key, e.target.value)}
                style={{ width: "100%", background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                  borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13,
                  boxSizing: "border-box", outline: "none" }} />
            )}
          </div>
        ))}

        {[
          { key: "exposure_type", label: "Type",     opts: ["vulnerability","supply_chain","configuration","manual"] },
          { key: "asset_type",   label: "Asset Type", opts: ["host","web_asset","api","service","dependency"] },
          { key: "severity",     label: "Severity",   opts: ["critical","high","medium","low"] },
        ].map(f => (
          <div key={f.key} style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.7 }}>{f.label}</div>
            <select value={form[f.key]} onChange={e => set(f.key, e.target.value)}
              style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13, width: "100%" }}>
              {f.opts.map(o => <option key={o} value={o}>{o.replace(/_/g," ")}</option>)}
            </select>
          </div>
        ))}

        <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
          <button onClick={submit} disabled={saving}
            style={{ flex: 1, background: C.accent, color: "#000", border: "none",
              borderRadius: 6, padding: "9px 0", fontWeight: 600, fontSize: 13, cursor: "pointer" }}>
            {saving ? "Saving…" : "Add Exposure"}
          </button>
          <button onClick={onClose}
            style={{ flex: 1, background: "rgba(255,255,255,0.05)", color: C.text, border: `1px solid ${C.border}`,
              borderRadius: 6, padding: "9px 0", fontWeight: 600, fontSize: 13, cursor: "pointer" }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ExposureRegisterPage() {
  const [items, setItems]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [activeTab, setTab]     = useState("all");
  const [filter, setFilter]     = useState({ sev: "all", status: "all", search: "" });
  const [showCreate, setCreate] = useState(false);
  const [syncing, setSyncing]   = useState(false);
  const [importing, setImp]     = useState(false);
  const [msg, setMsg]           = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (activeTab !== "all" && activeTab !== "other") params.set("exposure_type", activeTab);
      const r = await fetch(`${API_BASE}/api/comp/exposure?${params}&limit=300`, { credentials: "include" });
      const d = await r.json();
      const sorted = (d.items || []).sort(
        (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
      );
      setItems(sorted);
    } catch {
      setMsg({ type: "error", text: "Failed to load exposure register." });
    } finally {
      setLoading(false);
    }
  }, [activeTab]);

  useEffect(() => { load(); }, [load]);

  const updateStatus = async (id, status) => {
    try {
      const r = await fetch(`${API_BASE}/api/comp/exposure/${id}`,
        { method: "PUT", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status }) });
      if (!r.ok) throw new Error("Update failed");
      setItems(prev => prev.map(i => i.id === id ? { ...i, status } : i));
    } catch (e) {
      setMsg({ type: "error", text: e.message });
    }
  };

  const importASM = async () => {
    setImp(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/comp/exposure/import-asm`,
        { method: "POST", credentials: "include" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Import failed");
      setMsg({ type: "ok", text: `ASM import: ${d.imported} new, ${d.skipped} already tracked` });
      await load();
    } catch (e) {
      setMsg({ type: "error", text: e.message });
    } finally {
      setImp(false);
    }
  };

  const syncSIEM = async () => {
    setSyncing(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/comp/evidence/sync-siem`,
        { method: "POST", credentials: "include" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "SIEM sync failed");
      setMsg({ type: "ok", text: `SIEM sync: ${d.synced || 0} evidence items imported` });
    } catch (e) {
      setMsg({ type: "error", text: e.message });
    } finally {
      setSyncing(false);
    }
  };

  // Stats across all loaded items
  const total    = items.length;
  const critical = items.filter(i => i.severity === "critical").length;
  const open     = items.filter(i => i.status === "open").length;
  const resolved = items.filter(i => i.status === "resolved" || i.status === "accepted").length;

  // Filter visible rows
  const visible = items.filter(i => {
    if (activeTab === "other"
      && (i.exposure_type === "vulnerability" || i.exposure_type === "supply_chain")) return false;
    if (filter.sev !== "all" && i.severity !== filter.sev) return false;
    if (filter.status !== "all" && i.status !== filter.status) return false;
    if (filter.search) {
      const q = filter.search.toLowerCase();
      return (i.asset || "").toLowerCase().includes(q)
        || (i.title || "").toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div style={{ padding: "28px 32px", background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "system-ui, sans-serif" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Exposure Register</div>
          <div style={{ color: C.muted, fontSize: 13 }}>
            Consolidated attack-surface and compliance exposure tracking.
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={syncSIEM} disabled={syncing}
            style={{ background: "rgba(77,158,255,0.15)", color: C.blue, border: `1px solid ${C.blue}44`,
              borderRadius: 6, padding: "8px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
            {syncing ? "Syncing…" : "Sync from SIEM"}
          </button>
          <button onClick={importASM} disabled={importing}
            style={{ background: "rgba(255,140,0,0.15)", color: C.orange, border: `1px solid ${C.orange}44`,
              borderRadius: 6, padding: "8px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
            {importing ? "Importing…" : "Import ASM Scan"}
          </button>
          <button onClick={() => setCreate(true)}
            style={{ background: C.accent, color: "#000", border: "none",
              borderRadius: 6, padding: "8px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
            + Add Item
          </button>
        </div>
      </div>

      {/* Message */}
      {msg && (
        <div style={{ ...CARD, marginBottom: 20, padding: "10px 18px", fontSize: 13,
          borderColor: msg.type === "error" ? C.red : C.accent,
          color: msg.type === "error" ? C.red : C.accent }}>
          {msg.text}
          <button onClick={() => setMsg(null)}
            style={{ float: "right", background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 14 }}>
            ×
          </button>
        </div>
      )}

      {/* Stats */}
      <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
        <StatCard label="Total Items"         value={total}    color={C.text} />
        <StatCard label="Critical"            value={critical} color={C.red} />
        <StatCard label="Open"                value={open}     color={C.orange} />
        <StatCard label="Resolved / Accepted" value={resolved} color={C.accent} />
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20, borderBottom: `1px solid ${C.border}`, paddingBottom: 0 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{
              background: "none", border: "none", padding: "8px 16px",
              cursor: "pointer", fontWeight: 500, fontSize: 13,
              color: activeTab === t.id ? C.accent : C.muted,
              borderBottom: activeTab === t.id ? `2px solid ${C.accent}` : "2px solid transparent",
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <input placeholder="Search asset, title…"
          value={filter.search} onChange={e => setFilter(f => ({ ...f, search: e.target.value }))}
          style={{ flex: 1, minWidth: 200, background: "rgba(255,255,255,0.04)",
            border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 12px",
            color: C.text, fontSize: 13, outline: "none" }} />
        {[
          { key: "sev",    opts: ["all","critical","high","medium","low"],                          label: "Severity" },
          { key: "status", opts: ["all","open","in_progress","resolved","accepted","false_positive"], label: "Status" },
        ].map(({ key, opts, label }) => (
          <select key={key} value={filter[key]} onChange={e => setFilter(f => ({ ...f, [key]: e.target.value }))}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 13 }}>
            {opts.map(o => <option key={o} value={o}>{o === "all" ? `All ${label}` : o.replace(/_/g," ")}</option>)}
          </select>
        ))}
      </div>

      {/* Table */}
      {loading ? (
        <div style={{ color: C.muted, textAlign: "center", padding: 40, fontSize: 13 }}>Loading…</div>
      ) : visible.length === 0 ? (
        <div style={{ ...CARD, textAlign: "center", padding: "32px 24px", color: C.muted, fontSize: 13 }}>
          No exposure items match the current filter.
        </div>
      ) : (
        <div style={CARD}>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}`, color: C.muted, fontSize: 11,
                  textTransform: "uppercase", letterSpacing: 0.8 }}>
                  {["Asset", "Type", "Title", "Sev", "CVSS", "Source", "Status", "Age", "Actions"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.map(item => {
                  const ageDays = item.created_at
                    ? Math.floor((Date.now() - new Date(item.created_at)) / 86400000)
                    : null;
                  return (
                    <tr key={item.id} style={{ borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
                      <td style={{ padding: "10px 12px", color: C.accent, fontFamily: "monospace", fontSize: 11 }}>
                        {item.asset || "—"}
                      </td>
                      <td style={{ padding: "10px 12px" }}>
                        <TypeBadge type={item.exposure_type} />
                      </td>
                      <td style={{ padding: "10px 12px", color: C.text, maxWidth: 240 }}>
                        <div style={{ fontWeight: 500 }}>{item.title}</div>
                      </td>
                      <td style={{ padding: "10px 12px" }}>
                        <SevBadge sev={item.severity} />
                      </td>
                      <td style={{ padding: "10px 12px", color: C.muted, fontFamily: "monospace", fontSize: 11 }}>
                        {item.cvss_score ?? "—"}
                      </td>
                      <td style={{ padding: "10px 12px", color: C.muted, fontSize: 11 }}>
                        {item.source || "manual"}
                      </td>
                      <td style={{ padding: "10px 12px" }}>
                        <select
                          value={item.status}
                          onChange={e => updateStatus(item.id, e.target.value)}
                          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
                            borderRadius: 4, padding: "3px 6px", color: C.text, fontSize: 11 }}
                        >
                          {["open","in_progress","resolved","accepted","false_positive"].map(s => (
                            <option key={s} value={s}>{s.replace(/_/g," ")}</option>
                          ))}
                        </select>
                      </td>
                      <td style={{ padding: "10px 12px", color: ageDays > 30 ? C.orange : C.muted,
                        fontFamily: "monospace", fontSize: 11, whiteSpace: "nowrap" }}>
                        {ageDays !== null ? `${ageDays}d` : "—"}
                      </td>
                      <td style={{ padding: "10px 12px" }}>
                        {(item.status === "open" || item.status === "in_progress") && (
                          <button onClick={() => updateStatus(item.id, "resolved")}
                            style={{ background: `${C.accent}22`, color: C.accent, border: `1px solid ${C.accent}44`,
                              borderRadius: 4, padding: "3px 8px", fontSize: 11, cursor: "pointer" }}>
                            Resolve
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: 12, color: C.muted, fontSize: 12 }}>
            Showing {visible.length} of {total} items
          </div>
        </div>
      )}

      {showCreate && (
        <CreateModal
          onClose={() => setCreate(false)}
          onCreate={item => { setItems(prev => [item, ...prev]); }}
        />
      )}
    </div>
  );
}
