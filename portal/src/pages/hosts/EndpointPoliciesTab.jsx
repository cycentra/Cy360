/**
 * EndpointPoliciesTab.jsx
 * Create, manage, and apply endpoint control policies.
 * Each policy defines a set of remediation actions (isolate, scan, block USB, etc.),
 * a scope (all agents / group / specific agents), and a trigger mode (manual or
 * auto-trigger when specific Wazuh rule IDs fire).
 */

import { useState, useEffect, useCallback } from "react";

const API = "/api/siem";

// ── Style tokens (match AgentGroupsTab / dark theme) ──────────────────────────
const S = {
  card: {
    background: "rgba(255,255,255,0.03)",
    border: "1px solid rgba(255,255,255,0.07)",
    borderRadius: 8,
  },
  btn: (v = "default") => ({
    border: "1px solid",
    borderRadius: 4,
    cursor: "pointer",
    fontFamily: "monospace",
    fontSize: 11,
    padding: "5px 12px",
    ...(v === "accent"
      ? { background: "rgba(0,229,160,0.1)",  borderColor: "rgba(0,229,160,0.35)",  color: "#00e5a0" }
      : v === "danger"
      ? { background: "rgba(255,59,59,0.08)",  borderColor: "rgba(255,59,59,0.35)",  color: "#ff6b6b" }
      : v === "ghost"
      ? { background: "none",                  borderColor: "rgba(255,255,255,0.12)", color: "#aaa" }
      : v === "warn"
      ? { background: "rgba(255,140,0,0.08)",  borderColor: "rgba(255,140,0,0.35)",  color: "#ff8c00" }
      : { background: "rgba(77,158,255,0.1)",  borderColor: "rgba(77,158,255,0.35)", color: "#4d9eff" }),
  }),
  input: {
    background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
    color: "#e8eaed", padding: "6px 10px", borderRadius: 4,
    fontSize: 11, fontFamily: "monospace", outline: "none", width: "100%", boxSizing: "border-box",
  },
  label: { fontSize: 9, letterSpacing: "1.5px", color: "#666", marginBottom: 4, display: "block" },
  sectionHead: { fontSize: 9, letterSpacing: "2px", color: "#555", marginBottom: 10 },
};

const SEVERITY_COLOR  = { critical: "#ff3b3b", high: "#ff8c00", medium: "#4d9eff", low: "#00e5a0" };
const SCOPE_LABELS    = { local: "Specific Agents", all: "All Endpoints", group: "Agent Group", agents: "Agent List" };
const STATUS_COLOR    = { success: "#00e5a0", failed: "#ff6b6b", pending: "#ff8c00" };

// ── API helper ────────────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, { credentials: "include", ...opts });
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data: json };
}

function post(path, body) {
  return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}
function put(path, body) {
  return api(path, { method: "PUT",  headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}
function del(path) {
  return api(path, { method: "DELETE" });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function timeAgo(iso) {
  if (!iso) return "—";
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

// ── Action badge ──────────────────────────────────────────────────────────────
function ActionBadge({ action, catalog }) {
  const info = catalog[action] || { label: action, severity: "low" };
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      background: `${SEVERITY_COLOR[info.severity]}15`,
      border: `1px solid ${SEVERITY_COLOR[info.severity]}40`,
      color: SEVERITY_COLOR[info.severity], borderRadius: 3,
      fontSize: 10, padding: "2px 7px", marginRight: 4, marginBottom: 4,
    }}>
      {info.label}
    </span>
  );
}

// ── Scope badge ───────────────────────────────────────────────────────────────
function ScopeBadge({ scope_type, scope_value }) {
  const label = SCOPE_LABELS[scope_type] || scope_type;
  const val   = scope_value ? `: ${scope_value}` : "";
  return (
    <span style={{
      fontSize: 10, color: "#aaa",
      background: "rgba(255,255,255,0.05)",
      border: "1px solid rgba(255,255,255,0.1)",
      borderRadius: 3, padding: "2px 7px",
    }}>{label}{val}</span>
  );
}

// ── Create / Edit Policy Modal ────────────────────────────────────────────────
function PolicyFormModal({ policy, catalog, groups, onClose, onSaved }) {
  const editing = !!policy;
  const [form, setForm] = useState({
    name:          policy?.name         || "",
    description:   policy?.description  || "",
    actions:       policy?.actions      || [],
    scope_type:    policy?.scope_type   || "local",
    scope_value:   policy?.scope_value  || "",
    auto_trigger:  policy?.auto_trigger || false,
    trigger_rules: (policy?.trigger_rules || []).join(", "),
  });
  const [saving, setSaving] = useState(false);
  const [err, setErr]       = useState(null);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const toggleAction = (key) =>
    set("actions", form.actions.includes(key)
      ? form.actions.filter(a => a !== key)
      : [...form.actions, key]);

  const handleSave = async () => {
    if (!form.name.trim()) { setErr("Name is required"); return; }
    if (!form.actions.length) { setErr("Select at least one action"); return; }
    const rules = form.trigger_rules
      .split(/[,\s]+/)
      .map(r => parseInt(r, 10))
      .filter(n => !isNaN(n) && n > 0);
    const body = {
      name:          form.name.trim(),
      description:   form.description.trim(),
      actions:       form.actions,
      scope_type:    form.scope_type,
      scope_value:   form.scope_value.trim() || null,
      auto_trigger:  form.auto_trigger,
      trigger_rules: rules,
    };
    setSaving(true); setErr(null);
    const r = editing
      ? await put(`/endpoint-policies/${policy.id}`, body)
      : await post("/endpoint-policies", body);
    setSaving(false);
    if (!r.ok) { setErr(r.data?.error || "Save failed"); return; }
    onSaved(r.data.policy);
  };

  const actionKeys = Object.keys(catalog);

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000,
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        ...S.card, width: 600, maxHeight: "90vh", overflowY: "auto",
        padding: 24, display: "flex", flexDirection: "column", gap: 18,
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontFamily: "monospace", fontSize: 13, color: "#e8eaed", fontWeight: 600 }}>
            {editing ? "Edit Policy" : "New Endpoint Policy"}
          </span>
          <button onClick={onClose} style={{ ...S.btn("ghost"), padding: "3px 8px" }}>✕</button>
        </div>

        {/* Name + Description */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div>
            <label style={S.label}>POLICY NAME *</label>
            <input style={S.input} value={form.name}
              onChange={e => set("name", e.target.value)} placeholder="e.g. Ransomware Response" />
          </div>
          <div>
            <label style={S.label}>DESCRIPTION</label>
            <input style={S.input} value={form.description}
              onChange={e => set("description", e.target.value)} placeholder="Optional description" />
          </div>
        </div>

        {/* Actions */}
        <div>
          <label style={S.label}>ACTIONS *  (select all that apply)</label>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
            {actionKeys.map(key => {
              const info = catalog[key];
              const sel  = form.actions.includes(key);
              return (
                <div key={key} onClick={() => toggleAction(key)} style={{
                  ...S.card, padding: "8px 10px", cursor: "pointer",
                  border: sel
                    ? `1px solid ${SEVERITY_COLOR[info.severity]}60`
                    : "1px solid rgba(255,255,255,0.07)",
                  background: sel ? `${SEVERITY_COLOR[info.severity]}0d` : "rgba(255,255,255,0.03)",
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                    <span style={{
                      width: 14, height: 14, borderRadius: 2, flexShrink: 0,
                      border: `1px solid ${sel ? SEVERITY_COLOR[info.severity] : "#444"}`,
                      background: sel ? SEVERITY_COLOR[info.severity] : "transparent",
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 9, color: "#000",
                    }}>{sel ? "✓" : ""}</span>
                    <div>
                      <div style={{ fontSize: 11, color: "#e8eaed", fontFamily: "monospace" }}>
                        {info.label}
                        <span style={{
                          marginLeft: 6, fontSize: 9,
                          color: SEVERITY_COLOR[info.severity],
                        }}>{info.severity}</span>
                        {!info.reversible && (
                          <span style={{ marginLeft: 6, fontSize: 9, color: "#ff8c00" }}>irreversible</span>
                        )}
                      </div>
                      <div style={{ fontSize: 10, color: "#666", marginTop: 2, lineHeight: 1.3 }}>
                        {info.description}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Scope */}
        <div style={{ display: "flex", gap: 10 }}>
          <div style={{ flex: 1 }}>
            <label style={S.label}>SCOPE</label>
            <select style={{ ...S.input }} value={form.scope_type}
              onChange={e => { set("scope_type", e.target.value); set("scope_value", ""); }}>
              <option value="local">Specific Agents (select at apply time)</option>
              <option value="all">All Active Endpoints</option>
              <option value="group">Agent Group</option>
              <option value="agents">Agent ID List</option>
            </select>
          </div>
          {(form.scope_type === "group" || form.scope_type === "agents") && (
            <div style={{ flex: 1 }}>
              <label style={S.label}>
                {form.scope_type === "group" ? "GROUP NAME" : "AGENT IDs (JSON array)"}
              </label>
              {form.scope_type === "group" ? (
                <select style={{ ...S.input }} value={form.scope_value}
                  onChange={e => set("scope_value", e.target.value)}>
                  <option value="">— select group —</option>
                  {(groups || []).map(g => (
                    <option key={g.name} value={g.name}>{g.name}</option>
                  ))}
                </select>
              ) : (
                <input style={S.input} value={form.scope_value}
                  onChange={e => set("scope_value", e.target.value)}
                  placeholder='["001","002"]' />
              )}
            </div>
          )}
        </div>

        {/* Auto-trigger */}
        <div style={{ ...S.card, padding: "12px 14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: form.auto_trigger ? 12 : 0 }}>
            <div
              onClick={() => set("auto_trigger", !form.auto_trigger)}
              style={{
                width: 36, height: 20, borderRadius: 10,
                background: form.auto_trigger ? "rgba(0,229,160,0.6)" : "rgba(255,255,255,0.1)",
                position: "relative", cursor: "pointer", transition: "background 0.2s",
              }}>
              <div style={{
                position: "absolute", top: 3, left: form.auto_trigger ? 18 : 3,
                width: 14, height: 14, borderRadius: "50%", background: "#fff",
                transition: "left 0.2s",
              }} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: "#e8eaed", fontFamily: "monospace" }}>Auto-trigger</div>
              <div style={{ fontSize: 10, color: "#666" }}>
                Automatically apply when specific Wazuh rule IDs fire
              </div>
            </div>
          </div>
          {form.auto_trigger && (
            <div>
              <label style={S.label}>RULE IDs (comma-separated)</label>
              <input style={S.input} value={form.trigger_rules}
                onChange={e => set("trigger_rules", e.target.value)}
                placeholder="100203, 101002, 101003" />
              <div style={{ fontSize: 10, color: "#555", marginTop: 6 }}>
                After saving, click "Sync to Wazuh" to write the auto-trigger to ossec.conf.
              </div>
            </div>
          )}
        </div>

        {err && (
          <div style={{ fontSize: 11, color: "#ff6b6b", fontFamily: "monospace" }}>{err}</div>
        )}

        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button onClick={onClose} style={S.btn("ghost")}>Cancel</button>
          <button onClick={handleSave} disabled={saving} style={S.btn("accent")}>
            {saving ? "Saving…" : editing ? "Save Changes" : "Create Policy"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Apply Modal (agent picker for local scope) ────────────────────────────────
function ApplyModal({ policy, catalog, onClose, onApplied }) {
  const [agents, setAgents]     = useState([]);
  const [selected, setSelected] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [applying, setApplying] = useState(false);
  const [result, setResult]     = useState(null);
  const [err, setErr]           = useState(null);

  useEffect(() => {
    if (policy.scope_type !== "local") {
      setLoading(false); return;
    }
    api("/agent-groups/available-agents").then(r => {
      setLoading(false);
      if (r.ok) setAgents(r.data.agents || []);
    });
  }, [policy.scope_type]);

  const toggle = id =>
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);

  const handleApply = async () => {
    setApplying(true); setErr(null);
    const body = policy.scope_type === "local" ? { agent_ids: selected } : {};
    const r = await post(`/endpoint-policies/${policy.id}/apply`, body);
    setApplying(false);
    if (!r.ok) { setErr(r.data?.error || "Apply failed"); return; }
    setResult(r.data);
    onApplied();
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000,
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ ...S.card, width: 520, maxHeight: "80vh", overflowY: "auto", padding: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
          <span style={{ fontFamily: "monospace", fontSize: 13, color: "#e8eaed", fontWeight: 600 }}>
            Apply: {policy.name}
          </span>
          <button onClick={onClose} style={{ ...S.btn("ghost"), padding: "3px 8px" }}>✕</button>
        </div>

        {/* Actions summary */}
        <div style={{ marginBottom: 14 }}>
          <label style={S.label}>ACTIONS TO EXECUTE</label>
          <div>{(policy.actions || []).map(a =>
            <ActionBadge key={a} action={a} catalog={catalog} />
          )}</div>
        </div>

        {/* Scope */}
        {policy.scope_type === "local" && (
          <div>
            <label style={S.label}>SELECT TARGET AGENTS</label>
            {loading ? (
              <div style={{ color: "#666", fontSize: 11 }}>Loading agents…</div>
            ) : (
              <div style={{ maxHeight: 220, overflowY: "auto", ...S.card, padding: 8 }}>
                {agents.length === 0 && (
                  <div style={{ color: "#666", fontSize: 11, padding: 8 }}>No active agents found</div>
                )}
                {agents.map(a => (
                  <div key={a.id} onClick={() => toggle(a.id)} style={{
                    display: "flex", alignItems: "center", gap: 8,
                    padding: "6px 8px", cursor: "pointer", borderRadius: 4,
                    background: selected.includes(a.id) ? "rgba(77,158,255,0.08)" : "transparent",
                  }}>
                    <span style={{
                      width: 13, height: 13, borderRadius: 2, flexShrink: 0,
                      border: `1px solid ${selected.includes(a.id) ? "#4d9eff" : "#444"}`,
                      background: selected.includes(a.id) ? "#4d9eff" : "transparent",
                      fontSize: 9, color: "#000", display: "flex", alignItems: "center", justifyContent: "center",
                    }}>{selected.includes(a.id) ? "✓" : ""}</span>
                    <span style={{ fontFamily: "monospace", fontSize: 11, color: "#e8eaed" }}>
                      {a.name || a.id}
                    </span>
                    <span style={{ fontSize: 10, color: "#666" }}>{a.ip || ""}</span>
                    <span style={{ fontSize: 10, color: "#666", marginLeft: "auto" }}>
                      {(a["os.platform"] || a.os?.platform || "")}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {policy.scope_type !== "local" && (
          <div style={{ fontSize: 11, color: "#aaa", fontFamily: "monospace", padding: "8px 0" }}>
            Scope: <ScopeBadge scope_type={policy.scope_type} scope_value={policy.scope_value} />
            {" "}— all matching agents will be targeted.
          </div>
        )}

        {result && (
          <div style={{
            marginTop: 12, padding: 12, borderRadius: 6,
            background: "rgba(0,229,160,0.06)", border: "1px solid rgba(0,229,160,0.2)",
            fontSize: 11, fontFamily: "monospace", color: "#00e5a0",
          }}>
            ✓ Applied — {result.successes} succeeded, {result.failures} failed
            &nbsp;({result.agents_targeted} agent{result.agents_targeted !== 1 ? "s" : ""})
          </div>
        )}

        {err && <div style={{ marginTop: 8, fontSize: 11, color: "#ff6b6b" }}>{err}</div>}

        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 16 }}>
          <button onClick={onClose} style={S.btn("ghost")}>
            {result ? "Close" : "Cancel"}
          </button>
          {!result && (
            <button
              onClick={handleApply}
              disabled={applying || (policy.scope_type === "local" && !selected.length)}
              style={S.btn("warn")}>
              {applying ? "Applying…" : "Apply Now"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Policy Detail Panel ───────────────────────────────────────────────────────
function PolicyDetail({ policy, catalog, groups, onUpdate, onDelete }) {
  const [detailTab, setDetailTab]   = useState("overview");
  const [executions, setExecs]      = useState([]);
  const [execLoading, setExecLoad]  = useState(false);
  const [showEdit, setShowEdit]     = useState(false);
  const [showApply, setShowApply]   = useState(false);
  const [syncing, setSyncing]       = useState(false);
  const [syncMsg, setSyncMsg]       = useState(null);
  const [toggling, setToggling]     = useState(false);

  const loadExecs = useCallback(async () => {
    setExecLoad(true);
    const r = await api(`/endpoint-policies/${policy.id}/executions`);
    setExecLoad(false);
    if (r.ok) setExecs(r.data.executions || []);
  }, [policy.id]);

  useEffect(() => {
    if (detailTab === "history") loadExecs();
  }, [detailTab, loadExecs]);

  const handleToggle = async () => {
    setToggling(true);
    const r = await put(`/endpoint-policies/${policy.id}`, { enabled: !policy.enabled });
    setToggling(false);
    if (r.ok) onUpdate(r.data.policy);
  };

  const handleSync = async () => {
    setSyncing(true); setSyncMsg(null);
    const r = await post("/endpoint-policies/sync", {});
    setSyncing(false);
    setSyncMsg(r.ok
      ? `✓ Synced — ${r.data.blocks_generated} block(s) written, wazuh-manager ${r.data.wazuh_restarted ? "restarted" : "NOT restarted"}`
      : `✗ ${r.data?.error || "Sync failed"}`);
  };

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 0 }}>
      {/* Header */}
      <div style={{
        display: "flex", alignItems: "flex-start", justifyContent: "space-between",
        marginBottom: 16, gap: 12,
      }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <span style={{ fontFamily: "monospace", fontSize: 14, color: "#e8eaed", fontWeight: 600 }}>
              {policy.name}
            </span>
            {/* Enable toggle */}
            <div onClick={handleToggle} title={policy.enabled ? "Disable" : "Enable"}
              style={{
                width: 30, height: 16, borderRadius: 8,
                background: policy.enabled ? "rgba(0,229,160,0.5)" : "rgba(255,255,255,0.1)",
                position: "relative", cursor: toggling ? "wait" : "pointer",
              }}>
              <div style={{
                position: "absolute", top: 2, left: policy.enabled ? 15 : 2,
                width: 12, height: 12, borderRadius: "50%", background: "#fff",
                transition: "left 0.2s",
              }} />
            </div>
            <span style={{ fontSize: 10, color: policy.enabled ? "#00e5a0" : "#555" }}>
              {policy.enabled ? "ENABLED" : "DISABLED"}
            </span>
          </div>
          {policy.description && (
            <div style={{ fontSize: 11, color: "#666", fontFamily: "monospace" }}>
              {policy.description}
            </div>
          )}
        </div>
        <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
          <button onClick={() => setShowApply(true)} style={S.btn("warn")}>▶ Apply Now</button>
          <button onClick={() => setShowEdit(true)}  style={S.btn("ghost")}>Edit</button>
          {policy.auto_trigger && (
            <button onClick={handleSync} disabled={syncing} style={S.btn()}>
              {syncing ? "Syncing…" : "Sync to Wazuh"}
            </button>
          )}
          <button onClick={() => onDelete(policy.id)} style={S.btn("danger")}>Delete</button>
        </div>
      </div>

      {syncMsg && (
        <div style={{
          marginBottom: 12, padding: "8px 12px", borderRadius: 6, fontSize: 11,
          fontFamily: "monospace",
          background: syncMsg.startsWith("✓")
            ? "rgba(0,229,160,0.06)" : "rgba(255,59,59,0.06)",
          color: syncMsg.startsWith("✓") ? "#00e5a0" : "#ff6b6b",
          border: `1px solid ${syncMsg.startsWith("✓") ? "rgba(0,229,160,0.2)" : "rgba(255,59,59,0.2)"}`,
        }}>{syncMsg}</div>
      )}

      {/* Inner tabs */}
      <div style={{ display: "flex", gap: 2, borderBottom: "1px solid rgba(255,255,255,0.07)", marginBottom: 16 }}>
        {["overview", "history"].map(t => (
          <button key={t} onClick={() => setDetailTab(t)} style={{
            background: "none", border: "none",
            borderBottom: detailTab === t ? "2px solid #4d9eff" : "2px solid transparent",
            color: detailTab === t ? "#e8eaed" : "#555",
            padding: "6px 14px", cursor: "pointer",
            fontSize: 11, fontFamily: "monospace", marginBottom: -1,
          }}>{t === "overview" ? "Overview" : "Execution History"}</button>
        ))}
      </div>

      {/* Overview */}
      {detailTab === "overview" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* Actions */}
          <div style={{ ...S.card, padding: 14 }}>
            <div style={S.sectionHead}>ACTIONS</div>
            {(policy.actions || []).map(a => {
              const info = catalog[a] || { label: a, severity: "low", description: "", reversible: true };
              return (
                <div key={a} style={{
                  display: "flex", alignItems: "flex-start", gap: 10,
                  padding: "8px 0", borderBottom: "1px solid rgba(255,255,255,0.04)",
                }}>
                  <div style={{
                    width: 8, height: 8, borderRadius: "50%", marginTop: 3, flexShrink: 0,
                    background: SEVERITY_COLOR[info.severity] || "#555",
                  }} />
                  <div>
                    <div style={{ fontSize: 11, color: "#e8eaed", fontFamily: "monospace" }}>
                      {info.label}
                      {!info.reversible && (
                        <span style={{ marginLeft: 8, fontSize: 9, color: "#ff8c00" }}>⚠ irreversible</span>
                      )}
                      {info.timeout > 0 && (
                        <span style={{ marginLeft: 8, fontSize: 9, color: "#555" }}>
                          auto-reverts {info.timeout >= 3600 ? `${info.timeout/3600}h` : `${info.timeout/60}m`}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 10, color: "#555", marginTop: 2 }}>{info.description}</div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Scope + Trigger */}
          <div style={{ display: "flex", gap: 12 }}>
            <div style={{ ...S.card, padding: 14, flex: 1 }}>
              <div style={S.sectionHead}>SCOPE</div>
              <div style={{ fontSize: 11, color: "#e8eaed", fontFamily: "monospace", marginBottom: 6 }}>
                {SCOPE_LABELS[policy.scope_type] || policy.scope_type}
              </div>
              {policy.scope_value && (
                <div style={{ fontSize: 11, color: "#aaa" }}>{policy.scope_value}</div>
              )}
            </div>
            <div style={{ ...S.card, padding: 14, flex: 1 }}>
              <div style={S.sectionHead}>TRIGGER</div>
              <div style={{ fontSize: 11, color: "#e8eaed", fontFamily: "monospace", marginBottom: 6 }}>
                {policy.auto_trigger ? "Auto + Manual" : "Manual only"}
              </div>
              {policy.auto_trigger && policy.trigger_rules?.length > 0 && (
                <div style={{ fontSize: 10, color: "#aaa" }}>
                  Rules: {policy.trigger_rules.join(", ")}
                </div>
              )}
              {policy.auto_trigger && (!policy.trigger_rules || !policy.trigger_rules.length) && (
                <div style={{ fontSize: 10, color: "#ff8c00" }}>⚠ No rule IDs configured</div>
              )}
            </div>
          </div>

          {/* Meta */}
          <div style={{ fontSize: 10, color: "#444", fontFamily: "monospace" }}>
            Created by {policy.created_by || "—"} · {timeAgo(policy.created_at)}
            · Last updated {timeAgo(policy.updated_at)}
          </div>
        </div>
      )}

      {/* History */}
      {detailTab === "history" && (
        <div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 10 }}>
            <button onClick={loadExecs} style={S.btn("ghost")}>↻ Refresh</button>
          </div>
          {execLoading ? (
            <div style={{ color: "#555", fontSize: 11 }}>Loading…</div>
          ) : executions.length === 0 ? (
            <div style={{ color: "#444", fontSize: 11, textAlign: "center", padding: 32 }}>
              No executions yet — apply the policy manually or configure auto-trigger.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "monospace" }}>
              <thead>
                <tr style={{ color: "#555" }}>
                  {["Agent", "Action", "Trigger", "Status", "By", "Time"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "6px 8px",
                      borderBottom: "1px solid rgba(255,255,255,0.07)", fontWeight: 400 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {executions.map(ex => (
                  <tr key={ex.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                    <td style={{ padding: "7px 8px", color: "#e8eaed" }}>{ex.agent_name || ex.agent_id}</td>
                    <td style={{ padding: "7px 8px" }}>
                      <ActionBadge action={(ex.actions || [])[0] || "—"} catalog={catalog} />
                    </td>
                    <td style={{ padding: "7px 8px", color: "#666" }}>
                      {ex.trigger_type === "auto" ? "⚡ Auto" : "▶ Manual"}
                    </td>
                    <td style={{ padding: "7px 8px" }}>
                      <span style={{ color: STATUS_COLOR[ex.status] || "#aaa" }}>
                        {ex.status === "success" ? "✓" : ex.status === "failed" ? "✗" : "○"} {ex.status}
                      </span>
                      {ex.error_msg && (
                        <div style={{ fontSize: 10, color: "#ff6b6b", marginTop: 2 }}>{ex.error_msg}</div>
                      )}
                    </td>
                    <td style={{ padding: "7px 8px", color: "#555" }}>
                      {ex.triggered_by?.split("@")[0] || "—"}
                    </td>
                    <td style={{ padding: "7px 8px", color: "#555" }}>{timeAgo(ex.executed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {showEdit && (
        <PolicyFormModal
          policy={policy} catalog={catalog} groups={groups}
          onClose={() => setShowEdit(false)}
          onSaved={p => { setShowEdit(false); onUpdate(p); }} />
      )}

      {showApply && (
        <ApplyModal
          policy={policy} catalog={catalog}
          onClose={() => setShowApply(false)}
          onApplied={() => {
            if (detailTab === "history") loadExecs();
          }} />
      )}
    </div>
  );
}

// ── Main Tab ──────────────────────────────────────────────────────────────────
export function EndpointPoliciesTab() {
  const [policies, setPolicies] = useState([]);
  const [catalog, setCatalog]   = useState({});
  const [groups, setGroups]     = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading]   = useState(true);
  const [err, setErr]           = useState(null);
  const [showCreate, setCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setErr(null);
    const [polR, actR, grpR] = await Promise.all([
      api("/endpoint-policies"),
      api("/endpoint-policies/actions"),
      api("/agent-groups"),
    ]);
    setLoading(false);
    if (!polR.ok) { setErr(polR.data?.error || "Failed to load policies"); return; }
    setPolicies(polR.data.policies || []);
    if (actR.ok) {
      const map = {};
      (actR.data.actions || []).forEach(a => { map[a.key] = a; });
      setCatalog(map);
    }
    if (grpR.ok) setGroups(grpR.data.groups || []);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleDelete = async (id) => {
    if (!window.confirm("Delete this policy?")) return;
    const r = await del(`/endpoint-policies/${id}`);
    if (r.ok) {
      setPolicies(p => p.filter(x => x.id !== id));
      if (selected?.id === id) setSelected(null);
    }
  };

  const handleUpdate = (updated) => {
    setPolicies(p => p.map(x => x.id === updated.id ? updated : x));
    setSelected(updated);
  };

  const handleCreated = (policy) => {
    setPolicies(p => [policy, ...p]);
    setSelected(policy);
    setCreate(false);
  };

  const selPolicy = selected ? policies.find(p => p.id === selected.id) || selected : null;

  if (loading) return (
    <div style={{ color: "#555", fontSize: 12, textAlign: "center", padding: 48 }}>
      Loading policies…
    </div>
  );
  if (err) return (
    <div style={{ color: "#ff6b6b", fontSize: 12, padding: 24 }}>Error: {err}</div>
  );

  return (
    <div style={{ display: "flex", gap: 16, minHeight: 460 }}>
      {/* Left: policy list */}
      <div style={{ ...S.card, width: 260, flexShrink: 0, display: "flex", flexDirection: "column" }}>
        <div style={{
          padding: "12px 14px 10px", display: "flex",
          justifyContent: "space-between", alignItems: "center",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}>
          <span style={{ fontSize: 9, letterSpacing: "1.5px", color: "#666" }}>
            POLICIES ({policies.length})
          </span>
          <button onClick={() => setCreate(true)} style={{ ...S.btn("accent"), padding: "3px 10px" }}>
            + New
          </button>
        </div>
        <div style={{ flex: 1, overflowY: "auto" }}>
          {policies.length === 0 && (
            <div style={{ padding: 20, textAlign: "center" }}>
              <div style={{ color: "#444", fontSize: 11, marginBottom: 8 }}>No policies yet</div>
              <button onClick={() => setCreate(true)} style={S.btn("accent")}>
                Create your first policy
              </button>
            </div>
          )}
          {policies.map(p => (
            <div key={p.id} onClick={() => setSelected(p)} style={{
              padding: "10px 14px", cursor: "pointer",
              borderBottom: "1px solid rgba(255,255,255,0.04)",
              background: selPolicy?.id === p.id
                ? "rgba(77,158,255,0.07)" : "transparent",
              borderLeft: selPolicy?.id === p.id
                ? "2px solid #4d9eff" : "2px solid transparent",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 4 }}>
                <span style={{
                  width: 7, height: 7, borderRadius: "50%", flexShrink: 0,
                  background: p.enabled ? "#00e5a0" : "#444",
                }} />
                <span style={{
                  fontSize: 11, fontFamily: "monospace", color: "#e8eaed",
                  fontWeight: selPolicy?.id === p.id ? 600 : 400,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>{p.name}</span>
              </div>
              <div style={{ fontSize: 10, color: "#555", paddingLeft: 14, lineHeight: 1.4 }}>
                {(p.actions || []).length} action{p.actions?.length !== 1 ? "s" : ""}
                {" · "}{SCOPE_LABELS[p.scope_type] || p.scope_type}
              </div>
              {p.auto_trigger && (
                <div style={{ fontSize: 10, color: "#4d9eff", paddingLeft: 14 }}>
                  ⚡ Auto-trigger
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Right: detail or empty state */}
      {selPolicy ? (
        <div style={{ flex: 1, ...S.card, padding: 20, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <PolicyDetail
            policy={selPolicy} catalog={catalog} groups={groups}
            onUpdate={handleUpdate}
            onDelete={handleDelete} />
        </div>
      ) : (
        <div style={{
          flex: 1, ...S.card, display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center", gap: 12,
        }}>
          <div style={{ fontSize: 28, opacity: 0.2 }}>🔒</div>
          <div style={{ fontSize: 12, color: "#444", fontFamily: "monospace" }}>
            Select a policy to view details
          </div>
          <div style={{ fontSize: 11, color: "#333", textAlign: "center", maxWidth: 320 }}>
            Policies define remediation actions that can be applied to endpoints
            manually or triggered automatically by Wazuh rule matches.
          </div>
        </div>
      )}

      {showCreate && (
        <PolicyFormModal
          catalog={catalog} groups={groups}
          onClose={() => setCreate(false)}
          onSaved={handleCreated} />
      )}
    </div>
  );
}
