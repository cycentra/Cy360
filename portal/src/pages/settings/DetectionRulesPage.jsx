import { useState, useEffect, useCallback } from "react";
import { CyScanRulesContent } from "../edr/EdrCyScanRulesPage.jsx";

const API = "/api/detection-rules";

// ── Design tokens (mirrors EdrCyScanRulesPage.jsx's dark-theme tokens) ───────
const T = {
  bg:      "#0a0e1a",
  card:    "rgba(255,255,255,0.03)",
  border:  "1px solid rgba(255,255,255,0.07)",
  accent:  "#00e5a0",
  red:     "#ff3b3b",
  orange:  "#ff8c00",
  purple:  "#b06eff",
  blue:    "#4d9eff",
  text:    "rgba(255,255,255,0.85)",
  muted:   "rgba(255,255,255,0.4)",
  mono:    "'Space Mono', monospace",
};

// ── Primitives ────────────────────────────────────────────────────────────────
function Panel({ title, accent = T.accent, badge, children, right, style = {} }) {
  return (
    <div style={{ background: T.card, border: T.border, borderTop: `2px solid ${accent}`,
                  borderRadius: 5, padding: "18px 22px", ...style }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ color: T.muted, fontSize: 10, letterSpacing: "1.5px",
                         textTransform: "uppercase", fontFamily: T.mono }}>{title}</span>
          {badge != null && (
            <span style={{ background: `${accent}18`, color: accent, fontSize: 10,
                           fontFamily: T.mono, padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>
              {badge}
            </span>
          )}
        </div>
        {right}
      </div>
      {children}
    </div>
  );
}

function Btn({ onClick, children, accent = T.accent, disabled = false, style = {} }) {
  return (
    <button onClick={onClick} disabled={disabled}
      style={{ background: `${accent}18`, border: `1px solid ${accent}40`, color: accent,
               borderRadius: 4, padding: "6px 14px", fontSize: 11, fontFamily: T.mono,
               cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.5 : 1,
               transition: "opacity 0.15s", ...style }}>
      {children}
    </button>
  );
}

function Badge({ label, color }) {
  return (
    <span style={{ background: `${color}18`, color, fontSize: 10, fontFamily: T.mono,
                   padding: "2px 8px", borderRadius: 2, fontWeight: 700, whiteSpace: "nowrap" }}>
      {label}
    </span>
  );
}

function Toast({ msg, ok }) {
  if (!msg) return null;
  return (
    <div style={{ position: "fixed", bottom: 24, right: 24, zIndex: 9999,
                  background: ok ? "#0f2a1e" : "#2a0f0f",
                  border: `1px solid ${ok ? T.accent : T.red}`,
                  color: ok ? T.accent : T.red, padding: "10px 18px",
                  borderRadius: 4, fontSize: 12, fontFamily: T.mono }}>
      {msg}
    </div>
  );
}

function Toggle({ checked, onChange, disabled }) {
  return (
    <button onClick={onChange} disabled={disabled}
      style={{ width: 34, height: 18, borderRadius: 9, border: "none", cursor: disabled ? "wait" : "pointer",
               background: checked ? `${T.accent}40` : "rgba(255,255,255,0.08)", position: "relative",
               transition: "background 0.15s", flexShrink: 0 }}>
      <span style={{ position: "absolute", top: 2, left: checked ? 18 : 2, width: 14, height: 14,
                    borderRadius: "50%", background: checked ? T.accent : T.muted, transition: "left 0.15s" }} />
    </button>
  );
}

const inputStyle = {
  width: "100%", background: "rgba(255,255,255,0.04)", border: T.border,
  borderRadius: 3, padding: "8px 10px", color: T.text,
  fontSize: 12, fontFamily: T.mono, outline: "none", boxSizing: "border-box",
};

function Modal({ title, accent, onClose, width = 620, children }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 1000,
                  display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: "#0d1120", border: T.border, borderTop: `2px solid ${accent}`,
                    borderRadius: 6, padding: 28, width, maxWidth: "95vw",
                    maxHeight: "90vh", overflowY: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <span style={{ color: accent, fontFamily: T.mono, fontSize: 13, fontWeight: 700 }}>{title}</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: T.muted,
                                            fontSize: 18, cursor: "pointer" }}>×</button>
        </div>
        {children}
      </div>
    </div>
  );
}

const OPS = ["eq", "contains", "startswith", "endswith", "re", "in", "gte", "lte"];
const FIELD_HINT = "rule_id, rule_desc, category, agent_id, agent_name, agent_ip, username, src_ip, process_name, file_path, mitre_id, mitre_tactic, base_score, rule_level";

function ConditionBuilder({ conditions, onChange }) {
  const set = (i, k, v) => onChange(conditions.map((c, idx) => idx === i ? { ...c, [k]: v } : c));
  const add = () => onChange([...conditions, { field: "", op: "eq", value: "" }]);
  const remove = (i) => onChange(conditions.filter((_, idx) => idx !== i));

  return (
    <div>
      <div style={{ color: T.muted, fontSize: 9, marginBottom: 6 }}>
        Fields available: <span style={{ color: "rgba(255,255,255,0.5)" }}>{FIELD_HINT}</span>. All rows are ANDed.
      </div>
      {conditions.map((c, i) => (
        <div key={i} style={{ display: "flex", gap: 6, marginBottom: 6 }}>
          <input value={c.field} onChange={e => set(i, "field", e.target.value)}
                 placeholder="field" style={{ ...inputStyle, flex: 2 }} />
          <select value={c.op} onChange={e => set(i, "op", e.target.value)}
                  style={{ ...inputStyle, flex: 1 }}>
            {OPS.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
          <input value={c.value} onChange={e => set(i, "value", e.target.value)}
                 placeholder="value" style={{ ...inputStyle, flex: 2 }} />
          <Btn onClick={() => remove(i)} accent={T.red} style={{ flexShrink: 0 }}>×</Btn>
        </div>
      ))}
      <Btn onClick={add} accent={T.blue}>+ Add condition</Btn>
    </div>
  );
}

// ── Sigma tab ─────────────────────────────────────────────────────────────────
function SigmaEditModal({ initial, onClose, onSaved, notify }) {
  const [yamlText, setYamlText] = useState(initial?.yaml_text || `title: My Custom Rule
id: ${crypto.randomUUID?.() || "custom-rule"}
status: experimental
level: medium
logsource:
  product: linux
detection:
  selection:
    message|contains: "some suspicious string"
  condition: selection
`);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    setSaving(true); setErr("");
    try {
      const url = initial ? `${API}/sigma/${initial.rule_id}` : `${API}/sigma`;
      const r = await fetch(url, {
        method: initial ? "PUT" : "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yaml_text: yamlText }),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || "Save failed"); setSaving(false); return; }
      notify(`Sigma rule saved and active immediately.`);
      onSaved();
    } catch (e) { setErr("Network error"); setSaving(false); }
  }

  return (
    <Modal title={initial ? "EDIT CUSTOM SIGMA RULE" : "+ NEW CUSTOM SIGMA RULE"} accent={T.accent} onClose={onClose} width={680}>
      <div style={{ color: T.muted, fontSize: 11, marginBottom: 10 }}>
        Standard Sigma YAML — <code style={{ color: T.accent }}>title</code>, <code style={{ color: T.accent }}>level</code>,{" "}
        <code style={{ color: T.accent }}>logsource</code>, <code style={{ color: T.accent }}>detection</code> (selection + condition).
      </div>
      <textarea value={yamlText} onChange={e => setYamlText(e.target.value)}
                rows={18} style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6 }} />
      {err && <div style={{ color: T.red, fontSize: 11, fontFamily: T.mono, margin: "12px 0" }}>{err}</div>}
      <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", marginTop: 16 }}>
        <Btn onClick={onClose} accent={T.muted}>Cancel</Btn>
        <Btn onClick={submit} disabled={saving} accent={T.accent}>
          {saving ? "Validating & Saving…" : "Save & Activate"}
        </Btn>
      </div>
    </Modal>
  );
}

function SigmaTab({ notify }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [source, setSource] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null);
  const [showNew, setShowNew] = useState(false);
  const limit = 25;

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ q, source, limit, offset });
    try {
      const r = await fetch(`${API}/sigma?${params}`, { credentials: "include" });
      if (r.ok) { const d = await r.json(); setItems(d.items || []); setTotal(d.total || 0); }
    } catch (_) {}
    setLoading(false);
  }, [q, source, offset]);

  useEffect(() => { load(); }, [load]);

  async function toggle(rule) {
    const r = await fetch(`${API}/sigma/${encodeURIComponent(rule.rule_id)}/toggle`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    if (r.ok) { notify(`Rule ${rule.enabled ? "disabled" : "enabled"} — active immediately.`); load(); }
  }

  async function del(rule) {
    if (!window.confirm(`Delete custom rule "${rule.title}"? This cannot be undone.`)) return;
    const r = await fetch(`${API}/sigma/${encodeURIComponent(rule.rule_id)}`, { method: "DELETE", credentials: "include" });
    if (r.ok) { notify("Rule deleted."); load(); }
  }

  const levelColor = { critical: T.red, high: T.orange, medium: T.blue, low: T.muted };

  return (
    <div>
      <div style={{ display: "flex", gap: 10, marginBottom: 14, alignItems: "center" }}>
        <input value={q} onChange={e => { setOffset(0); setQ(e.target.value); }}
               placeholder="Search title or rule id…" style={{ ...inputStyle, maxWidth: 280 }} />
        <select value={source} onChange={e => { setOffset(0); setSource(e.target.value); }} style={{ ...inputStyle, maxWidth: 160 }}>
          <option value="">All sources</option>
          <option value="bundled">Bundled (starter)</option>
          <option value="imported">Imported (SigmaHQ)</option>
          <option value="custom">Custom</option>
        </select>
        <div style={{ flex: 1 }} />
        <Btn onClick={() => setShowNew(true)} accent={T.accent}>+ New Custom Rule</Btn>
      </div>

      <Panel title="Sigma Rules" accent={T.accent} badge={total}>
        {loading ? (
          <div style={{ color: T.muted, fontSize: 12, textAlign: "center", padding: 20 }}>Loading…</div>
        ) : (
          <>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                  {["Title", "Level", "Logsource", "Source", "Enabled", ""].map(h => (
                    <th key={h} style={{ color: T.muted, fontSize: 9, textTransform: "uppercase",
                                         padding: "6px 10px", textAlign: "left", fontWeight: 400 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map(r => (
                  <tr key={r.rule_id} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                    <td style={{ padding: "8px 10px", color: T.text, fontSize: 12, fontFamily: T.mono }}>{r.title}</td>
                    <td style={{ padding: "8px 10px" }}><Badge label={r.level} color={levelColor[r.level] || T.muted} /></td>
                    <td style={{ padding: "8px 10px", color: T.muted, fontSize: 11 }}>
                      {Object.entries(r.logsource || {}).map(([k, v]) => `${k}:${v}`).join(" ") || "—"}
                    </td>
                    <td style={{ padding: "8px 10px" }}>
                      <Badge label={r.source} color={r.source === "custom" ? T.purple : r.source === "imported" ? T.blue : T.accent} />
                    </td>
                    <td style={{ padding: "8px 10px" }}>
                      <Toggle checked={r.enabled} onChange={() => toggle(r)} />
                    </td>
                    <td style={{ padding: "8px 10px", whiteSpace: "nowrap" }}>
                      {r.editable && (
                        <>
                          <Btn onClick={() => setEditing(r)} accent={T.blue} style={{ marginRight: 6 }}>Edit</Btn>
                          <Btn onClick={() => del(r)} accent={T.red}>Delete</Btn>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 12 }}>
              <span style={{ color: T.muted, fontSize: 11 }}>
                {total === 0 ? "0" : `${offset + 1}–${Math.min(offset + limit, total)}`} of {total}
              </span>
              <div style={{ display: "flex", gap: 8 }}>
                <Btn onClick={() => setOffset(Math.max(0, offset - limit))} disabled={offset === 0} accent={T.muted}>← Prev</Btn>
                <Btn onClick={() => setOffset(offset + limit)} disabled={offset + limit >= total} accent={T.muted}>Next →</Btn>
              </div>
            </div>
          </>
        )}
      </Panel>

      {(showNew || editing) && (
        <SigmaEditModal
          initial={editing}
          onClose={() => { setShowNew(false); setEditing(null); }}
          onSaved={() => { setShowNew(false); setEditing(null); load(); }}
          notify={notify}
        />
      )}
    </div>
  );
}

// ── Generic built-in-rule toggle table, shared by Correlation + UEBA ────────
function BuiltInRuleTable({ rules, onToggle, extraCols = [] }) {
  const sevColor = { critical: T.red, high: T.orange, medium: T.blue, low: T.muted };
  return (
    <table style={{ width: "100%", borderCollapse: "collapse" }}>
      <thead>
        <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          {["Rule Key", "Name", ...extraCols.map(c => c.label), "Enabled"].map(h => (
            <th key={h} style={{ color: T.muted, fontSize: 9, textTransform: "uppercase",
                                 padding: "6px 10px", textAlign: "left", fontWeight: 400 }}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rules.map(r => (
          <tr key={r.rule_key} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
            <td style={{ padding: "8px 10px", color: T.blue, fontSize: 11, fontFamily: T.mono }}>{r.rule_key}</td>
            <td style={{ padding: "8px 10px", color: T.text, fontSize: 12 }}>{r.name}</td>
            {extraCols.map(c => (
              <td key={c.label} style={{ padding: "8px 10px" }}>
                {c.render ? c.render(r) : (
                  <span style={{ color: sevColor[r[c.key]] || T.muted, fontSize: 11 }}>{r[c.key]}</span>
                )}
              </td>
            ))}
            <td style={{ padding: "8px 10px" }}>
              <Toggle checked={r.enabled} onChange={() => onToggle(r)} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CustomRuleForm({ kind, initial, onClose, onSaved, notify }) {
  const [name, setName] = useState(initial?.name || "");
  const [description, setDescription] = useState(initial?.description || "");
  const [conditions, setConditions] = useState(initial?.conditions?.length ? initial.conditions : [{ field: "", op: "eq", value: "" }]);
  const [windowMinutes, setWindowMinutes] = useState(initial?.window_minutes ?? 15);
  const [minCount, setMinCount] = useState(initial?.min_count ?? 1);
  const [severityOverride, setSeverityOverride] = useState(initial?.severity_override || "");
  const [entityType, setEntityType] = useState(initial?.entity_type || "user");
  const [anomalyType, setAnomalyType] = useState(initial?.anomaly_type || "");
  const [riskContribution, setRiskContribution] = useState(initial?.risk_contribution ?? 40);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    if (!name.trim()) { setErr("Name is required."); return; }
    const cleanConditions = conditions.filter(c => c.field.trim());
    if (!cleanConditions.length) { setErr("At least one condition is required."); return; }
    if (kind === "ueba" && !anomalyType.trim()) { setErr("Anomaly type label is required."); return; }

    const body = {
      name, description, conditions: cleanConditions,
      window_minutes: Number(windowMinutes), min_count: Number(minCount),
      ...(kind === "correlation"
        ? { severity_override: severityOverride || null, tags: [] }
        : { entity_type: entityType, anomaly_type: anomalyType, risk_contribution: Number(riskContribution) }),
    };

    setSaving(true); setErr("");
    try {
      const base = `${API}/${kind}/custom`;
      const url = initial ? `${base}/${initial.id}` : base;
      const r = await fetch(url, {
        method: initial ? "PATCH" : "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) { const d = await r.json().catch(() => ({})); setErr(d.error || d.detail || "Save failed"); setSaving(false); return; }
      notify(`Custom ${kind} rule saved and active immediately.`);
      onSaved();
    } catch (e) { setErr("Network error"); setSaving(false); }
  }

  return (
    <Modal title={initial ? `EDIT CUSTOM ${kind.toUpperCase()} RULE` : `+ NEW CUSTOM ${kind.toUpperCase()} RULE`}
           accent={T.purple} onClose={onClose}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
        <div>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4 }}>Name *</div>
          <input value={name} onChange={e => setName(e.target.value)} style={inputStyle} />
        </div>
        <div>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4 }}>Description</div>
          <input value={description} onChange={e => setDescription(e.target.value)} style={inputStyle} />
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <ConditionBuilder conditions={conditions} onChange={setConditions} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: kind === "correlation" ? "1fr 1fr 1fr" : "1fr 1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
        <div>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4 }}>Window (minutes)</div>
          <input type="number" value={windowMinutes} onChange={e => setWindowMinutes(e.target.value)} style={inputStyle} />
        </div>
        <div>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4 }}>Min matching count</div>
          <input type="number" value={minCount} onChange={e => setMinCount(e.target.value)} style={inputStyle} />
        </div>
        {kind === "correlation" ? (
          <div>
            <div style={{ color: T.muted, fontSize: 10, marginBottom: 4 }}>Severity override</div>
            <select value={severityOverride} onChange={e => setSeverityOverride(e.target.value)} style={inputStyle}>
              <option value="">Don't escalate</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </div>
        ) : (
          <>
            <div>
              <div style={{ color: T.muted, fontSize: 10, marginBottom: 4 }}>Entity type</div>
              <select value={entityType} onChange={e => setEntityType(e.target.value)} style={inputStyle}>
                <option value="user">user</option>
                <option value="host">host</option>
              </select>
            </div>
            <div>
              <div style={{ color: T.muted, fontSize: 10, marginBottom: 4 }}>Risk contribution</div>
              <input type="number" value={riskContribution} onChange={e => setRiskContribution(e.target.value)} style={inputStyle} />
            </div>
          </>
        )}
      </div>

      {kind === "ueba" && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4 }}>Anomaly type label *</div>
          <input value={anomalyType} onChange={e => setAnomalyType(e.target.value)}
                 placeholder="e.g. custom_data_hoarding" style={inputStyle} />
        </div>
      )}

      {err && <div style={{ color: T.red, fontSize: 11, fontFamily: T.mono, marginBottom: 12 }}>{err}</div>}

      <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
        <Btn onClick={onClose} accent={T.muted}>Cancel</Btn>
        <Btn onClick={submit} disabled={saving} accent={T.purple}>{saving ? "Saving…" : "Save & Activate"}</Btn>
      </div>
    </Modal>
  );
}

function RuleEngineTab({ kind, notify }) {
  const [builtIn, setBuiltIn] = useState([]);
  const [custom, setCustom] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [b, c] = await Promise.all([
        fetch(`${API}/${kind}`, { credentials: "include" }),
        fetch(`${API}/${kind}/custom`, { credentials: "include" }),
      ]);
      if (b.ok) setBuiltIn(await b.json());
      if (c.ok) setCustom(await c.json());
    } catch (_) {}
    setLoading(false);
  }, [kind]);

  useEffect(() => { load(); }, [load]);

  async function toggleBuiltIn(rule) {
    const r = await fetch(`${API}/${kind}/${encodeURIComponent(rule.rule_key)}/toggle`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    if (r.ok) { notify(`${rule.rule_key} ${rule.enabled ? "disabled" : "enabled"} — active immediately.`); load(); }
  }

  async function toggleCustom(rule) {
    const r = await fetch(`${API}/${kind}/custom/${rule.id}`, {
      method: "PATCH", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...rule, enabled: !rule.enabled }),
    });
    if (r.ok) { notify(`Rule ${rule.enabled ? "disabled" : "enabled"}.`); load(); }
  }

  async function deleteCustom(rule) {
    if (!window.confirm(`Delete custom rule "${rule.name}"?`)) return;
    const r = await fetch(`${API}/${kind}/custom/${rule.id}`, { method: "DELETE", credentials: "include" });
    if (r.ok) { notify("Rule deleted."); load(); }
  }

  const extraCols = kind === "correlation"
    ? [{ label: "Severity", key: "severity" }, { label: "Tactics", render: r => (r.tactics || []).join(", ") || "—" }]
    : [{ label: "Risk", key: "risk_contribution" }];

  return (
    <div>
      <Panel title={`Built-in ${kind === "correlation" ? "Correlation Rules (CR-001..055)" : "UEBA Detectors"}`}
             accent={T.accent} badge={builtIn.length} style={{ marginBottom: 20 }}>
        {loading ? <div style={{ color: T.muted, fontSize: 12, padding: 20, textAlign: "center" }}>Loading…</div>
                 : <BuiltInRuleTable rules={builtIn} onToggle={toggleBuiltIn} extraCols={extraCols} />}
      </Panel>

      <Panel title="Custom Rules" accent={T.purple} badge={custom.length}
             right={<Btn onClick={() => setShowForm(true)} accent={T.purple}>+ New Custom Rule</Btn>}>
        {custom.length === 0 ? (
          <div style={{ color: T.muted, fontSize: 12, textAlign: "center", padding: "24px 0" }}>
            No custom {kind} rules yet.
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                {["Name", "Conditions", "Window / Count", "Enabled", ""].map(h => (
                  <th key={h} style={{ color: T.muted, fontSize: 9, textTransform: "uppercase",
                                       padding: "6px 10px", textAlign: "left", fontWeight: 400 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {custom.map(r => (
                <tr key={r.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                  <td style={{ padding: "8px 10px", color: T.text, fontSize: 12 }}>{r.name}</td>
                  <td style={{ padding: "8px 10px", color: T.muted, fontSize: 11 }}>
                    {(r.conditions || []).map(c => `${c.field} ${c.op} ${c.value}`).join(" AND ")}
                  </td>
                  <td style={{ padding: "8px 10px", color: T.muted, fontSize: 11 }}>
                    {r.window_minutes}m / {r.min_count}
                  </td>
                  <td style={{ padding: "8px 10px" }}>
                    <Toggle checked={r.enabled} onChange={() => toggleCustom(r)} />
                  </td>
                  <td style={{ padding: "8px 10px", whiteSpace: "nowrap" }}>
                    <Btn onClick={() => setEditing(r)} accent={T.blue} style={{ marginRight: 6 }}>Edit</Btn>
                    <Btn onClick={() => deleteCustom(r)} accent={T.red}>Delete</Btn>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {(showForm || editing) && (
        <CustomRuleForm
          kind={kind}
          initial={editing}
          onClose={() => { setShowForm(false); setEditing(null); }}
          onSaved={() => { setShowForm(false); setEditing(null); load(); }}
          notify={notify}
        />
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
const TABS = [
  { id: "sigma",       label: "Sigma" },
  { id: "yara",        label: "YARA / CyScan" },
  { id: "correlation", label: "Correlation" },
  { id: "ueba",        label: "UEBA" },
];

export default function DetectionRulesPage() {
  const [tab, setTab] = useState("sigma");
  const [toast, setToast] = useState({ msg: "", ok: true });

  const notify = (msg, ok = true) => {
    setToast({ msg, ok });
    setTimeout(() => setToast({ msg: "", ok: true }), 4000);
  };

  return (
    <div style={{ padding: "24px 28px", background: T.bg, minHeight: "100vh", color: T.text }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
          <span style={{ color: T.accent, fontSize: 18, fontFamily: T.mono, fontWeight: 800 }}>Detection Rules</span>
        </div>
        <div style={{ color: T.muted, fontSize: 12 }}>
          Manage every rule type feeding Internal Exposure from one place. Changes save and activate
          immediately — no restart, no waiting for the next scheduled reload.
        </div>
      </div>

      <div style={{ display: "flex", gap: 6, marginBottom: 20, borderBottom: T.border, paddingBottom: 0 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ background: "none", border: "none", borderBottom: tab === t.id ? `2px solid ${T.accent}` : "2px solid transparent",
                     color: tab === t.id ? T.accent : T.muted, fontFamily: T.mono, fontSize: 12,
                     padding: "8px 16px", cursor: "pointer", fontWeight: tab === t.id ? 700 : 400 }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "sigma" && <SigmaTab notify={notify} />}
      {tab === "yara" && <CyScanRulesContent />}
      {tab === "correlation" && <RuleEngineTab kind="correlation" notify={notify} />}
      {tab === "ueba" && <RuleEngineTab kind="ueba" notify={notify} />}

      <Toast msg={toast.msg} ok={toast.ok} />
    </div>
  );
}
