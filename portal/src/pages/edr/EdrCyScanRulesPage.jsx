import { useState, useEffect, useCallback } from "react";

const API = "/api/edr";

// ── Design tokens ─────────────────────────────────────────────────────────────
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
function Panel({ title, accent = T.accent, badge, children, style = {} }) {
  return (
    <div style={{ background: T.card, border: T.border, borderTop: `2px solid ${accent}`,
                  borderRadius: 5, padding: "18px 22px", ...style }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <span style={{ color: T.muted, fontSize: 10, letterSpacing: "1.5px",
                       textTransform: "uppercase", fontFamily: T.mono }}>{title}</span>
        {badge != null && (
          <span style={{ background: `${accent}18`, color: accent, fontSize: 10,
                         fontFamily: T.mono, padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>
            {badge}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

function KpiCard({ label, value, accent = T.accent, sub }) {
  return (
    <div style={{ background: T.card, border: T.border, borderTop: `2px solid ${accent}`,
                  padding: "16px 20px", borderRadius: 4, flex: "1 1 130px", minWidth: 120 }}>
      <div style={{ color: accent, fontSize: 28, fontWeight: 800, fontFamily: T.mono, lineHeight: 1 }}>
        {value}
      </div>
      <div style={{ color: T.muted, fontSize: 10, letterSpacing: "1.5px", marginTop: 5, textTransform: "uppercase" }}>
        {label}
      </div>
      {sub && <div style={{ color: "rgba(255,255,255,0.22)", fontSize: 10, marginTop: 2 }}>{sub}</div>}
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

// ── CyScan rule upload modal ───────────────────────────────────────────────────
const EXAMPLE_RULE = `rule ZeroDay_Example {
  meta:
    description = "Detects example zero-day artefact"
    author      = "SOC Team"
    date        = "2026-06-28"
  strings:
    $magic = { 4D 5A 90 00 }
    $str1  = "evil_payload" nocase
  condition:
    $magic at 0 and $str1
}`;

function UploadModal({ onClose, onSaved }) {
  const [form, setForm] = useState({
    name: "", threat_name: "", mitre_id: "", rule_text: EXAMPLE_RULE,
  });
  const [saving, setSaving] = useState(false);
  const [err, setErr]       = useState("");

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function submit() {
    if (!form.name.trim() || !form.threat_name.trim() || !form.rule_text.trim()) {
      setErr("Name, threat name, and rule text are required.");
      return;
    }
    setSaving(true);
    setErr("");
    try {
      const r = await fetch(`${API}/yara-rules/custom`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || "Save failed"); setSaving(false); return; }
      onSaved(d);
    } catch (e) {
      setErr("Network error");
      setSaving(false);
    }
  }

  const inputStyle = {
    width: "100%", background: "rgba(255,255,255,0.04)", border: T.border,
    borderRadius: 3, padding: "8px 10px", color: T.text,
    fontSize: 12, fontFamily: T.mono, outline: "none", boxSizing: "border-box",
  };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 1000,
                  display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: "#0d1120", border: T.border, borderTop: `2px solid ${T.accent}`,
                    borderRadius: 6, padding: 28, width: 680, maxWidth: "95vw",
                    maxHeight: "90vh", overflowY: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <span style={{ color: T.accent, fontFamily: T.mono, fontSize: 13, fontWeight: 700 }}>
            + NEW CUSTOM CYSCAN RULE
          </span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: T.muted,
                                            fontSize: 18, cursor: "pointer" }}>×</button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <div>
            <div style={{ color: T.muted, fontSize: 10, marginBottom: 4, textTransform: "uppercase" }}>Rule Name *</div>
            <input value={form.name} onChange={e => set("name", e.target.value)}
                   placeholder="e.g. Log4Shell_Exploit_Payload" style={inputStyle} />
          </div>
          <div>
            <div style={{ color: T.muted, fontSize: 10, marginBottom: 4, textTransform: "uppercase" }}>Threat Name *</div>
            <input value={form.threat_name} onChange={e => set("threat_name", e.target.value)}
                   placeholder="e.g. CVE-2021-44228" style={inputStyle} />
          </div>
        </div>

        <div style={{ marginBottom: 12 }}>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4, textTransform: "uppercase" }}>MITRE ATT&CK ID (optional)</div>
          <input value={form.mitre_id} onChange={e => set("mitre_id", e.target.value)}
                 placeholder="e.g. T1203" style={{ ...inputStyle, width: "50%" }} />
        </div>

        <div style={{ marginBottom: 16 }}>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4, textTransform: "uppercase" }}>
            CyScan Rule Text *
            <span style={{ color: T.muted, marginLeft: 8, fontSize: 9 }}>
              Validated server-side before storing
            </span>
          </div>
          <textarea value={form.rule_text} onChange={e => set("rule_text", e.target.value)}
                    rows={16} style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6 }} />
        </div>

        {err && (
          <div style={{ color: T.red, fontSize: 11, fontFamily: T.mono, marginBottom: 12 }}>
            {err}
          </div>
        )}

        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <Btn onClick={onClose} accent={T.muted}>Cancel</Btn>
          <Btn onClick={submit} disabled={saving} accent={T.accent}>
            {saving ? "Validating & Saving…" : "Save & Activate"}
          </Btn>
        </div>

        <div style={{ marginTop: 18, padding: "10px 14px", background: "rgba(0,229,160,0.04)",
                      border: "1px solid rgba(0,229,160,0.12)", borderRadius: 4 }}>
          <div style={{ color: T.accent, fontSize: 10, fontFamily: T.mono, marginBottom: 4 }}>
            HOW THIS DEPLOYS
          </div>
          <div style={{ color: T.muted, fontSize: 11, lineHeight: 1.7 }}>
            Once saved, this rule is immediately available to all active agents.
            Agents pick up the merged ruleset on their <strong style={{ color: T.text }}>next hourly sync</strong> (max 60 min wait)
            or <strong style={{ color: T.text }}>immediately</strong> if you trigger a Fleet Scan below.
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Fleet scan confirm modal ──────────────────────────────────────────────────
function FleetScanModal({ onClose, onTriggered }) {
  const [scanPath, setScanPath] = useState("/");
  const [reason,   setReason]   = useState("Zero-day threat hunt");
  const [loading,  setLoading]  = useState(false);
  const [err, setErr]           = useState("");

  async function trigger() {
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${API}/fleet-scan`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_path: scanPath, yara_rules: "all", reason }),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || "Failed"); setLoading(false); return; }
      onTriggered(d);
    } catch (e) {
      setErr("Network error"); setLoading(false);
    }
  }

  const inputStyle = {
    width: "100%", background: "rgba(255,255,255,0.04)", border: T.border,
    borderRadius: 3, padding: "8px 10px", color: T.text,
    fontSize: 12, fontFamily: T.mono, outline: "none", boxSizing: "border-box",
  };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", zIndex: 1000,
                  display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: "#0d1120", border: T.border, borderTop: `2px solid ${T.orange}`,
                    borderRadius: 6, padding: 28, width: 480, maxWidth: "95vw" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <span style={{ color: T.orange, fontFamily: T.mono, fontSize: 13, fontWeight: 700 }}>
            ⚡ TRIGGER FLEET SCAN
          </span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: T.muted, fontSize: 18, cursor: "pointer" }}>×</button>
        </div>

        <div style={{ color: T.muted, fontSize: 11, lineHeight: 1.7, marginBottom: 16 }}>
          This pushes a <strong style={{ color: T.text }}>CyScan</strong> command to every active CyEDR agent.
          Agents scan their filesystem using both the bundled CyCentra ruleset and
          your active <strong style={{ color: T.accent }}>custom CyScan rules</strong>. Results flow back
          within 5 minutes and appear in EDR Detections + Threat Hunting findings.
        </div>

        <div style={{ marginBottom: 12 }}>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4, textTransform: "uppercase" }}>Scan Path</div>
          <input value={scanPath} onChange={e => setScanPath(e.target.value)}
                 placeholder="/" style={inputStyle} />
          <div style={{ color: T.muted, fontSize: 9, marginTop: 3 }}>
            Use / for full filesystem. Use /tmp or /var/tmp for dropped-payload hunting.
          </div>
        </div>

        <div style={{ marginBottom: 16 }}>
          <div style={{ color: T.muted, fontSize: 10, marginBottom: 4, textTransform: "uppercase" }}>Reason (audit log)</div>
          <input value={reason} onChange={e => setReason(e.target.value)} style={inputStyle} />
        </div>

        {err && <div style={{ color: T.red, fontSize: 11, fontFamily: T.mono, marginBottom: 12 }}>{err}</div>}

        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <Btn onClick={onClose} accent={T.muted}>Cancel</Btn>
          <Btn onClick={trigger} disabled={loading} accent={T.orange}>
            {loading ? "Queueing…" : "Scan All Agents Now"}
          </Btn>
        </div>
      </div>
    </div>
  );
}

// ── Rule detail / view modal ──────────────────────────────────────────────────
function RuleDetailModal({ rule, onClose, onDelete, onToggle }) {
  const [deleting, setDeleting] = useState(false);
  const [toggling, setToggling] = useState(false);

  async function doDelete() {
    if (!window.confirm(`Delete rule "${rule.name}"? This cannot be undone.`)) return;
    setDeleting(true);
    const r = await fetch(`${API}/yara-rules/custom/${rule.id}`, {
      method: "DELETE", credentials: "include",
    });
    if (r.ok) onDelete(rule.id);
  }

  async function doToggle() {
    setToggling(true);
    const action = rule.active ? "deactivate" : "activate";
    const r = await fetch(`${API}/yara-rules/custom/${rule.id}/${action}`, {
      method: "POST", credentials: "include",
    });
    if (r.ok) { const d = await r.json(); onToggle(d); }
    setToggling(false);
  }

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", zIndex: 1000,
                  display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: "#0d1120", border: T.border, borderTop: `2px solid ${T.purple}`,
                    borderRadius: 6, padding: 28, width: 700, maxWidth: "95vw",
                    maxHeight: "90vh", overflowY: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div>
            <span style={{ color: T.text, fontFamily: T.mono, fontSize: 13, fontWeight: 700 }}>{rule.name}</span>
            <span style={{ marginLeft: 10 }}>
              <Badge label={rule.active ? "ACTIVE" : "DISABLED"} color={rule.active ? T.accent : T.muted} />
            </span>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: T.muted, fontSize: 18, cursor: "pointer" }}>×</button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 16 }}>
          <div>
            <div style={{ color: T.muted, fontSize: 9, textTransform: "uppercase" }}>Threat</div>
            <div style={{ color: T.orange, fontSize: 12, fontFamily: T.mono }}>{rule.threat_name}</div>
          </div>
          <div>
            <div style={{ color: T.muted, fontSize: 9, textTransform: "uppercase" }}>MITRE</div>
            <div style={{ color: T.blue, fontSize: 12, fontFamily: T.mono }}>{rule.mitre_id || "—"}</div>
          </div>
          <div>
            <div style={{ color: T.muted, fontSize: 9, textTransform: "uppercase" }}>Matches (all time)</div>
            <div style={{ color: rule.match_count > 0 ? T.red : T.muted, fontSize: 12, fontFamily: T.mono }}>
              {rule.match_count}
            </div>
          </div>
        </div>

        <div style={{ marginBottom: 16 }}>
          <div style={{ color: T.muted, fontSize: 10, textTransform: "uppercase", marginBottom: 6 }}>CyScan Rule Text</div>
          <pre style={{ background: "rgba(0,0,0,0.4)", border: T.border, borderRadius: 4,
                        padding: "14px 16px", color: T.text, fontSize: 11, fontFamily: T.mono,
                        overflowX: "auto", maxHeight: 360, overflowY: "auto", margin: 0 }}>
            {rule.rule_text}
          </pre>
        </div>

        <div style={{ display: "flex", gap: 10, justifyContent: "space-between", alignItems: "center" }}>
          <Btn onClick={doDelete} disabled={deleting} accent={T.red}>
            {deleting ? "Deleting…" : "Delete Rule"}
          </Btn>
          <div style={{ display: "flex", gap: 10 }}>
            <Btn onClick={doToggle} disabled={toggling} accent={rule.active ? T.orange : T.accent}>
              {toggling ? "…" : rule.active ? "Deactivate" : "Activate"}
            </Btn>
            <Btn onClick={onClose} accent={T.muted}>Close</Btn>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function EdrCyScanRulesPage() {
  const [rules,         setRules]         = useState([]);
  const [loading,       setLoading]       = useState(true);
  const [showUpload,    setShowUpload]    = useState(false);
  const [showFleet,     setShowFleet]     = useState(false);
  const [selectedRule,  setSelectedRule]  = useState(null);
  const [toast,         setToast]         = useState({ msg: "", ok: true });
  const [lastScan,      setLastScan]      = useState(null);

  const notify = (msg, ok = true) => {
    setToast({ msg, ok });
    setTimeout(() => setToast({ msg: "", ok: true }), 4000);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/yara-rules/custom`, { credentials: "include" });
      if (r.ok) { const d = await r.json(); setRules(d.rules || []); }
    } catch (_) {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  function handleSaved(rule) {
    setShowUpload(false);
    setRules(rs => [rule, ...rs]);
    notify(`Rule "${rule.name}" saved and activated. Agents will pick it up on next sync or fleet scan.`);
  }

  function handleFleetTriggered(data) {
    setShowFleet(false);
    setLastScan(data);
    notify(`Fleet scan queued for ${data.queued} agents (Scan ID: ${data.scan_id.slice(0,8)}…)`, true);
  }

  function handleDelete(id) {
    setSelectedRule(null);
    setRules(rs => rs.filter(r => r.id !== id));
    notify("Rule deleted.", true);
  }

  function handleToggle(data) {
    setRules(rs => rs.map(r => r.id === data.rule_id ? { ...r, active: data.active } : r));
    setSelectedRule(null);
    notify(`Rule ${data.active ? "activated" : "deactivated"}.`, true);
  }

  const activeCount   = rules.filter(r => r.active).length;
  const inactiveCount = rules.length - activeCount;
  const totalMatches  = rules.reduce((s, r) => s + (r.match_count || 0), 0);

  return (
    <div style={{ padding: "24px 28px", background: T.bg, minHeight: "100vh", color: T.text }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
            <span style={{ color: T.accent, fontSize: 18, fontFamily: T.mono, fontWeight: 800 }}>
              Custom Threat Hunting
            </span>
            <Badge label="CYSCAN RULES" color={T.accent} />
          </div>
          <div style={{ color: T.muted, fontSize: 12 }}>
            Upload analyst-authored CyScan (YARA) rules for zero-day hunting. Rules deploy to all CyEDR agents
            automatically every hour or instantly via Fleet Scan.
          </div>
          <div style={{
            marginTop: 10, padding: "8px 14px",
            background: "rgba(0,229,160,0.05)", border: "1px solid rgba(0,229,160,0.15)",
            borderRadius: 4, fontSize: 11, color: "rgba(255,255,255,0.5)", lineHeight: 1.6,
          }}>
            <strong style={{ color: T.accent }}>This is the rule authoring tool.</strong>{" "}
            Write a YARA rule here when a new zero-day drops, push it to endpoints via Fleet Scan, and matches
            will automatically surface as incidents under{" "}
            <strong style={{ color: "rgba(255,255,255,0.75)" }}>Internal Exposure → Threat Hunting</strong> via hunt rules HT-013 and HT-014.
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Btn onClick={() => setShowFleet(true)} accent={T.orange}>
            ⚡ Fleet Scan Now
          </Btn>
          <Btn onClick={() => setShowUpload(true)} accent={T.accent}>
            + New CyScan Rule
          </Btn>
        </div>
      </div>

      {/* KPI Row */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
        <KpiCard label="Total Rules" value={rules.length} accent={T.accent} />
        <KpiCard label="Active" value={activeCount} accent={T.accent}
                 sub="Deployed to fleet on next sync" />
        <KpiCard label="Disabled" value={inactiveCount} accent={T.muted} />
        <KpiCard label="Total Scan Matches" value={totalMatches}
                 accent={totalMatches > 0 ? T.red : T.muted}
                 sub="Across all agents, all time" />
        {lastScan && (
          <KpiCard label="Last Fleet Scan" value={lastScan.queued} accent={T.orange}
                   sub={`Agents scanned — ${lastScan.scan_id.slice(0,8)}…`} />
        )}
      </div>

      {/* How it works banner */}
      <div style={{ background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.12)",
                    borderRadius: 5, padding: "14px 18px", marginBottom: 24,
                    display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
        {[
          { step: "1 — Write", color: T.accent, desc: "Author a CyScan rule targeting zero-day indicators — file magic bytes, strings, PE structures, binary hashes." },
          { step: "2 — Upload", color: T.blue, desc: "Upload here. Platform validates rule syntax and stores in the database. Rule goes live instantly." },
          { step: "3 — Hunt", color: T.orange, desc: "Click Fleet Scan to push to all agents NOW, or wait up to 60 min for the automated hourly deploy. Matches appear in Threat Hunting + EDR Detections." },
        ].map(({ step, color, desc }) => (
          <div key={step}>
            <div style={{ color, fontFamily: T.mono, fontSize: 11, fontWeight: 700, marginBottom: 4 }}>{step}</div>
            <div style={{ color: T.muted, fontSize: 11, lineHeight: 1.6 }}>{desc}</div>
          </div>
        ))}
      </div>

      {/* Rules table */}
      <Panel title="Custom CyScan Rules" accent={T.purple} badge={rules.length}>
        {loading ? (
          <div style={{ color: T.muted, fontSize: 12, fontFamily: T.mono, padding: "20px 0", textAlign: "center" }}>
            Loading rules…
          </div>
        ) : rules.length === 0 ? (
          <div style={{ color: T.muted, fontSize: 12, textAlign: "center", padding: "40px 0" }}>
            <div style={{ fontSize: 32, marginBottom: 10 }}>🎯</div>
            <div>No custom CyScan rules yet.</div>
            <div style={{ marginTop: 6, fontSize: 11 }}>
              When a new zero-day is disclosed, click <strong style={{ color: T.accent }}>+ New CyScan Rule</strong> to add a detection rule immediately.
            </div>
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                {["Rule Name", "Threat / CVE", "MITRE", "Status", "Matches", "Last Deployed", ""].map(h => (
                  <th key={h} style={{ color: T.muted, fontSize: 9, textTransform: "uppercase",
                                       letterSpacing: "1px", padding: "6px 10px", textAlign: "left",
                                       fontWeight: 400, whiteSpace: "nowrap" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.id}
                    onClick={() => {
                      fetch(`${API}/yara-rules/custom/${rule.id}`, { credentials: "include" })
                        .then(r => r.json()).then(d => setSelectedRule(d));
                    }}
                    style={{ borderBottom: "1px solid rgba(255,255,255,0.03)",
                             cursor: "pointer", transition: "background 0.1s" }}
                    onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.02)"}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                  <td style={{ padding: "10px 10px", color: T.text, fontSize: 12, fontFamily: T.mono }}>
                    {rule.name}
                  </td>
                  <td style={{ padding: "10px 10px" }}>
                    <Badge label={rule.threat_name} color={T.orange} />
                  </td>
                  <td style={{ padding: "10px 10px", color: T.blue, fontSize: 11, fontFamily: T.mono }}>
                    {rule.mitre_id || "—"}
                  </td>
                  <td style={{ padding: "10px 10px" }}>
                    <Badge label={rule.active ? "ACTIVE" : "DISABLED"} color={rule.active ? T.accent : T.muted} />
                  </td>
                  <td style={{ padding: "10px 10px", color: rule.match_count > 0 ? T.red : T.muted,
                               fontSize: 12, fontFamily: T.mono, fontWeight: rule.match_count > 0 ? 700 : 400 }}>
                    {rule.match_count}
                  </td>
                  <td style={{ padding: "10px 10px", color: T.muted, fontSize: 11 }}>
                    {rule.last_deployed
                      ? new Date(rule.last_deployed).toLocaleString()
                      : <span style={{ color: "rgba(255,255,255,0.2)" }}>Not yet deployed</span>}
                  </td>
                  <td style={{ padding: "10px 10px" }}>
                    <span style={{ color: T.muted, fontSize: 11 }}>View →</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {/* Automation note */}
      <div style={{ marginTop: 16, padding: "12px 16px", background: T.card, border: T.border,
                    borderRadius: 4, display: "flex", gap: 20, flexWrap: "wrap" }}>
        <div>
          <div style={{ color: T.muted, fontSize: 9, textTransform: "uppercase", marginBottom: 2 }}>
            Autonomous Deployment
          </div>
          <div style={{ color: T.text, fontSize: 11 }}>
            Every agent fetches the latest CyScan ruleset on its hourly IOC sync.
            All active rules are merged and applied on the endpoint automatically.
          </div>
        </div>
        <div>
          <div style={{ color: T.muted, fontSize: 9, textTransform: "uppercase", marginBottom: 2 }}>
            Threat Hunter Integration
          </div>
          <div style={{ color: T.text, fontSize: 11 }}>
            CyScan matches flow into the <code style={{ color: T.accent }}>alerts</code> table. Hunt rules
            <code style={{ color: T.orange }}> HT-013</code> and <code style={{ color: T.orange }}>HT-014</code> sweep
            for them every 6 hours and create Incidents automatically.
          </div>
        </div>
      </div>

      {/* Modals */}
      {showUpload   && <UploadModal    onClose={() => setShowUpload(false)} onSaved={handleSaved} />}
      {showFleet    && <FleetScanModal onClose={() => setShowFleet(false)}  onTriggered={handleFleetTriggered} />}
      {selectedRule && (
        <RuleDetailModal
          rule={selectedRule}
          onClose={() => setSelectedRule(null)}
          onDelete={handleDelete}
          onToggle={handleToggle}
        />
      )}

      <Toast msg={toast.msg} ok={toast.ok} />
    </div>
  );
}
