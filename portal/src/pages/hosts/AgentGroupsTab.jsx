/**
 * AgentGroupsTab.jsx
 * Wazuh agent group management: create/view/edit/delete groups,
 * manage agent.conf, and bulk-assign/reassign agents.
 */

import { useState, useEffect, useCallback, useRef } from "react";

const API = "/api/siem";

// ── shared style tokens ────────────────────────────────────────────────────────
const S = {
  card: {
    background: "rgba(255,255,255,0.03)",
    border: "1px solid rgba(255,255,255,0.07)",
    borderRadius: 8,
  },
  btn: (variant = "default") => ({
    border: "1px solid",
    borderRadius: 4,
    cursor: "pointer",
    fontFamily: "monospace",
    fontSize: 11,
    padding: "5px 12px",
    ...(variant === "accent"
      ? { background: "rgba(0,229,160,0.1)", borderColor: "rgba(0,229,160,0.35)", color: "#00e5a0" }
      : variant === "danger"
      ? { background: "rgba(255,59,59,0.08)", borderColor: "rgba(255,59,59,0.35)", color: "#ff6b6b" }
      : variant === "ghost"
      ? { background: "none", borderColor: "rgba(255,255,255,0.12)", color: "#aaa" }
      : { background: "rgba(77,158,255,0.1)", borderColor: "rgba(77,158,255,0.35)", color: "#4d9eff" }),
  }),
  input: {
    background: "rgba(255,255,255,0.05)",
    border: "1px solid rgba(255,255,255,0.12)",
    color: "#e8eaed",
    padding: "6px 10px",
    borderRadius: 4,
    fontSize: 11,
    fontFamily: "monospace",
    outline: "none",
  },
  label: { fontSize: 9, letterSpacing: "1.5px", color: "#666", marginBottom: 6 },
};

const STATUS_DOT = { active: "#00e5a0", disconnected: "#ff8c00", never_connected: "#555", unknown: "#555" };

function StatusDot({ status }) {
  return (
    <span style={{
      display: "inline-block", width: 7, height: 7, borderRadius: "50%",
      background: STATUS_DOT[status] || "#555", marginRight: 5, flexShrink: 0,
    }} />
  );
}

// ── API helpers ────────────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const res = await fetch(`${API}${path}`, { credentials: "include", ...opts });
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data: json };
}

// ── Create Group Modal ─────────────────────────────────────────────────────────
function CreateGroupModal({ onClose, onCreated }) {
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState(null);

  const handleCreate = async () => {
    const id = name.trim();
    if (!id) return;
    setSaving(true);
    setErr(null);
    const r = await apiFetch("/agent-groups", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ group_id: id }),
    });
    setSaving(false);
    if (!r.ok) { setErr(r.data?.error || "Create failed"); return; }
    onCreated(id);
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1200,
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        ...S.card, padding: 24, width: 360,
      }}>
        <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 16, color: "#e8eaed" }}>
          Create Agent Group
        </div>
        <div style={S.label}>GROUP NAME</div>
        <input
          autoFocus
          value={name} onChange={e => setName(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleCreate()}
          placeholder="e.g. windows-servers"
          style={{ ...S.input, width: "100%", boxSizing: "border-box", marginBottom: 12 }}
        />
        {err && <div style={{ color: "#ff6b6b", fontSize: 11, marginBottom: 10 }}>{err}</div>}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button onClick={onClose} style={S.btn("ghost")}>Cancel</button>
          <button onClick={handleCreate} disabled={saving || !name.trim()} style={S.btn("accent")}>
            {saving ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Agent Assignment Modal ─────────────────────────────────────────────────────
function AssignAgentsModal({ groupName, currentAgentIds, onClose, onAssigned }) {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(new Set());
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState(null);

  const loadAgents = useCallback(async () => {
    setLoading(true);
    const r = await apiFetch("/agent-groups/available-agents");
    setLoading(false);
    if (r.ok) setAgents(r.data.agents || []);
  }, []);

  useEffect(() => { loadAgents(); }, [loadAgents]);

  const currentSet = new Set(currentAgentIds);

  const filtered = agents.filter(a => {
    if (currentSet.has(a.id)) return false; // already in group — show in different state
    const q = search.toLowerCase();
    if (!q) return true;
    return (a.name || "").toLowerCase().includes(q) || (a.ip || "").includes(q) || (a.id || "").includes(q);
  });

  // agents already in this group (for display only)
  const alreadyIn = agents.filter(a => currentSet.has(a.id));

  const toggleAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map(a => a.id)));
    }
  };

  const toggle = id => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const handleAssign = async () => {
    if (!selected.size) return;
    setSaving(true);
    setErr(null);
    const r = await apiFetch(`/agent-groups/${encodeURIComponent(groupName)}/agents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_ids: [...selected] }),
    });
    setSaving(false);
    if (!r.ok) { setErr(r.data?.error || "Assignment failed"); return; }
    onAssigned([...selected]);
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1200,
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        ...S.card, padding: 0, width: 560, maxHeight: "80vh",
        display: "flex", flexDirection: "column",
      }}>
        {/* Header */}
        <div style={{ padding: "16px 20px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: "#e8eaed", marginBottom: 2 }}>
            Assign Agents → <span style={{ color: "#00e5a0" }}>{groupName}</span>
          </div>
          <div style={{ fontSize: 10, color: "#666" }}>
            {alreadyIn.length} already in group · {filtered.length} available
          </div>
        </div>

        {/* Search */}
        <div style={{ padding: "10px 16px", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          <input
            autoFocus
            placeholder="Search by name, IP or agent ID…"
            value={search} onChange={e => setSearch(e.target.value)}
            style={{ ...S.input, width: "100%", boxSizing: "border-box" }}
          />
        </div>

        {/* Agent list */}
        <div style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
          {loading ? (
            <div style={{ padding: 20, color: "#444", fontSize: 11, textAlign: "center" }}>
              Loading agents…
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: 20, color: "#444", fontSize: 11, textAlign: "center" }}>
              {search ? "No agents match this search." : "All agents are already in this group."}
            </div>
          ) : (
            <>
              {/* Select-all row */}
              <div
                onClick={toggleAll}
                style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "6px 16px", cursor: "pointer",
                  borderBottom: "1px solid rgba(255,255,255,0.04)",
                  fontSize: 10, color: "#888",
                }}
              >
                <input
                  type="checkbox" readOnly
                  checked={selected.size === filtered.length && filtered.length > 0}
                  style={{ accentColor: "#00e5a0", cursor: "pointer" }}
                />
                <span>Select all ({filtered.length})</span>
                {selected.size > 0 && (
                  <span style={{ color: "#00e5a0", marginLeft: "auto" }}>
                    {selected.size} selected
                  </span>
                )}
              </div>
              {filtered.map(a => (
                <div
                  key={a.id}
                  onClick={() => toggle(a.id)}
                  style={{
                    display: "flex", alignItems: "center", gap: 10,
                    padding: "7px 16px", cursor: "pointer",
                    background: selected.has(a.id) ? "rgba(0,229,160,0.04)" : "transparent",
                    borderBottom: "1px solid rgba(255,255,255,0.03)",
                  }}
                >
                  <input
                    type="checkbox" readOnly checked={selected.has(a.id)}
                    style={{ accentColor: "#00e5a0", cursor: "pointer", flexShrink: 0 }}
                  />
                  <StatusDot status={a.status} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, color: "#e8eaed", fontWeight: 500 }}>{a.name || a.id}</div>
                    <div style={{ fontSize: 9, color: "#666" }}>
                      {a.ip || "—"} · {(a.os || {}).platform || "unknown"}
                      {(a.groups || []).length > 0 && (
                        <span style={{ color: "#4d9eff", marginLeft: 6 }}>
                          in: {a.groups.join(", ")}
                        </span>
                      )}
                    </div>
                  </div>
                  <span style={{ fontSize: 9, color: "#555", fontFamily: "monospace" }}>
                    #{a.id}
                  </span>
                </div>
              ))}
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: "12px 16px",
          borderTop: "1px solid rgba(255,255,255,0.07)",
          display: "flex", gap: 8, justifyContent: "flex-end", alignItems: "center",
        }}>
          {err && <span style={{ color: "#ff6b6b", fontSize: 11, flex: 1 }}>{err}</span>}
          <button onClick={onClose} style={S.btn("ghost")}>Cancel</button>
          <button
            onClick={handleAssign}
            disabled={saving || selected.size === 0}
            style={{ ...S.btn("accent"), opacity: selected.size === 0 ? 0.4 : 1 }}
          >
            {saving ? "Assigning…" : `Assign ${selected.size || ""} Agent${selected.size !== 1 ? "s" : ""}`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Config Editor ──────────────────────────────────────────────────────────────
function ConfigEditor({ groupName }) {
  const [config, setConfig] = useState("");
  const [original, setOriginal] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState(null); // { text, type }

  const loadConfig = useCallback(async () => {
    setLoading(true);
    setMsg(null);
    const r = await apiFetch(`/agent-groups/${encodeURIComponent(groupName)}/config`);
    setLoading(false);
    if (r.ok) {
      setConfig(r.data.config || "");
      setOriginal(r.data.config || "");
    } else {
      setMsg({ text: r.data?.error || "Failed to load config", type: "error" });
    }
  }, [groupName]);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  const handleSave = async () => {
    setSaving(true);
    setMsg(null);
    const r = await fetch(`${API}/agent-groups/${encodeURIComponent(groupName)}/config`, {
      method: "PUT",
      credentials: "include",
      headers: { "Content-Type": "application/octet-stream" },
      body: config,
    });
    setSaving(false);
    if (r.ok) {
      setOriginal(config);
      setMsg({ text: "Configuration saved successfully.", type: "ok" });
    } else {
      const j = await r.json().catch(() => ({}));
      setMsg({ text: j?.error || "Save failed", type: "error" });
    }
  };

  const dirty = config !== original;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={S.label}>AGENT.CONF (XML)</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {msg && (
            <span style={{ fontSize: 10, color: msg.type === "ok" ? "#00e5a0" : "#ff6b6b" }}>
              {msg.text}
            </span>
          )}
          <button onClick={loadConfig} style={S.btn("ghost")} disabled={loading}>
            ↺ Reload
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !dirty}
            style={{ ...S.btn("accent"), opacity: dirty ? 1 : 0.4 }}
          >
            {saving ? "Saving…" : "Save Config"}
          </button>
        </div>
      </div>
      {loading ? (
        <div style={{ color: "#444", fontSize: 11, padding: "12px 0" }}>Loading config…</div>
      ) : (
        <textarea
          value={config}
          onChange={e => setConfig(e.target.value)}
          spellCheck={false}
          style={{
            ...S.input,
            width: "100%", boxSizing: "border-box",
            height: 220, resize: "vertical",
            fontFamily: "monospace", fontSize: 11,
            lineHeight: 1.5,
          }}
        />
      )}
    </div>
  );
}

// ── Group Detail Panel ─────────────────────────────────────────────────────────
function GroupDetailPanel({ group, onClose, onGroupDeleted }) {
  const [agents, setAgents] = useState([]);
  const [agentTotal, setAgentTotal] = useState(0);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [agentSearch, setAgentSearch] = useState("");
  const [showAssign, setShowAssign] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [removeErr, setRemoveErr] = useState(null);

  const loadAgents = useCallback(async () => {
    setAgentsLoading(true);
    const r = await apiFetch(
      `/agent-groups/${encodeURIComponent(group.name)}/agents?limit=500${agentSearch ? `&search=${encodeURIComponent(agentSearch)}` : ""}`
    );
    setAgentsLoading(false);
    if (r.ok) {
      setAgents(r.data.agents || []);
      setAgentTotal(r.data.total || 0);
    }
  }, [group.name, agentSearch]);

  useEffect(() => { loadAgents(); }, [loadAgents]);

  const handleRemove = async agentId => {
    setRemoveErr(null);
    const r = await apiFetch(`/agent-groups/${encodeURIComponent(group.name)}/agents`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_ids: [agentId] }),
    });
    if (!r.ok) { setRemoveErr(r.data?.error || "Remove failed"); return; }
    loadAgents();
  };

  const handleDelete = async () => {
    setDeleting(true);
    const r = await apiFetch(`/agent-groups/${encodeURIComponent(group.name)}`, { method: "DELETE" });
    setDeleting(false);
    if (!r.ok) { setRemoveErr(r.data?.error || "Delete failed"); return; }
    onGroupDeleted(group.name);
  };

  return (
    <div style={{
      flex: 1, display: "flex", flexDirection: "column", minWidth: 0,
      paddingLeft: 20,
    }}>
      {/* Panel header */}
      <div style={{
        display: "flex", alignItems: "center", gap: 10, marginBottom: 20,
        paddingBottom: 14, borderBottom: "1px solid rgba(255,255,255,0.07)",
      }}>
        <button onClick={onClose} style={{ ...S.btn("ghost"), padding: "3px 8px", fontSize: 14 }}>
          ←
        </button>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: "#e8eaed" }}>{group.name}</div>
          <div style={{ fontSize: 10, color: "#666" }}>
            {group.count ?? agentTotal} agent{(group.count ?? agentTotal) !== 1 ? "s" : ""} · Agent Group
          </div>
        </div>
        {!confirmDelete ? (
          <button onClick={() => setConfirmDelete(true)} style={S.btn("danger")}>
            Delete Group
          </button>
        ) : (
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span style={{ fontSize: 10, color: "#ff6b6b" }}>Are you sure?</span>
            <button onClick={() => setConfirmDelete(false)} style={S.btn("ghost")}>No</button>
            <button onClick={handleDelete} disabled={deleting} style={S.btn("danger")}>
              {deleting ? "Deleting…" : "Yes, Delete"}
            </button>
          </div>
        )}
      </div>

      {removeErr && (
        <div style={{
          background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.25)",
          borderRadius: 6, padding: "8px 12px", marginBottom: 12, color: "#ff6b6b", fontSize: 11,
        }}>{removeErr}</div>
      )}

      {/* Config editor */}
      <div style={{ ...S.card, padding: "14px 16px", marginBottom: 16 }}>
        <ConfigEditor groupName={group.name} />
      </div>

      {/* Agents in group */}
      <div style={{ ...S.card, padding: "14px 16px", flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#e8eaed", flex: 1 }}>
            Agents in Group
            <span style={{ color: "#666", fontWeight: 400, marginLeft: 6 }}>({agentTotal})</span>
          </div>
          <input
            placeholder="Search agents…"
            value={agentSearch} onChange={e => setAgentSearch(e.target.value)}
            style={{ ...S.input, width: 160 }}
          />
          <button onClick={() => setShowAssign(true)} style={S.btn("accent")}>
            + Assign Agents
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto" }}>
          {agentsLoading ? (
            <div style={{ color: "#444", fontSize: 11, padding: "12px 0" }}>Loading agents…</div>
          ) : agents.length === 0 ? (
            <div style={{ color: "#444", fontSize: 11, padding: "12px 0" }}>
              No agents in this group{agentSearch ? " matching your search" : ""}.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  {["ID", "Name", "IP", "OS", "Status", ""].map(h => (
                    <th key={h} style={{
                      textAlign: "left", fontSize: 9, color: "#555",
                      letterSpacing: "1px", padding: "4px 8px",
                      borderBottom: "1px solid rgba(255,255,255,0.05)",
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {agents.map(a => (
                  <tr key={a.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                    <td style={{ padding: "6px 8px", fontSize: 10, color: "#666", fontFamily: "monospace" }}>
                      {a.id}
                    </td>
                    <td style={{ padding: "6px 8px", fontSize: 11, color: "#e8eaed" }}>
                      {a.name || "—"}
                    </td>
                    <td style={{ padding: "6px 8px", fontSize: 10, color: "#888", fontFamily: "monospace" }}>
                      {a.ip || "—"}
                    </td>
                    <td style={{ padding: "6px 8px", fontSize: 10, color: "#888" }}>
                      {(a.os || {}).platform || "—"}
                    </td>
                    <td style={{ padding: "6px 8px" }}>
                      <div style={{ display: "flex", alignItems: "center" }}>
                        <StatusDot status={a.status} />
                        <span style={{ fontSize: 10, color: "#888" }}>{a.status || "unknown"}</span>
                      </div>
                    </td>
                    <td style={{ padding: "6px 8px", textAlign: "right" }}>
                      <button
                        onClick={() => handleRemove(a.id)}
                        style={{ ...S.btn("danger"), padding: "2px 8px", fontSize: 10 }}
                        title="Remove from group"
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {showAssign && (
        <AssignAgentsModal
          groupName={group.name}
          currentAgentIds={agents.map(a => a.id)}
          onClose={() => setShowAssign(false)}
          onAssigned={() => { setShowAssign(false); loadAgents(); }}
        />
      )}
    </div>
  );
}

// ── Main exported component ────────────────────────────────────────────────────
export function AgentGroupsTab() {
  const [groups, setGroups] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [selected, setSelected] = useState(null); // group object
  const [showCreate, setShowCreate] = useState(false);

  const loadGroups = useCallback(async () => {
    setLoading(true);
    setErr(null);
    const r = await apiFetch("/agent-groups");
    setLoading(false);
    if (!r.ok) {
      setErr(r.data?.error || "Failed to load groups");
      return;
    }
    setGroups(r.data.groups || []);
    setTotal(r.data.total || 0);
  }, []);

  useEffect(() => { loadGroups(); }, [loadGroups]);

  const handleGroupCreated = async name => {
    setShowCreate(false);
    await loadGroups();
    // auto-select the newly created group
    setSelected({ name, count: 0 });
  };

  const handleGroupDeleted = async name => {
    if (selected?.name === name) setSelected(null);
    await loadGroups();
  };

  return (
    <div style={{ display: "flex", gap: 0, minHeight: 500 }}>
      {/* Left: group list */}
      <div style={{
        width: 260, flexShrink: 0,
        borderRight: "1px solid rgba(255,255,255,0.07)",
        paddingRight: 20, display: "flex", flexDirection: "column",
      }}>
        <div style={{ display: "flex", alignItems: "center", marginBottom: 14 }}>
          <div style={{ flex: 1, fontSize: 11, fontWeight: 700, color: "#e8eaed" }}>
            Agent Groups
            <span style={{ color: "#666", fontWeight: 400, marginLeft: 5 }}>({total})</span>
          </div>
          <button onClick={() => setShowCreate(true)} style={S.btn("accent")}>
            + New
          </button>
        </div>

        {err && (
          <div style={{
            background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.25)",
            borderRadius: 6, padding: "8px 12px", marginBottom: 12,
            color: "#ff6b6b", fontSize: 11,
          }}>{err}</div>
        )}

        {loading ? (
          <div style={{ color: "#444", fontSize: 11, padding: "12px 0" }}>Loading groups…</div>
        ) : groups.length === 0 ? (
          <div style={{ color: "#555", fontSize: 11, padding: "12px 0" }}>
            No groups defined yet. Click <strong>+ New</strong> to create one.
          </div>
        ) : (
          <div style={{ flex: 1, overflowY: "auto" }}>
            {groups.map(g => (
              <div
                key={g.name}
                onClick={() => setSelected(g)}
                style={{
                  padding: "10px 12px", borderRadius: 6, cursor: "pointer",
                  marginBottom: 4,
                  background: selected?.name === g.name
                    ? "rgba(77,158,255,0.1)" : "rgba(255,255,255,0.02)",
                  border: selected?.name === g.name
                    ? "1px solid rgba(77,158,255,0.3)" : "1px solid rgba(255,255,255,0.05)",
                  transition: "background .15s",
                }}
              >
                <div style={{ fontSize: 12, fontWeight: 600, color: "#e8eaed", marginBottom: 2 }}>
                  {g.name}
                </div>
                <div style={{ fontSize: 10, color: "#666" }}>
                  {g.count ?? 0} agent{(g.count ?? 0) !== 1 ? "s" : ""}
                </div>
              </div>
            ))}
          </div>
        )}

        <button
          onClick={loadGroups}
          style={{ ...S.btn("ghost"), marginTop: 12, width: "100%", textAlign: "center" }}
          disabled={loading}
        >
          ↺ Refresh
        </button>
      </div>

      {/* Right: detail or empty state */}
      {selected ? (
        <GroupDetailPanel
          key={selected.name}
          group={selected}
          onClose={() => setSelected(null)}
          onGroupDeleted={handleGroupDeleted}
        />
      ) : (
        <div style={{
          flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
          color: "#444", fontSize: 12,
        }}>
          Select a group to view details, manage its configuration, and assign agents.
        </div>
      )}

      {showCreate && (
        <CreateGroupModal
          onClose={() => setShowCreate(false)}
          onCreated={handleGroupCreated}
        />
      )}
    </div>
  );
}
