/**
 * PolicyDocumentsPage.jsx
 * ========================
 * Framework collection tabs, document upload dropzone, indexed doc list,
 * delete + reindex buttons.
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const FRAMEWORKS = ["iso27001", "nis2", "dora", "soc2", "nist_csf", "pci_dss"];

function fmtTs(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" }); }
  catch { return ts; }
}

function DropZone({ collectionId, onUploaded }) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [msg, setMsg] = useState(null);
  const ref = useRef(null);

  const uploadFile = (file) => {
    if (!file) return;
    setUploading(true); setMsg(null);
    const fd = new FormData();
    fd.append("file", file);
    fd.append("framework", collectionId.replace("policy-", ""));
    fetch(`${API_BASE}/api/comp/policy-docs/collections/${collectionId}/documents`, {
      method: "POST", credentials: "include", body: fd,
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { setMsg({ ok: true, text: "Uploaded and indexed" }); onUploaded(); })
      .catch(e => setMsg({ ok: false, text: `Upload failed (${e})` }))
      .finally(() => setUploading(false));
  };

  return (
    <div>
      <div
        onDragEnter={() => setDragging(true)}
        onDragLeave={() => setDragging(false)}
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); setDragging(false); uploadFile(e.dataTransfer.files[0]); }}
        onClick={() => ref.current?.click()}
        style={{
          border: `2px dashed ${dragging ? C.accent : "rgba(255,255,255,0.12)"}`,
          borderRadius: 8, padding: "28px 20px", textAlign: "center", cursor: "pointer",
          background: dragging ? "rgba(0,229,160,0.04)" : "rgba(255,255,255,0.01)",
          transition: "all 0.2s",
        }}>
        <input ref={ref} type="file" style={{ display: "none" }}
          accept=".pdf,.docx,.txt,.md"
          onChange={e => uploadFile(e.target.files[0])} />
        <div style={{ color: uploading ? C.accent : C.muted, fontSize: 12, fontFamily: "monospace" }}>
          {uploading ? "Uploading..." : (
            <>
              <div style={{ marginBottom: 6 }}>Drag & drop a document here, or click to browse</div>
              <div style={{ fontSize: 9, textTransform: "uppercase", letterSpacing: "1px" }}>
                Supported: PDF, DOCX, TXT, Markdown
              </div>
            </>
          )}
        </div>
      </div>
      {msg && (
        <div style={{ color: msg.ok ? C.accent : C.red, fontSize: 10, fontFamily: "monospace", marginTop: 8 }}>
          {msg.text}
        </div>
      )}
    </div>
  );
}

export function PolicyDocumentsPage() {
  const [collections, setCollections] = useState([]);
  const [activeCol, setActiveCol]     = useState(null);
  const [docs, setDocs]               = useState([]);
  const [loading, setLoading]         = useState(true);
  const [docsLoading, setDocsLoading] = useState(false);
  const [newFw, setNewFw]             = useState("iso27001");
  const [creating, setCreating]       = useState(false);
  const [reindexMsg, setReindexMsg]   = useState(null);

  const loadCollections = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/policy-docs/collections`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        const cols = d.collections || [];
        setCollections(cols);
        if (cols.length > 0 && !activeCol) setActiveCol(cols[0].id || cols[0].name);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  const loadDocs = (colId) => {
    if (!colId) return;
    setDocsLoading(true);
    fetch(`${API_BASE}/api/comp/policy-docs/collections/${colId}/documents`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setDocs(d.documents || []); setDocsLoading(false); })
      .catch(() => setDocsLoading(false));
  };

  useEffect(() => { loadCollections(); }, []);
  useEffect(() => { if (activeCol) loadDocs(activeCol); }, [activeCol]);

  const handleCreateCollection = () => {
    setCreating(true);
    fetch(`${API_BASE}/api/comp/policy-docs/collections`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ framework: newFw }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { loadCollections(); setActiveCol(d.id || d.name); })
      .catch(e => alert(`Create failed: ${e}`))
      .finally(() => setCreating(false));
  };

  const handleDeleteDoc = (docId) => {
    if (!confirm("Delete this document?")) return;
    fetch(`${API_BASE}/api/comp/policy-docs/documents/${docId}`, { method: "DELETE", credentials: "include" })
      .then(r => r.ok ? loadDocs(activeCol) : alert("Delete failed"));
  };

  const handleReindex = () => {
    if (!activeCol) return;
    setReindexMsg("Reindexing...");
    fetch(`${API_BASE}/api/comp/policy-docs/collections/${activeCol}/reindex`, {
      method: "POST", credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => setReindexMsg(d.status === "reindexing" ? "Reindexing started" : d.detail))
      .catch(e => setReindexMsg(`Failed: ${e}`));
    setTimeout(() => setReindexMsg(null), 4000);
  };

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
        <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Policy Documents</h1>
        <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
          Manage RAG document collections per compliance framework
        </div>
      </div>

      {/* Create new collection */}
      <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8,
        padding: "14px 20px", marginBottom: 20, display: "flex", gap: 12, alignItems: "center" }}>
        <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1px",
          textTransform: "uppercase" }}>New Collection</div>
        <select value={newFw} onChange={e => setNewFw(e.target.value)}
          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
            color: C.text, borderRadius: 4, padding: "6px 10px", fontFamily: "monospace",
            fontSize: 11, cursor: "pointer" }}>
          {FRAMEWORKS.map(f => <option key={f} value={f}>{f.toUpperCase()}</option>)}
        </select>
        <button onClick={handleCreateCollection} disabled={creating}
          style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
            color: C.accent, padding: "7px 16px", borderRadius: 4, fontFamily: "monospace",
            fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: creating ? 0.6 : 1 }}>
          {creating ? "Creating..." : "Create Collection"}
        </button>
        <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
          Creates collection named <code style={{ color: C.accent }}>policy-{newFw}</code> in CyMind RAG
        </div>
      </div>

      {loading ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 24 }}>
          Loading collections...
        </div>
      ) : collections.length === 0 ? (
        <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8,
          padding: 32, textAlign: "center", color: C.muted, fontFamily: "monospace", fontSize: 12 }}>
          No collections yet. Create a collection to start uploading policy documents.
        </div>
      ) : (
        <div style={{ display: "flex", gap: 20 }}>
          {/* Collection tabs (left sidebar) */}
          <div style={{ width: 200, flexShrink: 0 }}>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
              textTransform: "uppercase", marginBottom: 10 }}>Collections</div>
            {collections.map(col => {
              const colId = col.id || col.name;
              return (
                <button key={colId} onClick={() => setActiveCol(colId)}
                  style={{
                    width: "100%", padding: "10px 14px", borderRadius: 6, marginBottom: 6,
                    background: activeCol === colId ? "rgba(0,229,160,0.08)" : "rgba(255,255,255,0.02)",
                    border: `1px solid ${activeCol === colId ? "rgba(0,229,160,0.3)" : C.border}`,
                    color: activeCol === colId ? C.accent : C.muted,
                    fontFamily: "monospace", fontSize: 11, cursor: "pointer", textAlign: "left",
                  }}>
                  <div style={{ fontWeight: 700 }}>{(col.name || colId).replace("policy-", "").toUpperCase()}</div>
                  {col.doc_count !== undefined && (
                    <div style={{ fontSize: 9, marginTop: 2, opacity: 0.7 }}>{col.doc_count} docs</div>
                  )}
                </button>
              );
            })}
          </div>

          {/* Document panel */}
          <div style={{ flex: 1 }}>
            {activeCol && (
              <>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
                  marginBottom: 16 }}>
                  <div style={{ color: C.accent, fontSize: 13, fontFamily: "monospace", fontWeight: 700 }}>
                    {activeCol}
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    {reindexMsg && (
                      <span style={{ color: C.orange, fontSize: 10, fontFamily: "monospace" }}>
                        {reindexMsg}
                      </span>
                    )}
                    <button onClick={handleReindex}
                      style={{ background: "rgba(77,158,255,0.1)", border: `1px solid ${C.blue}30`,
                        color: C.blue, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
                        fontSize: 10, fontWeight: 700, cursor: "pointer" }}>
                      Reindex Collection
                    </button>
                  </div>
                </div>

                {/* Upload zone */}
                <div style={{ marginBottom: 20 }}>
                  <DropZone collectionId={activeCol} onUploaded={() => loadDocs(activeCol)} />
                </div>

                {/* Document list */}
                {docsLoading ? (
                  <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12 }}>Loading documents...</div>
                ) : docs.length === 0 ? (
                  <div style={{ background: "rgba(255,255,255,0.01)", border: `1px solid ${C.border}`,
                    borderRadius: 6, padding: 20, textAlign: "center",
                    color: C.muted, fontFamily: "monospace", fontSize: 11 }}>
                    No documents in this collection yet. Upload your first policy document above.
                  </div>
                ) : (
                  <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                          {["Document", "Type", "Indexed", "Uploaded", ""].map(h => (
                            <th key={h} style={{ padding: "10px 14px", textAlign: "left",
                              color: C.muted, fontSize: 9, fontFamily: "monospace",
                              letterSpacing: "1px", textTransform: "uppercase" }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {docs.map((d, i) => (
                          <tr key={d.id} style={{ borderBottom: `1px solid rgba(255,255,255,0.03)`,
                            background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
                            <td style={{ padding: "10px 14px", color: C.text, fontSize: 11 }}>{d.name}</td>
                            <td style={{ padding: "10px 14px" }}>
                              <span style={{ background: "rgba(77,158,255,0.12)", color: C.blue,
                                fontSize: 9, fontFamily: "monospace", padding: "2px 6px", borderRadius: 3 }}>
                                {d.file_type || "—"}
                              </span>
                            </td>
                            <td style={{ padding: "10px 14px" }}>
                              <span style={{ color: d.indexed ? C.accent : C.orange, fontSize: 10,
                                fontFamily: "monospace" }}>
                                {d.indexed ? "Indexed" : "Pending"}
                              </span>
                            </td>
                            <td style={{ padding: "10px 14px", color: C.muted, fontSize: 10,
                              fontFamily: "monospace" }}>
                              {fmtTs(d.created_at)}
                            </td>
                            <td style={{ padding: "10px 14px" }}>
                              <button onClick={() => handleDeleteDoc(d.id)}
                                style={{ background: "rgba(255,59,59,0.1)", border: `1px solid ${C.red}30`,
                                  color: C.red, padding: "4px 10px", borderRadius: 3, fontFamily: "monospace",
                                  fontSize: 9, cursor: "pointer", fontWeight: 700 }}>Delete</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
