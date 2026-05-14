/**
 * PolicyDocumentsPage.jsx
 * ========================
 * Flat organisational policy document store — not organised by framework.
 * Accessible only via the GRC Posture "Getting Started" workflow widget.
 *
 * Documents are stored in a single "org-policies" RAG collection in CyMind.
 * Framework reference docs (ISO 27001, NIS2, DORA, etc.) are managed separately
 * under System Settings → Security Compliance → Framework Documents.
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const ORG_COLLECTION = "org-policies";

const RECOMMENDED_DOCS = [
  { name: "Information Security Policy",          tag: "security",    desc: "Overarching IS policy covering objectives, scope, and responsibilities (ISO 27001 A.5.1, NIS2 Art.21)." },
  { name: "Access Control Policy",                tag: "security",    desc: "Rules for granting, reviewing, and revoking logical and physical access (ISO 27001 A.5.15–A.5.18, PCI Req 7–8)." },
  { name: "Incident Response Plan",               tag: "security",    desc: "Step-by-step IR playbook including roles, escalation paths, and notification SLAs (NIS2 Art.23, DORA Art.17)." },
  { name: "Risk Management Policy",               tag: "security",    desc: "Methodology for identifying, assessing, treating, and monitoring information security risks (ISO 27001 Cl.6.1)." },
  { name: "Business Continuity / DR Plan",        tag: "operations",  desc: "RTO/RPO targets, failover procedures, and test schedules (ISO 27001 A.5.30, DORA Art.11–12)." },
  { name: "Asset Management Policy",              tag: "operations",  desc: "Inventory, classification, and handling requirements for hardware, software, and data assets (ISO 27001 A.5.9–A.5.13)." },
  { name: "Vendor / Third-Party Security Policy", tag: "security",    desc: "Due-diligence, contractual, and monitoring requirements for suppliers (ISO 27001 A.5.19–A.5.22, DORA Art.28–30)." },
  { name: "Data Classification & Handling Policy",tag: "privacy",     desc: "Data classification tiers (Public / Internal / Confidential / Restricted) and handling rules per tier." },
  { name: "Acceptable Use Policy",                tag: "hr",          desc: "Permitted and prohibited use of corporate systems, data, and internet by employees and contractors." },
  { name: "Change Management Policy",             tag: "operations",  desc: "Request, approval, testing, and roll-back process for infrastructure and application changes (ISO 27001 A.8.32)." },
  { name: "Vulnerability Management Policy",      tag: "security",    desc: "Scan cadence, patch SLAs by severity, and exception process (NIS2 Art.21(2)(e), PCI Req 6, 11)." },
  { name: "Privacy / GDPR Compliance Policy",     tag: "privacy",     desc: "Data subject rights, lawful basis, retention periods, DPA obligations, and breach notification (AVG/GDPR Art.24–32)." },
];

const TAG_COLORS = {
  security: "#4d9eff", privacy: "#b06eff", hr: "#ff8c00",
  operations: "#00e5a0", legal: "#ff3b3b", finance: "#ffd700",
};

function fmtTs(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" }); }
  catch { return ts; }
}

function fmtSize(bytes) {
  if (!bytes) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function TagBadge({ tag }) {
  const color = TAG_COLORS[tag?.toLowerCase()] || C.muted;
  return (
    <span style={{
      background: `${color}15`, border: `1px solid ${color}35`, color,
      fontSize: 9, fontFamily: "monospace", padding: "2px 7px", borderRadius: 10,
      textTransform: "uppercase", letterSpacing: "0.5px",
    }}>
      {tag}
    </span>
  );
}

function GuidancePanel() {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ background: "rgba(77,158,255,0.05)", border: `1px solid rgba(77,158,255,0.18)`,
      borderRadius: 8, marginBottom: 24, overflow: "hidden" }}>

      {/* Header — always visible */}
      <button onClick={() => setOpen(o => !o)}
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 10,
          padding: "14px 20px", background: "none", border: "none",
          cursor: "pointer", textAlign: "left" }}>
        <span style={{ fontSize: 14 }}>📋</span>
        <div style={{ flex: 1 }}>
          <div style={{ color: C.blue, fontSize: 11, fontWeight: 700,
            fontFamily: "monospace" }}>
            What to upload — Policy & Governance Document Guide
          </div>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>
            Recommended document types, naming conventions, and upload guidance
          </div>
        </div>
        <span style={{ color: C.muted, fontSize: 11 }}>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div style={{ padding: "0 20px 20px" }}>

          {/* Key notes strip */}
          <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
            {[
              { icon: "📄", title: "Supported formats", body: "PDF · DOCX · TXT · Markdown (.md)" },
              { icon: "🔄", title: "Review cycle", body: "Review and re-upload annually, or after any major control change, audit, or incident." },
              { icon: "✅", title: "Accuracy requirement", body: "Documents must reflect your organisation's actual operational processes and controls — not aspirational or template text." },
            ].map(({ icon, title, body }) => (
              <div key={title} style={{ flex: "1 1 200px", background: "rgba(255,255,255,0.03)",
                border: `1px solid rgba(255,255,255,0.06)`, borderRadius: 6,
                padding: "12px 14px" }}>
                <div style={{ fontSize: 16, marginBottom: 6 }}>{icon}</div>
                <div style={{ color: C.text, fontSize: 10, fontWeight: 700,
                  fontFamily: "monospace", marginBottom: 4 }}>{title}</div>
                <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                  lineHeight: 1.6 }}>{body}</div>
              </div>
            ))}
          </div>

          {/* Recommended documents table */}
          <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace",
            textTransform: "uppercase", letterSpacing: "1.5px", marginBottom: 10 }}>
            Recommended Policy Documents
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 20 }}>
            {RECOMMENDED_DOCS.map(d => {
              const color = TAG_COLORS[d.tag] || C.muted;
              return (
                <div key={d.name} style={{ display: "flex", gap: 10, alignItems: "flex-start",
                  padding: "9px 12px", background: "rgba(255,255,255,0.02)",
                  borderRadius: 5, border: `1px solid rgba(255,255,255,0.04)` }}>
                  <span style={{ background: `${color}15`, color, border: `1px solid ${color}30`,
                    fontSize: 8, fontFamily: "monospace", fontWeight: 700,
                    padding: "2px 7px", borderRadius: 10, flexShrink: 0,
                    textTransform: "uppercase", marginTop: 1 }}>
                    {d.tag}
                  </span>
                  <div>
                    <div style={{ color: C.text, fontSize: 11, fontWeight: 600,
                      marginBottom: 2 }}>{d.name}</div>
                    <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                      lineHeight: 1.5 }}>{d.desc}</div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Naming conventions */}
          <div style={{ color: C.muted, fontSize: 8, fontFamily: "monospace",
            textTransform: "uppercase", letterSpacing: "1.5px", marginBottom: 10 }}>
            Recommended Naming Convention
          </div>
          <div style={{ background: "rgba(255,255,255,0.03)", border: `1px solid rgba(255,255,255,0.07)`,
            borderRadius: 6, padding: "14px 16px", marginBottom: 16 }}>
            <div style={{ color: C.accent, fontSize: 11, fontFamily: "monospace",
              fontWeight: 700, marginBottom: 10 }}>
              {"<Policy_Name>_v<Version>_<Year>.pdf"}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {[
                "Information_Security_Policy_v1.2_2026.pdf",
                "Incident_Response_Plan_v3.0_2026.pdf",
                "Access_Control_Policy_v2.1_2026.pdf",
                "Risk_Management_Policy_v1.0_2026.pdf",
                "Business_Continuity_DR_Plan_v2.3_2026.pdf",
              ].map(ex => (
                <div key={ex} style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>
                  <span style={{ color: "rgba(255,255,255,0.25)", marginRight: 8 }}>→</span>
                  {ex}
                </div>
              ))}
            </div>
          </div>

          {/* Framework docs note */}
          <div style={{ background: "rgba(176,110,255,0.06)",
            border: "1px solid rgba(176,110,255,0.2)", borderRadius: 6,
            padding: "12px 16px", display: "flex", gap: 10, alignItems: "flex-start" }}>
            <span style={{ fontSize: 14, flexShrink: 0 }}>ℹ️</span>
            <div>
              <div style={{ color: C.purple, fontSize: 10, fontWeight: 700,
                fontFamily: "monospace", marginBottom: 4 }}>
                Framework Reference Documents
              </div>
              <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
                lineHeight: 1.7 }}>
                This store is for your <strong style={{ color: C.text }}>organisation's own operational documents</strong> —
                policies, plans, and procedures your team actually follows.<br />
                Framework standard documents (e.g. <em>ISO/IEC 27001:2022</em>, <em>NIST SP 800-53</em>,
                PCI DSS v4.0 specification) are uploaded separately under{" "}
                <strong style={{ color: C.purple }}>System Settings → Security Compliance → Framework Documents</strong>
                . Uploading the framework standard enables CyMind to cross-reference your policy documents against
                the exact control language in the standard. You should upload a reference document for each framework
                you intend to assess (NIS2, DORA, SOC 2, PCI DSS, NIST CSF, ISO 27001).
              </div>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}

function DropZone({ onUploaded }) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [msg, setMsg]           = useState(null);
  const [tag, setTag]           = useState("security");
  const ref = useRef(null);

  const uploadFile = (file) => {
    if (!file) return;
    setUploading(true); setMsg(null);
    const fd = new FormData();
    fd.append("file", file);
    fd.append("tag", tag);
    fetch(`${API_BASE}/api/comp/policy-docs/collections/${ORG_COLLECTION}/documents`, {
      method: "POST", credentials: "include", body: fd,
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => { setMsg({ ok: true, text: "Document uploaded and queued for indexing" }); onUploaded(); })
      .catch(e => setMsg({ ok: false, text: `Upload failed (${e})` }))
      .finally(() => setUploading(false));
  };

  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 10 }}>
        <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
          textTransform: "uppercase", letterSpacing: "1px" }}>Category tag</div>
        <select value={tag} onChange={e => setTag(e.target.value)}
          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
            color: C.text, borderRadius: 4, padding: "4px 8px", fontFamily: "monospace",
            fontSize: 11, cursor: "pointer" }}>
          {Object.keys(TAG_COLORS).map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
          <option value="other">other</option>
        </select>
      </div>
      <div
        onDragEnter={() => setDragging(true)}
        onDragLeave={() => setDragging(false)}
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); setDragging(false); uploadFile(e.dataTransfer.files[0]); }}
        onClick={() => ref.current?.click()}
        style={{
          border: `2px dashed ${dragging ? C.accent : "rgba(255,255,255,0.12)"}`,
          borderRadius: 8, padding: "32px 20px", textAlign: "center", cursor: "pointer",
          background: dragging ? "rgba(0,229,160,0.04)" : "rgba(255,255,255,0.01)",
          transition: "all 0.2s",
        }}>
        <input ref={ref} type="file" style={{ display: "none" }}
          accept=".pdf,.docx,.txt,.md"
          onChange={e => uploadFile(e.target.files[0])} />
        <div style={{ fontSize: 20, marginBottom: 8 }}>📄</div>
        <div style={{ color: uploading ? C.accent : C.muted, fontSize: 12, fontFamily: "monospace" }}>
          {uploading ? "Uploading and indexing..." : (
            <>
              <div style={{ marginBottom: 4 }}>Drag & drop a policy document, or click to browse</div>
              <div style={{ fontSize: 9, textTransform: "uppercase", letterSpacing: "1px", opacity: 0.6 }}>
                PDF · DOCX · TXT · Markdown
              </div>
            </>
          )}
        </div>
      </div>
      {msg && (
        <div style={{ color: msg.ok ? C.accent : C.red, fontSize: 10,
          fontFamily: "monospace", marginTop: 8 }}>{msg.text}</div>
      )}
    </div>
  );
}

export function PolicyDocumentsPage() {
  const [docs, setDocs]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [search, setSearch]     = useState("");
  const [filterTag, setFilterTag] = useState("all");
  const [deleting, setDeleting] = useState(null);
  const [reindexMsg, setReindexMsg] = useState(null);

  const load = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/comp/policy-docs/collections/${ORG_COLLECTION}/documents`,
      { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setDocs(d.documents || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    // Ensure org-policies collection exists, then load
    fetch(`${API_BASE}/api/comp/policy-docs/collections`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ framework: "org-policies" }),
    }).finally(() => load());
  }, []);

  const handleDelete = (docId) => {
    if (!confirm("Delete this policy document? It will be removed from the RAG index.")) return;
    setDeleting(docId);
    fetch(`${API_BASE}/api/comp/policy-docs/documents/${docId}`,
      { method: "DELETE", credentials: "include" })
      .then(r => r.ok ? load() : alert("Delete failed"))
      .finally(() => setDeleting(null));
  };

  const handleReindex = () => {
    setReindexMsg("Reindexing...");
    fetch(`${API_BASE}/api/comp/policy-docs/collections/${ORG_COLLECTION}/reindex`,
      { method: "POST", credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(() => setReindexMsg("Reindex started"))
      .catch(() => setReindexMsg("Reindex failed"));
    setTimeout(() => setReindexMsg(null), 4000);
  };

  const allTags = [...new Set(docs.map(d => d.tag || d.framework).filter(Boolean))];
  const filtered = docs.filter(d => {
    const matchSearch = !search || d.name?.toLowerCase().includes(search.toLowerCase());
    const matchTag    = filterTag === "all" || (d.tag || d.framework) === filterTag;
    return matchSearch && matchTag;
  });

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
          textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
        <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>
          Policy Documents
        </h1>
        <div style={{ color: C.muted, fontSize: 11, marginTop: 6, fontFamily: "monospace",
          lineHeight: 1.6, maxWidth: 720 }}>
          Upload and manage your organisation's operational and business policy documents.
          These are org-specific — they are not linked to any particular compliance framework.
          Once indexed, the CyMind RAG pipeline uses them to enrich compliance assessments,
          gap analyses, and report generation.
          <span style={{ color: C.blue, marginLeft: 8 }}>
            Framework reference documents (ISO 27001, NIS2, DORA, etc.) are managed under{" "}
            <strong>System Settings → Security Compliance → Framework Documents</strong>.
          </span>
        </div>
      </div>

      {/* Guidance panel */}
      <GuidancePanel />

      {/* Upload zone */}
      <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20, marginBottom: 24 }}>
        <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
          textTransform: "uppercase", letterSpacing: "1.5px", marginBottom: 14 }}>
          Upload Policy Document
        </div>
        <DropZone onUploaded={load} />
      </div>

      {/* Filters + reindex */}
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 16, flexWrap: "wrap" }}>
        <input
          placeholder="Search documents..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
            color: C.text, borderRadius: 4, padding: "7px 12px", fontFamily: "monospace",
            fontSize: 11, minWidth: 220, outline: "none" }}
        />
        <select value={filterTag} onChange={e => setFilterTag(e.target.value)}
          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
            color: C.text, borderRadius: 4, padding: "7px 10px", fontFamily: "monospace",
            fontSize: 11, cursor: "pointer" }}>
          <option value="all">All categories</option>
          {allTags.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          {reindexMsg && (
            <span style={{ color: C.orange, fontSize: 10, fontFamily: "monospace" }}>{reindexMsg}</span>
          )}
          <button onClick={handleReindex}
            style={{ background: "rgba(77,158,255,0.1)", border: `1px solid ${C.blue}30`,
              color: C.blue, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 10, fontWeight: 700, cursor: "pointer" }}>
            Reindex All
          </button>
        </div>
      </div>

      {/* Document list */}
      {loading ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 32, textAlign: "center" }}>
          Loading documents...
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8,
          padding: 40, textAlign: "center", color: C.muted, fontFamily: "monospace", fontSize: 12 }}>
          {docs.length === 0
            ? "No policy documents uploaded yet. Use the upload zone above to add your first document."
            : "No documents match your filters."}
        </div>
      ) : (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Document", "Category", "Status", "Uploaded", ""].map(h => (
                  <th key={h} style={{ padding: "10px 16px", textAlign: "left",
                    color: C.muted, fontSize: 9, fontFamily: "monospace",
                    letterSpacing: "1px", textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((d, i) => (
                <tr key={d.id} style={{
                  borderBottom: `1px solid rgba(255,255,255,0.03)`,
                  background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
                }}>
                  <td style={{ padding: "11px 16px" }}>
                    <div style={{ color: C.text, fontSize: 12, fontWeight: 500 }}>{d.name}</div>
                    <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>
                      {d.file_type?.toUpperCase() || "—"} · {fmtSize(d.file_size)}
                    </div>
                  </td>
                  <td style={{ padding: "11px 16px" }}>
                    <TagBadge tag={d.tag || d.framework || "uncategorised"} />
                  </td>
                  <td style={{ padding: "11px 16px" }}>
                    <span style={{
                      color: d.indexed ? C.accent : C.orange,
                      fontSize: 10, fontFamily: "monospace",
                    }}>
                      {d.indexed ? "✓ Indexed" : "⧗ Pending"}
                    </span>
                  </td>
                  <td style={{ padding: "11px 16px", color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    {fmtTs(d.created_at)}
                    {d.uploaded_by && (
                      <div style={{ fontSize: 9, marginTop: 1, opacity: 0.7 }}>{d.uploaded_by}</div>
                    )}
                  </td>
                  <td style={{ padding: "11px 16px" }}>
                    <button onClick={() => handleDelete(d.id)}
                      disabled={deleting === d.id}
                      style={{ background: "rgba(255,59,59,0.1)", border: `1px solid ${C.red}30`,
                        color: C.red, padding: "4px 10px", borderRadius: 3, fontFamily: "monospace",
                        fontSize: 9, cursor: "pointer", fontWeight: 700,
                        opacity: deleting === d.id ? 0.5 : 1 }}>
                      {deleting === d.id ? "..." : "Delete"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ padding: "10px 16px", borderTop: `1px solid ${C.border}`,
            color: C.muted, fontSize: 9, fontFamily: "monospace" }}>
            {filtered.length} document{filtered.length !== 1 ? "s" : ""}
            {filterTag !== "all" || search ? ` (filtered from ${docs.length})` : ""}
          </div>
        </div>
      )}
    </div>
  );
}
