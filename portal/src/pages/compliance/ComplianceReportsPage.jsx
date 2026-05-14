/**
 * ComplianceReportsPage.jsx
 * ==========================
 * Report list, generate button (triggers background APScheduler job),
 * progress indicator, download button.
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../../core/constants.js";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const FRAMEWORKS = ["all", "nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss"];

function fmtTs(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString("en-US", { month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hour12: false }); }
  catch { return ts; }
}

function ProgressBar({ progress, status }) {
  const color = status === "failed" ? C.red : status === "complete" ? C.accent : C.orange;
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ color, fontSize: 9, fontFamily: "monospace", textTransform: "uppercase" }}>
          {status}
        </span>
        <span style={{ color: C.muted, fontSize: 9, fontFamily: "monospace" }}>{progress}%</span>
      </div>
      <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, width: 200 }}>
        <div style={{ height: "100%", width: `${progress}%`, background: color,
          borderRadius: 2, transition: "width 0.5s ease" }} />
      </div>
    </div>
  );
}

export function ComplianceReportsPage() {
  const [reports, setReports]       = useState([]);
  const [loading, setLoading]       = useState(true);
  const [framework, setFramework]   = useState("all");
  const [generating, setGenerating] = useState(false);
  const [activeJob, setActiveJob]   = useState(null);
  const pollRef = useRef(null);

  const loadReports = () => {
    fetch(`${API_BASE}/api/comp/reports`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setReports(d.reports || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { loadReports(); }, []);

  const pollJob = (jobId) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(() => {
      fetch(`${API_BASE}/api/comp/reports/jobs/${jobId}`, { credentials: "include" })
        .then(r => r.ok ? r.json() : Promise.reject(r.status))
        .then(job => {
          setActiveJob(job);
          if (job.status === "complete" || job.status === "failed") {
            clearInterval(pollRef.current);
            setGenerating(false);
            if (job.status === "complete") loadReports();
          }
        })
        .catch(() => { clearInterval(pollRef.current); setGenerating(false); });
    }, 2000);
  };

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const handleGenerate = () => {
    setGenerating(true); setActiveJob(null);
    fetch(`${API_BASE}/api/comp/reports/generate`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ framework }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setActiveJob({ job_id: d.job_id, status: "pending", progress: 0 }); pollJob(d.job_id); })
      .catch(e => { setGenerating(false); alert(`Generate failed: ${e}`); });
  };

  const inp = {
    background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
    borderRadius: 4, color: C.text, fontFamily: "monospace", fontSize: 11,
    padding: "7px 10px", outline: "none", cursor: "pointer",
  };

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: "2px", fontFamily: "monospace",
            textTransform: "uppercase", marginBottom: 4 }}>SECURITY COMPLIANCE</div>
          <h1 style={{ color: C.text, fontSize: 20, fontWeight: 700, margin: 0 }}>Compliance Reports</h1>
          <div style={{ color: C.muted, fontSize: 11, marginTop: 4, fontFamily: "monospace" }}>
            Background report generation — runs as a scheduled job
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <select value={framework} onChange={e => setFramework(e.target.value)} style={inp}>
            {FRAMEWORKS.map(f => <option key={f} value={f}>{f === "all" ? "All Frameworks" : f.toUpperCase()}</option>)}
          </select>
          <button onClick={handleGenerate} disabled={generating}
            style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: generating ? 0.6 : 1 }}>
            {generating ? "Generating..." : "Generate Report"}
          </button>
        </div>
      </div>

      {/* Active job progress */}
      {activeJob && (
        <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8,
          padding: "16px 20px", marginBottom: 20 }}>
          <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace", letterSpacing: "1.5px",
            textTransform: "uppercase", marginBottom: 10 }}>Active Report Job</div>
          <div style={{ color: C.text, fontSize: 11, fontFamily: "monospace", marginBottom: 10 }}>
            Job ID: {activeJob.job_id}
          </div>
          <ProgressBar progress={activeJob.progress || 0} status={activeJob.status} />
          {activeJob.error && (
            <div style={{ color: C.red, fontSize: 10, fontFamily: "monospace", marginTop: 8 }}>
              Error: {activeJob.error}
            </div>
          )}
        </div>
      )}

      {/* Reports list */}
      {loading ? (
        <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12, padding: 24 }}>Loading...</div>
      ) : reports.length === 0 ? (
        <div style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 8,
          padding: 32, textAlign: "center", color: C.muted, fontFamily: "monospace", fontSize: 12 }}>
          No reports generated yet. Use the Generate Report button to create your first report.
        </div>
      ) : (
        <div style={{ display: "grid", gap: 12 }}>
          {reports.map(r => (
            <div key={r.id} style={{ background: "#0d1117", border: `1px solid ${C.border}`,
              borderRadius: 8, padding: "16px 20px", display: "flex", alignItems: "center",
              justifyContent: "space-between" }}>
              <div>
                <div style={{ color: C.text, fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{r.title}</div>
                <div style={{ display: "flex", gap: 16 }}>
                  <span style={{ color: C.blue, fontSize: 9, fontFamily: "monospace",
                    textTransform: "uppercase" }}>{r.framework}</span>
                  <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    Score: {r.overall_score ? `${Math.round(r.overall_score)}%` : "N/A"}
                  </span>
                  <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    {fmtTs(r.created_at)}
                  </span>
                  <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
                    by {r.generated_by || "system"}
                  </span>
                </div>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                {r.has_pdf && (
                  <a href={`${API_BASE}/api/comp/reports/${r.id}/download`}
                    style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
                      color: C.accent, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
                      fontSize: 10, fontWeight: 700, cursor: "pointer", textDecoration: "none",
                      display: "inline-block" }}>
                    Download PDF
                  </a>
                )}
                <a href={`${API_BASE}/api/comp/reports/${r.id}/download`}
                  style={{ background: "rgba(77,158,255,0.1)", border: `1px solid ${C.blue}30`,
                    color: C.blue, padding: "6px 14px", borderRadius: 4, fontFamily: "monospace",
                    fontSize: 10, fontWeight: 700, cursor: "pointer", textDecoration: "none",
                    display: "inline-block" }}>
                  Download JSON
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
