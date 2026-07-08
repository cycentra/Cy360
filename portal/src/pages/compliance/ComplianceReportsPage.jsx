/**
 * ComplianceReportsPage.jsx
 * ==========================
 * Report list, generate button (triggers background APScheduler job),
 * progress indicator, download button.
 */

import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../../core/constants.js";
import { CY_FW_FILTER_KEY } from "./ComplianceDashboardPage.jsx";

const C = {
  bg: "#090b10", surface: "#0d1117", border: "rgba(255,255,255,0.07)",
  text: "rgba(255,255,255,0.82)", muted: "rgba(255,255,255,0.45)",
  accent: "#00e5a0", red: "#ff3b3b", orange: "#ff8c00", blue: "#4d9eff", purple: "#b06eff",
};

const ALL_FRAMEWORKS = ["all", "nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss", "gdpr"];

function _getFilteredFrameworks() {
  try {
    const s = JSON.parse(localStorage.getItem(CY_FW_FILTER_KEY));
    if (Array.isArray(s) && s.length) return ["all", ...s];
  } catch { /* ignore */ }
  return ALL_FRAMEWORKS;
}

const FRAMEWORKS = ALL_FRAMEWORKS;

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
  const filteredFrameworks = _getFilteredFrameworks();
  const [generating, setGenerating] = useState(false);
  const [activeJob, setActiveJob]   = useState(null);
  const pollRef = useRef(null);

  // Board report state
  const today = new Date().toISOString().split("T")[0];
  const firstOfMonth = today.slice(0, 8) + "01";
  const [boardStart, setBoardStart]   = useState(firstOfMonth);
  const [boardEnd, setBoardEnd]       = useState(today);
  const [boardGen, setBoardGen]       = useState(false);
  const [boardJob, setBoardJob]       = useState(null);
  const boardPollRef = useRef(null);

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

  const pollBoardJob = (jobId) => {
    if (boardPollRef.current) clearInterval(boardPollRef.current);
    boardPollRef.current = setInterval(() => {
      fetch(`${API_BASE}/api/comp/reports/jobs/${jobId}`, { credentials: "include" })
        .then(r => r.ok ? r.json() : Promise.reject(r.status))
        .then(job => {
          setBoardJob(job);
          if (job.status === "complete" || job.status === "failed") {
            clearInterval(boardPollRef.current);
            setBoardGen(false);
            if (job.status === "complete") loadReports();
          }
        })
        .catch(() => { clearInterval(boardPollRef.current); setBoardGen(false); });
    }, 2000);
  };

  useEffect(() => () => {
    if (pollRef.current) clearInterval(pollRef.current);
    if (boardPollRef.current) clearInterval(boardPollRef.current);
  }, []);

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

  const handleBoardGenerate = () => {
    if (!boardStart || !boardEnd) { alert("Select both period start and end dates."); return; }
    setBoardGen(true); setBoardJob(null);
    fetch(`${API_BASE}/api/comp/reports/generate-board`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ period_start: boardStart, period_end: boardEnd }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => { setBoardJob({ job_id: d.job_id, status: "pending", progress: 0 }); pollBoardJob(d.job_id); })
      .catch(e => { setBoardGen(false); alert(`Board report failed: ${e}`); });
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
            {filteredFrameworks.map(f => <option key={f} value={f}>{f === "all" ? "All Frameworks" : f.toUpperCase()}</option>)}
          </select>
          <button onClick={handleGenerate} disabled={generating}
            style={{ background: `${C.accent}10`, border: `1px solid ${C.accent}40`,
              color: C.accent, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace",
              fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: generating ? 0.6 : 1 }}>
            {generating ? "Generating..." : "Generate Report"}
          </button>
        </div>
      </div>

      {/* Board Report generator */}
      <div style={{ background: "#0d1117", border: `1px solid rgba(176,110,255,0.25)`,
        borderRadius: 8, padding: "18px 20px", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
          flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ color: C.purple, fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: 2 }}>
              BOARD / EXECUTIVE REPORT
            </div>
            <div style={{ color: C.text, fontSize: 12, fontFamily: "monospace" }}>
              Unified multi-framework executive summary PDF for board or CISO presentation
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <input type="date" value={boardStart} onChange={e => setBoardStart(e.target.value)}
              style={{ ...inp, padding: "7px 10px" }} />
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>to</span>
            <input type="date" value={boardEnd} onChange={e => setBoardEnd(e.target.value)}
              style={{ ...inp, padding: "7px 10px" }} />
            <button onClick={handleBoardGenerate} disabled={boardGen}
              style={{ background: `rgba(176,110,255,0.10)`, border: `1px solid rgba(176,110,255,0.40)`,
                color: C.purple, padding: "8px 18px", borderRadius: 4, fontFamily: "monospace",
                fontSize: 11, fontWeight: 700, cursor: "pointer", opacity: boardGen ? 0.6 : 1 }}>
              {boardGen ? "Generating..." : "Generate Board Report"}
            </button>
          </div>
        </div>
        {boardJob && (
          <div style={{ marginTop: 14 }}>
            <div style={{ color: C.muted, fontSize: 9, fontFamily: "monospace",
              letterSpacing: "1.5px", marginBottom: 8 }}>Job: {boardJob.job_id}</div>
            <ProgressBar progress={boardJob.progress || 0} status={boardJob.status} />
            {boardJob.error && (
              <div style={{ color: C.red, fontSize: 10, fontFamily: "monospace", marginTop: 8 }}>
                Error: {boardJob.error}
              </div>
            )}
          </div>
        )}
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
