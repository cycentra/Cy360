/**
 * src/pages/guest-scan/GuestScanPage.jsx
 * =========================================
 * Standalone guest scan page — accessible at /guest-scan without login.
 * Offers Standard scan only (Deep/Passive are visible but greyed out).
 * After completion, shows a limited free-tier dashboard.
 *
 * Uses the same /api/scan/* endpoints as the main app; no auth required
 * since the Flask backend doesn't enforce session on these routes.
 */

import { useState, useRef, useEffect } from "react";

// ── Helpers ───────────────────────────────────────────────────────────────────

const API_BASE = "";

function genGuestUid() {
  return "guest_" + Math.random().toString(36).slice(2, 10);
}

// Standard scan module sequence — matches SCAN_PROFILES["standard"] in cycentra_scan.py
const MODULES = [
  "DNS Reconnaissance", "Subdomain Enumeration", "Web Analysis",
  "Crypto & SSL Audit", "Email Security Check", "WHOIS & History",
  "OSINT Gathering", "Cloud Infrastructure",
  "Generating Report",
];

const RISK_CONFIG = {
  critical: { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)", label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "rgba(255,140,0,0.12)",  label: "HIGH"     },
  medium:   { color: "#f5c518", bg: "rgba(245,197,24,0.12)", label: "MEDIUM"   },
  low:      { color: "#00e5a0", bg: "rgba(0,229,160,0.12)",  label: "LOW"      },
};

// ── GuestDashboard ────────────────────────────────────────────────────────────

// Shared check/cross icon pair
function CheckIcon({ color = "#00e5a0" }) {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  );
}
function CrossIcon({ color = "#ff3b3b" }) {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5">
      <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  );
}

function widgetCard(borderColor) {
  return {
    background: "rgba(255,255,255,0.025)",
    border: "1px solid rgba(255,255,255,0.07)",
    borderTop: `2px solid ${borderColor}`,
    borderRadius: 5,
    padding: "18px 22px",
    flex: 1,
    minWidth: 280,
  };
}

function WidgetLabel({ children }) {
  return (
    <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px",
      textTransform: "uppercase", fontFamily: "monospace", marginBottom: 14 }}>
      {children}
    </div>
  );
}

function WidgetNote({ children }) {
  return (
    <div style={{ marginTop: 10, padding: "5px 8px", background: "rgba(255,255,255,0.04)",
      borderRadius: 3, color: "rgba(255,255,255,0.4)", fontSize: 10, fontFamily: "monospace",
      fontStyle: "italic", lineHeight: 1.4 }}>
      {children}
    </div>
  );
}

function StatusRow({ label, ok, okText = "Pass", failText = "Issue", okColor = "#00e5a0", failColor = "#ff8c00", detail = null }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 7 }}>
      <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>{label}</span>
      <span style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, fontFamily: "monospace",
        color: ok ? okColor : failColor }}>
        {ok ? <CheckIcon color={okColor}/> : <CrossIcon color={failColor}/>}
        {detail !== null ? detail : (ok ? okText : failText)}
      </span>
    </div>
  );
}

function RiskDonut({ assets = [] }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach(a => (a.vulnerabilities || []).forEach(v => {
    const s = v.severity?.toLowerCase();
    if (counts[s] !== undefined) counts[s]++;
  }));
  const total      = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const colors     = ["#ff3b3b", "#ff8c00", "#f5c518", "#00e5a0"];
  const keys       = ["critical", "high", "medium", "low"];
  const totalVulns = Object.values(counts).reduce((a, b) => a + b, 0);
  let cumulative   = 0;
  const segments   = keys.map((k, i) => {
    const pct = counts[k] / total;
    const s   = cumulative * 360;
    const e   = (cumulative + pct) * 360;
    cumulative += pct;
    const r = 60, cx = 80, cy = 80;
    const toR = deg => (deg - 90) * Math.PI / 180;
    const x1 = cx + r * Math.cos(toR(s)); const y1 = cy + r * Math.sin(toR(s));
    const x2 = cx + r * Math.cos(toR(e)); const y2 = cy + r * Math.sin(toR(e));
    const d  = pct === 0 ? "" : `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${pct > 0.5 ? 1 : 0} 1 ${x2} ${y2} Z`;
    return { d, color: colors[i], key: k, count: counts[k] };
  });
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
      <svg width="160" height="160" style={{ flexShrink: 0 }}>
        <circle cx="80" cy="80" r="60" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.05)" strokeWidth="1"/>
        {segments.map(s => s.d && <path key={s.key} d={s.d} fill={s.color} opacity="0.85"/>)}
        <circle cx="80" cy="80" r="38" fill="#0d1117"/>
        <text x="80" y="76" textAnchor="middle" fill="white" fontSize="22" fontWeight="800" fontFamily="'Space Mono',monospace">{totalVulns}</text>
        <text x="80" y="94" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="9" fontFamily="monospace">FINDINGS</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {keys.map((k, i) => (
          <div key={k} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: colors[i] }}/>
            <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, width: 65 }}>
              {k.charAt(0).toUpperCase() + k.slice(1)}
            </span>
            <span style={{ color: colors[i], fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{counts[k]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Real-data widgets (read from raw_results) ──────────────────────────────────

function SslWidget({ asset }) {
  const ssl      = asset?.raw_results?.crypto?.results?.ssl || {};
  const cert     = ssl.cert_info || {};
  const sslEnabled = ssl.ssl_enabled !== false;
  const daysLeft = cert.days_to_expiry ?? null;
  const protocol = cert.protocol || ssl.protocol || null;
  const cipher   = cert.cipher || null;
  const ocsp     = cert.ocsp_stapling ?? false;
  const chainValid = cert.chain_valid !== false;
  const issues   = ssl.issues || [];
  const pqc      = asset?.raw_results?.crypto?.results?.pqc?.server_pqc ?? false;

  const daysColor = daysLeft === null ? "rgba(255,255,255,0.4)"
    : daysLeft < 30 ? "#ff3b3b"
    : daysLeft < 60 ? "#ff8c00"
    : "#00e5a0";

  const protocolColor = protocol
    ? (protocol.includes("1.3") ? "#00e5a0" : protocol.includes("1.2") ? "#f5c518" : "#ff3b3b")
    : "rgba(255,255,255,0.3)";

  return (
    <div style={widgetCard("#f5c518")}>
      <WidgetLabel>SSL / Crypto Health</WidgetLabel>
      <StatusRow label="SSL Enabled" ok={sslEnabled} okColor="#00e5a0" failColor="#ff3b3b"/>
      {protocol && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Protocol</span>
          <span style={{ color: protocolColor, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{protocol}</span>
        </div>
      )}
      {daysLeft !== null && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Cert Expires</span>
          <span style={{ color: daysColor, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{daysLeft}d</span>
        </div>
      )}
      <StatusRow label="Chain Valid" ok={chainValid}/>
      <StatusRow label="OCSP Stapling" ok={ocsp} okColor="#00e5a0" failColor="#f5c518" failText="Off"/>
      <StatusRow label="PQC Hybrid TLS" ok={pqc} okColor="#00e5a0" failColor="rgba(255,255,255,0.3)" failText="Not detected"/>
      {issues.length > 0 && (
        <div style={{ marginTop: 8, display: "flex", justifyContent: "space-between" }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Active Issues</span>
          <span style={{ color: "#ff8c00", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{issues.length}</span>
        </div>
      )}
      {cipher && (
        <div style={{ marginTop: 6, padding: "4px 7px", background: "rgba(245,197,24,0.07)", borderRadius: 3 }}>
          <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace" }}>{cipher}</span>
        </div>
      )}
      <WidgetNote>Full cipher suite audit and PQC readiness available in Deep Scan.</WidgetNote>
    </div>
  );
}

function EmailSecurityWidget({ asset }) {
  const email      = asset?.raw_results?.email_sec?.results || {};
  const spf        = email.spf || {};
  const dmarc      = email.dmarc || {};
  const dkimList   = Array.isArray(email.dkim) ? email.dkim : [];
  const dnssec     = email.dnssec || {};
  const spoofRisk  = email.spoofing_risk?.level || null;
  const eliteScore = email.elite_score || "—";
  const eliteStatus = email.elite_status || "basic";

  const dmarcPolicy   = dmarc.policy || (dmarc.present ? "present" : null);
  const dmarcOk       = dmarcPolicy === "reject";
  const dmarcColor    = dmarcPolicy === "reject" ? "#00e5a0"
    : dmarcPolicy === "quarantine" ? "#f5c518"
    : "#ff3b3b";
  const dmarcLabel    = dmarcPolicy || "Missing";

  const spoofColor = spoofRisk === "low" ? "#00e5a0" : spoofRisk === "medium" ? "#f5c518" : spoofRisk === "high" ? "#ff3b3b" : "rgba(255,255,255,0.3)";
  const validDkim  = dkimList.filter(d => d.valid !== false).length;

  return (
    <div style={widgetCard("#b06eff")}>
      <WidgetLabel>Email Security</WidgetLabel>
      <StatusRow label="SPF" ok={!!spf.present} failColor="#ff3b3b"/>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
        <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>DKIM</span>
        <span style={{ color: dkimList.length > 0 ? "#00e5a0" : "#ff8c00", fontSize: 11, fontFamily: "monospace" }}>
          {dkimList.length > 0 ? `${validDkim}/${dkimList.length} valid` : "Not found"}
        </span>
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
        <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>DMARC</span>
        <span style={{ display: "flex", alignItems: "center", gap: 5, color: dmarcColor, fontSize: 11, fontFamily: "monospace" }}>
          {dmarcOk ? <CheckIcon color={dmarcColor}/> : <CrossIcon color={dmarcColor}/>}
          {dmarcLabel}
        </span>
      </div>
      <StatusRow label="DNSSEC" ok={!!dnssec.enabled} failColor="#f5c518" failText="Disabled"/>
      {spoofRisk && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Spoofing Risk</span>
          <span style={{ color: spoofColor, fontSize: 11, fontFamily: "monospace", fontWeight: 700, textTransform: "uppercase" }}>{spoofRisk}</span>
        </div>
      )}
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 2 }}>
        <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Elite Score</span>
        <span style={{ color: eliteStatus === "elite" ? "#00e5a0" : eliteStatus === "robust" ? "#4d9eff" : "#f5c518",
          fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{eliteScore}</span>
      </div>
      <WidgetNote>MTA-STS, BIMI, and full email threat correlation available in Deep Scan.</WidgetNote>
    </div>
  );
}

const PORT_LABELS = { 21: "FTP", 22: "SSH", 25: "SMTP", 80: "HTTP", 443: "HTTPS",
  3306: "MySQL", 3389: "RDP", 5432: "PgSQL", 6379: "Redis", 8080: "Alt-HTTP",
  8443: "Alt-HTTPS", 27017: "MongoDB" };

function WebSecurityWidget({ asset }) {
  const web       = asset?.raw_results?.web?.results || {};
  const ports     = web.ports || [];
  const exposed   = web.exposed_paths || [];
  const jsSecrets = web.js_secrets || [];
  const http      = web.http_analysis || {};
  const headers   = http.http_headers || [];
  const redirects = http.redirects_to_https ?? null;
  const fingerprints = web.fingerprints || {};

  const critPaths = exposed.filter(p => (p.severity || p.status || "").toString().match(/critical|200/i)).length;
  const banner    = Object.values(fingerprints)[0]?.banner || null;

  return (
    <div style={widgetCard("#ff8c00")}>
      <WidgetLabel>Web Security</WidgetLabel>
      {ports.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 9, fontFamily: "monospace", letterSpacing: "1px", marginBottom: 5 }}>OPEN PORTS</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
            {ports.slice(0, 6).map(p => (
              <span key={p} style={{ background: p === 22 || p === 3389 || p === 3306 ? "rgba(255,59,59,0.12)" : "rgba(255,140,0,0.1)",
                color: p === 22 || p === 3389 || p === 3306 ? "#ff8c00" : "rgba(255,255,255,0.55)",
                fontSize: 10, fontFamily: "monospace", padding: "2px 7px", borderRadius: 3 }}>
                {p}{PORT_LABELS[p] ? ` (${PORT_LABELS[p]})` : ""}
              </span>
            ))}
            {ports.length > 6 && <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>+{ports.length - 6} more</span>}
          </div>
        </div>
      )}
      {redirects !== null && <StatusRow label="HTTPS Redirect" ok={redirects} failColor="#ff3b3b"/>}
      {exposed.length > 0 && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Exposed Paths</span>
          <span style={{ color: critPaths > 0 ? "#ff3b3b" : "#ff8c00", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
            {exposed.length}{critPaths > 0 ? ` (${critPaths} critical)` : ""}
          </span>
        </div>
      )}
      {jsSecrets.length > 0 && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>JS Secrets Found</span>
          <span style={{ color: "#ff3b3b", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{jsSecrets.length} found</span>
        </div>
      )}
      {headers.length > 0 && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Missing Headers</span>
          <span style={{ color: "#f5c518", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{headers.length}</span>
        </div>
      )}
      {banner && (
        <div style={{ marginTop: 4, padding: "3px 7px", background: "rgba(0,0,0,0.2)", borderRadius: 3 }}>
          <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace" }}>{banner}</span>
        </div>
      )}
      <WidgetNote>Full CORS audit, WAF detection, and API endpoint mapping available in Deep Scan.</WidgetNote>
    </div>
  );
}

function DnsWidget({ asset, data }) {
  const dns     = asset?.raw_results?.dns?.results || {};
  const records = dns.records || {};
  const typos   = dns.typos || {};
  const subSum  = data?.subdomain_summary || {};
  // reuse DNSSEC from email_sec module (same underlying check)
  const dnssec  = asset?.raw_results?.email_sec?.results?.dnssec || {};

  const aCount  = (records.A || records.a || []).length;
  const mxCount = (records.MX || records.mx || []).length;
  const typoReg = Array.isArray(typos.registered) ? typos.registered.length : (typeof typos.registered === "number" ? typos.registered : 0);

  return (
    <div style={widgetCard("#4d9eff")}>
      <WidgetLabel>DNS Overview</WidgetLabel>
      {aCount > 0 && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>A Records</span>
          <span style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{aCount}</span>
        </div>
      )}
      {mxCount > 0 && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>MX Records</span>
          <span style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{mxCount}</span>
        </div>
      )}
      <StatusRow label="DNSSEC" ok={!!dnssec.enabled} failColor="#f5c518" failText="Disabled"/>
      {typoReg > 0 && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Typosquats Registered</span>
          <span style={{ color: "#ff8c00", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{typoReg} domains</span>
        </div>
      )}
      {subSum.total != null && (
        <div style={{ marginTop: 6, padding: "6px 8px", background: "rgba(77,158,255,0.06)", borderRadius: 3 }}>
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 9, fontFamily: "monospace", marginBottom: 4 }}>SUBDOMAIN SUMMARY</div>
          <div style={{ display: "flex", gap: 12 }}>
            {[["Total", subSum.total, "#4d9eff"], ["Live", subSum.live, "#00e5a0"], ["New", subSum.new, "#f5c518"]].map(([l, v, c]) => (
              <div key={l}>
                <div style={{ color: c, fontSize: 16, fontFamily: "monospace", fontWeight: 800 }}>{v ?? 0}</div>
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace" }}>{l}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      <WidgetNote>Typosquatting takedown analysis and full DNS history available in Deep Scan.</WidgetNote>
    </div>
  );
}

function CloudWidget({ asset }) {
  const cloud    = asset?.raw_results?.cloud?.results || {};
  const providers = cloud.providers || [];
  const buckets  = cloud.buckets || [];
  const k8s      = cloud.k8s_exposed ?? false;
  const pubBuckets = buckets.filter(b => b.public || b.listable).length;
  const privBuckets = buckets.length - pubBuckets;

  const PROVIDER_COLORS = { AWS: "#ff8c00", Azure: "#4d9eff", GCP: "#00e5a0", Cloudflare: "#f5c518" };

  if (providers.length === 0 && buckets.length === 0 && !k8s) {
    return (
      <div style={widgetCard("#00e5a0")}>
        <WidgetLabel>Cloud Exposure</WidgetLabel>
        <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace", display: "flex", alignItems: "center", gap: 6 }}>
          <CheckIcon color="#00e5a0"/> No cloud infrastructure detected
        </div>
        <WidgetNote>Kubernetes cluster exposure, Azure/GCP misconfiguration, and metadata endpoint probing available in Deep Scan.</WidgetNote>
      </div>
    );
  }

  return (
    <div style={widgetCard("#00e5a0")}>
      <WidgetLabel>Cloud Exposure</WidgetLabel>
      {providers.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 10 }}>
          {providers.map(p => (
            <span key={p} style={{ background: `rgba(255,255,255,0.06)`, color: PROVIDER_COLORS[p] || "rgba(255,255,255,0.5)",
              fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 3, border: `1px solid ${(PROVIDER_COLORS[p] || "#fff")}30` }}>
              {p}
            </span>
          ))}
        </div>
      )}
      {buckets.length > 0 && (
        <>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
            <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Public Buckets</span>
            <span style={{ color: pubBuckets > 0 ? "#ff3b3b" : "#00e5a0", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{pubBuckets}</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 7 }}>
            <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Private Buckets</span>
            <span style={{ color: "#00e5a0", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{privBuckets}</span>
          </div>
        </>
      )}
      <StatusRow label="K8s API Exposed" ok={!k8s} okText="No" failText="Exposed" failColor="#ff3b3b"/>
      <WidgetNote>Kubernetes cluster exposure, Azure/GCP misconfiguration, and metadata endpoint probing available in Deep Scan.</WidgetNote>
    </div>
  );
}

// ── Partial-locked premium widgets (deep-only) ─────────────────────────────────

function PartialLockedWidget({ title, accent = "#00e5a0", teaser }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}40`, borderRadius: 5, padding: "18px 22px", flex: 1, minWidth: 280 }}>
      <WidgetLabel>{title}</WidgetLabel>
      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 12, fontFamily: "monospace", marginBottom: 10 }}>
        {teaser}
      </div>
      {/* blurred preview bars */}
      <div style={{ marginBottom: 10 }}>
        {[75, 55, 65].map((w, i) => (
          <div key={i} style={{ height: 10, width: `${w}%`, background: `${accent}18`,
            borderRadius: 3, marginBottom: 7, filter: "blur(2px)" }}/>
        ))}
      </div>
      <div style={{ display: "inline-flex", alignItems: "center", gap: 6, background: "rgba(255,255,255,0.04)",
        border: "1px solid rgba(255,255,255,0.08)", borderRadius: 3, padding: "5px 10px" }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.25)" strokeWidth="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>
          Available in Deep Scan — request Licensed Portal
        </span>
      </div>
    </div>
  );
}

function GuestDashboard({ data, onRescan }) {
  const assets   = data?.assets || [];
  const asset    = assets[0] || {};
  const domain   = data?.meta?.domain || "—";
  const scanId   = data?.meta?.scan_id || "—";
  const postureScore = data?.meta?.posture_score ?? null;
  const postureGrade = data?.meta?.posture_grade || null;

  const totalFindings = (asset.vulnerabilities || []).length;
  const critCount     = (asset.vulnerabilities || []).filter(v => v.severity?.toLowerCase() === "critical").length;
  const subdomains    = data?.subdomain_summary?.total ?? 0;
  const openPorts     = (asset?.raw_results?.web?.results?.ports || []).length;

  // Dark web / supply chain — only present if deep scan
  const darkWebRaw     = asset?.raw_results?.dark_web;
  const supplyChainRaw = asset?.raw_results?.supply_chain;
  const darkWebTeaser  = darkWebRaw
    ? `${(darkWebRaw.results?.hits || []).length} breach record(s) found`
    : "Dark web breach monitoring requires Deep Scan";
  const supplyChainTeaser = supplyChainRaw
    ? `${(supplyChainRaw.results?.vulnerable_libs || []).length} vulnerable JS libraries detected`
    : "CDN & third-party JS vulnerability analysis requires Deep Scan";

  return (
    <div style={{ minHeight: "100vh", background: "#090b10",
      backgroundImage: "radial-gradient(ellipse at 20% 30%, rgba(0,229,160,0.025) 0%, transparent 50%)",
      fontFamily: "system-ui, sans-serif" }}>

      {/* Top bar */}
      <div style={{ height: 52, background: "rgba(10,12,18,0.98)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 24px", position: "sticky", top: 0, zIndex: 60 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <svg width="20" height="20" viewBox="0 0 24 24">
            <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
            <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
          </svg>
          <div style={{ color: "white", fontFamily: "'Space Mono',monospace", fontSize: 12, fontWeight: 700, letterSpacing: "2px" }}>
            CY<span style={{ color: "#00e5a0" }}>CENTRA</span>
            <span style={{ color: "#00e5a0", fontSize: 8, letterSpacing: "4px", opacity: 0.6, marginLeft: 4 }}>360°</span>
          </div>
          <span style={{ background: "rgba(0,229,160,0.12)", color: "#00e5a0", fontSize: 9, fontFamily: "monospace",
            fontWeight: 700, padding: "2px 8px", borderRadius: 2, letterSpacing: "1px", marginLeft: 8 }}>
            FREE SCAN
          </span>
        </div>
        <button onClick={onRescan}
          style={{ background: "transparent", color: "rgba(255,255,255,0.65)", border: "1px solid rgba(255,255,255,0.12)",
            borderRadius: 4, padding: "5px 14px", fontSize: 11, fontFamily: "monospace", cursor: "pointer" }}>
          ← New Scan
        </button>
      </div>

      <div style={{ padding: "28px 32px", maxWidth: 1200, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white", margin: 0 }}>Free Scan Results</h1>
            <span style={{ background: "rgba(0,229,160,0.1)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.3)",
              fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px", borderRadius: 2 }}>
              STANDARD SCAN
            </span>
          </div>
          <p style={{ color: "rgba(255,255,255,0.62)", fontSize: 13, marginTop: 4, marginBottom: 0 }}>
            {domain} · Scan ID: {scanId}
          </p>
        </div>

        {/* Row 0: Stat strip — 5 cards full width */}
        <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
          {[
            {
              label: "Security Posture",
              value: postureScore !== null ? `${postureScore}` : "—",
              sub: postureGrade ? `Grade ${postureGrade}` : null,
              accent: postureScore !== null
                ? (postureScore >= 70 ? "#00e5a0" : postureScore >= 50 ? "#f5c518" : "#ff3b3b")
                : "#4d9eff",
            },
            { label: "Total Findings", value: totalFindings, accent: "#ff8c00" },
            { label: "Critical",       value: critCount,     accent: critCount > 0 ? "#ff3b3b" : "#00e5a0" },
            { label: "Subdomains",     value: subdomains,    accent: "#4d9eff" },
            { label: "Open Ports",     value: openPorts,     accent: openPorts > 5 ? "#ff8c00" : "#00e5a0" },
          ].map(c => (
            <div key={c.label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
              borderTop: `2px solid ${c.accent}`, padding: "16px 20px", borderRadius: 4, flex: 1, minWidth: 120 }}>
              <div style={{ color: c.accent, fontSize: 28, fontWeight: 800, fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>{c.value}</div>
              {c.sub && <div style={{ color: c.accent, fontSize: 11, fontFamily: "monospace", opacity: 0.8, marginTop: 2 }}>{c.sub}</div>}
              <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 10, letterSpacing: "1.5px", marginTop: 5, textTransform: "uppercase" }}>{c.label}</div>
            </div>
          ))}
        </div>

        {/* Row 1: Risk donut + SSL + Email security */}
        <div style={{ display: "flex", gap: 14, marginBottom: 14, flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 260px", background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
            borderTop: "2px solid #ff3b3b", borderRadius: 5, padding: "18px 22px" }}>
            <WidgetLabel>Overall Risk Distribution</WidgetLabel>
            <RiskDonut assets={assets}/>
          </div>
          <div style={{ flex: "1 1 280px" }}><SslWidget asset={asset}/></div>
          <div style={{ flex: "1 1 280px" }}><EmailSecurityWidget asset={asset}/></div>
        </div>

        {/* Row 2: Web Security + DNS Overview + Cloud Exposure */}
        <div style={{ display: "flex", gap: 14, marginBottom: 14, flexWrap: "wrap" }}>
          <WebSecurityWidget asset={asset}/>
          <DnsWidget asset={asset} data={data}/>
          <CloudWidget asset={asset}/>
        </div>

        {/* Row 3: 3 partial-locked premium widgets */}
        <div style={{ display: "flex", gap: 14, marginBottom: 24, flexWrap: "wrap" }}>
          <PartialLockedWidget title="Dark Web Monitoring" accent="#ff3b3b" teaser={darkWebTeaser}/>
          <PartialLockedWidget title="Supply Chain Risk" accent="#4d9eff" teaser={supplyChainTeaser}/>
          <PartialLockedWidget title="AI Risk Score & Remediation" accent="#b06eff"
            teaser="AI-powered risk scoring and step-by-step remediation requires Deep Scan"/>
        </div>

        {/* Upsell banner */}
        <div style={{ background: "linear-gradient(135deg, rgba(0,229,160,0.06) 0%, rgba(77,158,255,0.04) 100%)",
          border: "1px solid rgba(0,229,160,0.15)", borderRadius: 8, padding: "24px 28px",
          display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 24, flexWrap: "wrap" }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#00e5a0", flexShrink: 0 }}/>
              <div style={{ color: "white", fontSize: 15, fontWeight: 700 }}>Standard Scan Complete</div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, lineHeight: 1.7, maxWidth: 560 }}>
              This Standard Scan report covers your active attack surface across DNS, Web, SSL/Crypto, Email, and Cloud.
            </div>
            <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
              Deep Scan adds: <span style={{ color: "#ff8c00" }}>Dark Web breach intelligence</span>,{" "}
              <span style={{ color: "#4d9eff" }}>Supply Chain JS risk</span>,{" "}
              <span style={{ color: "#b06eff" }}>AI-powered step-by-step remediation</span>,{" "}
              Social Engineering intel, Mobile &amp; API exposure.
            </div>
          </div>
          <a href="https://cycentra.com/#contact" target="_blank" rel="noreferrer"
            style={{ display: "inline-block", background: "#00e5a0", color: "#0d0f14",
              fontFamily: "'Space Mono',monospace", fontWeight: 700, fontSize: 12, letterSpacing: "1px",
              padding: "12px 22px", borderRadius: 4, textDecoration: "none", whiteSpace: "nowrap",
              flexShrink: 0, alignSelf: "center" }}>
            Request Licensed Portal →
          </a>
        </div>

        <div style={{ marginTop: 16, textAlign: "center", color: "rgba(255,255,255,0.42)", fontSize: 11, fontFamily: "monospace" }}>
          Powered by CyCentra 360 · Free scan provided as a courtesy · Results are indicative only
        </div>
      </div>
    </div>
  );
}

// ── GuestScanPage ─────────────────────────────────────────────────────────────

export function GuestScanPage() {
  const [domain,        setDomain]      = useState("");
  const [email,         setEmail]       = useState("");
  const [scanState,     setScanState]   = useState("idle");
  const [progress,      setProgress]    = useState(0);
  const [currentModule, setCurrentModule] = useState("");
  const [elapsed,       setElapsed]     = useState(0);
  const [lastLog,       setLastLog]     = useState("");
  const [scanData,      setScanData]    = useState(null);
  const uidRef   = useRef(genGuestUid());
  const timerRef = useRef(null);
  const pollRef  = useRef(null);

  // Cleanup intervals on unmount (e.g. user navigates away mid-scan)
  useEffect(() => {
    return () => {
      clearInterval(pollRef.current);
      clearInterval(timerRef.current);
    };
  }, []);

  const fmt           = s => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  const circumference = 2 * Math.PI * 54;
  const strokeDash    = circumference - (progress / 100) * circumference;

  // Retry fetching the scan result — the log says "done" before the JSON is flushed to disk
  const fetchResultWithRetry = async (uid, attempts = 8, delayMs = 2500) => {
    for (let i = 0; i < attempts; i++) {
      try {
        const r = await fetch(`${API_BASE}/api/scans/latest?uid=${encodeURIComponent(uid)}`);
        if (r.ok) {
          const raw = await r.json();
          if (raw?.assets || raw?.meta) return raw; // valid result
        }
      } catch {}
      if (i < attempts - 1) await new Promise(res => setTimeout(res, delayMs));
    }
    return null;
  };

  const pollStatus = () => {
    let noProgressCount = 0, pollCount = 0;
    pollRef.current = setInterval(async () => {
      try {
        pollCount++;
        const res = await fetch(`${API_BASE}/api/scan/status`);
        if (!res.ok) return;
        const s = await res.json();

        if (s.progress != null && s.progress > 0) setProgress(s.progress);
        if (s.current_module) setCurrentModule(s.current_module);
        if (s.last_log)       setLastLog(s.last_log);

        const logText = (s.last_log || "").toLowerCase();
        const isDone  = (!s.running && s.progress >= 98) ||
                        logText.includes("portal json saved") ||
                        logText.includes("ndjson report saved") ||
                        logText.includes("all done") ||
                        logText.includes("scan complete");

        if (isDone) {
          clearInterval(pollRef.current); clearInterval(timerRef.current);
          setProgress(100); setCurrentModule("Complete"); setScanState("done");
          setLastLog("Loading your results...");
          // Retry loop: the JSON file may not be flushed yet when the log fires
          const raw = await fetchResultWithRetry(uidRef.current);
          if (raw) {
            setScanData(raw);
          } else {
            setLastLog("Results unavailable — please try scanning again.");
            setScanState("error");
          }
          return;
        }

        if (pollCount > 8 && s.running === false && (s.progress || 0) < 5) {
          noProgressCount++;
          if (noProgressCount >= 4) {
            const raw = await fetchResultWithRetry(uidRef.current, 3, 1500);
            if (raw?.assets?.length) {
              clearInterval(pollRef.current); clearInterval(timerRef.current);
              setProgress(100); setScanState("done"); setScanData(raw);
            } else {
              clearInterval(pollRef.current); clearInterval(timerRef.current);
              setLastLog("Scan engine not responding. Please try again later.");
              setScanState("error");
            }
          }
        } else if (s.running === true || s.progress > 0) {
          noProgressCount = 0;
        }
      } catch {}
    }, 3000);
  };

  const startScan = async () => {
    if (!domain) return;
    setScanState("running"); setProgress(2); setElapsed(0);
    setLastLog("Connecting to scan engine..."); setCurrentModule("Initialising...");

    let secs = 0;
    timerRef.current = setInterval(() => { secs++; setElapsed(secs); }, 1000);

    try {
      const res = await fetch(`${API_BASE}/api/scan/trigger`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain,
          scan_type: "standard",
          notify_email: email,
          include_subdomains: true,
          uid: uidRef.current,
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.status === 503) {
        setLastLog(body.error || "Scan engine not found");
        setCurrentModule("Waiting for scan engine...");
      } else if (!res.ok) {
        setLastLog(`Error: ${body.error || res.statusText}`);
        setScanState("error"); clearInterval(timerRef.current); return;
      } else {
        setLastLog(`Scan started for ${domain} — polling for progress...`);
        setCurrentModule("DNS Reconnaissance"); setProgress(5);
      }
    } catch (e) {
      setLastLog(`Cannot reach backend: ${e.message}`);
      setScanState("error"); clearInterval(timerRef.current); return;
    }
    pollStatus();
  };

  const resetScan = () => {
    clearInterval(timerRef.current); clearInterval(pollRef.current);
    uidRef.current = genGuestUid();
    setScanState("idle"); setProgress(0); setElapsed(0);
    setCurrentModule(""); setLastLog(""); setScanData(null);
  };

  // Show limited dashboard after scan completes
  if (scanState === "done" && scanData) {
    return <GuestDashboard data={scanData} onRescan={resetScan}/>;
  }

  return (
    <div style={{ minHeight: "100vh", background: "#090b10",
      backgroundImage: "radial-gradient(ellipse at 20% 30%, rgba(0,229,160,0.025) 0%, transparent 50%)",
      fontFamily: "system-ui, sans-serif" }}>

      {/* Top bar */}
      <div style={{ height: 52, background: "rgba(10,12,18,0.98)", borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex", alignItems: "center", padding: "0 24px", position: "sticky", top: 0, zIndex: 60 }}>
        <svg width="20" height="20" viewBox="0 0 24 24" style={{ marginRight: 10 }}>
          <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" strokeWidth="1.5"/>
          <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
        </svg>
        <div style={{ color: "white", fontFamily: "'Space Mono',monospace", fontSize: 12, fontWeight: 700, letterSpacing: "2px" }}>
          CY<span style={{ color: "#00e5a0" }}>CENTRA</span>
          <span style={{ color: "#00e5a0", fontSize: 8, letterSpacing: "4px", opacity: 0.6, marginLeft: 4 }}>360°</span>
        </div>
        <span style={{ background: "rgba(0,229,160,0.1)", color: "#00e5a0", fontSize: 9, fontFamily: "monospace",
          fontWeight: 700, padding: "2px 8px", borderRadius: 2, letterSpacing: "1px", marginLeft: 12 }}>
          FREE SCAN
        </span>
      </div>

      {/* Hero */}
      <div style={{ textAlign: "center", padding: "48px 24px 32px" }}>
        <h1 style={{ color: "white", fontSize: 28, fontWeight: 700, margin: "0 0 10px" }}>
          Free Attack Surface Scan
        </h1>
        <p style={{ color: "rgba(255,255,255,0.65)", fontSize: 14, maxWidth: 500, margin: "0 auto" }}>
          Get an instant security overview of any domain — powered by CyCentra's ASM engine.
          No account required.
        </p>
      </div>

      {/* Main content */}
      <div style={{ maxWidth: 960, margin: "0 auto", padding: "0 24px 48px",
        display: "grid", gridTemplateColumns: "1fr 340px", gap: 24, alignItems: "start" }}>

        {/* Form panel */}
        <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 6, padding: 28 }}>

          {/* Domain input */}
          <div style={{ marginBottom: 18 }}>
            <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 8 }}>
              Target Domain *
            </label>
            <input type="text" value={domain} onChange={e => setDomain(e.target.value)}
              placeholder="example.com" disabled={scanState === "running"}
              style={{ width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
                color: "white", padding: "12px 16px", borderRadius: 4, fontSize: 14, fontFamily: "monospace",
                outline: "none", boxSizing: "border-box", opacity: scanState === "running" ? 0.5 : 1 }}/>
          </div>

          {/* Email input */}
          <div style={{ marginBottom: 18 }}>
            <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 8 }}>
              Notify Email <span style={{ color: "rgba(255,255,255,0.2)", fontWeight: 400 }}>(optional)</span>
            </label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)}
              placeholder="you@company.com" disabled={scanState === "running"}
              style={{ width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
                color: "white", padding: "12px 16px", borderRadius: 4, fontSize: 14, fontFamily: "monospace",
                outline: "none", boxSizing: "border-box", opacity: scanState === "running" ? 0.5 : 1 }}/>
          </div>

          {/* Three-tier scan comparison matrix — educational */}
          <div style={{ marginBottom: 22 }}>
            <label style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", display: "block", marginBottom: 10 }}>
              Scan Tiers
            </label>

            {/* Bubble row: Standard (active) + Deep + Passive (licensed) */}
            <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
              {[
                { id: "passive",  label: "Passive",  badge: "OSINT",      color: "#b06eff", active: false },
                { id: "standard", label: "Standard", badge: "THIS SCAN",  color: "#00e5a0", active: true  },
                { id: "deep",     label: "Deep",     badge: "LICENSED",   color: "#ff8c00", active: false },
              ].map(t => (
                <div key={t.id}
                  style={{ flex: 1, padding: "8px 6px", textAlign: "center",
                    border: `1px solid ${t.active ? `${t.color}50` : "rgba(255,255,255,0.06)"}`,
                    borderRadius: 4,
                    background: t.active ? `${t.color}12` : "rgba(255,255,255,0.02)",
                    opacity: t.active ? 1 : 0.5, cursor: t.active ? "default" : "not-allowed" }}>
                  <div style={{ color: t.active ? t.color : "rgba(255,255,255,0.25)", fontSize: 9,
                    fontFamily: "monospace", letterSpacing: "1px", textTransform: "uppercase", marginBottom: 2 }}>{t.badge}</div>
                  <div style={{ color: t.active ? t.color : "rgba(255,255,255,0.4)", fontSize: 13, fontWeight: 700 }}>{t.label}</div>
                </div>
              ))}
            </div>

            {/* Comparison table — reflects actual SCAN_PROFILES in cycentra_scan.py */}
            <div style={{ background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, overflow: "hidden" }}>
              {[
                { feature: "DNS / WHOIS",            passive: true,  standard: true,  deep: true  },
                { feature: "Email Security",          passive: true,  standard: true,  deep: true  },
                { feature: "Dark Web / OSINT",        passive: true,  standard: false, deep: true  },
                { feature: "Subdomain Enumeration",   passive: false, standard: true,  deep: true  },
                { feature: "Web Security Analysis",   passive: false, standard: true,  deep: true  },
                { feature: "SSL / Crypto Audit",      passive: false, standard: true,  deep: true  },
                { feature: "Cloud Exposure",          passive: false, standard: true,  deep: true  },
                { feature: "Supply Chain Risk",       passive: false, standard: false, deep: true  },
                { feature: "Social Engineering",      passive: false, standard: false, deep: true  },
                { feature: "Mobile & API Checks",     passive: false, standard: false, deep: true  },
                { feature: "AI Risk Remediation",     passive: false, standard: false, deep: "step-by-step" },
                { feature: "PDF Technical Report",    passive: false, standard: false, deep: true  },
              ].map((row, i, arr) => (
                <div key={row.feature} style={{ display: "grid", gridTemplateColumns: "1fr 52px 52px 52px",
                  borderBottom: i < arr.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
                  alignItems: "center" }}>
                  <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace", padding: "7px 12px" }}>
                    {row.feature}
                  </div>
                  {[
                    { val: row.passive,  color: "#b06eff" },
                    { val: row.standard, color: "#00e5a0" },
                    { val: row.deep,     color: "#ff8c00" },
                  ].map((cell, ci) => (
                    <div key={ci} style={{ textAlign: "center", fontSize: 11 }}>
                      {cell.val === true  && <span style={{ color: cell.color }}>✓</span>}
                      {cell.val === false && <span style={{ color: "rgba(255,255,255,0.1)" }}>–</span>}
                      {typeof cell.val === "string" && <span style={{ color: cell.color, fontSize: 9, fontFamily: "monospace" }}>{cell.val}</span>}
                    </div>
                  ))}
                </div>
              ))}
            </div>
            <div style={{ marginTop: 8, color: "rgba(255,255,255,0.25)", fontSize: 10, fontFamily: "monospace", textAlign: "right" }}>
              Passive &nbsp;·&nbsp; Standard &nbsp;·&nbsp; Deep
            </div>
          </div>

          {/* Action buttons */}
          {scanState === "idle" && (
            <button onClick={startScan} disabled={!domain}
              style={{ width: "100%", background: domain ? "#00e5a0" : "rgba(0,229,160,0.2)",
                color: domain ? "#0d0f14" : "rgba(0,229,160,0.3)", fontFamily: "'Space Mono',monospace",
                fontWeight: 700, fontSize: 13, letterSpacing: "1px", padding: "14px 24px",
                border: "none", borderRadius: 4, cursor: domain ? "pointer" : "not-allowed", textTransform: "uppercase" }}>
              Launch Free Scan →
            </button>
          )}

          {scanState === "running" && (
            <button disabled style={{ width: "100%", background: "rgba(0,229,160,0.1)", color: "rgba(0,229,160,0.4)",
              fontFamily: "monospace", fontSize: 13, padding: "14px", border: "1px solid rgba(0,229,160,0.2)",
              borderRadius: 4, cursor: "not-allowed" }}>
              Scanning...
            </button>
          )}

          {scanState === "done" && !scanData && (
            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={resetScan} style={{ flex: 1, background: "transparent", color: "rgba(255,255,255,0.5)",
                border: "1px solid rgba(255,255,255,0.15)", borderRadius: 4, padding: "12px", fontFamily: "monospace",
                fontSize: 12, cursor: "pointer" }}>New Scan</button>
              <button
                onClick={async () => {
                  setLastLog("Retrying...");
                  const raw = await fetchResultWithRetry(uidRef.current, 5, 2000);
                  if (raw) setScanData(raw);
                  else setLastLog("Still loading — please wait a moment and try again.");
                }}
                style={{ flex: 1, background: "rgba(0,229,160,0.08)", color: "#00e5a0",
                  border: "1px solid rgba(0,229,160,0.25)", borderRadius: 4, padding: "12px", fontFamily: "monospace",
                  fontSize: 12, cursor: "pointer", fontWeight: 700 }}>
                View Results →
              </button>
            </div>
          )}

          {scanState === "error" && (
            <button onClick={resetScan} style={{ width: "100%", background: "rgba(255,59,59,0.15)", color: "#ff3b3b",
              border: "1px solid rgba(255,59,59,0.3)", borderRadius: 4, padding: "12px",
              fontFamily: "monospace", fontSize: 12, cursor: "pointer" }}>← Try Again</button>
          )}
        </div>

        {/* Progress panel */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 6, padding: 24, textAlign: "center" }}>
            <div style={{ position: "relative", display: "inline-flex", alignItems: "center",
              justifyContent: "center", marginBottom: 16 }}>
              <svg width="128" height="128" style={{ transform: "rotate(-90deg)" }}>
                <circle cx="64" cy="64" r="54" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8"/>
                <circle cx="64" cy="64" r="54" fill="none"
                  stroke={scanState === "error" ? "#ff3b3b" : scanState !== "idle" ? "#00e5a0" : "rgba(0,229,160,0.2)"}
                  strokeWidth="8" strokeLinecap="round"
                  strokeDasharray={circumference} strokeDashoffset={strokeDash}
                  style={{ transition: "stroke-dashoffset 1s ease", filter: scanState !== "idle" ? "drop-shadow(0 0 8px #00e5a060)" : "none" }}/>
              </svg>
              <div style={{ position: "absolute", textAlign: "center" }}>
                <div style={{ color: scanState === "error" ? "#ff3b3b" : "#00e5a0", fontSize: 26,
                  fontFamily: "'Space Mono',monospace", fontWeight: 700 }}>
                  {scanState === "idle" ? "--:--" : fmt(elapsed)}
                </div>
                <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, letterSpacing: "1.5px",
                  fontFamily: "monospace", marginTop: 2 }}>
                  {scanState === "idle" ? "READY" : scanState === "done" ? "COMPLETE" : scanState === "error" ? "FAILED" : "ELAPSED"}
                </div>
              </div>
            </div>

            {scanState === "running" && <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace", marginBottom: 10 }}>{currentModule}...</div>}
            {scanState === "done"    && <div style={{ color: "#00e5a0", fontSize: 14, fontWeight: 700, marginBottom: 6 }}>✓ Scan Complete</div>}
            {scanState === "error"   && <div style={{ color: "#ff3b3b", fontSize: 13, marginBottom: 6 }}>✗ Could not reach backend</div>}

            <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2 }}>
              <div style={{ height: "100%", width: `${progress}%`, background: scanState === "error" ? "#ff3b3b" : "#00e5a0",
                borderRadius: 2, transition: "width 1s ease" }}/>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 5 }}>
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>0%</span>
              <span style={{ color: progress > 0 ? "#00e5a0" : "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>{Math.round(progress)}%</span>
              <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>100%</span>
            </div>

            {lastLog && (
              <div style={{ marginTop: 8, background: "rgba(0,0,0,0.3)", borderRadius: 3, padding: "5px 10px",
                color: scanState === "error" ? "#ff6b6b" : "rgba(0,229,160,0.5)", fontSize: 10,
                fontFamily: "monospace", whiteSpace: "normal", wordBreak: "break-word", lineHeight: 1.5 }}>
                {lastLog}
              </div>
            )}
          </div>

          {/* Module checklist */}
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 6, padding: 18 }}>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, letterSpacing: "1.5px",
              textTransform: "uppercase", fontFamily: "monospace", marginBottom: 10 }}>Scan Modules</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {MODULES.map((m, i) => {
                const modIdx = Math.min(MODULES.length - 1, Math.floor((progress / 100) * MODULES.length));
                const done   = progress > 0 && i < modIdx;
                const active = i === modIdx && scanState === "running";
                return (
                  <div key={m} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 13, height: 13, borderRadius: "50%", flexShrink: 0,
                      background: done ? "#00e5a0" : active ? "rgba(0,229,160,0.2)" : "rgba(255,255,255,0.05)",
                      border: active ? "1.5px solid #00e5a0" : "none",
                      display: "flex", alignItems: "center", justifyContent: "center" }}>
                      {done   && <span style={{ fontSize: 7, color: "#0d0f14", fontWeight: 900 }}>✓</span>}
                      {active && <div style={{ width: 5, height: 5, borderRadius: "50%", background: "#00e5a0" }}/>}
                    </div>
                    <span style={{ fontSize: 11, fontFamily: "monospace",
                      color: done ? "rgba(255,255,255,0.7)" : active ? "#00e5a0" : "rgba(255,255,255,0.25)" }}>
                      {m}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Trust badge */}
          <div style={{ background: "rgba(0,229,160,0.04)", border: "1px solid rgba(0,229,160,0.12)",
            borderRadius: 6, padding: "14px 18px", textAlign: "center" }}>
            <div style={{ color: "rgba(0,229,160,0.7)", fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>
              ✓ No registration required
            </div>
            <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, lineHeight: 1.5 }}>
              Scan results are ephemeral and not retained.<br/>
              For continuous monitoring and Deep Scan reports, use the Licensed Portal.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
