/**
 * src/pages/guest-scan/GuestScanPage.jsx
 * =========================================
 * Standalone guest scan page — accessible at /guest-scan without login.
 * Offers Standard scan only (Deep/Passive are visible but greyed out).
 * After completion, shows a limited free-tier dashboard.
 *
 * Design language matches DashboardPage.jsx exactly:
 *   - ASMPostureWidget half-circle gauge (same SVG math)
 *   - StatCard border/font/size spec
 *   - ASMWidget wrapper (same background/border/borderTop/padding)
 *   - ESecRow (same pass/fail colors and icon logic)
 *   - statRow helper (same flex justify-between row format)
 *   - RiskDonut (same SVG segment math and color array)
 *   - CertTimeline (same bar visual)
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
  "Dark Web Monitoring", "Supply Chain Analysis",
  "Social Engineering Intel", "Mobile & API Checks",
  "Generating Report",
];

const RISK_CONFIG = {
  critical: { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)", label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "rgba(255,140,0,0.12)",  label: "HIGH"     },
  medium:   { color: "#f5c518", bg: "rgba(245,197,24,0.12)", label: "MEDIUM"   },
  low:      { color: "#00e5a0", bg: "rgba(0,229,160,0.12)",  label: "LOW"      },
};

// ── GuestDashboard design primitives (mirrors DashboardPage.jsx exactly) ──────

// Shared check/cross icon pair — same as DashboardPage ESecRow icons
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

// ESecRow — exact match of DashboardPage ESecRow (pass=null = neutral/—)
function ESecRow({ label, value, pass }) {
  const color = pass === null ? "rgba(255,255,255,0.35)" : pass ? "#00e5a0" : "#ff3b3b";
  const icon  = pass === null ? "—" : pass ? "✓" : "✗";
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>{label}</span>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, maxWidth: 170,
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value || "—"}</span>
        <span style={{ color, fontWeight: 700, fontSize: 12 }}>{icon}</span>
      </div>
    </div>
  );
}

// ASMWidget wrapper — exact match of DashboardPage ASMWidget
function ASMWidget({ title, children, accent = "#00e5a0", badge }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`, borderRadius: 5, padding: "18px 22px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px",
          textTransform: "uppercase", fontFamily: "monospace" }}>{title}</div>
        {badge != null && (
          <span style={{ background: `${accent}18`, color: accent, fontSize: 10, fontFamily: "monospace",
            padding: "2px 8px", borderRadius: 2, fontWeight: 700 }}>{badge}</span>
        )}
      </div>
      {children}
    </div>
  );
}

// statRow helper — exact match of DashboardPage statRow
function StatRows({ items }) {
  return items.map(r => (
    <div key={r.label} style={{ display: "flex", justifyContent: "space-between",
      padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 12 }}>{r.label}</span>
      <span style={{ color: r.color, fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{r.val}</span>
    </div>
  ));
}

// StatCard — exact match of DashboardPage StatCard
function StatCard({ label, value, accent, sub }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${accent}`, padding: "18px 22px", borderRadius: 4,
      flex: 1, minWidth: 130 }}>
      <div style={{ color: accent, fontSize: 30, fontWeight: 800,
        fontFamily: "'Space Mono',monospace", lineHeight: 1 }}>{value}</div>
      <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px",
        marginTop: 5, textTransform: "uppercase" }}>{label}</div>
      {sub && <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 10, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// WidgetNote — dim italic footer inside a widget
function WidgetNote({ children }) {
  return (
    <div style={{ marginTop: 10, padding: "5px 8px", background: "rgba(255,255,255,0.04)",
      borderRadius: 3, color: "rgba(255,255,255,0.4)", fontSize: 10, fontFamily: "monospace",
      fontStyle: "italic", lineHeight: 1.4 }}>
      {children}
    </div>
  );
}

// StatusRow — used inside SSL/Web widgets for simple pass/fail rows
function StatusRow({ label, ok, okText = "Pass", failText = "Issue",
  okColor = "#00e5a0", failColor = "#ff8c00", detail = null }) {
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

// ── ASMPostureWidget — identical half-circle gauge SVG as DashboardPage ────────
function ASMPostureWidget({ score, grade, domain, lastScan }) {
  const gradeColor = {
    "A+": "#00e5a0", A: "#00e5a0", B: "#4d9eff",
    C: "#f5c518", D: "#ff8c00", F: "#ff3b3b",
  }[grade] || "#00e5a0";

  // Gauge: 0-100 mapped to 180° arc (half-circle) — same math as DashboardPage
  const radius = 52, cx = 70, cy = 70;
  const arcLen = Math.PI * radius;
  const filled = score != null ? (score / 100) * arcLen : 0;

  return (
    <div style={{
      background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.07)",
      borderTop: `2px solid ${gradeColor}`, borderRadius: 6, padding: "18px 24px",
      display: "flex", alignItems: "center", gap: 28, flexWrap: "wrap",
      marginBottom: 14,
    }}>
      {/* Half-circle gauge */}
      <div style={{ flexShrink: 0, position: "relative" }}>
        <svg width="140" height="80" style={{ overflow: "visible" }}>
          {/* Track */}
          <path d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
            fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" strokeLinecap="round"/>
          {/* Fill */}
          <path d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
            fill="none" stroke={gradeColor} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${filled} ${arcLen}`}
            style={{ transition: "stroke-dasharray 1.2s ease", filter: `drop-shadow(0 0 6px ${gradeColor}60)` }}/>
          {/* Score label */}
          <text x={cx} y={cy - 6} textAnchor="middle" fill="white" fontSize="28" fontWeight="800"
            fontFamily="'Space Mono',monospace">
            {score != null ? score : "—"}
          </text>
          <text x={cx} y={cy + 10} textAnchor="middle" fill="rgba(255,255,255,0.3)" fontSize="9"
            fontFamily="monospace" letterSpacing="1">
            POSTURE SCORE
          </text>
          {/* Grade pill */}
          <rect x={cx - 16} y={cy + 18} width="32" height="18" rx="3"
            fill={`${gradeColor}20`} stroke={`${gradeColor}50`} strokeWidth="1"/>
          <text x={cx} y={cy + 31} textAnchor="middle" fill={gradeColor} fontSize="11"
            fontWeight="700" fontFamily="'Space Mono',monospace">
            {grade || "—"}
          </text>
        </svg>
      </div>

      {/* Labels */}
      <div style={{ flex: 1, minWidth: 160 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
          <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, letterSpacing: "1.5px",
            textTransform: "uppercase", fontFamily: "monospace" }}>
            Overall ASM Security Posture
          </span>
          <span style={{ background: "rgba(0,229,160,0.15)", color: "#00e5a0",
            border: "1px solid rgba(0,229,160,0.4)", fontSize: 9, fontFamily: "monospace",
            fontWeight: 700, padding: "1px 6px", borderRadius: 2, letterSpacing: "1px" }}>
            STANDARD SCAN
          </span>
        </div>
        <div style={{ color: gradeColor, fontSize: 32, fontWeight: 800,
          fontFamily: "'Space Mono',monospace", lineHeight: 1, marginBottom: 4 }}>
          Grade {grade || "—"}
        </div>
        {domain && (
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11,
            fontFamily: "monospace", marginBottom: 2 }}>{domain}</div>
        )}
        {lastScan && (
          <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 10, fontFamily: "monospace" }}>
            Last scan: {lastScan}
          </div>
        )}
      </div>

      {/* Score band guide — same as DashboardPage */}
      <div style={{ display: "flex", flexDirection: "column", gap: 4, flexShrink: 0 }}>
        {[
          ["A+", ">= 90", "#00e5a0"],
          ["A",  ">= 80", "#00e5a0"],
          ["B",  ">= 70", "#4d9eff"],
          ["C",  ">= 55", "#f5c518"],
          ["D",  ">= 35", "#ff8c00"],
          ["F",  "< 35",  "#ff3b3b"],
        ].map(([g, range, c]) => (
          <div key={g} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ color: grade === g ? c : "rgba(255,255,255,0.15)", fontSize: 10,
              fontFamily: "monospace", fontWeight: grade === g ? 700 : 400, width: 16 }}>{g}</span>
            <span style={{ color: grade === g ? "rgba(255,255,255,0.5)" : "rgba(255,255,255,0.12)",
              fontSize: 9, fontFamily: "monospace" }}>{range}</span>
          </div>
        ))}
      </div>
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

// CertTimeline — matches DashboardPage CertTimeline visual (mini progress bar)
function CertTimeline({ daysLeft, domain: certDomain }) {
  if (daysLeft === null) return null;
  const color = daysLeft < 0 ? "#ff3b3b" : daysLeft < 30 ? "#ff8c00" : daysLeft < 90 ? "#f5c518" : "#00e5a0";
  const pct   = Math.min(100, Math.max(0, (daysLeft / 365) * 100));
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ color: "rgba(255,255,255,0.6)", fontSize: 11, fontFamily: "monospace",
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 160 }}>
          {certDomain}
        </span>
        <span style={{ color, fontSize: 10, fontFamily: "monospace", fontWeight: 700, flexShrink: 0 }}>
          {daysLeft < 0 ? "EXPIRED" : `${daysLeft}d`}
        </span>
      </div>
      <div style={{ height: 3, background: "rgba(255,255,255,0.07)", borderRadius: 2 }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 2,
          boxShadow: `0 0 4px ${color}60` }}/>
      </div>
    </div>
  );
}

function SslWidget({ asset }) {
  const ssl        = asset?.raw_results?.crypto?.results?.ssl || {};
  const cert       = ssl.cert_info || {};
  // After the crypto_checks.py bug fix, ssl_enabled reflects TLS handshake success.
  // Belt-and-suspenders: also check protocol field for backward compat with pre-fix JSONs.
  const _proto     = cert.protocol || ssl.protocol || null;
  const sslEnabled = ssl.ssl_enabled !== false || (_proto && _proto !== "Unknown");
  const daysLeft   = cert.days_to_expiry ?? null;
  const protocol   = _proto;
  const cipher     = cert.cipher || null;
  const ocsp       = cert.ocsp_stapling ?? false;
  const chainValid = cert.chain_valid !== false;
  const issues     = ssl.issues || [];
  const pqc        = asset?.raw_results?.crypto?.results?.pqc?.server_pqc ?? false;
  const domain     = asset?.host || "";

  const expiredCount  = daysLeft !== null && daysLeft < 0 ? 1 : 0;
  const expiring30    = daysLeft !== null && daysLeft >= 0 && daysLeft <= 30 ? 1 : 0;
  const protocolColor = protocol
    ? (protocol.includes("1.3") ? "#00e5a0" : protocol.includes("1.2") ? "#f5c518" : "#ff3b3b")
    : "rgba(255,255,255,0.3)";

  return (
    <ASMWidget title="2. SSL / Crypto Health" accent="#f5c518"
      badge={expiredCount > 0 ? `${expiredCount} EXPIRED` : null}>
      <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
        <StatRows items={[
          { label: "Certs Monitored", val: 1,             color: "rgba(255,255,255,0.7)" },
          { label: "Expired",         val: expiredCount,  color: expiredCount > 0 ? "#ff3b3b" : "#00e5a0" },
          { label: "Expiring <30d",   val: expiring30,    color: expiring30 > 0 ? "#ff8c00" : "#00e5a0" },
          ...(protocol ? [{ label: "Protocol", val: protocol, color: protocolColor }] : []),
          { label: "PQC Hybrid TLS",  val: pqc ? "Ready" : "Not detected",
            color: pqc ? "#00e5a0" : "rgba(255,255,255,0.3)" },
          ...(issues.length > 0 ? [{ label: "Active Issues", val: issues.length, color: "#ff8c00" }] : []),
        ]}/>
      </div>
      <CertTimeline daysLeft={daysLeft} domain={domain}/>
      {cipher && (
        <div style={{ marginTop: 6, padding: "4px 7px", background: "rgba(245,197,24,0.07)", borderRadius: 3 }}>
          <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace" }}>{cipher}</span>
        </div>
      )}
      <WidgetNote>Full cipher suite audit and certificate chain depth available in Deep Scan.</WidgetNote>
    </ASMWidget>
  );
}

function EmailSecurityWidget({ asset }) {
  const email       = asset?.raw_results?.email_sec?.results || {};
  const spf         = email.spf || {};
  const dmarc       = email.dmarc || {};
  const dkimList    = Array.isArray(email.dkim) ? email.dkim : [];
  const dnssec      = email.dnssec || {};
  const eliteScore  = email.elite_score ?? null;
  const eliteStatus = email.elite_status || "basic";
  // BIMI: may be present in elite_checks or directly on email results
  const bimi        = email.elite_checks?.bimi || email.bimi || {};

  const dmarcPolicy  = dmarc.policy || (dmarc.present ? "present" : null);
  const dmarcPass    = dmarcPolicy === "reject";
  const dmarcLabel   = dmarcPolicy || "Missing";
  const validDkim    = dkimList.filter(d => d.valid !== false).length;
  const dkimVal      = dkimList.length > 0
    ? `${validDkim} selector(s)`
    : "Not found";

  const eliteColor = eliteStatus === "elite" ? "#00e5a0"
    : eliteStatus === "robust" ? "#4d9eff"
    : "#f5c518";

  return (
    <ASMWidget title="3. Email Security" accent="#b06eff">
      {/* Use ESecRow — exact match of DashboardPage ESecRow component */}
      <ESecRow label="SPF"    value={spf.record?.slice(0, 40) || null} pass={!!spf.present}/>
      <ESecRow label="DKIM"   value={dkimVal}   pass={dkimList.length > 0 && validDkim > 0}/>
      <ESecRow label="DMARC"  value={dmarcLabel} pass={dmarcPass}/>
      <ESecRow label="DNSSEC" value={dnssec.enabled ? "Enabled" : "Disabled"}
        pass={!!dnssec.enabled}/>
      {bimi.status && (
        <ESecRow label="BIMI" value={bimi.status} pass={bimi.status === "pass"}/>
      )}
      {eliteScore !== null && (
        <div style={{ marginTop: 6, display: "flex", justifyContent: "space-between", padding: "5px 0" }}>
          <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace" }}>Elite Score</span>
          <span style={{ color: eliteColor, fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>
            {eliteScore}/100 · {eliteStatus}
          </span>
        </div>
      )}
      <WidgetNote>MTA-STS, TLS-RPT, and anti-spoofing correlation available in Deep Scan.</WidgetNote>
    </ASMWidget>
  );
}

const PORT_LABELS = { 21: "FTP", 22: "SSH", 25: "SMTP", 80: "HTTP", 443: "HTTPS",
  3306: "MySQL", 3389: "RDP", 5432: "PgSQL", 6379: "Redis", 8080: "Alt-HTTP",
  8443: "Alt-HTTPS", 27017: "MongoDB" };

function WebSecurityWidget({ asset }) {
  const web         = asset?.raw_results?.web?.results || {};
  const ports       = web.ports || [];
  const exposed     = web.exposed_paths || [];
  const jsSecrets   = web.js_secrets || [];
  const http        = web.http_analysis || {};
  const headers     = http.http_headers || [];
  const redirects   = http.redirects_to_https ?? null;
  const fingerprints = web.fingerprints || {};
  const vulns       = asset?.vulnerabilities || [];

  // Top 4 web/vuln_scanner findings — same filter logic as DashboardPage webVulns
  const webVulns = vulns.filter(v => {
    const m = (v.module || "").toLowerCase();
    return m === "web" || m === "crypto" || m === "web_analysis" ||
           m === "vuln_scanner" || m === "nuclei" ||
           v.source === "port_banner" || v.source === "exposed_path" || v.source === "js_secret";
  });

  const critPaths = exposed.filter(p =>
    (p.severity || "").toString().toLowerCase() === "critical"
  ).length;
  const banner = Object.values(fingerprints)[0]?.banner || null;

  return (
    <ASMWidget title="4. Web Security" accent="#ff8c00">
      {/* Port badges — same style as DashboardPage PORT EXPOSURE section */}
      {ports.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: "rgba(255,255,255,0.25)", fontSize: 9, fontFamily: "monospace",
            letterSpacing: "1px", marginBottom: 5 }}>OPEN PORTS</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
            {ports.slice(0, 6).map(p => (
              <span key={p} style={{
                background: (p === 22 || p === 3389 || p === 3306)
                  ? "rgba(255,59,59,0.12)" : "rgba(255,140,0,0.1)",
                color: (p === 22 || p === 3389 || p === 3306)
                  ? "#ff8c00" : "rgba(255,255,255,0.55)",
                border: `1px solid rgba(255,140,0,0.2)`,
                fontSize: 10, fontFamily: "monospace", padding: "2px 7px", borderRadius: 3 }}>
                {p}{PORT_LABELS[p] ? ` (${PORT_LABELS[p]})` : ""}
              </span>
            ))}
            {ports.length > 6 && (
              <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>
                +{ports.length - 6} more
              </span>
            )}
          </div>
        </div>
      )}
      {/* statRow-style rows */}
      <StatRows items={[
        ...(redirects !== null ? [{ label: "HTTPS Redirect", val: redirects ? "Yes" : "No",
          color: redirects ? "#00e5a0" : "#ff3b3b" }] : []),
        ...(exposed.length > 0 ? [{ label: "Exposed Paths", val: `${exposed.length}${critPaths > 0 ? ` (${critPaths} critical)` : ""}`,
          color: critPaths > 0 ? "#ff3b3b" : "#ff8c00" }] : []),
        ...(jsSecrets.length > 0 ? [{ label: "JS Secrets", val: `${jsSecrets.length} found`, color: "#ff3b3b" }] : []),
        ...(headers.length > 0 ? [{ label: "Missing Headers", val: headers.length, color: "#f5c518" }] : []),
      ]}/>
      {/* Top 4 web findings — same colored-dot list as DashboardPage */}
      {webVulns.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 5, marginTop: 8 }}>
          {webVulns.slice(0, 4).map((v, i) => {
            const cfg = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.low;
            return (
              <div key={i} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%",
                  background: cfg.color, flexShrink: 0 }}/>
                <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 11,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {v.vulnerability}
                </span>
                {v.cvss && (
                  <span style={{ color: "rgba(255,140,0,0.5)", fontSize: 9,
                    fontFamily: "monospace", flexShrink: 0 }}>{v.cvss}</span>
                )}
              </div>
            );
          })}
        </div>
      )}
      {banner && (
        <div style={{ marginTop: 6, padding: "3px 7px", background: "rgba(0,0,0,0.2)", borderRadius: 3 }}>
          <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9, fontFamily: "monospace" }}>{banner}</span>
        </div>
      )}
      <WidgetNote>Full CORS audit, WAF detection, and API endpoint mapping in Deep Scan.</WidgetNote>
    </ASMWidget>
  );
}

function DnsWidget({ asset, data }) {
  const dns     = asset?.raw_results?.dns?.results || {};
  const records = dns.records || {};
  const typos   = dns.typos || {};
  const subSum  = data?.subdomain_summary || {};
  // DNSSEC from email_sec module (same underlying DNS check)
  const dnssec  = asset?.raw_results?.email_sec?.results?.dnssec || {};

  const aCount   = (records.A || records.a || []).length;
  const mxCount  = (records.MX || records.mx || []).length;
  const nsCount  = (records.NS || records.ns || []).length;
  const typoReg  = Array.isArray(typos.registered)
    ? typos.registered.length
    : (typeof typos.registered === "number" ? typos.registered : 0);

  // Up to 3 A-record IPs to display below the stat rows
  const aRecords = records.A || records.a || [];

  return (
    <ASMWidget title="5. DNS Overview" accent="#4d9eff">
      <StatRows items={[
        ...(aCount > 0   ? [{ label: "A Records",  val: aCount,  color: "#4d9eff" }] : []),
        ...(mxCount > 0  ? [{ label: "MX Records", val: mxCount, color: "#4d9eff" }] : []),
        ...(nsCount > 0  ? [{ label: "NS Records", val: nsCount, color: "#4d9eff" }] : []),
        { label: "DNSSEC", val: dnssec.enabled ? "Enabled" : "Disabled",
          color: dnssec.enabled ? "#00e5a0" : "#f5c518" },
        ...(typoReg > 0 ? [{ label: "Typosquats Registered", val: `${typoReg} domains`,
          color: "#ff8c00" }] : []),
      ]}/>
      {subSum.total != null && (
        <div style={{ marginTop: 8, padding: "6px 8px", background: "rgba(77,158,255,0.06)", borderRadius: 3 }}>
          <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 9, fontFamily: "monospace", marginBottom: 4 }}>
            SUBDOMAIN SUMMARY
          </div>
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
      {aRecords.length > 0 && (
        <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 3 }}>
          {aRecords.slice(0, 3).map((ip, i) => (
            <div key={i} style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <span style={{ color: "rgba(77,158,255,0.5)", fontSize: 9, fontFamily: "monospace" }}>A</span>
              <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>{ip}</span>
            </div>
          ))}
        </div>
      )}
      <WidgetNote>Typosquatting monitoring and DNS change alerts available in Deep Scan.</WidgetNote>
    </ASMWidget>
  );
}

function CloudWidget({ asset }) {
  const cloud      = asset?.raw_results?.cloud?.results || {};
  const providers  = cloud.providers || [];
  const buckets    = cloud.buckets || [];
  const k8s        = cloud.k8s_exposed ?? false;
  const pubBuckets = buckets.filter(b => b.public || b.listable).length;
  const privBuckets = buckets.length - pubBuckets;

  // Provider color map — matches DashboardPage CloudWidget exactly
  const PROVIDER_COLORS = {
    AWS: "#ff9900", Azure: "#0072c6", GCP: "#4285f4", Cloudflare: "#f48120",
  };

  if (providers.length === 0 && buckets.length === 0 && !k8s) {
    return (
      <ASMWidget title="6. Cloud Exposure" accent="#00e5a0">
        <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace",
          display: "flex", alignItems: "center", gap: 6 }}>
          <CheckIcon color="#00e5a0"/> No cloud infrastructure detected
        </div>
        <WidgetNote>Kubernetes cluster exposure and metadata endpoint probing in Deep Scan.</WidgetNote>
      </ASMWidget>
    );
  }

  return (
    <ASMWidget title="6. Cloud Exposure" accent="#00e5a0">
      {providers.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 10 }}>
          {providers.map(p => (
            <span key={p} style={{
              background: "rgba(255,255,255,0.06)",
              color: PROVIDER_COLORS[p] || "rgba(255,255,255,0.5)",
              fontSize: 10, fontFamily: "monospace", fontWeight: 700,
              padding: "2px 8px", borderRadius: 3,
              border: `1px solid ${(PROVIDER_COLORS[p] || "#fff")}30` }}>
              {p}
            </span>
          ))}
        </div>
      )}
      <StatRows items={[
        ...(buckets.length > 0 ? [
          { label: "Public Buckets",  val: pubBuckets,  color: pubBuckets > 0 ? "#ff3b3b" : "#00e5a0" },
          { label: "Private Buckets", val: privBuckets, color: "#00e5a0" },
        ] : []),
        { label: "K8s API Exposed", val: k8s ? "Exposed" : "No", color: k8s ? "#ff3b3b" : "#00e5a0" },
      ]}/>
      <WidgetNote>Kubernetes cluster exposure and metadata endpoint probing in Deep Scan.</WidgetNote>
    </ASMWidget>
  );
}

// ── Partial-locked premium widgets (deep-only) ─────────────────────────────────
// Uses the same ASMWidget wrapper with a semi-transparent overlay.

function PartialLockedWidget({ title, accent = "#00e5a0", teaser }) {
  return (
    <div style={{ flex: 1, minWidth: 280 }}>
      <ASMWidget title={title} accent={`${accent}40`}>
        {/* Teaser: live data line or "no data" message */}
        <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 12,
          fontFamily: "monospace", marginBottom: 10 }}>
          {teaser}
        </div>
        {/* Blurred content preview */}
        <div style={{ marginBottom: 10 }}>
          {[75, 55, 65].map((w, i) => (
            <div key={i} style={{ height: 10, width: `${w}%`,
              background: `${accent}18`, borderRadius: 3, marginBottom: 7,
              filter: "blur(2px)" }}/>
          ))}
        </div>
        {/* Lock overlay */}
        <div style={{ display: "inline-flex", alignItems: "center", gap: 6,
          background: "rgba(255,255,255,0.04)",
          border: "1px solid rgba(255,255,255,0.08)", borderRadius: 3, padding: "5px 10px" }}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none"
            stroke="rgba(255,255,255,0.25)" strokeWidth="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 10, fontFamily: "monospace" }}>
            Full analysis available in Deep Scan · Request Licensed Portal →
          </span>
        </div>
      </ASMWidget>
    </div>
  );
}

function DarkWebWidget({ asset }) {
  const dw     = asset?.raw_results?.dark_web?.results || {};
  const hibp   = Array.isArray(dw.hibp)   ? dw.hibp   : [];
  const pastes = Array.isArray(dw.pastes) ? dw.pastes : [];
  const hits   = hibp.length;
  const breachColor = hits > 0 ? "#ff3b3b" : "#00e5a0";

  return (
    <ASMWidget title="7. Dark Web Monitoring" accent="#ff3b3b" badge={hits > 0 ? `${hits} BREACH${hits > 1 ? "ES" : ""}` : null}>
      <StatRows items={[
        { label: "Breach Records",  val: hits,          color: breachColor },
        { label: "Paste Mentions",  val: pastes.length, color: pastes.length > 0 ? "#ff8c00" : "#00e5a0" },
      ]}/>
      {hits === 0 && pastes.length === 0 && (
        <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace",
          display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
          <CheckIcon color="#00e5a0"/> No breach data found
        </div>
      )}
      {hits > 0 && (
        <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
          {hibp.slice(0, 3).map((b, i) => (
            <div key={i} style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#ff3b3b", flexShrink: 0 }}/>
              <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, fontFamily: "monospace" }}>
                {typeof b === "string" ? b : (b.Name || b.name || "Breach record").slice(0, 40)}
              </span>
            </div>
          ))}
        </div>
      )}
      <WidgetNote>Breach records via CyTIM dark web feeds. Full credential monitoring in Deep Scan.</WidgetNote>
    </ASMWidget>
  );
}

function SupplyChainWidget({ asset }) {
  const sc       = asset?.raw_results?.supply_chain?.results || {};
  const scripts  = Array.isArray(sc.scripts) ? sc.scripts : [];
  const count    = sc.count ?? scripts.length;
  const risks    = scripts.filter(s => s.risk === "high" || s.risk_level === "high").length;
  const noSri    = scripts.filter(s => !s.integrity && !s.sri).length;
  const riskColor = risks > 0 ? "#ff3b3b" : count > 0 ? "#ff8c00" : "#00e5a0";

  return (
    <ASMWidget title="8. Supply Chain Risk" accent="#4d9eff" badge={risks > 0 ? `${risks} HIGH RISK` : null}>
      <StatRows items={[
        { label: "Third-party Scripts", val: count,  color: count > 0 ? "#ff8c00" : "#00e5a0" },
        { label: "High Risk Scripts",   val: risks,  color: riskColor },
        { label: "No SRI Integrity",    val: noSri,  color: noSri > 0 ? "#f5c518" : "#00e5a0" },
      ]}/>
      {count === 0 && (
        <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace",
          display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
          <CheckIcon color="#00e5a0"/> No external scripts detected
        </div>
      )}
      <WidgetNote>CDN integrity and Magecart-pattern detection. Step-by-step remediation in Deep Scan.</WidgetNote>
    </ASMWidget>
  );
}

function SocialEngWidget({ asset }) {
  const se      = asset?.raw_results?.social_eng?.results || {};
  const typos   = Array.isArray(se.typosquats)       ? se.typosquats       : [];
  const emails  = Array.isArray(se.emails)            ? se.emails            : [];
  const phishing = Array.isArray(se.phishing_domains) ? se.phishing_domains : [];
  const regTypos = typos.filter(t => t.registered).length;

  return (
    <ASMWidget title="9. Social Engineering" accent="#b06eff">
      <StatRows items={[
        { label: "Typosquat Domains",     val: typos.length,   color: typos.length > 0 ? "#ff8c00" : "#00e5a0" },
        { label: "Registered Typosquats", val: regTypos,       color: regTypos > 0 ? "#ff3b3b" : "#00e5a0" },
        { label: "Exposed Emails",        val: emails.length,  color: emails.length > 0 ? "#f5c518" : "#00e5a0" },
        ...(phishing.length > 0 ? [{ label: "Phishing Domains", val: phishing.length, color: "#ff3b3b" }] : []),
      ]}/>
      {typos.length === 0 && emails.length === 0 && (
        <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace",
          display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
          <CheckIcon color="#00e5a0"/> No social engineering indicators found
        </div>
      )}
    </ASMWidget>
  );
}

function MobileApiWidget({ asset }) {
  const ma         = asset?.raw_results?.mobile_api?.results || {};
  const endpoints  = Array.isArray(ma.api_findings) ? ma.api_findings
                   : Array.isArray(ma.endpoints)    ? ma.endpoints : [];
  const deeplinks  = Array.isArray(ma.deeplinks)   ? ma.deeplinks  : [];
  const appLinks   = Array.isArray(ma.app_links)   ? ma.app_links  : [];
  const exposed    = endpoints.filter(e => e.risk === "high" || e.severity === "high").length;

  return (
    <ASMWidget title="10. Mobile & API Checks" accent="#f5c518">
      <StatRows items={[
        { label: "API Endpoints Found", val: endpoints.length, color: endpoints.length > 0 ? "#f5c518" : "#00e5a0" },
        { label: "High-Risk Exposed",   val: exposed,          color: exposed > 0 ? "#ff3b3b" : "#00e5a0" },
        { label: "Deep Links",          val: deeplinks.length, color: deeplinks.length > 0 ? "#4d9eff" : "#00e5a0" },
        { label: "App Links",           val: appLinks.length,  color: appLinks.length > 0 ? "#4d9eff" : "#00e5a0" },
      ]}/>
      {endpoints.length === 0 && deeplinks.length === 0 && (
        <div style={{ color: "#00e5a0", fontSize: 12, fontFamily: "monospace",
          display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
          <CheckIcon color="#00e5a0"/> No mobile/API exposure detected
        </div>
      )}
    </ASMWidget>
  );
}

function GuestDashboard({ data, onRescan }) {
  const assets   = data?.assets || [];
  const asset    = assets[0] || {};
  const domain   = data?.meta?.domain || "—";
  const scanId   = data?.meta?.scan_id || "—";
  const lastScan = data?.meta?.last_scan
    ? new Date(data.meta.last_scan).toLocaleString() : null;
  const postureScore = data?.meta?.posture_score ?? null;
  const postureGrade = data?.meta?.posture_grade || null;

  const vulns         = asset.vulnerabilities || [];
  const totalFindings = vulns.length;
  const critCount     = vulns.filter(v => v.severity?.toLowerCase() === "critical").length;
  const subdomains    = data?.subdomain_summary?.total ?? 0;
  const openPorts     = (asset?.raw_results?.web?.results?.ports || []).length;

  // Grade letter for stat card — same color logic as DashboardPage grade display
  const gradeAccent = postureScore !== null
    ? (postureScore >= 80 ? "#00e5a0" : postureScore >= 70 ? "#4d9eff" : postureScore >= 55 ? "#f5c518" : postureScore >= 35 ? "#ff8c00" : "#ff3b3b")
    : "#4d9eff";


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
          New Scan
        </button>
      </div>

      <div style={{ padding: "28px 32px", maxWidth: 1200, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ marginBottom: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "white", margin: 0 }}>
              Attack Surface Overview
            </h1>
            <span style={{ background: "rgba(0,229,160,0.15)", color: "#00e5a0",
              border: "1px solid rgba(0,229,160,0.4)",
              fontSize: 10, fontFamily: "monospace", fontWeight: 700, padding: "2px 8px",
              borderRadius: 2, letterSpacing: "1px" }}>
              STANDARD SCAN
            </span>
          </div>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 4, marginBottom: 0 }}>
            {domain} · Scan ID: {scanId}
          </p>
        </div>

        {/* ── Stat cards — matches DashboardPage StatCard exactly ── */}
        <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
          <StatCard
            label="Security Grade"
            value={postureGrade || "—"}
            accent={gradeAccent}
            sub={postureScore !== null ? `Score ${postureScore}/100` : null}
          />
          <StatCard
            label="Total Findings"
            value={totalFindings}
            accent="#ff8c00"
            sub="Across all modules"
          />
          <StatCard
            label="Critical"
            value={critCount}
            accent={critCount > 0 ? "#ff3b3b" : "#00e5a0"}
          />
          <StatCard
            label="Open Ports"
            value={openPorts}
            accent={openPorts > 5 ? "#ff8c00" : "#00e5a0"}
            sub="Detected open"
          />
          <StatCard
            label="Subdomains"
            value={subdomains}
            accent="#4d9eff"
            sub={data?.subdomain_summary?.live != null ? `${data.subdomain_summary.live} live` : null}
          />
        </div>

        {/* ── Posture Gauge — identical half-circle SVG as DashboardPage ASMPostureWidget ── */}
        <ASMPostureWidget
          score={postureScore}
          grade={postureGrade}
          domain={domain}
          lastScan={lastScan}
        />

        {/* ── Row 1: Risk Donut + SSL/Crypto + Email Security ── */}
        <div style={{ display: "flex", gap: 14, marginBottom: 14, flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 260px" }}>
            <ASMWidget title="1. Overall Risk Overview" accent="#ff3b3b">
              <RiskDonut assets={assets}/>
            </ASMWidget>
          </div>
          <div style={{ flex: "1 1 280px" }}><SslWidget asset={asset}/></div>
          <div style={{ flex: "1 1 280px" }}><EmailSecurityWidget asset={asset}/></div>
        </div>

        {/* ── Row 2: Web Security + DNS Overview + Cloud Exposure ── */}
        <div style={{ display: "flex", gap: 14, marginBottom: 14, flexWrap: "wrap" }}>
          <WebSecurityWidget asset={asset}/>
          <DnsWidget asset={asset} data={data}/>
          <CloudWidget asset={asset}/>
        </div>

        {/* ── Row 3: Dark Web + Supply Chain (now standard) + AI locked ── */}
        <div style={{ display: "flex", gap: 14, marginBottom: 14, flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 280px" }}><DarkWebWidget asset={asset}/></div>
          <div style={{ flex: "1 1 280px" }}><SupplyChainWidget asset={asset}/></div>
          <PartialLockedWidget title="AI Risk Score & Remediation" accent="#b06eff"
            teaser="AI-powered scoring requires Deep Scan"/>
        </div>

        {/* ── Row 4: Social Engineering + Mobile & API (now standard) ── */}
        <div style={{ display: "flex", gap: 14, marginBottom: 24, flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 280px" }}><SocialEngWidget asset={asset}/></div>
          <div style={{ flex: "1 1 280px" }}><MobileApiWidget asset={asset}/></div>
        </div>

        {/* ── Upsell banner ── */}
        <div style={{ background: "linear-gradient(135deg, rgba(0,229,160,0.06) 0%, rgba(77,158,255,0.04) 100%)",
          border: "1px solid rgba(0,229,160,0.15)", borderRadius: 8, padding: "24px 28px",
          display: "flex", alignItems: "flex-start", justifyContent: "space-between",
          gap: 24, flexWrap: "wrap" }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#00e5a0", flexShrink: 0 }}/>
              <div style={{ color: "white", fontSize: 15, fontWeight: 700 }}>
                Standard Scan Complete — {domain}
              </div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, lineHeight: 1.7, maxWidth: 560 }}>
              This report covers your full external attack surface across 12 detection modules.
            </div>
            <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
              <span style={{ color: "#b06eff" }}>Deep Scan</span> elevates every finding with{" "}
              <span style={{ color: "#ff8c00" }}>AI-powered root-cause analysis</span>{" "}
              and step-by-step technical remediation — plus a full PDF Technical Report.
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
                { feature: "Dark Web / OSINT",        passive: true,  standard: true,  deep: true  },
                { feature: "Subdomain Enumeration",   passive: false, standard: true,  deep: true  },
                { feature: "Web Security Analysis",   passive: false, standard: true,  deep: true  },
                { feature: "SSL / Crypto Audit",      passive: false, standard: true,  deep: true  },
                { feature: "Cloud Exposure",          passive: false, standard: true,  deep: true  },
                { feature: "Supply Chain Risk",       passive: false, standard: true,  deep: true  },
                { feature: "Social Engineering",      passive: false, standard: true,  deep: true  },
                { feature: "Mobile & API Checks",     passive: false, standard: true,  deep: true  },
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
