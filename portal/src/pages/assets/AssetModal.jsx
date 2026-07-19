/**
 * src/pages/assets/AssetModal.jsx
 *
 * v2: Full expansion — adds WHOIS, DNS records, SSL detail, exposed paths list,
 *     cloud buckets/K8s, OSINT/MISP, social engineering, mobile/API, supply chain
 *     risks, and IP enrichment (ASN, country, city) to the asset detail panel.
 */

import { useState } from "react";
import { RISK_CONFIG, STATUS_CONFIG } from '../../core/constants.js';

function Badge({ risk }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.low;
  return <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`, fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", fontFamily: "monospace", padding: "2px 8px", borderRadius: "2px" }}>{cfg.label}</span>;
}

function SevBadge({ severity }) {
  const cfg = RISK_CONFIG[severity?.toLowerCase()] || RISK_CONFIG.low;
  return <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}35`, fontSize: "9px", fontWeight: 700, fontFamily: "monospace", padding: "1px 5px", borderRadius: "2px", whiteSpace: "nowrap" }}>{severity}</span>;
}

function formatDate(dateStr) {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function Section({ title, children, accent = "#00e5a0" }) {
  return (
    <div style={{ marginBottom: 22 }}>
      <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 10, letterSpacing: "1px", textTransform: "uppercase", marginBottom: 10, fontFamily: "monospace", borderBottom: `1px solid ${accent}20`, paddingBottom: 4 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function KV({ label, value, mono = true }) {
  if (!value && value !== 0) return null;
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <span style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace" }}>{label}</span>
      <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 12, fontFamily: mono ? "monospace" : "inherit", maxWidth: 220, textAlign: "right", wordBreak: "break-word" }}>{value}</span>
    </div>
  );
}

export function AssetModal({ asset, onClose, onStatusChange }) {
  const [activeSection, setActiveSection] = useState("overview");
  if (!asset) return null;
  const cfg  = RISK_CONFIG[asset.risk] || RISK_CONFIG.low;
  const days = asset.cert_days ?? null;
  const isPrimary = asset.tags?.includes("primary");
  const isSubdomain = asset.type === "Subdomain";
  const isIP = asset.tags?.includes("ip");

  const sections = [
    { id: "overview",   label: "Overview" },
    ...(isPrimary ? [
      { id: "vulns",    label: `Vulns (${asset.vulnerabilities?.length || 0})` },
      { id: "dns",      label: "DNS" },
      { id: "ssl",      label: "SSL" },
      { id: "cloud",    label: "Cloud" },
      { id: "whois",    label: "WHOIS" },
      { id: "osint",    label: "OSINT" },
      { id: "social",   label: "Social Eng" },
      { id: "mobile",   label: "Mobile/API" },
      { id: "supply",   label: "Supply Chain" },
    ] : []),
    ...(isSubdomain ? [{ id: "vulns", label: `Vulns (${asset.vulnerabilities?.length || 0})` }] : []),
  ].filter(Boolean);

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", zIndex: 100, display: "flex", justifyContent: "flex-end" }} onClick={onClose}>
      <div style={{ width: "min(660px,96vw)", height: "100vh", background: "#0d1117", borderLeft: "1px solid rgba(255,255,255,0.08)", overflowY: "auto", display: "flex", flexDirection: "column" }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ padding: "18px 22px", borderBottom: "1px solid rgba(255,255,255,0.07)", display: "flex", justifyContent: "space-between", alignItems: "flex-start", position: "sticky", top: 0, background: "#0d1117", zIndex: 10 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
              <Badge risk={asset.risk}/>
              <span style={{ color: "white", fontFamily: "monospace", fontSize: 14, fontWeight: 700 }}>{asset.host}</span>
              {asset.is_new && <span style={{ background: "rgba(255,140,0,0.15)", color: "#ff8c00", fontSize: 9, fontFamily: "monospace", fontWeight: 700, padding: "1px 5px", borderRadius: 2 }}>NEW</span>}
            </div>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>{asset.type} · {asset.ip}</div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.65)", cursor: "pointer", fontSize: 20, padding: 4 }}>×</button>
        </div>

        {/* Section tabs */}
        {sections.length > 1 && (
          <div style={{ display: "flex", gap: 2, padding: "8px 22px", borderBottom: "1px solid rgba(255,255,255,0.06)", overflowX: "auto", flexShrink: 0, scrollbarWidth: "none" }}>
            {sections.map(s => (
              <button key={s.id} onClick={() => setActiveSection(s.id)}
                style={{ background: activeSection === s.id ? "rgba(0,229,160,0.1)" : "transparent",
                  border: activeSection === s.id ? "1px solid rgba(0,229,160,0.3)" : "1px solid transparent",
                  color: activeSection === s.id ? "#00e5a0" : "rgba(255,255,255,0.35)",
                  padding: "4px 10px", borderRadius: 3, fontSize: 10, fontFamily: "monospace", cursor: "pointer", whiteSpace: "nowrap" }}>
                {s.label}
              </button>
            ))}
          </div>
        )}

        <div style={{ padding: "18px 22px", flex: 1 }}>

          {/* ── OVERVIEW ───────────────────────────────────────────────────── */}
          {activeSection === "overview" && (
            <div>
              {/* Cert banner */}
              {days !== null && (
                <div style={{ background: days < 0 ? "rgba(255,59,59,0.08)" : days < 30 ? "rgba(255,140,0,0.08)" : "rgba(0,229,160,0.08)", border: `1px solid ${days < 0 ? "rgba(255,59,59,0.3)" : days < 30 ? "rgba(255,140,0,0.3)" : "rgba(0,229,160,0.2)"}`, borderRadius: 4, padding: "10px 14px", marginBottom: 18 }}>
                  <div style={{ color: days < 0 ? "#ff3b3b" : days < 30 ? "#ff8c00" : "#00e5a0", fontSize: 12, fontWeight: 600 }}>
                    SSL Certificate: {days < 0 ? "EXPIRED" : `${days} days remaining`}
                  </div>
                  {asset.cert_expiry && <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11, marginTop: 2 }}>Expires {formatDate(asset.cert_expiry)}</div>}
                </div>
              )}

              {/* Summary */}
              {asset.summary && (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, lineHeight: 1.6, marginBottom: 18 }}>{asset.summary}</div>
              )}

              {/* Core fields */}
              <Section title="Asset Details">
                <KV label="Host"       value={asset.host}/>
                <KV label="IP"         value={asset.ip}/>
                <KV label="Type"       value={asset.type}/>
                <KV label="Risk Score" value={asset.risk_score != null ? `${asset.risk_score}/10` : null}/>
                <KV label="Owner"      value={asset.owner}/>
                <KV label="First Seen" value={asset.first_seen}/>
                <KV label="Last Seen"  value={asset.last_seen}/>
                {asset.registrar && <KV label="Registrar" value={asset.registrar}/>}
              </Section>

              {/* Ports */}
              {asset.ports?.length > 0 && (
                <Section title="Open Ports">
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {asset.ports.map(p => (
                      <span key={p} style={{ background: "rgba(0,229,160,0.08)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.2)", fontSize: 11, fontFamily: "monospace", padding: "3px 9px", borderRadius: 2 }}>:{p}</span>
                    ))}
                  </div>
                </Section>
              )}

              {/* Exposed paths */}
              {asset.exposed_paths?.length > 0 && (
                <Section title={`Exposed Paths (${asset.exposed_paths.length})`} accent="#f5c518">
                  <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                    {asset.exposed_paths.slice(0, 15).map((p, i) => (
                      <div key={i} style={{ color: "#f5c518", fontSize: 11, fontFamily: "monospace", padding: "3px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                        {typeof p === "string" ? p : (p.path || JSON.stringify(p))}
                      </div>
                    ))}
                    {asset.exposed_paths.length > 15 && (
                      <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>+{asset.exposed_paths.length - 15} more paths</div>
                    )}
                  </div>
                </Section>
              )}

              {/* IP enrichment (for IP sub-assets) */}
              {isIP && (
                <Section title="IP Intelligence" accent="#4d9eff">
                  <KV label="ASN"           value={asset.asn}/>
                  <KV label="Organization"  value={asset.owner}/>
                  <KV label="Country"       value={asset.country}/>
                  <KV label="City"          value={asset.city}/>
                  <KV label="Hostname"      value={asset.hostname}/>
                  <KV label="Cloud Provider"value={asset.cloud_provider}/>
                  <KV label="Reverse DNS"   value={asset.reverse_dns}/>
                </Section>
              )}

              {/* Subdomain intel */}
              {isSubdomain && (
                <Section title="Subdomain Intel">
                  <KV label="DNS Status" value={asset.live === true ? "● LIVE" : asset.live === false ? "○ Not Resolving" : "—"} />
                  <KV label="Change"     value={asset.change}/>
                  <KV label="CNAME"      value={asset.cname}/>
                  {asset.resolved_ips?.length > 1 && (
                    <div style={{ padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                      <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 12, fontFamily: "monospace", marginBottom: 4 }}>Resolved IPs</div>
                      {asset.resolved_ips.map((ip, i) => (
                        <div key={i} style={{ color: "rgba(255,255,255,0.6)", fontSize: 11, fontFamily: "monospace", padding: "2px 0" }}>{ip}</div>
                      ))}
                    </div>
                  )}
                  {asset.sources?.length > 0 && (
                    <div style={{ padding: "8px 0" }}>
                      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace", marginBottom: 6 }}>DISCOVERED VIA</div>
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                        {asset.sources.map(s => (
                          <span key={s} style={{ background: "rgba(0,229,160,0.06)", color: "#00e5a0", border: "1px solid rgba(0,229,160,0.2)", fontSize: 10, fontFamily: "monospace", padding: "2px 7px", borderRadius: 2 }}>{s}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </Section>
              )}

              {/* Quick vuln summary for non-primary */}
              {!isPrimary && asset.vulnerabilities?.length > 0 && (
                <Section title={`Vulnerabilities (${asset.vulnerabilities.length})`} accent="#ff3b3b">
                  <VulnList vulns={asset.vulnerabilities}/>
                </Section>
              )}

              {/* Status update */}
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── VULNERABILITIES ───────────────────────────────────────────── */}
          {activeSection === "vulns" && (
            <div>
              <Section title={`Vulnerabilities (${asset.vulnerabilities?.length || 0})`} accent="#ff3b3b">
                {asset.vulnerabilities?.length > 0
                  ? <VulnList vulns={asset.vulnerabilities} expanded/>
                  : <div style={{ color: "rgba(0,229,160,0.5)", fontSize: 12, fontFamily: "monospace" }}>✓ No vulnerabilities</div>
                }
              </Section>
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── DNS ───────────────────────────────────────────────────────── */}
          {activeSection === "dns" && (
            <div>
              {/* DNS Records */}
              {asset.dns_records && Object.keys(asset.dns_records).length > 0 && (
                <Section title="DNS Records" accent="#4d9eff">
                  {Object.entries(asset.dns_records).map(([type, records]) => (
                    Array.isArray(records) && records.length > 0 && (
                      <div key={type} style={{ marginBottom: 10 }}>
                        <div style={{ color: "#4d9eff", fontSize: 10, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>{type}</div>
                        {records.slice(0, 6).map((r, i) => (
                          <div key={i} style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", padding: "2px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                            {typeof r === "string" ? r : (r.value || r.address || JSON.stringify(r))}
                          </div>
                        ))}
                      </div>
                    )
                  ))}
                </Section>
              )}

              {/* IP enrichment */}
              {asset.dns_ips?.length > 0 && (
                <Section title="IP Addresses" accent="#4d9eff">
                  {asset.dns_ips.map((ipObj, i) => (
                    <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 3, padding: "8px 12px", marginBottom: 6 }}>
                      <div style={{ color: "#4d9eff", fontSize: 12, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>{ipObj.ip}</div>
                      {ipObj.org     && <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11 }}>Org: {ipObj.org}</div>}
                      {ipObj.asn     && <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11 }}>ASN: {ipObj.asn}</div>}
                      {ipObj.country && <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11 }}>Country: {ipObj.country} {ipObj.city ? `· ${ipObj.city}` : ""}</div>}
                      {ipObj.cloud_provider && <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11 }}>Cloud: {ipObj.cloud_provider}</div>}
                      {ipObj.reverse_dns && <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11 }}>rDNS: {ipObj.reverse_dns}</div>}
                    </div>
                  ))}
                </Section>
              )}

              {/* DNS takeovers */}
              {asset.dns_takeovers?.length > 0 && (
                <Section title="Potential Takeovers" accent="#ff3b3b">
                  {asset.dns_takeovers.map((t, i) => (
                    <div key={i} style={{ color: "#ff3b3b", fontSize: 11, fontFamily: "monospace", padding: "3px 0" }}>{typeof t === "string" ? t : JSON.stringify(t)}</div>
                  ))}
                </Section>
              )}

              {/* Unregistered typosquats */}
              {asset.dns_unregistered?.length > 0 && (
                <Section title={`Unregistered Typosquats (${asset.dns_unregistered.length})`} accent="#ff8c00">
                  <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                    {asset.dns_unregistered.slice(0, 10).map((t, i) => (
                      <div key={i} style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace", padding: "2px 0" }}>{t}</div>
                    ))}
                    {asset.dns_unregistered.length > 10 && <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>+{asset.dns_unregistered.length - 10} more</div>}
                  </div>
                </Section>
              )}

              {!asset.dns_records && !asset.dns_ips?.length && (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>No DNS data available for this asset.</div>
              )}
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── SSL ───────────────────────────────────────────────────────── */}
          {activeSection === "ssl" && (
            <div>
              {asset.ssl_detail ? (
                <Section title="SSL Certificate Details" accent="#f5c518">
                  <KV label="Days to Expiry"   value={asset.cert_days != null ? (asset.cert_days < 0 ? "EXPIRED" : `${asset.cert_days} days`) : null}/>
                  <KV label="Expires"          value={asset.cert_expiry ? formatDate(asset.cert_expiry) : null}/>
                  <KV label="Issuer"           value={asset.ssl_detail.issuer}/>
                  <KV label="Subject"          value={asset.ssl_detail.subject}/>
                  <KV label="Protocol"         value={asset.ssl_detail.protocol}/>
                  <KV label="Cipher Suite"     value={asset.ssl_detail.cipher}/>
                  <KV label="Chain Valid"      value={asset.ssl_detail.chain_valid != null ? (asset.ssl_detail.chain_valid ? "✓ Valid" : "✗ Invalid") : null}/>
                  <KV label="SAN Valid"        value={asset.ssl_detail.san_valid  != null ? (asset.ssl_detail.san_valid  ? "✓ Valid" : "✗ Invalid") : null}/>
                  <KV label="OCSP Stapling"    value={asset.ssl_detail.ocsp_stapling != null ? (asset.ssl_detail.ocsp_stapling ? "✓ Enabled" : "✗ Disabled") : null}/>
                  <KV label="Heartbleed Risk"  value={asset.ssl_detail.heartbleed_risk != null ? (asset.ssl_detail.heartbleed_risk ? "⚠ Yes" : "✓ No") : null}/>
                  <KV label="Compression"      value={asset.ssl_detail.compression_enabled != null ? (asset.ssl_detail.compression_enabled ? "⚠ Enabled" : "✓ Disabled") : null}/>
                  {asset.ssl_detail.san_details?.length > 0 && (
                    <div style={{ padding: "5px 0" }}>
                      <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, fontFamily: "monospace", marginBottom: 4 }}>SANs</div>
                      {asset.ssl_detail.san_details.slice(0, 8).map((s, i) => (
                        <div key={i} style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontFamily: "monospace", padding: "2px 0" }}>{s}</div>
                      ))}
                    </div>
                  )}
                </Section>
              ) : (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>No SSL certificate data available.</div>
              )}

              {/* PQC */}
              {asset.pqc_data && (
                <Section title="Post-Quantum Cryptography" accent="#b06eff">
                  <KV label="PQC Ready"  value={asset.pqc_data.supported ? "✓ Yes" : "✗ No"}/>
                  <KV label="Algorithm"  value={asset.pqc_data.algorithm}/>
                  <KV label="Status"     value={asset.pqc_data.status}/>
                </Section>
              )}

              {/* HTTP analysis */}
              {asset.http_analysis && (
                <Section title="HTTP Security Headers" accent="#ff8c00">
                  <KV label="HTTPS Redirect"  value={asset.http_analysis.redirects_to_https != null ? (asset.http_analysis.redirects_to_https ? "✓ Yes" : "✗ No") : null}/>
                  <KV label="CORS Issues"     value={asset.http_analysis.cors_issues?.length > 0 ? asset.http_analysis.cors_issues.join(", ") : (asset.http_analysis.cors_issues != null ? "None detected" : null)}/>
                  {asset.http_analysis.http_headers && Object.keys(asset.http_analysis.http_headers).length > 0 && (
                    <div style={{ padding: "5px 0" }}>
                      <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, fontFamily: "monospace", marginBottom: 4 }}>Missing Security Headers</div>
                      {Object.entries(asset.http_analysis.http_headers).slice(0, 8).map(([h, v]) => (
                        <div key={h} style={{ color: "rgba(255,59,59,0.6)", fontSize: 11, fontFamily: "monospace", padding: "2px 0" }}>✗ {h}</div>
                      ))}
                    </div>
                  )}
                </Section>
              )}

              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── CLOUD ─────────────────────────────────────────────────────── */}
          {activeSection === "cloud" && (
            <div>
              {asset.cloud_data ? (
                <>
                  <Section title="Cloud Infrastructure" accent="#4d9eff">
                    {asset.cloud_data.providers?.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, fontFamily: "monospace", marginBottom: 4 }}>Providers</div>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {asset.cloud_data.providers.map((p, i) => (
                            <span key={i} style={{ background: "rgba(77,158,255,0.1)", color: "#4d9eff", border: "1px solid rgba(77,158,255,0.25)", fontSize: 11, fontFamily: "monospace", padding: "2px 8px", borderRadius: 2 }}>{p}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {asset.cloud_data.k8s_exposed && (
                      <div style={{ background: "rgba(255,59,59,0.08)", border: "1px solid rgba(255,59,59,0.25)", borderRadius: 3, padding: "8px 10px", marginBottom: 10 }}>
                        <div style={{ color: "#ff3b3b", fontSize: 12, fontWeight: 700 }}>⚠ Kubernetes API Exposed</div>
                        {typeof asset.cloud_data.k8s_exposed === "object" && (
                          <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, marginTop: 4 }}>
                            {JSON.stringify(asset.cloud_data.k8s_exposed)}
                          </div>
                        )}
                      </div>
                    )}
                  </Section>
                  {/* Bucket list */}
                  {asset.cloud_data.buckets?.length > 0 && (
                    <Section title={`Storage Buckets (${asset.cloud_data.buckets.length})`} accent="#ff8c00">
                      {asset.cloud_data.buckets.map((b, i) => (
                        <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 3, padding: "8px 12px", marginBottom: 6 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 12, fontFamily: "monospace" }}>{b.name || b.url || b}</span>
                            {b.public != null && (
                              <span style={{ color: b.public ? "#ff3b3b" : "#00e5a0", fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>
                                {b.public ? "PUBLIC" : "PRIVATE"}
                              </span>
                            )}
                          </div>
                          {b.provider && <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>{b.provider}</div>}
                          {b.issues?.length > 0 && <div style={{ color: "#ff8c00", fontSize: 11, marginTop: 4 }}>{b.issues.join(", ")}</div>}
                        </div>
                      ))}
                    </Section>
                  )}
                </>
              ) : (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>No cloud infrastructure data available.</div>
              )}
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── WHOIS ─────────────────────────────────────────────────────── */}
          {activeSection === "whois" && (
            <div>
              {asset.whois_full ? (
                <Section title="WHOIS Information" accent="#4d9eff">
                  <KV label="Domain"           value={asset.whois_full.domain_name}/>
                  <KV label="Registrar"        value={asset.whois_full.registrar}/>
                  <KV label="Registrar URL"    value={asset.whois_full.registrar_url}/>
                  <KV label="Created"          value={asset.whois_full.creation_date ? formatDate(asset.whois_full.creation_date) : null}/>
                  <KV label="Updated"          value={asset.whois_full.updated_date  ? formatDate(asset.whois_full.updated_date)  : null}/>
                  <KV label="Expires"          value={asset.whois_full.expiration_date ? formatDate(asset.whois_full.expiration_date) : null}/>
                  <KV label="Status"           value={Array.isArray(asset.whois_full.status) ? asset.whois_full.status.join(", ") : asset.whois_full.status}/>
                  <KV label="DNSSEC"           value={asset.whois_full.dnssec}/>
                  {asset.whois_full.name_servers?.length > 0 && (
                    <div style={{ padding: "5px 0" }}>
                      <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 11, fontFamily: "monospace", marginBottom: 4 }}>Name Servers</div>
                      {asset.whois_full.name_servers.map((ns, i) => (
                        <div key={i} style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", padding: "2px 0" }}>{ns}</div>
                      ))}
                    </div>
                  )}
                </Section>
              ) : (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>No WHOIS data available.</div>
              )}
              {asset.whois_history?.length > 0 && (
                <Section title="WHOIS History" accent="#4d9eff">
                  {asset.whois_history.slice(0, 5).map((h, i) => (
                    <div key={i} style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, fontFamily: "monospace", padding: "3px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                      {typeof h === "string" ? h : JSON.stringify(h)}
                    </div>
                  ))}
                </Section>
              )}
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── OSINT / MISP ──────────────────────────────────────────────── */}
          {activeSection === "osint" && (
            <div>
              {/* MISP threat intel */}
              {asset.osint_data?.misp?.length > 0 && (
                <Section title={`MISP Threat Intel (${asset.osint_data.misp.length} hits)`} accent="#b06eff">
                  {asset.osint_data.misp.slice(0, 10).map((hit, i) => (
                    <div key={i} style={{ background: "rgba(176,110,255,0.06)", border: "1px solid rgba(176,110,255,0.15)", borderRadius: 3, padding: "8px 12px", marginBottom: 6 }}>
                      <div style={{ color: "#b06eff", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{hit.type || hit.category || "Indicator"}</div>
                      <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, marginTop: 2 }}>{hit.value || hit.attribute || JSON.stringify(hit)}</div>
                      {hit.event_name && <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, marginTop: 2 }}>Event: {hit.event_name}</div>}
                    </div>
                  ))}
                </Section>
              )}

              {/* Shodan CVE findings */}
              {asset.osint_data?.cves?.length > 0 && (
                <Section title={`Shodan CVE Findings (${asset.osint_data.cves.length})`} accent="#ff3b3b">
                  {asset.osint_data.cves.slice(0, 8).map((c, i) => {
                    const cfg2 = RISK_CONFIG[c.severity?.toLowerCase()] || RISK_CONFIG.low;
                    return (
                      <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${cfg2.color}15`, borderLeft: `2px solid ${cfg2.color}`, padding: "8px 12px", borderRadius: 2, marginBottom: 5 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ color: "white", fontSize: 12, fontWeight: 600 }}>{c.vulnerability || c.cve_id}</span>
                          <SevBadge severity={c.severity}/>
                        </div>
                        {c.description && <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, marginTop: 4 }}>{c.description}</div>}
                        {c.cvss && <span style={{ color: "rgba(255,140,0,0.7)", fontSize: 10, fontFamily: "monospace" }}>CVSS {c.cvss}</span>}
                      </div>
                    );
                  })}
                </Section>
              )}

              {/* Shodan raw matches */}
              {asset.osint_data?.shodan?.length > 0 && (
                <Section title={`Shodan Results (${asset.osint_data.shodan.length})`} accent="#4d9eff">
                  {asset.osint_data.shodan.slice(0, 5).map((s, i) => (
                    <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 3, padding: "8px 12px", marginBottom: 5 }}>
                      {s.port   && <div style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace" }}>Port: {s.port}</div>}
                      {s.product && <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 11 }}>{s.product} {s.version || ""}</div>}
                      {s.hostnames?.length > 0 && <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace" }}>{s.hostnames.join(", ")}</div>}
                    </div>
                  ))}
                </Section>
              )}

              {!asset.osint_data?.misp?.length && !asset.osint_data?.cves?.length && !asset.osint_data?.shodan?.length && (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>No OSINT data available. Run a scan with OSINT module enabled.</div>
              )}
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── SOCIAL ENGINEERING ────────────────────────────────────────── */}
          {activeSection === "social" && (
            <div>
              {asset.social_eng ? (
                <>
                  {asset.social_eng.risk_assessment && (
                    <div style={{ background: "rgba(255,140,0,0.08)", border: "1px solid rgba(255,140,0,0.2)", borderRadius: 4, padding: "10px 14px", marginBottom: 16 }}>
                      <div style={{ color: asset.social_eng.risk_assessment.level === "High" ? "#ff3b3b" : asset.social_eng.risk_assessment.level === "Medium" ? "#ff8c00" : "#00e5a0", fontSize: 13, fontWeight: 700 }}>
                        Social Engineering Risk: {asset.social_eng.risk_assessment.level}
                      </div>
                      {asset.social_eng.risk_assessment.score != null && (
                        <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11, marginTop: 2 }}>Score: {asset.social_eng.risk_assessment.score}/10</div>
                      )}
                      {asset.social_eng.risk_assessment.reasons?.length > 0 && (
                        <div style={{ marginTop: 6 }}>
                          {asset.social_eng.risk_assessment.reasons.map((r, i) => (
                            <div key={i} style={{ color: "rgba(255,255,255,0.5)", fontSize: 11, marginTop: 2 }}>• {r}</div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  {asset.social_eng.emails?.length > 0 && (
                    <Section title={`Exposed Employees (${asset.social_eng.emails.length})`} accent="#ff8c00">
                      {asset.social_eng.emails.map((e, i) => (
                        <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 3, padding: "8px 12px", marginBottom: 5 }}>
                          <div style={{ color: "#ff8c00", fontSize: 12, fontFamily: "monospace" }}>{e.email || e}</div>
                          {e.first_name && <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 11 }}>{e.first_name} {e.last_name || ""} {e.position ? `· ${e.position}` : ""}</div>}
                          {e.confidence && <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>Confidence: {e.confidence}</div>}
                          {e.source && <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace" }}>Source: {e.source}</div>}
                        </div>
                      ))}
                    </Section>
                  )}
                  {asset.social_eng.linkedin?.length > 0 && (
                    <Section title={`LinkedIn Profiles (${asset.social_eng.linkedin.length})`} accent="#4d9eff">
                      {asset.social_eng.linkedin.map((p, i) => (
                        <div key={i} style={{ padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                          <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 12 }}>{p.name || p.url}</div>
                          {p.url && p.name && <div style={{ color: "rgba(77,158,255,0.5)", fontSize: 10, fontFamily: "monospace" }}>{p.url}</div>}
                        </div>
                      ))}
                    </Section>
                  )}
                  {asset.social_eng.email_patterns?.length > 0 && (
                    <Section title="Email Patterns" accent="#b06eff">
                      <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                        {asset.social_eng.email_patterns.map((p, i) => (
                          <span key={i} style={{ background: "rgba(176,110,255,0.08)", color: "#b06eff", border: "1px solid rgba(176,110,255,0.2)", fontSize: 10, fontFamily: "monospace", padding: "2px 7px", borderRadius: 2 }}>{p}</span>
                        ))}
                      </div>
                    </Section>
                  )}
                </>
              ) : (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>No social engineering data. Run a deep scan to enable this module.</div>
              )}
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── MOBILE / API ──────────────────────────────────────────────── */}
          {activeSection === "mobile" && (
            <div>
              {asset.mobile_api ? (
                <>
                  {asset.mobile_api.api_findings?.length > 0 && (
                    <Section title={`API Security Findings (${asset.mobile_api.api_findings.length})`} accent="#ff8c00">
                      {asset.mobile_api.api_findings.map((f, i) => (
                        <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 3, padding: "8px 12px", marginBottom: 6 }}>
                          <div style={{ color: "rgba(255,255,255,0.7)", fontSize: 11, fontFamily: "monospace" }}>{f.url || f.endpoint}</div>
                          {f.status && <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 10, marginTop: 2 }}>Status: {f.status}</div>}
                          {f.cors_wildcard && <div style={{ color: "#ff3b3b", fontSize: 11, marginTop: 3 }}>⚠ CORS wildcard origin</div>}
                          {f.rate_limited === false && <div style={{ color: "#ff8c00", fontSize: 11, marginTop: 2 }}>⚠ No rate limiting detected</div>}
                          {f.issues?.length > 0 && (
                            <div style={{ marginTop: 4 }}>
                              {f.issues.map((issue, j) => <div key={j} style={{ color: "#f5c518", fontSize: 10 }}>• {issue}</div>)}
                            </div>
                          )}
                        </div>
                      ))}
                    </Section>
                  )}
                  {asset.mobile_api.apk_secrets?.length > 0 && (
                    <Section title={`APK Secrets (${asset.mobile_api.apk_secrets.length})`} accent="#ff3b3b">
                      {asset.mobile_api.apk_secrets.map((s, i) => (
                        <div key={i} style={{ background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 3, padding: "6px 10px", marginBottom: 4, fontSize: 11, fontFamily: "monospace", color: "#ff6464", wordBreak: "break-all" }}>
                          {typeof s === "string" ? s : JSON.stringify(s)}
                        </div>
                      ))}
                    </Section>
                  )}
                  {(asset.mobile_api.app_links?.apk_links?.length > 0 || asset.mobile_api.app_links?.ipa_links?.length > 0) && (
                    <Section title="App Store Links" accent="#4d9eff">
                      {[...(asset.mobile_api.app_links.apk_links || []), ...(asset.mobile_api.app_links.ipa_links || []), ...(asset.mobile_api.app_links.store_links || [])].map((l, i) => (
                        <div key={i} style={{ color: "#4d9eff", fontSize: 11, fontFamily: "monospace", padding: "3px 0" }}>{l}</div>
                      ))}
                    </Section>
                  )}
                  {asset.mobile_api.deeplinks?.length > 0 && (
                    <Section title="Deep Links" accent="#b06eff">
                      {asset.mobile_api.deeplinks.map((d, i) => (
                        <div key={i} style={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", padding: "2px 0" }}>{typeof d === "string" ? d : JSON.stringify(d)}</div>
                      ))}
                    </Section>
                  )}
                  {!asset.mobile_api.api_findings?.length && !asset.mobile_api.apk_secrets?.length && (
                    <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>No mobile/API findings for this asset.</div>
                  )}
                </>
              ) : (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>No mobile/API data. Run a deep scan to enable this module.</div>
              )}
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

          {/* ── SUPPLY CHAIN ──────────────────────────────────────────────── */}
          {activeSection === "supply" && (
            <div>
              {asset.supply_chain?.risks?.length > 0 ? (
                <Section title={`Supply Chain Risks (${asset.supply_chain.risks.length})`} accent="#f5c518">
                  {asset.supply_chain.risks.map((r, i) => {
                    const sc = RISK_CONFIG[r.severity?.toLowerCase()] || RISK_CONFIG.low;
                    return (
                      <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${sc.color}15`, borderLeft: `2px solid ${sc.color}`, padding: "10px 12px", borderRadius: 2, marginBottom: 6 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                          <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 12, fontFamily: "monospace", fontWeight: 600 }}>{r.library || r.url?.split("/").pop() || "Unknown library"}</span>
                          <SevBadge severity={r.severity}/>
                        </div>
                        {r.url && <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 10, fontFamily: "monospace", marginBottom: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.url}</div>}
                        {r.osv_id && <div style={{ color: "rgba(245,197,24,0.6)", fontSize: 10, fontFamily: "monospace" }}>OSV: {r.osv_id}</div>}
                        {r.cve_ids?.length > 0 && <div style={{ color: "rgba(255,59,59,0.6)", fontSize: 10, fontFamily: "monospace" }}>CVEs: {r.cve_ids.join(", ")}</div>}
                        {r.cvss && <div style={{ color: "rgba(255,140,0,0.6)", fontSize: 10, fontFamily: "monospace" }}>CVSS: {r.cvss}</div>}
                        {r.reason && <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 11, marginTop: 4 }}>{r.reason}</div>}
                      </div>
                    );
                  })}
                </Section>
              ) : (
                <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontFamily: "monospace" }}>
                  {asset.supply_chain ? "No supply chain risks found." : "No supply chain data. Run a scan with this module enabled."}
                </div>
              )}
              <StatusButtons asset={asset} onStatusChange={onStatusChange} onClose={onClose}/>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

// ── Shared sub-components ─────────────────────────────────────────────────────

function VulnList({ vulns, expanded = false }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {vulns.map((v, i) => {
        const vc = RISK_CONFIG[v.severity?.toLowerCase()] || RISK_CONFIG.low;
        return (
          <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${vc.color}20`, borderLeft: `2px solid ${vc.color}`, padding: "8px 12px", borderRadius: 2 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ color: "white", fontSize: 12, fontWeight: 600, flex: 1, marginRight: 8 }}>{typeof v.vulnerability === "string" ? v.vulnerability : String(v.vulnerability || "—")}</span>
              <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                {v.cvss && <span style={{ color: "rgba(255,140,0,0.7)", fontSize: 9, fontFamily: "monospace" }}>CVSS {v.cvss}</span>}
                <span style={{ background: vc.bg, color: vc.color, border: `1px solid ${vc.color}35`, fontSize: "9px", fontWeight: 700, fontFamily: "monospace", padding: "1px 5px", borderRadius: "2px" }}>{v.severity}</span>
              </div>
            </div>
            {(expanded || !v.recommendation) && v.description && (
              <div style={{ color: "rgba(255,255,255,0.45)", fontSize: 11, marginBottom: 4 }}>{v.description}</div>
            )}
            {expanded && v.recommendation && (
              <div style={{ color: "#00e5a0", fontSize: 11 }}>✓ {v.recommendation}</div>
            )}
            <div style={{ display: "flex", gap: 8, marginTop: 4, flexWrap: "wrap" }}>
              {v.module && <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10, fontFamily: "monospace" }}>Module: {v.module}</span>}
              {v.epss   && <span style={{ color: "rgba(255,140,0,0.5)", fontSize: 10, fontFamily: "monospace" }}>EPSS {v.epss_pct ?? Math.round(v.epss * 100)}%</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function StatusButtons({ asset, onStatusChange, onClose }) {
  return (
    <div style={{ marginTop: 24, paddingTop: 16, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
      <div style={{ color: "rgba(255,255,255,0.62)", fontSize: 10, letterSpacing: "1px", textTransform: "uppercase", marginBottom: 10, fontFamily: "monospace" }}>Update Status</div>
      <div style={{ display: "flex", gap: 8 }}>
        {["open", "in_review", "resolved"].map(s => {
          const cfg = STATUS_CONFIG[s] || { color: "#888", label: s };
          return (
            <button key={s} onClick={() => { onStatusChange(asset.id, s); onClose(); }}
              style={{ padding: "8px 16px", borderRadius: 3, border: `1px solid ${cfg.color}40`, background: asset.status === s ? `${cfg.color}20` : "transparent", color: cfg.color, fontFamily: "monospace", fontSize: 11, letterSpacing: "1px", cursor: "pointer", textTransform: "uppercase", fontWeight: asset.status === s ? 700 : 400 }}>
              {cfg.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
