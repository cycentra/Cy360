/**
 * src/core/adapter.js
 * ====================
 * Translates raw cycentra_scan.py JSON output into the UI asset model.
 * This is the single file responsible for all scan-data → UI mapping.
 *
 * Isolating this means:
 *  - Data shape bugs (e.g. cloud vs cloud_infra) are fixed here only
 *  - Unit-testable without React
 *  - Safe to change without touching any page component
 */

// ── Main adapter ──────────────────────────────────────────────────────────────

export function adaptCyCentraJSON(raw) {
  if (!raw?.assets) return null;

  const sevMap = {
    Critical: "critical", High: "high",
    Medium: "medium", Low: "low", Informational: "low",
  };
  const allAssets = [];

  raw.assets.forEach(a => {
    const vulns  = a.vulnerabilities || [];
    const topSev = vulns.reduce((acc, v) => {
      const order  = { critical: 0, high: 1, medium: 2, low: 3 };
      const mapped = sevMap[v.severity] || "low";
      return order[mapped] < order[acc] ? mapped : acc;
    }, "low");

    const ports    = a.raw_results?.web?.results?.ports || [];
    const certInfo = a.raw_results?.crypto?.results?.ssl?.cert_info
                   || a.raw_results?.web?.results?.ssl?.cert_info
                   || null;
    const certExpiry = certInfo?.days_to_expiry != null
      ? (() => {
          const d = new Date();
          d.setDate(d.getDate() + certInfo.days_to_expiry);
          return d.toISOString().split("T")[0];
        })()
      : null;

    const cySiemAlerts = vulns
      .filter(v => v.severity === "Critical" || v.severity === "High")
      .map((v, i) => ({
        rule_id:     `CC-${100000 + i}`,
        level:       v.severity === "Critical" ? 12 : 8,
        description: v.vulnerability,
        asset:       a.host,
        ts:          raw.meta?.last_scan || new Date().toISOString(),
        module:      v.module,
      }));

    const subRaw     = a.raw_results?.subdomains?.results || [];
    const subdomains = [...new Set(
      subRaw.flatMap(s =>
        typeof s === "string"
          ? s.split("\n").map(d => d.trim()).filter(Boolean)
          : []
      )
    )];

    const emailSec    = a.raw_results?.email_sec?.results    || null;
    // NOTE: scan key is "cloud" (not "cloud_infra") — fixed here
    const cloudData   = a.raw_results?.cloud?.results        || null;
    const supplyChain = a.raw_results?.supply_chain?.results || null;
    const darkWeb     = a.raw_results?.dark_web?.results     || null;

    // Determine asset type from web fingerprints
    const fps  = a.raw_results?.web?.results?.fingerprints;
    const type = (() => {
      if (fps?.cms)         return fps.cms;
      if (fps?.framework)   return fps.framework;
      if (fps?.server)      return fps.server;
      const ips = a.raw_results?.dns?.results?.ips || [];
      if (ips.length)       return "IP Asset";
      return "Web Asset";
    })();

    allAssets.push({
      id:            a.id,
      host:          a.host,
      ip:            a.raw_results?.dns?.results?.ips?.[0]?.ip || "—",
      type,
      ports:         ports.map?.(p => p.port ?? p).filter(Boolean) || [],
      risk:          topSev,
      risk_score:    a.risk_score ?? 0,
      cves:          a.cves || [],
      vulnerabilities: vulns,
      cert_expiry:   certExpiry,
      cert_days:     certInfo?.days_to_expiry ?? null,
      owner:         a.raw_results?.whois?.results?.registrant || a.host,
      status:        "open",
      first_seen:    raw.meta?.last_scan?.split("T")[0] || "—",
      last_seen:     raw.meta?.last_scan?.split("T")[0] || "—",
      tags:          ["primary"],
      subdomains,
      exposed_paths: a.raw_results?.web?.results?.exposed_paths || [],
      email_sec:     emailSec,
      cloud_data:    cloudData,
      supply_chain:  supplyChain,
      dark_web:      darkWeb,
      summary:       a.summary || "",
      cySiemAlerts,
    });

    // Typosquat sub-assets
    (a.raw_results?.dns?.results?.typos?.registered || []).forEach((typo, i) => {
      allAssets.push({
        id:            `${a.id}-typo-${i}`,
        host:          typo,
        ip:            "—",
        type:          "Typosquat (Registered)",
        ports:         [],
        risk:          "high",
        risk_score:    7,
        cves:          [],
        vulnerabilities: [{
          vulnerability: "Registered Typosquat Domain",
          severity:      "High",
          risk_score:    7,
          description:   `${typo} is registered and could be used for phishing or brand abuse.`,
          recommendation:"Investigate ownership. If malicious, file abuse report or acquire the domain.",
          module:        "DNS",
        }],
        cert_expiry:   null,
        cert_days:     null,
        owner:         "Unknown (3rd party)",
        status:        "open",
        first_seen:    raw.meta?.last_scan?.split("T")[0] || "—",
        last_seen:     raw.meta?.last_scan?.split("T")[0] || "—",
        tags:          ["external", "typosquat"],
        subdomains:    [],
        exposed_paths: [],
        summary:       `Typosquat domain registered: ${typo}`,
        cySiemAlerts:  [],
      });
    });
  });

  return {
    meta:         raw.meta,
    assets:       allAssets,
    cysiemAlerts: allAssets.flatMap(a => a.cySiemAlerts),
  };
}

// ── Stat helpers (used by DashboardPage) ──────────────────────────────────────

export function getEmailSecData(assets) {
  const primary = assets.find(a => a.tags?.includes("primary"));
  const e       = primary?.email_sec;
  if (!e) return null;
  return {
    spf:    { value: e.spf?.record  || null, pass: e.spf?.valid  ?? null },
    dkim:   { value: e.dkim?.[0]?.selector || null, pass: e.dkim?.[0]?.valid ?? null },
    dmarc:  { value: e.dmarc?.policy || null, pass: e.dmarc?.present ?? null },
    bimi:   { value: e.elite_checks?.bimi?.record    || null, pass: e.elite_checks?.bimi?.status    === "pass" },
    mta_sts:{ value: e.elite_checks?.mta_sts?.policy || null, pass: e.elite_checks?.mta_sts?.status === "pass" },
  };
}

export function getWebSecStats(assets) {
  const allVulns    = assets.flatMap(a =>
    (a.vulnerabilities || []).filter(v => v.module === "Web" || v.module === "Crypto")
  );
  const exposedPaths = assets.reduce((acc, a) => acc + (a.exposed_paths?.length || 0), 0);
  return { vulns: allVulns.length, paths: exposedPaths };
}

export function getInfraStats(assets) {
  const ips   = assets.filter(a => a.type?.startsWith("IP")).length;
  const ports = [...new Set(assets.flatMap(a => a.ports || []))].length;
  const cloud = assets.filter(a => a.cloud_data).length;
  return { ips, ports, cloud };
}

export function getSupplyChainRisk(assets) {
  const primary = assets.find(a => a.tags?.includes("primary"));
  const sc      = primary?.supply_chain;
  if (!sc) return { count: 0, high: 0 };
  if (sc.risks !== undefined) {
    return {
      count: sc.count ?? sc.scripts?.length ?? 0,
      high:  sc.high  ?? sc.risks?.filter(r => r.severity === "High" || r.severity === "Critical").length ?? 0,
    };
  }
  if (Array.isArray(sc)) return { count: sc.length, high: 0 };
  return { count: 0, high: 0 };
}

export function getBrandData(assets) {
  const typos   = assets.filter(a => a.type === "Typosquat (Registered)");
  const darkweb = assets.flatMap(a => [
    ...(a.dark_web?.ahmia || []),
    ...(a.dark_web?.hibp  || []),
  ]);
  return { typos: typos.length, darkweb: darkweb.length };
}

export function getSSLData(assets) {
  const withCerts = assets.filter(a => a.cert_days != null);
  const expired   = withCerts.filter(a => a.cert_days < 0).length;
  const critical  = withCerts.filter(a => a.cert_days >= 0 && a.cert_days < 30).length;
  const tls10     = assets.filter(a =>
    (a.vulnerabilities || []).some(v =>
      v.vulnerability?.includes("TLS 1.0") || v.vulnerability?.includes("TLS1.0")
    )
  ).length;
  return { total: withCerts.length, expired, critical, weakTLS: tls10 };
}

// ── Date utilities ────────────────────────────────────────────────────────────

export function daysUntil(dateStr) {
  if (!dateStr) return null;
  return Math.ceil((new Date(dateStr) - new Date()) / 86400000);
}

export function formatDate(dateStr) {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
  });
}
