/**
 * src/core/adapter.js
 * ====================
 * Translates raw cycentra_scan.py JSON into the UI asset model.
 *
 * FIXED: Primary asset now gets tags ["external","primary"].
 *        Subdomain sub-assets are created from raw_results.subdomains.results.
 *        IP sub-assets are created from raw_results.dns.results.ips (index > 0).
 *        Typosquat sub-assets from raw_results.dns.results.typos.registered.
 *        All match the original App.jsx adaptCyCentraJSON exactly.
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

    // ── Ports ────────────────────────────────────────────────────────────────
    const ports = a.raw_results?.web?.results?.ports || [];

    // ── SSL cert ─────────────────────────────────────────────────────────────
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

    // ── CySIEM alert bridge ───────────────────────────────────────────────────
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

    // ── Subdomains (for sub-asset creation below) ─────────────────────────────
    const subRaw  = a.raw_results?.subdomains?.results || [];
    // v1.0.45+: results are enriched dicts {subdomain,live,is_new,change,resolved_ips,sources}
    // Legacy:   results may still be plain strings — handle both formats
    const subEntries = subRaw.map(s => {
      if (typeof s === "string") {
        const name = s.trim();
        return name ? { subdomain: name, live: null, is_new: false, change: null, resolved_ips: [], sources: [], cname: null } : null;
      }
      return (s && typeof s === "object" && s.subdomain) ? s : null;
    }).filter(e => e && e.subdomain);
    const subdomains = [...new Set(subEntries.map(e => e.subdomain))];

    // ── Module data slices ────────────────────────────────────────────────────
    const emailSec    = a.raw_results?.email_sec?.results    || null;
    const cloudData   = a.raw_results?.cloud?.results        || null;  // key is "cloud" not "cloud_infra"
    const supplyChain = a.raw_results?.supply_chain?.results || null;
    const darkWeb     = a.raw_results?.dark_web?.results     || null;
    const brandData   = a.raw_results?.dns?.results?.typos   || null;

    // ── Asset type from web fingerprints ──────────────────────────────────────
    const type = (() => {
      const b = a.raw_results?.web?.results?.fingerprints?.["80"]?.banner || "";
      if (b.includes("LiteSpeed")) return "Web Server (LiteSpeed)";
      if (b.includes("nginx"))     return "Web Server (Nginx)";
      if (b.includes("Apache"))    return "Web Server (Apache)";
      return "Web Asset";
    })();

    // ── PRIMARY ASSET ─────────────────────────────────────────────────────────
    // tags: ["external","primary"] — both tags required for dashboard stat helpers
    allAssets.push({
      id:            a.id,
      host:          a.host,
      ip:            a.raw_results?.dns?.results?.ips?.[0]?.ip || "—",
      type,
      ports:         ports.map?.(p => p.port ?? p).filter(Boolean) || [],
      risk:          topSev,
      risk_score:    a.risk_score ?? 0,
      cves:          vulns.map(v => v.vulnerability),
      vulnerabilities: vulns,
      cert_expiry:   certExpiry,
      cert_days:     certInfo?.days_to_expiry ?? null,
      owner:         raw.meta?.org || "Unknown",
      status:        "open",
      first_seen:    raw.meta?.last_scan?.split("T")[0] || "—",
      last_seen:     raw.meta?.last_scan?.split("T")[0] || "—",
      tags:          ["external", "primary"],   // ← FIXED: was ["primary"] only
      subdomains,
      exposed_paths: a.raw_results?.web?.results?.exposed_paths || [],
      email_sec:     emailSec,
      cloud_data:    cloudData,
      supply_chain:  supplyChain,
      dark_web:      darkWeb,
      brand_data:    brandData,
      dns_raw:       a.raw_results?.dns?.results || null,
      registrar:     a.raw_results?.whois?.results?.whois?.registrar || null,
      summary:       a.summary || "",
      cySiemAlerts,
    });

    // ── SUBDOMAIN SUB-ASSETS ──────────────────────────────────────────────────
    // type="Subdomain" + tags=["external","subdomain"]
    // Required for widget 6 "Subdomains" count and Assets table filtering
    subEntries.forEach((entry, i) => {
      if (entry.subdomain === a.host) return;   // skip if identical to primary
      const isNew  = entry.is_new  === true;
      const isLive = entry.live    === true;
      const change = entry.change  || null;
      const subTags = ["external", "subdomain"];
      if (isNew)             subTags.push("new");
      if (!isLive && entry.live !== null) subTags.push("historical");
      allAssets.push({
        id:            `${a.id}-sub-${i}`,
        host:          entry.subdomain,
        ip:            entry.resolved_ips?.[0] || "—",
        type:          "Subdomain",
        ports:         [],
        risk:          isLive ? "low" : "info",
        risk_score:    isLive ? 2 : 0,
        live:          isLive,
        is_new:        isNew,
        change,
        cname:         entry.cname || null,
        sources:       entry.sources || [],
        cves:          [],
        vulnerabilities: [],
        cert_expiry:   null,
        cert_days:     null,
        owner:         raw.meta?.org || "Unknown",
        status:        "open",
        first_seen:    raw.meta?.last_scan?.split("T")[0] || "—",
        last_seen:     raw.meta?.last_scan?.split("T")[0] || "—",
        tags:          subTags,
        subdomains:    [],
        exposed_paths: [],
        email_sec:     null,
        cloud_data:    null,
        supply_chain:  null,
        dark_web:      null,
        summary:       `Subdomain of ${a.host} — ${isLive ? "LIVE" : "historical"}${isNew ? " (NEW)" : ""}`,
        cySiemAlerts:  [],
      });
    });

    // ── IP SUB-ASSETS ─────────────────────────────────────────────────────────
    // tags=["external","ip"] — required for widget 6 "IP Addresses" count
    // Skip index 0 (already used as primary asset's .ip field)
    (a.raw_results?.dns?.results?.ips || []).forEach((ipObj, i) => {
      if (i === 0) return;
      allAssets.push({
        id:            `${a.id}-ip-${i}`,
        host:          ipObj.ip,
        ip:            ipObj.ip,
        type:          `IP (${ipObj.org || "Unknown"})`,
        ports:         [],
        risk:          "low",
        risk_score:    1,
        cves:          [],
        vulnerabilities: [],
        cert_expiry:   null,
        cert_days:     null,
        owner:         ipObj.org || raw.meta?.org || "Unknown",
        status:        "open",
        first_seen:    raw.meta?.last_scan?.split("T")[0] || "—",
        last_seen:     raw.meta?.last_scan?.split("T")[0] || "—",
        tags:          ["external", "ip"],
        subdomains:    [],
        exposed_paths: [],
        email_sec:     null,
        cloud_data:    null,
        supply_chain:  null,
        dark_web:      null,
        summary:       `IP address: ${ipObj.ip} (${ipObj.country || "?"})`,
        cySiemAlerts:  [],
      });
    });

    // ── TYPOSQUAT SUB-ASSETS ──────────────────────────────────────────────────
    // type="Typosquat (Registered)" — required for widget 8 brand count
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
          recommendation: "Investigate ownership. If malicious, file abuse report or acquire the domain.",
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
        email_sec:     null,
        cloud_data:    null,
        supply_chain:  null,
        dark_web:      null,
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
  // Must find primary asset that has email_sec populated
  const primary = assets.find(a => a.tags?.includes("primary") && a.email_sec);
  const e       = primary?.email_sec;
  if (!e) return null;
  return {
    spf:    { value: e.spf?.record   || null, pass: e.spf?.present   ?? null },
    dkim:   { value: e.dkim?.[0]?.selector || null, pass: e.dkim?.[0]?.valid ?? null },
    dmarc:  { value: e.dmarc?.policy || null, pass: e.dmarc?.present ?? null },
    bimi:   { value: e.elite_checks?.bimi?.record    || null, pass: e.elite_checks?.bimi?.status    === "pass" },
    mta_sts:{ value: e.elite_checks?.mta_sts?.policy || null, pass: e.elite_checks?.mta_sts?.status === "pass" },
  };
}

export function getWebSecStats(assets) {
  const allVulns     = assets.flatMap(a =>
    (a.vulnerabilities || []).filter(v => v.module === "Web" || v.module === "Crypto")
  );
  const exposedPaths = assets.reduce((acc, a) => acc + (a.exposed_paths?.length || 0), 0);
  return { vulns: allVulns.length, paths: exposedPaths };
}

export function getInfraStats(assets) {
  // IP count: assets with tag "ip" OR type starting with "IP"
  const ips   = assets.filter(a => a.tags?.includes("ip") || a.type?.startsWith("IP")).length;
  const ports = [...new Set(assets.flatMap(a => a.ports || []))].length;
  const cloud = assets.filter(a => a.cloud_data).length;
  return { ips, ports, cloud };
}

export function getSupplyChainRisk(assets) {
  const primary = assets.find(a => a.tags?.includes("primary"));
  const sc      = primary?.supply_chain;
  if (!sc) return { count: 0, high: 0 };
  // Structured format: { scripts, risks, count, high }
  if (sc.risks !== undefined) {
    return {
      count: sc.count ?? sc.scripts?.length ?? 0,
      high:  sc.high  ?? sc.risks?.filter(r => r.severity === "High" || r.severity === "Critical").length ?? 0,
    };
  }
  // Legacy flat array
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
