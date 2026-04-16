/**
 * src/core/adapter.js
 * ====================
 * Translates raw cycentra_scan.py JSON into the UI asset model.
 *
 * v2: Enriches vulnerabilities with raw vuln_scanner/nuclei fields (CVSS, EPSS,
 *     compliance_impact, source, discovered_at). Exposes all previously ignored
 *     module data on primary assets. Fixes module-name filter bug in getWebSecStats.
 */

// ── Vulnerability enrichment ──────────────────────────────────────────────────

function _enrichVulns(vulns, vsFindings, nucFindings) {
  // Build lookup maps by lowercase vulnerability name for O(1) enrichment
  const vsMap  = {};
  const nucMap = {};
  vsFindings.forEach(f  => { if (f.vulnerability) vsMap[f.vulnerability.toLowerCase()]  = f; });
  nucFindings.forEach(f => { if (f.vulnerability) nucMap[f.vulnerability.toLowerCase()] = f; });

  const enriched = vulns.map(v => {
    const key   = v.vulnerability?.toLowerCase() || "";
    const extra = vsMap[key] || nucMap[key] || {};
    return {
      ...v,
      cvss:             v.cvss             ?? extra.cvss             ?? null,
      epss:             v.epss             ?? extra.epss             ?? null,
      epss_pct:         v.epss_pct         ?? extra.epss_pct         ?? null,
      compliance_impact:v.compliance_impact?? extra.compliance_impact?? null,
      discovered_at:    v.discovered_at    ?? extra.discovered_at    ?? null,
      source:           v.source           ?? extra.source           ?? null,
      cve_refs:         v.cve_refs         ?? extra.cve_refs         ?? null,
      template_id:      v.template_id      ?? extra.template_id      ?? null,
      matched_at:       v.matched_at       ?? extra.matched_at       ?? null,
    };
  });

  // Add scanner/nuclei findings not already present in the curated list
  const existingKeys = new Set(vulns.map(v => v.vulnerability?.toLowerCase() || ""));
  [...vsFindings, ...nucFindings].forEach(f => {
    if (!f.vulnerability) return;
    const k = f.vulnerability.toLowerCase();
    if (existingKeys.has(k)) return;
    existingKeys.add(k);
    enriched.push({
      vulnerability:    f.vulnerability,
      severity:         f.severity          || "Low",
      risk_score:       f.risk_score        ?? null,
      description:      f.description       || "",
      recommendation:   f.recommendation    || "",
      module:           f.module            || (vsFindings.includes(f) ? "vuln_scanner" : "nuclei"),
      cvss:             f.cvss              ?? null,
      epss:             f.epss              ?? null,
      epss_pct:         f.epss_pct          ?? null,
      compliance_impact:f.compliance_impact ?? null,
      discovered_at:    f.discovered_at     ?? null,
      source:           f.source            ?? null,
      cve_refs:         f.cve_refs          ?? null,
      template_id:      f.template_id       ?? null,
      matched_at:       f.matched_at        ?? null,
    });
  });

  return enriched;
}

// ── Main adapter ──────────────────────────────────────────────────────────────

export function adaptCyCentraJSON(raw) {
  if (!raw?.assets) return null;

  const sevMap = {
    Critical: "critical", High: "high",
    Medium: "medium", Low: "low", Informational: "low",
  };
  const allAssets = [];

  raw.assets.forEach(a => {
    // Enrich vulnerabilities with raw scanner data
    const vsFindings  = a.raw_results?.vuln_scanner?.results?.findings  || [];
    const nucFindings = a.raw_results?.nuclei?.results?.findings         || [];
    const vulns = _enrichVulns(a.vulnerabilities || [], vsFindings, nucFindings);

    const topSev = vulns.reduce((acc, v) => {
      const order  = { critical: 0, high: 1, medium: 2, low: 3 };
      const mapped = sevMap[v.severity] || "low";
      return order[mapped] < order[acc] ? mapped : acc;
    }, "low");

    // ── Ports ────────────────────────────────────────────────────────────────
    const ports = a.raw_results?.web?.results?.ports || [];

    // ── SSL cert — full detail ────────────────────────────────────────────────
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
        cvss:        v.cvss   ?? null,
        risk_score:  v.risk_score ?? null,
        source:      v.source ?? null,
      }));

    // ── Subdomains ────────────────────────────────────────────────────────────
    const subRaw  = a.raw_results?.subdomains?.results || [];
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
    const cloudData   = a.raw_results?.cloud?.results        || null;
    const supplyChain = a.raw_results?.supply_chain?.results || null;
    const darkWeb     = a.raw_results?.dark_web?.results     || null;
    const brandData   = a.raw_results?.dns?.results?.typos   || null;

    // ── New module data slices (previously ignored) ───────────────────────────
    const osintData   = a.raw_results?.osint?.results        || null;
    const socialEng   = a.raw_results?.social_eng?.results   || null;
    const mobileApi   = a.raw_results?.mobile_api?.results   || null;
    const whoisFull   = a.raw_results?.whois?.results?.whois || null;
    const whoisHistory= a.raw_results?.whois?.results?.history || null;
    const dnsRecords  = a.raw_results?.dns?.results?.records || null;
    const dnsIps      = a.raw_results?.dns?.results?.ips     || [];
    const dnsTakeovers= a.raw_results?.dns?.results?.takeovers || [];
    const dnsUnreg    = a.raw_results?.dns?.results?.typos?.unregistered || [];
    const sslDetail   = certInfo;  // full cert_info: cipher, protocol, chain, OCSP etc.
    const pqcData     = a.raw_results?.crypto?.results?.pqc  || null;
    const deepSsl     = a.raw_results?.crypto_deep?.results?.ssl?.cert_info || null;
    const webHttp     = a.raw_results?.web?.results?.http_analysis || null;
    const webApiEp    = a.raw_results?.web?.results?.api_endpoints || [];
    const jsSecrets   = a.raw_results?.web?.results?.js_secrets    || [];
    const fingerprints= a.raw_results?.web?.results?.fingerprints  || {};

    // ── Asset type from web fingerprints ──────────────────────────────────────
    const type = (() => {
      const b = fingerprints?.["80"]?.banner || "";
      if (b.includes("LiteSpeed")) return "Web Server (LiteSpeed)";
      if (b.includes("nginx"))     return "Web Server (Nginx)";
      if (b.includes("Apache"))    return "Web Server (Apache)";
      return "Web Asset";
    })();

    // ── PRIMARY ASSET ─────────────────────────────────────────────────────────
    allAssets.push({
      id:            a.id,
      host:          a.host,
      ip:            dnsIps[0]?.ip || "—",
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
      tags:          ["external", "primary"],
      subdomains,
      exposed_paths: a.raw_results?.web?.results?.exposed_paths || [],
      // Previously-rendered data
      email_sec:     emailSec,
      cloud_data:    cloudData,
      supply_chain:  supplyChain,
      dark_web:      darkWeb,
      brand_data:    brandData,
      dns_raw:       a.raw_results?.dns?.results || null,
      registrar:     whoisFull?.registrar || null,
      summary:       a.summary || "",
      cySiemAlerts,
      // New: previously-ignored data
      osint_data:    osintData,
      social_eng:    socialEng,
      mobile_api:    mobileApi,
      whois_full:    whoisFull,
      whois_history: whoisHistory,
      dns_records:   dnsRecords,
      dns_ips:       dnsIps,
      dns_takeovers: dnsTakeovers,
      dns_unregistered: dnsUnreg,
      ssl_detail:    sslDetail,
      pqc_data:      pqcData,
      deep_ssl:      deepSsl,
      http_analysis: webHttp,
      api_endpoints: webApiEp,
      js_secrets:    jsSecrets,
      fingerprints,
    });

    // ── SUBDOMAIN SUB-ASSETS ──────────────────────────────────────────────────
    subEntries.forEach((entry, i) => {
      if (entry.subdomain === a.host) return;
      const isNew  = entry.is_new  === true;
      const isLive = entry.live    === true;
      const change = entry.change  || null;
      const subTags = ["external", "subdomain"];
      if (isNew)                            subTags.push("new");
      if (!isLive && entry.live !== null)   subTags.push("historical");
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
        resolved_ips:  entry.resolved_ips || [],
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
    dnsIps.forEach((ipObj, i) => {
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
        // Expose full IP enrichment for modal display
        asn:           ipObj.asn     || null,
        country:       ipObj.country || null,
        city:          ipObj.city    || null,
        hostname:      ipObj.hostname || null,
        cloud_provider: ipObj.cloud_provider || null,
        reverse_dns:   ipObj.reverse_dns || null,
        summary:       `IP address: ${ipObj.ip} (${ipObj.country || "?"})`,
        cySiemAlerts:  [],
      });
    });

    // ── TYPOSQUAT SUB-ASSETS ──────────────────────────────────────────────────
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
    subdomain_summary: raw.subdomain_summary || null,
  };
}

// ── Stat helpers (used by DashboardPage) ──────────────────────────────────────

export function getEmailSecData(assets) {
  const primary = assets.find(a => a.tags?.includes("primary") && a.email_sec);
  const e       = primary?.email_sec;
  if (!e) return null;
  return {
    spf:       { value: e.spf?.record      || null, pass: e.spf?.present      ?? null },
    dkim:      { value: e.dkim?.[0]?.selector || null, pass: e.dkim?.[0]?.valid ?? null },
    dmarc:     { value: e.dmarc?.policy    || null, pass: e.dmarc?.present    ?? null },
    bimi:      { value: e.elite_checks?.bimi?.record    || null,   pass: e.elite_checks?.bimi?.status    === "pass" },
    mta_sts:   { value: e.elite_checks?.mta_sts?.policy || null,   pass: e.elite_checks?.mta_sts?.status === "pass" },
    tls_rpt:   { value: e.elite_checks?.tls_rpt?.record || null,   pass: e.elite_checks?.tls_rpt?.status === "pass" },
    dnssec:    { value: e.dnssec?.status   || null, pass: e.dnssec?.valid     ?? null },
    spoofing_risk: e.spoofing_risk          || null,
    elite_score:   e.elite_score            ?? null,
    elite_status:  e.elite_status           || null,
    mx:        e.mx                         || [],
    mx_tls:    e.mx_tls                     || null,
  };
}

export function getWebSecStats(assets) {
  // Count all web-related vulnerabilities (not just module==="Web")
  const webModules = new Set(["Web", "web", "web_analysis", "vuln_scanner", "nuclei", "Crypto", "crypto"]);
  const allVulns  = assets.flatMap(a =>
    (a.vulnerabilities || []).filter(v => webModules.has(v.module) || v.source === "port_banner" || v.source === "exposed_path" || v.source === "js_secret")
  );
  const exposedPaths = assets.reduce((acc, a) => acc + (a.exposed_paths?.length || 0), 0);
  return { vulns: allVulns.length, paths: exposedPaths };
}

export function getInfraStats(assets) {
  const ips   = assets.filter(a => a.tags?.includes("ip") || a.type?.startsWith("IP")).length;
  const ports = [...new Set(assets.flatMap(a => a.ports || []))].length;
  const cloud = assets.filter(a => a.cloud_data).length;
  return { ips, ports, cloud };
}

export function getSupplyChainRisk(assets) {
  const primary = assets.find(a => a.tags?.includes("primary"));
  const sc      = primary?.supply_chain;
  if (!sc) return { count: 0, high: 0, risks: [] };
  if (sc.risks !== undefined) {
    return {
      count: sc.count ?? sc.scripts?.length ?? 0,
      high:  sc.high  ?? sc.risks?.filter(r => r.severity === "High" || r.severity === "Critical").length ?? 0,
      risks: sc.risks || [],
    };
  }
  if (Array.isArray(sc)) return { count: sc.length, high: 0, risks: [] };
  return { count: 0, high: 0, risks: [] };
}

export function getBrandData(assets) {
  const typos   = assets.filter(a => a.type === "Typosquat (Registered)");
  const primary = assets.find(a => a.tags?.includes("primary"));
  const ahmia   = primary?.dark_web?.ahmia || [];
  const hibp    = primary?.dark_web?.hibp  || [];
  return {
    typos:    typos.length,
    darkweb:  ahmia.length + hibp.length,
    ahmia,
    hibp,
  };
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

export function getOsintData(assets) {
  const primary = assets.find(a => a.tags?.includes("primary"));
  return {
    misp:    primary?.osint_data?.misp              || [],
    shodan:  primary?.osint_data?.shodan            || [],
    cves:    primary?.osint_data?.shodan_cve_findings || [],
  };
}

export function getSocialEngData(assets) {
  const primary = assets.find(a => a.tags?.includes("primary"));
  const s       = primary?.social_eng;
  if (!s) return null;
  return {
    emails:          s.emails         || [],
    email_list:      s.email_list     || [],
    email_patterns:  s.email_patterns || [],
    linkedin:        s.linkedin       || [],
    risk_assessment: s.risk_assessment || null,
  };
}

export function getMobileApiData(assets) {
  const primary = assets.find(a => a.tags?.includes("primary"));
  const m       = primary?.mobile_api;
  if (!m) return null;
  return {
    app_links:   m.app_links    || {},
    api_findings:m.api_findings || [],
    apk_secrets: m.apk_secrets  || [],
    deeplinks:   m.deeplinks    || [],
  };
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
