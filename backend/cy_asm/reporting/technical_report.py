"""
reporting/technical_report.py
CyCentra ASM — Technical Security Report

Audience: Security engineers, DevSecOps, IT teams
Language: Technical — CVE IDs, CVSS scores, exact paths, remediation steps
Emphasis: Every finding with full detail, module-by-module breakdown,
          subdomain table, SSL deep-dive, port/service inventory
Charts: Module bar, risk timeline, CVSS histogram, SSL donut, email bar
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether, NextPageTemplate, PageBreak, Paragraph, Spacer,
    Table, TableStyle,
)

from .charts import (
    module_bar, risk_timeline, cvss_histogram, severity_pie,
    ssl_donut, email_score_bar, subdomain_bar, posture_gauge,
)
from .pdf_base import (
    BODY_W, C_BLUE, C_BORDER, C_GREEN, C_LIGHT, C_NAVY, C_ORANGE, C_RED,
    C_SKY, C_SUBTLE, C_TEXT, C_YELLOW, MARGIN, SEV_COLOR, STYLES, W,
    CyCentraDocTemplate, build_cover, compute_posture_score,
    finding_table, img_from_bytes, metric_card, rule,
    section_header, severity_badge,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _truncate(s: str, n: int = 80) -> str:
    s = str(s or "")
    return s[:n] + "…" if len(s) > n else s


def _sev_sort_key(f: Dict) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
        str(f.get("severity", "low")).lower(), 4
    )


# ── Cover + TOC ───────────────────────────────────────────────────────────────

def _toc(sections: List[str]) -> List:
    story = []
    story += section_header("Table of Contents")
    for i, name in enumerate(sections, 1):
        row = Table(
            [[Paragraph(f"{i}.", STYLES["toc"]),
              Paragraph(name, STYLES["toc"]),
              Paragraph(f"p. {i + 2}", STYLES["toc"])]],
            colWidths=[0.8*cm, BODY_W - 1.6*cm, 0.8*cm],
        )
        row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
        ]))
        story.append(row)
    story.append(PageBreak())
    return story


# ── Section: Scan Metadata ────────────────────────────────────────────────────

def _scan_metadata(meta: Dict, score: int, grade: str, sub_summary: Dict) -> List:
    story = []
    story += section_header("Scan Metadata & Summary Statistics",
                             "Parameters and high-level results for this assessment")

    rows = [
        ["Domain",           meta.get("domain", "")],
        ["Organisation",     meta.get("org", "")],
        ["Scan ID",          meta.get("scan_id", "")],
        ["Scan Type",        meta.get("scan_type", "standard").title()],
        ["Scan Date",        meta.get("last_scan", "")[:19]],
        ["Subdomains Found", str(sub_summary.get("total", 0))],
        ["Live Subdomains",  str(sub_summary.get("live", 0))],
        ["New Subdomains",   str(sub_summary.get("new", 0))],
        ["Security Score",   f"{score}/100 (Grade {grade})"],
    ]
    t = finding_table(rows, [5*cm, BODY_W - 5*cm], ["Parameter", "Value"])
    story.append(t)
    return story


# ── Section: All Findings ─────────────────────────────────────────────────────

def _all_findings_section(all_f: List[Dict]) -> List:
    story = []
    story += section_header("Complete Findings Register",
                             f"All {len(all_f)} findings sorted by risk score — full detail for remediation")

    # Charts row
    pie_buf  = severity_pie({
        "Critical": sum(1 for f in all_f if str(f.get("severity","")).lower() == "critical"),
        "High":     sum(1 for f in all_f if str(f.get("severity","")).lower() == "high"),
        "Medium":   sum(1 for f in all_f if str(f.get("severity","")).lower() == "medium"),
        "Low":      sum(1 for f in all_f if str(f.get("severity","")).lower() == "low"),
    })
    hist_buf = cvss_histogram(all_f)
    tl_buf   = risk_timeline(all_f[:50])

    row1 = Table(
        [[img_from_bytes(pie_buf, BODY_W * 0.44), img_from_bytes(hist_buf, BODY_W * 0.52)]],
        colWidths=[BODY_W * 0.46, BODY_W * 0.54],
    )
    row1.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(row1)
    story.append(Spacer(1, 4))
    story.append(img_from_bytes(tl_buf, BODY_W))
    story.append(Paragraph("Figure: Risk score per finding (left=highest risk).",
                            STYLES["caption"]))
    story.append(Spacer(1, 10))

    # Individual finding cards
    sorted_f = sorted(all_f, key=_sev_sort_key)
    for i, f in enumerate(sorted_f, 1):
        sev      = f.get("severity", "Medium")
        vuln     = f.get("vulnerability", "Unknown")
        desc     = f.get("description", "No description available.")
        rec      = f.get("recommendation", "Review and remediate.")
        module   = f.get("module", "scan")
        risk     = f.get("risk_score", 5)
        cvss     = f.get("cvss", 0)
        epss     = f.get("epss", 0)
        cves     = f.get("cve_refs", f.get("cve_ids", []))
        port     = f.get("port", "")
        path     = f.get("path", "")
        comp     = f.get("compliance_impact", {})

        header_table = Table(
            [[
                Paragraph(f"<b>#{i}  {_truncate(vuln, 55)}</b>", STYLES["finding_title"]),
                severity_badge(sev),
            ]],
            colWidths=[BODY_W - 2.5*cm, 2.2*cm],
        )
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (-1, -1), C_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))

        meta_parts = [f"Module: <b>{module}</b>", f"Risk: <b>{risk}/10</b>"]
        if cvss:  meta_parts.append(f"CVSS: <b>{cvss}</b>")
        if epss:  meta_parts.append(f"EPSS: <b>{epss*100:.1f}%</b>")
        if port:  meta_parts.append(f"Port: <b>{port}</b>")
        if path:  meta_parts.append(f"Path: <b>{path}</b>")
        if cves:  meta_parts.append(f"CVE: <b>{', '.join(cves[:3])}</b>")

        comp_str = ""
        if comp:
            comp_str = "  |  ".join([f"<b>{k.upper()}:</b> {v}" for k, v in comp.items()])

        items = [
            header_table,
            Paragraph("  |  ".join(meta_parts), STYLES["body_small"]),
            Paragraph(f"<b>Description:</b> {desc}", STYLES["body"]),
            Paragraph(f"<b>Remediation:</b> {rec}", STYLES["body"]),
        ]
        if comp_str:
            items.append(Paragraph(f"<b>Compliance:</b> {comp_str}", STYLES["body_small"]))
        items.append(rule(C_BORDER, space_before=3, space_after=3))

        story.append(KeepTogether(items))

    return story


# ── Section: Module Breakdown ─────────────────────────────────────────────────

def _module_breakdown(all_f: List[Dict], results: Dict) -> List:
    story = []
    story += section_header("Module-by-Module Analysis",
                             "Results organised by scan module with per-module issue counts")

    # Module bar chart
    module_counts: Dict[str, int] = {}
    for f in all_f:
        m = str(f.get("module", "unknown")).replace("_", " ").title()
        module_counts[m] = module_counts.get(m, 0) + 1
    if module_counts:
        bar_buf = module_bar(module_counts)
        story.append(img_from_bytes(bar_buf, BODY_W * 0.7))
        story.append(Paragraph("Figure: Issue count per scan module.", STYLES["caption"]))
        story.append(Spacer(1, 8))

    # Per-module summaries
    module_map: Dict[str, str] = {
        "dns":          "DNS Reconnaissance",
        "subdomains":   "Subdomain Enumeration",
        "web":          "Web Analysis",
        "crypto":       "Crypto & SSL Audit",
        "email_sec":    "Email Security",
        "cloud":        "Cloud Infrastructure",
        "whois":        "WHOIS & History",
        "osint":        "Passive OSINT",
        "dark_web":     "Dark Web Monitoring",
        "supply_chain": "Supply Chain",
        "social_eng":   "Social Engineering",
        "mobile_api":   "Mobile & API",
        "vuln_scanner": "Vulnerability Scanner",
        "nuclei":       "Nuclei Scanner",
        "crypto_deep":  "Deep SSL Audit",
    }

    for key, label in module_map.items():
        mod_data = results.get(key, {})
        if not mod_data or mod_data.get("skipped"):
            continue
        summary = mod_data.get("summary", "")
        issues  = mod_data.get("issues", [])
        if not summary and not issues:
            continue

        story.append(Paragraph(f"<b>{label}</b>", STYLES["h3"]))
        if summary:
            story.append(Paragraph(summary, STYLES["body"]))
        if issues:
            for iss in issues[:8]:
                story.append(Paragraph(str(iss)[:120], STYLES["bullet"]))
        story.append(Spacer(1, 4))

    return story


# ── Section: Subdomains ───────────────────────────────────────────────────────

def _subdomain_section(results: Dict, sub_summary: Dict) -> List:
    story = []
    story += section_header("Subdomain Inventory",
                             "All discovered subdomains with live status, IPs, and discovery source")

    live  = sub_summary.get("live", 0)
    hist  = sub_summary.get("historical", 0)
    new_s = sub_summary.get("new", 0)

    if live + hist > 0:
        sub_buf = subdomain_bar(live, hist, new_s)
        story.append(img_from_bytes(sub_buf, 7 * cm))
        story.append(Spacer(1, 8))

    sub_entries = results.get("subdomains", {}).get("results", [])
    if not sub_entries:
        story.append(Paragraph("No subdomain data available.", STYLES["body"]))
        return story

    rows = []
    for e in sub_entries[:200]:
        if not isinstance(e, dict):
            continue
        live_flag = "✓" if e.get("live") else "–"
        new_flag  = "NEW" if e.get("is_new") else e.get("change", "")
        ips = ", ".join(e.get("resolved_ips", [])[:3]) or e.get("cname", "") or "–"
        srcs = ", ".join(e.get("sources", []))[:30] or "–"
        rows.append([
            Paragraph(e.get("subdomain", ""), STYLES["body_small"]),
            Paragraph(live_flag, STYLES["body_small"]),
            Paragraph(ips[:35], STYLES["body_small"]),
            Paragraph(new_flag[:12], STYLES["body_small"]),
            Paragraph(srcs, STYLES["body_small"]),
        ])

    if rows:
        t = finding_table(rows, [6*cm, 1.2*cm, 4*cm, 1.8*cm, 3.5*cm],
                          ["Subdomain", "Live", "IP / CNAME", "Change", "Sources"])
        story.append(t)
        if len(sub_entries) > 200:
            story.append(Paragraph(f"… and {len(sub_entries)-200} more (truncated).",
                                   STYLES["body_small"]))
    return story


# ── Section: DNS ──────────────────────────────────────────────────────────────

def _dns_section(results: Dict) -> List:
    story = []
    story += section_header("DNS Records & Typosquatting",
                             "Enumerated DNS records and registered lookalike domains")

    dns_r   = results.get("dns", {}).get("results", {})
    records = dns_r.get("records", {})
    typos   = dns_r.get("typos", {})

    if records:
        rows = []
        for rtype, vals in records.items():
            if not vals:
                continue
            for v in vals[:5]:
                rows.append([rtype, Paragraph(str(v)[:80], STYLES["body_small"])])
        if rows:
            t = finding_table(rows, [2.5*cm, BODY_W - 2.5*cm], ["Type", "Value"])
            story.append(t)
            story.append(Spacer(1, 8))

    registered = typos.get("registered", [])
    if registered:
        story.append(Paragraph(
            f"<b>⚠ Registered Typosquatting Domains ({len(registered)}):</b>",
            STYLES["h3"]))
        for td in registered[:15]:
            story.append(Paragraph(td, STYLES["bullet"]))
    else:
        story.append(Paragraph("No registered typosquatting domains detected.", STYLES["body"]))

    return story


# ── Section: SSL Deep Dive ────────────────────────────────────────────────────

def _ssl_section(results: Dict) -> List:
    story = []
    story += section_header("SSL/TLS Certificate Analysis",
                             "Full certificate chain, cipher, and PQC readiness assessment")

    ssl_r   = results.get("crypto", {}).get("results", {}).get("ssl", {})
    cert    = ssl_r.get("cert_info", {})
    pqc_r   = results.get("crypto", {}).get("results", {}).get("pqc", {})

    ssl_ok    = ssl_r.get("ssl_enabled", False)
    days_left = cert.get("days_to_expiry")
    chain_ok  = cert.get("chain_valid", False)
    san_ok    = cert.get("san_valid", False)

    ssl_buf = ssl_donut(ssl_ok, days_left, chain_ok, san_ok)
    story.append(img_from_bytes(ssl_buf, BODY_W * 0.55))
    story.append(Spacer(1, 8))

    details = [
        ("Issuer",           cert.get("issuer", "Unknown")),
        ("Protocol",         cert.get("protocol", "Unknown")),
        ("Cipher",           cert.get("cipher", "Unknown")),
        ("Days to Expiry",   str(days_left) if days_left is not None else "Unknown"),
        ("Chain Valid",      "Yes" if chain_ok else "No"),
        ("SAN Valid",        "Yes" if san_ok else "No"),
        ("Self-Signed",      "Yes" if cert.get("self_signed") else "No"),
        ("OCSP Stapling",    "Yes" if cert.get("ocsp_stapling") else "No"),
        ("PQC Ready",        "Yes" if pqc_r and pqc_r.get("server_pqc") else "No"),
    ]
    rows = [[Paragraph(k, STYLES["body_small"]), Paragraph(str(v), STYLES["body_small"])]
            for k, v in details]
    t = finding_table(rows, [5*cm, BODY_W - 5*cm], ["Property", "Value"])
    story.append(t)

    ssl_issues = ssl_r.get("issues", [])
    if ssl_issues:
        story.append(Paragraph("<b>Issues Detected:</b>", STYLES["h3"]))
        for iss in ssl_issues:
            story.append(Paragraph(str(iss), STYLES["bullet"]))

    return story


# ── Section: Email ────────────────────────────────────────────────────────────

def _email_section(results: Dict) -> List:
    story = []
    story += section_header("Email Security Controls",
                             "SPF, DMARC, DKIM, MTA-STS, BIMI, and spoofing risk assessment")

    email_r = results.get("email_sec", {}).get("results", {})
    checks = {
        "SPF":     email_r.get("spf",   {}).get("present", False),
        "DMARC":   email_r.get("dmarc", {}).get("present", False),
        "DKIM":    bool(email_r.get("dkim", [])),
        "DNSSEC":  email_r.get("dnssec", {}).get("enabled", False),
        "MTA-STS": email_r.get("elite_checks", {}).get("mta_sts", {}).get("status") == "pass",
        "BIMI":    email_r.get("elite_checks", {}).get("bimi", {}).get("status") == "pass",
        "TLS-RPT": email_r.get("elite_checks", {}).get("tls_rpt", {}).get("status") == "pass",
        "CAA":     bool(email_r.get("elite_checks", {}).get("caa_ssl", {}).get("caa_records", [])),
    }
    score_str = email_r.get("elite_score", "?/8")
    email_buf = email_score_bar(score_str, checks)
    story.append(img_from_bytes(email_buf, BODY_W * 0.65))
    story.append(Spacer(1, 8))

    # Record details
    record_rows = []
    spf_rec   = email_r.get("spf",   {}).get("record")
    dmarc_rec = email_r.get("dmarc", {}).get("record")
    if spf_rec:
        record_rows.append(["SPF",   Paragraph(_truncate(spf_rec, 90),   STYLES["body_small"])])
    if dmarc_rec:
        record_rows.append(["DMARC", Paragraph(_truncate(dmarc_rec, 90), STYLES["body_small"])])
    for dkim in email_r.get("dkim", [])[:3]:
        record_rows.append([
            f"DKIM ({dkim.get('selector','')})",
            Paragraph(_truncate(dkim.get("record",""), 90), STYLES["body_small"]),
        ])
    if record_rows:
        t = finding_table(record_rows, [3*cm, BODY_W - 3*cm], ["Control", "Record"])
        story.append(t)

    spoof = email_r.get("spoofing_risk", {})
    if spoof.get("level") != "none":
        story.append(Paragraph(
            f"<b>⚠ Spoofing Risk: {spoof.get('level','')} — {spoof.get('note','')}</b>",
            STYLES["body"]))

    return story


# ── Section: Cloud ────────────────────────────────────────────────────────────

def _cloud_section(results: Dict) -> List:
    story = []
    story += section_header("Cloud Infrastructure Exposure",
                             "S3/GCS/Azure/DO bucket enumeration and Kubernetes API exposure")

    cloud_r = results.get("cloud", {}).get("results", {})
    buckets = cloud_r.get("buckets", [])
    k8s     = cloud_r.get("k8s_exposed", False)
    provs   = cloud_r.get("providers", [])

    if provs:
        story.append(Paragraph(f"<b>Cloud Providers:</b> {', '.join(provs)}", STYLES["body"]))
    if k8s:
        story.append(Paragraph(
            "⚠ <b>Kubernetes API appears exposed on port 6443!</b> "
            "Restrict immediately via network policy or firewall.", STYLES["body"]))
    story.append(Spacer(1, 6))

    if buckets:
        rows = []
        for b in buckets[:50]:
            rows.append([
                Paragraph(b.get("url","")[:60], STYLES["body_small"]),
                Paragraph(b.get("risk",""), STYLES["body_small"]),
                Paragraph(str(b.get("status","")), STYLES["body_small"]),
                Paragraph(b.get("details",""), STYLES["body_small"]),
            ])
        t = finding_table(rows, [7.5*cm, 3*cm, 1.5*cm, 4.5*cm],
                          ["URL", "Risk", "Status", "Details"])
        story.append(t)
    else:
        story.append(Paragraph("No exposed public cloud buckets detected.", STYLES["body"]))

    return story


# ── Section: Ports / Web ──────────────────────────────────────────────────────

def _web_section(results: Dict) -> List:
    story = []
    story += section_header("Web & Port Analysis",
                             "Open ports, service fingerprints, exposed paths, and JavaScript secrets")

    web_r    = results.get("web", {}).get("results", {})
    ports    = web_r.get("ports", [])
    fps      = web_r.get("fingerprints", {})
    exposed  = web_r.get("exposed_paths", [])
    secrets  = web_r.get("js_secrets", [])
    http_a   = web_r.get("http_analysis", {})

    # Port table
    if ports:
        port_rows = []
        for p in ports[:30]:
            fp_data = fps.get(p, {})
            banner  = fp_data.get("banner", "Unknown")[:50]
            vulns   = fp_data.get("vulns", [])
            port_rows.append([
                str(p),
                Paragraph(banner, STYLES["body_small"]),
                Paragraph(", ".join(vulns[:3]) or "None", STYLES["body_small"]),
            ])
        t = finding_table(port_rows, [2*cm, 8*cm, 6.5*cm],
                          ["Port", "Banner / Service", "CVEs Detected"])
        story.append(t)
        story.append(Spacer(1, 8))

    # HTTP headers
    hdr_issues = http_a.get("http_headers", [])
    if hdr_issues:
        story.append(Paragraph("<b>Missing HTTP Security Headers:</b>", STYLES["h3"]))
        for h in hdr_issues:
            story.append(Paragraph(str(h), STYLES["bullet"]))
        story.append(Spacer(1, 6))

    # Exposed paths
    if exposed:
        story.append(Paragraph("<b>Exposed / Sensitive Paths:</b>", STYLES["h3"]))
        rows = []
        for ep in exposed[:30]:
            sev_col = SEV_COLOR.get(ep.get("severity","Medium"), C_YELLOW)
            rows.append([
                Paragraph(ep.get("path",""), STYLES["body_small"]),
                Paragraph(str(ep.get("status","")), STYLES["body_small"]),
                Paragraph(ep.get("severity",""), STYLES["body_small"]),
            ])
        t = finding_table(rows, [8*cm, 2*cm, 2.5*cm],
                          ["Path", "HTTP Status", "Severity"])
        story.append(t)
        story.append(Spacer(1, 6))

    # JS Secrets
    if secrets:
        story.append(Paragraph(f"<b>⚠ JavaScript Secrets ({len(secrets)} found):</b>",
                               STYLES["h3"]))
        rows = []
        for s in secrets[:20]:
            rows.append([
                Paragraph(s.get("type",""), STYLES["body_small"]),
                Paragraph(s.get("value","")[:40] + "…", STYLES["body_small"]),
                Paragraph(s.get("source",""), STYLES["body_small"]),
            ])
        t = finding_table(rows, [4.5*cm, 6*cm, 6*cm],
                          ["Secret Type", "Value Preview", "Source File"])
        story.append(t)

    return story


# ── Section: Supply Chain ─────────────────────────────────────────────────────

def _supply_chain_section(results: Dict) -> List:
    story = []
    story += section_header("Supply Chain & Third-Party Risk",
                             "External JavaScript libraries with known CVEs (OSV.dev enriched)")

    sc_r  = results.get("supply_chain", {}).get("results", {})
    risks = sc_r.get("risks", [])

    if not risks:
        story.append(Paragraph("No vulnerable third-party dependencies detected.", STYLES["body"]))
        return story

    rows = []
    for r in risks[:30]:
        cve_str = ", ".join(r.get("cve_ids", [])) or r.get("osv_id","") or "–"
        rows.append([
            Paragraph(r.get("library","")[:25], STYLES["body_small"]),
            Paragraph(r.get("severity",""), STYLES["body_small"]),
            Paragraph(str(r.get("cvss","")), STYLES["body_small"]),
            Paragraph(cve_str[:30], STYLES["body_small"]),
            Paragraph(r.get("reason","")[:60], STYLES["body_small"]),
        ])
    t = finding_table(rows, [4*cm, 2*cm, 1.5*cm, 3.5*cm, 5.5*cm],
                      ["Library", "Severity", "CVSS", "CVE / OSV ID", "Reason"])
    story.append(t)
    return story


# ── Section: Dark Web ─────────────────────────────────────────────────────────

def _dark_web_section(results: Dict) -> List:
    story = []
    story += section_header("Dark Web & Breach Intelligence",
                             "HaveIBeenPwned breach records and Ahmia dark-web mentions")

    dw_r = results.get("dark_web", {}).get("results", {})
    hibp = dw_r.get("hibp", [])
    ahmia = dw_r.get("ahmia", [])

    if hibp:
        story.append(Paragraph(f"<b>Data Breaches ({len(hibp)}):</b>", STYLES["h3"]))
        rows = []
        for b in hibp[:20]:
            rows.append([
                Paragraph(b.get("title",""), STYLES["body_small"]),
                Paragraph(b.get("breach_date",""), STYLES["body_small"]),
                Paragraph(", ".join(b.get("data_classes",[]))[:60], STYLES["body_small"]),
            ])
        t = finding_table(rows, [4*cm, 2.5*cm, 10*cm],
                          ["Breach", "Date", "Exposed Data Types"])
        story.append(t)
        story.append(Spacer(1, 6))

    if ahmia:
        story.append(Paragraph(f"<b>Dark Web Mentions ({len(ahmia)}):</b>", STYLES["h3"]))
        for m in ahmia[:10]:
            story.append(Paragraph(f"• {m.get('title','')} — {m.get('risk','')}",
                                   STYLES["body_small"]))
    if not hibp and not ahmia:
        story.append(Paragraph("No dark web or breach intelligence hits found.", STYLES["body"]))

    return story


# ── Section: OSINT ────────────────────────────────────────────────────────────

def _osint_section(results: Dict) -> List:
    story = []
    story += section_header("Passive OSINT & Threat Intelligence",
                             "MISP IOC attributes and Shodan-confirmed vulnerabilities")

    osint_r = results.get("osint", {}).get("results", {})
    shodan  = osint_r.get("shodan_cve_findings", [])
    misp    = osint_r.get("misp", [])

    if shodan:
        story.append(Paragraph(f"<b>Shodan CVE Findings ({len(shodan)}):</b>", STYLES["h3"]))
        rows = []
        for s in shodan[:20]:
            rows.append([
                Paragraph(s.get("vulnerability",""), STYLES["body_small"]),
                Paragraph(str(s.get("cvss","")), STYLES["body_small"]),
                Paragraph(s.get("severity",""), STYLES["body_small"]),
                Paragraph(f"{s.get('ip','')}:{s.get('port','')}", STYLES["body_small"]),
                Paragraph(s.get("description","")[:60], STYLES["body_small"]),
            ])
        t = finding_table(rows, [3*cm, 1.5*cm, 2*cm, 3.5*cm, 6.5*cm],
                          ["CVE", "CVSS", "Severity", "IP:Port", "Description"])
        story.append(t)
        story.append(Spacer(1, 6))

    if misp:
        story.append(Paragraph(f"<b>MISP Threat Intelligence ({len(misp)} attributes):</b>",
                               STYLES["h3"]))
        for attr in misp[:10]:
            story.append(Paragraph(
                f"• [{attr.get('type','')}] {attr.get('value','')} — "
                f"{attr.get('category','')}",
                STYLES["body_small"]))

    if not shodan and not misp:
        story.append(Paragraph("No OSINT or threat intelligence hits found.", STYLES["body"]))

    return story


# ── Main builder ──────────────────────────────────────────────────────────────

def generate_technical_report(portal_json: Dict[str, Any],
                               output_path: str) -> str:
    """
    Generate a technical PDF report from a cy_asm portal JSON payload.
    Returns the path to the saved PDF file.
    """
    meta        = portal_json.get("meta", {})
    domain      = meta.get("domain", "unknown")
    org         = meta.get("org", "Unknown Organisation")
    scan_id     = meta.get("scan_id", "ASM-0000")
    scan_date   = meta.get("last_scan", datetime.now().isoformat())[:10]

    assets  = portal_json.get("assets", [{}])
    asset   = assets[0] if assets else {}
    all_f   = asset.get("vulnerabilities", [])
    results = asset.get("raw_results", {})

    sub_summary = portal_json.get("subdomain_summary", {})

    ssl_r    = results.get("crypto", {}).get("results", {}).get("ssl", {})
    email_r  = results.get("email_sec", {}).get("results", {})
    score, grade = compute_posture_score(
        all_f,
        sub_summary.get("total", 0),
        ssl_r.get("ssl_enabled", False),
        email_r.get("elite_status", ""),
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    doc = CyCentraDocTemplate(
        output_path,
        report_type="Technical",
        domain=domain,
        scan_id=scan_id,
        pagesize=(595.28, 841.89),
        leftMargin=0, rightMargin=0, topMargin=0, bottomMargin=0,
    )

    story = []

    # Cover
    story += build_cover("Technical", domain, org, scan_id, scan_date, score, grade)
    story.append(NextPageTemplate("Content"))
    story.append(PageBreak())

    # Sections
    story += _scan_metadata(meta, score, grade, sub_summary)
    story.append(PageBreak())

    story += _all_findings_section(all_f)
    story.append(PageBreak())

    story += _module_breakdown(all_f, results)
    story.append(PageBreak())

    story += _subdomain_section(results, sub_summary)
    story.append(PageBreak())

    story += _dns_section(results)
    story.append(PageBreak())

    story += _ssl_section(results)
    story.append(PageBreak())

    story += _email_section(results)
    story.append(PageBreak())

    story += _cloud_section(results)
    story.append(PageBreak())

    story += _web_section(results)
    story.append(PageBreak())

    story += _supply_chain_section(results)
    story.append(PageBreak())

    story += _dark_web_section(results)
    story.append(PageBreak())

    story += _osint_section(results)

    doc.multiBuild(story)
    return output_path
