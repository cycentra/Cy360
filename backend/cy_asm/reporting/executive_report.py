"""
reporting/executive_report.py
CyCentra ASM — Executive Security Posture Report

Audience: C-Suite, Board, CISO, Risk Committee
Language: Business-level, no raw CVE IDs
Emphasis: Risk exposure, business impact, posture score, top priorities
Charts: Gauge, pie, radar, world map, KPI strip
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import (
    Image, KeepTogether, PageBreak, Paragraph, Spacer, Table, TableStyle,
)

from .charts import (
    posture_gauge, severity_pie, radar_chart, world_map,
    subdomain_bar, ssl_donut, email_score_bar, cvss_histogram,
)
from .pdf_base import (
    BODY_W, C_BLUE, C_BORDER, C_GREEN, C_LIGHT, C_MID, C_NAVY, C_ORANGE,
    C_RED, C_SKY, C_SUBTLE, C_TEXT, C_YELLOW, MARGIN, SEV_COLOR, STYLES, W,
    CyCentraDocTemplate, build_cover, compute_posture_score,
    extract_domain_scores, finding_table, img_from_bytes, metric_card,
    rule, section_header, severity_badge,
)


# ── AI-style risk narrative helpers ──────────────────────────────────────────

_CRITICAL_NARRATIVES = {
    "default": (
        "A critical-severity finding poses an immediate threat to the confidentiality, "
        "integrity, or availability of business assets. Exploitation by a threat actor — "
        "including automated scanning tools that probe the internet continuously — could "
        "result in full system compromise, data exfiltration, or service disruption. "
        "These findings require emergency remediation, typically within 24-48 hours."
    ),
    "ssl": (
        "The SSL/TLS configuration does not meet current security standards. "
        "An attacker in a privileged network position could decrypt traffic, "
        "intercept credentials, or redirect users to malicious sites. "
        "This finding directly impacts customer trust and regulatory compliance under NIS2 and GDPR."
    ),
    "exposure": (
        "Sensitive data or administrative interfaces have been discovered on the public internet. "
        "These represent a direct entry point for attackers. Automated scanning tools will have "
        "already identified these paths. Immediate removal or access restriction is required."
    ),
    "credential": (
        "Credentials or API keys were found exposed in client-accessible resources. "
        "This gives any actor who finds them the same level of access as internal staff. "
        "All exposed credentials should be rotated immediately and access logs reviewed."
    ),
}

def _get_narrative(vuln: str, sev: str) -> str:
    v = vuln.lower()
    if any(k in v for k in ("ssl", "tls", "cert", "crypto")):
        return _CRITICAL_NARRATIVES["ssl"]
    if any(k in v for k in ("secret", "key", "token", "credential", "password")):
        return _CRITICAL_NARRATIVES["credential"]
    if any(k in v for k in ("exposed", "path", "admin", "git", "env", "backup")):
        return _CRITICAL_NARRATIVES["exposure"]
    return _CRITICAL_NARRATIVES["default"]

_BUSINESS_IMPACT = {
    "Critical": "Immediate business disruption risk. Potential for significant financial loss, regulatory penalties, and reputational damage.",
    "High":     "Elevated risk of breach. Could enable attackers to gain a foothold and escalate within the environment.",
    "Medium":   "Moderate risk. Contributes to the attack surface; combination with other vulnerabilities increases overall exposure.",
    "Low":      "Limited direct impact. Best-practice remediation recommended to reduce overall attack surface.",
}

_REMEDIATION_PRIORITY = {
    "Critical": "Emergency — within 24 hours",
    "High":     "Urgent — within 7 days",
    "Medium":   "Scheduled — within 30 days",
    "Low":      "Planned — within 90 days",
}


# ── Section builders ──────────────────────────────────────────────────────────

def _exec_summary(data: Dict, score: int, grade: str, styles) -> List:
    story = []
    story += section_header("Executive Summary")

    all_f   = data.get("all_findings", [])
    crit_n  = sum(1 for f in all_f if str(f.get("severity","")).lower() == "critical")
    high_n  = sum(1 for f in all_f if str(f.get("severity","")).lower() == "high")
    med_n   = sum(1 for f in all_f if str(f.get("severity","")).lower() == "medium")
    low_n   = sum(1 for f in all_f if str(f.get("severity","")).lower() == "low")
    domain  = data.get("domain", "")

    intro = (
        f"This report presents the results of an automated External Attack Surface Management "
        f"(EASM) scan performed against <b>{domain}</b>. The assessment covers DNS configuration, "
        f"SSL/TLS posture, subdomain exposure, cloud storage, email security controls, "
        f"web application surface, supply chain risk, and publicly known vulnerabilities. "
        f"A total of <b>{len(all_f)} findings</b> were identified across all domains and assets."
    )
    story.append(Paragraph(intro, styles["body"]))
    story.append(Spacer(1, 10))

    # KPI strip
    cards = [
        metric_card(str(score),    "Posture Score",      C_RED if score < 50 else C_ORANGE if score < 70 else C_GREEN),
        metric_card(str(crit_n),   "Critical Findings",  C_RED if crit_n else C_GREEN),
        metric_card(str(high_n),   "High Findings",      C_ORANGE if high_n else C_GREEN),
        metric_card(str(med_n),    "Medium Findings",    C_YELLOW if med_n else C_GREEN),
        metric_card(str(len(all_f)), "Total Issues",     C_NAVY),
    ]
    cards_row = Table([cards], colWidths=[3.8 * cm] * 5,
                      hAlign="CENTER")
    cards_row.setStyle(TableStyle([
        ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",  (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(cards_row)
    story.append(Spacer(1, 12))

    # Posture narrative
    if score >= 80:
        posture_text = (
            f"The organisation's external security posture is rated <b>Strong (Grade {grade})</b>. "
            f"The majority of critical controls are in place. Continued improvement is recommended "
            f"in the areas highlighted in this report."
        )
    elif score >= 60:
        posture_text = (
            f"The organisation's external security posture is rated <b>Moderate (Grade {grade})</b>. "
            f"Several significant gaps have been identified that, if exploited, could lead to "
            f"a material security incident. Prioritised remediation is strongly recommended."
        )
    else:
        posture_text = (
            f"The organisation's external security posture is rated <b>Weak (Grade {grade})</b>. "
            f"Multiple critical and high-severity vulnerabilities were identified. "
            f"The current exposure level represents an elevated risk of compromise. "
            f"Immediate executive attention and resource allocation is required."
        )
    story.append(Paragraph(posture_text, styles["body"]))
    return story


def _posture_visual(score: int, results: Dict) -> List:
    story = []
    story += section_header("Security Posture Overview",
                             "Visual summary of the organisation's external attack surface score and domain breakdown")

    # Gauge + Radar side by side
    gauge_buf  = posture_gauge(score, "Overall Score")
    radar_data = extract_domain_scores(results)
    radar_buf  = radar_chart(radar_data)

    row = Table(
        [[img_from_bytes(gauge_buf, 7.5 * cm), img_from_bytes(radar_buf, 7.5 * cm)]],
        colWidths=[BODY_W / 2, BODY_W / 2],
    )
    row.setStyle(TableStyle([
        ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(row)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Left: Overall security posture score (0-100). "
        "Right: Per-domain security scores — outer edge = 100% (ideal).",
        STYLES["caption"]))
    return story


def _risk_breakdown(all_f: List[Dict]) -> List:
    story = []
    story += section_header("Risk Breakdown",
                             "Distribution of findings by severity and risk impact")

    counts = {
        "Critical": sum(1 for f in all_f if str(f.get("severity","")).lower() == "critical"),
        "High":     sum(1 for f in all_f if str(f.get("severity","")).lower() == "high"),
        "Medium":   sum(1 for f in all_f if str(f.get("severity","")).lower() == "medium"),
        "Low":      sum(1 for f in all_f if str(f.get("severity","")).lower() == "low"),
        "Info":     sum(1 for f in all_f if str(f.get("severity","")).lower() in ("info","informational")),
    }

    pie_buf  = severity_pie(counts)
    hist_buf = cvss_histogram(all_f)

    row = Table(
        [[img_from_bytes(pie_buf, BODY_W * 0.46), img_from_bytes(hist_buf, BODY_W * 0.46)]],
        colWidths=[BODY_W * 0.5, BODY_W * 0.5],
    )
    row.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"),
                              ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(row)
    story.append(Spacer(1, 6))

    # Risk table
    sev_rows = []
    for sev, count in counts.items():
        if count == 0:
            continue
        sev_rows.append([
            Paragraph(f"<b>{sev}</b>", STYLES["body"]),
            Paragraph(str(count), STYLES["body"]),
            Paragraph(_BUSINESS_IMPACT.get(sev, ""), STYLES["body_small"]),
            Paragraph(_REMEDIATION_PRIORITY.get(sev, ""), STYLES["body_small"]),
        ])
    if sev_rows:
        t = finding_table(sev_rows,
                          [2.5*cm, 1.5*cm, 8*cm, 4.5*cm],
                          ["Severity", "Count", "Business Impact", "Remediation Timeline"])
        # Colour severity cells
        for i, row_data in enumerate(sev_rows, 1):
            sev_text = row_data[0].text if hasattr(row_data[0], 'text') else ""
            sev_key  = [k for k in SEV_COLOR if k in str(sev_rows[i-1][0])]
            if sev_key:
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, i), (0, i), SEV_COLOR[sev_key[0]]),
                    ("TEXTCOLOR",  (0, i), (0, i), colors.white),
                ]))
        story.append(t)
    return story


def _top_risks(all_f: List[Dict]) -> List:
    story = []
    story += section_header("Top 10 Risk Findings",
                             "Highest-priority findings ranked by risk score — business context and recommended actions")

    sorted_f = sorted(all_f, key=lambda x: x.get("risk_score", 0), reverse=True)[:10]

    for i, f in enumerate(sorted_f, 1):
        sev   = f.get("severity", "Medium")
        vuln  = f.get("vulnerability", "Unknown Finding")
        score = f.get("risk_score", 5)
        mod   = f.get("module", "scan")
        rec   = f.get("recommendation", "Review and remediate according to vendor guidance.")
        narrative = _get_narrative(vuln, sev)

        items = [
            Table(
                [[
                    Paragraph(f"<b>{i}. {vuln[:60]}</b>", STYLES["finding_title"]),
                    severity_badge(sev),
                    Paragraph(f"Risk: {score}/10", STYLES["body_small"]),
                ]],
                colWidths=[BODY_W - 4.5*cm, 2*cm, 2.2*cm],
            ),
            Paragraph(f"<b>Business Risk:</b> {narrative}", STYLES["body"]),
            Paragraph(f"<b>Impact:</b> {_BUSINESS_IMPACT.get(sev, '')}", STYLES["body"]),
            Paragraph(f"<b>Recommended Action:</b> {rec}", STYLES["body"]),
            Paragraph(f"<i>Module: {mod}  |  Priority: {_REMEDIATION_PRIORITY.get(sev,'')}</i>",
                      STYLES["body_small"]),
            rule(C_BORDER, space_before=4, space_after=4),
        ]
        story.append(KeepTogether(items))

    return story


def _infrastructure_section(results: Dict) -> List:
    story = []
    story += section_header("Infrastructure Overview",
                             "Geographic distribution, cloud presence, and subdomain footprint")

    # World map
    dns_ips = results.get("dns", {}).get("results", {}).get("ips", [])
    country_counts: Dict[str, int] = {}
    for ip_info in dns_ips:
        cc = ip_info.get("country", "")
        if cc and len(cc) == 2:
            country_counts[cc.upper()] = country_counts.get(cc.upper(), 0) + 1
    if country_counts:
        map_buf = world_map(country_counts)
        story.append(img_from_bytes(map_buf, BODY_W))
        story.append(Paragraph("Figure: Detected infrastructure geographic distribution.",
                               STYLES["caption"]))
        story.append(Spacer(1, 8))

    # Subdomain bar
    sub_data = results.get("subdomains", {})
    live  = sub_data.get("subdomain_summary", {}).get("live", 0) or \
            results.get("live_subdomains", 0)
    hist  = sub_data.get("subdomain_summary", {}).get("historical", 0) or \
            results.get("historical_subdomains", 0)
    new_s = sub_data.get("subdomain_summary", {}).get("new", 0) or \
            results.get("new_subdomains", 0)

    if live + hist > 0:
        sub_buf = subdomain_bar(live, hist, new_s)
        story.append(img_from_bytes(sub_buf, 7 * cm))
        story.append(Paragraph("Figure: Subdomain status breakdown.", STYLES["caption"]))
        story.append(Spacer(1, 8))

    # Cloud providers
    providers = results.get("results", {}).get("cloud", {}).get("results", {}).get("providers", [])
    if providers:
        story.append(Paragraph(
            f"<b>Cloud Providers Detected:</b> {', '.join(providers)}",
            STYLES["body"]))

    return story


def _email_ssl_section(results: Dict) -> List:
    story = []
    story += section_header("Email & SSL Security",
                             "Email authentication controls and certificate posture")

    email_r  = results.get("results", {}).get("email_sec", {}).get("results", {})
    ssl_r    = results.get("results", {}).get("crypto", {}).get("results", {}).get("ssl", {})

    # Email controls
    checks = {
        "SPF":      email_r.get("spf",   {}).get("present", False),
        "DMARC":    email_r.get("dmarc", {}).get("present", False),
        "DKIM":     bool(email_r.get("dkim", [])),
        "DNSSEC":   email_r.get("dnssec", {}).get("enabled", False),
        "MTA-STS":  email_r.get("elite_checks", {}).get("mta_sts", {}).get("status") == "pass",
        "BIMI":     email_r.get("elite_checks", {}).get("bimi", {}).get("status") == "pass",
        "TLS-RPT":  email_r.get("elite_checks", {}).get("tls_rpt", {}).get("status") == "pass",
        "CAA":      bool(email_r.get("elite_checks", {}).get("caa_ssl", {}).get("caa_records", [])),
    }
    score_str = email_r.get("elite_score", "?/8")
    email_buf = email_score_bar(score_str, checks)

    # SSL
    cert_info = ssl_r.get("cert_info", {})
    ssl_ok    = ssl_r.get("ssl_enabled", False)
    days_left = cert_info.get("days_to_expiry")
    chain_ok  = cert_info.get("chain_valid", False)
    san_ok    = cert_info.get("san_valid", False)
    ssl_buf   = ssl_donut(ssl_ok, days_left, chain_ok, san_ok)

    row = Table(
        [[img_from_bytes(email_buf, BODY_W * 0.52), img_from_bytes(ssl_buf, BODY_W * 0.44)]],
        colWidths=[BODY_W * 0.54, BODY_W * 0.46],
    )
    row.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"),
                              ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(row)
    return story


def _compliance_section() -> List:
    story = []
    story += section_header("Regulatory Compliance Alignment",
                             "Mapping of findings to NIS2, DORA, and ISO 27001 control requirements")

    intro = (
        "The findings identified in this report have been mapped to the relevant articles "
        "of the NIS2 Directive (EU 2022/2555), the DORA Regulation (EU 2022/2554), and "
        "ISO/IEC 27001:2022 Annex A controls. This mapping provides a framework for "
        "prioritising remediation from a regulatory risk perspective."
    )
    story.append(Paragraph(intro, STYLES["body"]))
    story.append(Spacer(1, 8))

    rows = [
        ["SSL/TLS",       "Art.21.2.h", "Art.9.2",  "A.8.24", "Encryption & channel security"],
        ["Exposed Paths", "Art.21.2.e", "Art.9.4",  "A.8.3",  "Access control & exposure"],
        ["Secrets/Keys",  "Art.21.2.d", "Art.9.3",  "A.8.12", "Secrets management"],
        ["CVE Patching",  "Art.21.2.e", "Art.7.2",  "A.8.8",  "Vulnerability management"],
        ["Email Auth",    "Art.21.2.h", "Art.9.2",  "A.8.24", "Anti-spoofing / authentication"],
        ["DNS Security",  "Art.21.2.e", "Art.9.4",  "A.8.3",  "DNS hygiene & DNSSEC"],
        ["Cloud Storage", "Art.21.2.e", "Art.9.4",  "A.8.9",  "Cloud configuration management"],
    ]
    t = finding_table(rows, [3.5*cm, 2.5*cm, 2.5*cm, 2.5*cm, 5.5*cm],
                      ["Finding Category", "NIS2", "DORA", "ISO 27001", "Control Description"])
    story.append(t)
    return story


def _recommendations_section(all_f: List[Dict]) -> List:
    story = []
    story += section_header("Strategic Recommendations",
                             "Prioritised actions for leadership review and resource allocation")

    crit_f = [f for f in all_f if str(f.get("severity","")).lower() == "critical"]
    high_f = [f for f in all_f if str(f.get("severity","")).lower() == "high"]

    immediate = []
    for f in crit_f[:5]:
        immediate.append(f"Remediate: <b>{f.get('vulnerability','')[:50]}</b> — {f.get('recommendation','')[:120]}")
    if not immediate:
        immediate.append("No critical findings — maintain current controls and schedule regular scans.")

    short_term = []
    for f in high_f[:5]:
        short_term.append(f"Address: <b>{f.get('vulnerability','')[:50]}</b> — {f.get('recommendation','')[:120]}")
    if not short_term:
        short_term.append("No high-severity findings — review medium findings for risk-based prioritisation.")

    story.append(Paragraph("<b>Immediate Actions (0-48 hours):</b>", STYLES["h3"]))
    for item in immediate:
        story.append(Paragraph(item, STYLES["bullet"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>Short-Term Actions (7-30 days):</b>", STYLES["h3"]))
    for item in short_term:
        story.append(Paragraph(item, STYLES["bullet"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>Strategic Investments (30-90 days):</b>", STYLES["h3"]))
    strategic = [
        "Implement a continuous External Attack Surface Management (EASM) programme.",
        "Adopt a formal patch management process with SLA-based CVSS severity thresholds.",
        "Enforce certificate lifecycle management automation (ACME/Let's Encrypt or equivalent).",
        "Conduct quarterly third-party penetration testing of critical exposed assets.",
        "Evaluate Post-Quantum Cryptography (PQC) readiness for TLS infrastructure.",
    ]
    for item in strategic:
        story.append(Paragraph(item, STYLES["bullet"]))

    return story


# ── Main builder ──────────────────────────────────────────────────────────────

def generate_executive_report(portal_json: Dict[str, Any],
                               output_path: str) -> str:
    """
    Generate an executive PDF report from a cy_asm portal JSON payload.
    Returns the path to the saved PDF file.
    """
    meta      = portal_json.get("meta", {})
    domain    = meta.get("domain", "unknown")
    org       = meta.get("org", "Unknown Organisation")
    scan_id   = meta.get("scan_id", "ASM-0000")
    scan_date = meta.get("last_scan", datetime.now().isoformat())[:10]
    scan_type = meta.get("scan_type", "standard")

    assets    = portal_json.get("assets", [{}])
    asset     = assets[0] if assets else {}
    all_f     = asset.get("vulnerabilities", [])
    results   = asset.get("raw_results", {})

    sub_summary = portal_json.get("subdomain_summary", {})

    # Flatten results for helpers
    flat = {
        "domain":               domain,
        "all_findings":         all_f,
        "live_subdomains":      sub_summary.get("live", 0),
        "historical_subdomains": sub_summary.get("historical", 0),
        "new_subdomains":       sub_summary.get("new", 0),
        "results":              results,
    }

    ssl_r       = results.get("crypto", {}).get("results", {}).get("ssl", {})
    email_r     = results.get("email_sec", {}).get("results", {})
    score, grade = compute_posture_score(
        all_f,
        sub_summary.get("total", 0),
        ssl_r.get("ssl_enabled", False),
        email_r.get("elite_status", ""),
    )

    # Build PDF
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    doc = CyCentraDocTemplate(
        output_path,
        report_type="Executive",
        domain=domain,
        scan_id=scan_id,
        pagesize=(595.28, 841.89),
        leftMargin=0, rightMargin=0, topMargin=0, bottomMargin=0,
    )

    story = []

    # Cover
    story += build_cover("Executive", domain, org, scan_id, scan_date, score, grade)

    # Switch to content template
    from reportlab.platypus import NextPageTemplate
    story.append(NextPageTemplate("Content"))
    story.append(PageBreak())

    # Sections
    story += _exec_summary(flat, score, grade, STYLES)
    story.append(PageBreak())

    story += _posture_visual(score, flat)
    story.append(PageBreak())

    story += _risk_breakdown(all_f)
    story.append(PageBreak())

    story += _top_risks(all_f)
    story.append(PageBreak())

    story += _infrastructure_section(flat)
    story.append(PageBreak())

    story += _email_ssl_section(flat)
    story.append(PageBreak())

    story += _compliance_section()
    story.append(PageBreak())

    story += _recommendations_section(all_f)

    doc.multiBuild(story)
    return output_path
