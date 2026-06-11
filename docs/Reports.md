# CyCentra ASM — PDF Report Generator

## Overview

Generates two professional PDF reports after every scan:

| Report | Audience | Focus |
|--------|----------|-------|
| **Executive** | C-Suite, CISO, Board | Security posture score, business risk, top priorities, compliance mapping |
| **Technical** | Security engineers, IT | All findings with CVE/CVSS detail, module breakdown, subdomain inventory, remediation steps |

## Directory Structure

```
cy_asm/
└── reporting/
    ├── __init__.py
    ├── charts.py              # Chart/graph engine (matplotlib)
    ├── pdf_base.py            # Shared styles, templates, helpers
    ├── executive_report.py    # Executive report builder
    ├── technical_report.py    # Technical report builder
    ├── generate_reports.py    # Entry point + demo data generator
    ├── INTEGRATION_PATCH.py   # 5-line patch for cycentra_scan.py
    └── README.md
```

## Output Location

```
/var/log/cycentra/cy-asm/reports/<tenant_id>/
    executive_<domain>_<timestamp>.pdf
    technical_<domain>_<timestamp>.pdf
```

Override with env var:
```bash
export CYCENTRA_REPORT_DIR=/custom/path
```

## Standalone Usage

```bash
# With a real portal JSON:
python3 reporting/generate_reports.py /var/log/cycentra/cy-asm/scans/<tenant>/scan_domain_1234.json

# Demo reports (no scan needed):
python3 reporting/generate_reports.py example.com
```

## Integration with cycentra_scan.py

Add 5 lines to `cycentra_scan.py` after the portal JSON is saved
(see `INTEGRATION_PATCH.py` for exact location):

```python
try:
    from reporting.generate_reports import hook_into_scan
    hook_into_scan(portal_payload, final_tenant_id, domain, timestamp)
except Exception as _rpt_err:
    logger.warning(f"⚠️ [Reports] PDF generation failed (scan unaffected): {_rpt_err}")
```

## Dependencies

All required packages are standard Python and available via pip:

```bash
pip install reportlab matplotlib numpy pillow --break-system-packages
```

## Report Contents

### Executive Report
1. **Cover Page** — Domain, score, grade, scan metadata
2. **Executive Summary** — KPI strip (score, critical/high/medium count)
3. **Security Posture Overview** — Gauge chart + radar chart
4. **Risk Breakdown** — Severity pie, CVSS histogram, impact table
5. **Top 10 Risk Findings** — Business narrative, impact, recommended action
6. **Infrastructure Overview** — World map, subdomain bar, cloud providers
7. **Email & SSL Security** — Control check bars, SSL donut
8. **Regulatory Compliance** — NIS2/DORA/ISO 27001 mapping table
9. **Strategic Recommendations** — Immediate / short-term / strategic actions

### Technical Report
1. **Cover Page** — Same branded cover, "Technical" label
2. **Scan Metadata** — Parameters table
3. **Complete Findings Register** — All findings with CVE, CVSS, EPSS, compliance tags
4. **Module-by-Module Analysis** — Bar chart + per-module summaries
5. **Subdomain Inventory** — Full table with live/historical/new/IP/sources
6. **DNS Records & Typosquatting** — Record table + registered typosquats
7. **SSL/TLS Deep Dive** — Full cert details, cipher, PQC status
8. **Email Security Controls** — SPF/DMARC/DKIM/MTA-STS/BIMI records + scoring
9. **Cloud Infrastructure** — Bucket table with risk level
10. **Web & Port Analysis** — Open ports, banners, exposed paths, JS secrets
11. **Supply Chain Risk** — Vulnerable libraries with OSV/CVE data
12. **Dark Web & Breach Intelligence** — HIBP breaches, Ahmia mentions
13. **Passive OSINT** — Shodan CVEs, MISP attributes

## Security Posture Score

Calculated from 0–100:

| Deduction | Per Item | Cap |
|-----------|----------|-----|
| Critical finding | -12 | -48 |
| High finding | -6 | -30 |
| Medium finding | -2 | -16 |
| Low finding | -0.5 | -5 |
| SSL issues | -10 | — |
| Weak email | -5 | — |
| SSL OK bonus | +5 | — |
| Elite email bonus | +3 | — |

Grades: A+ ≥90 · A ≥80 · B ≥70 · C ≥55 · D ≥35 · F <35
