"""
modules/nuclei_scanner.py
CyCentra ASM — Nuclei Template Scanner

Wraps the Nuclei CLI (https://github.com/projectdiscovery/nuclei) to run
9,000+ community CVE/exposure/misconfiguration templates against a target.

Install:
  apt install nuclei
  OR go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

Gracefully skipped when nuclei is not on PATH — never blocks the pipeline.
"""
import asyncio
import json
import logging
import re
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger("cycentra.modules.nuclei_scanner")

_NUCLEI_SEVERITY_CVSS: Dict[str, float] = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     0.5,
    "unknown":  3.0,
}


def _nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def _extract_cve_ids(hit: dict) -> List[str]:
    classification = hit.get("info", {}).get("classification", {})
    cves = classification.get("cve-id", [])
    if isinstance(cves, list):
        return [c.upper() for c in cves if c]
    if isinstance(cves, str) and cves:
        return [cves.upper()]
    template = hit.get("template-id", "")
    if re.match(r"CVE-\d{4}-\d+", template.upper()):
        return [template.upper()]
    return []


def _nuclei_cvss(hit: dict, sev_raw: str) -> float:
    score = hit.get("info", {}).get("classification", {}).get("cvss-score")
    if score is not None:
        try:
            return float(score)
        except (ValueError, TypeError):
            pass
    return _NUCLEI_SEVERITY_CVSS.get(sev_raw, 3.0)


async def run_nuclei_scan(domain: str, timeout: int = 300) -> List[Dict[str, Any]]:
    """
    Run nuclei against domain using cve, exposure, and misconfiguration tags.
    Returns normalised findings compatible with the cy_asm pipeline.
    """
    if not _nuclei_available():
        logger.info(
            "[Nuclei] nuclei not found on PATH — skipping. "
            "Install: apt install nuclei"
        )
        return []

    cmd = [
        "nuclei",
        "-u", f"https://{domain}",
        "-tags", "cve,exposure,misconfiguration",
        "-json",
        "-silent",
        "-timeout", "10",
        "-rate-limit", "50",
        "-no-color",
    ]

    logger.info(f"[Nuclei] Starting scan for {domain}...")
    findings: List[Dict[str, Any]] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning(f"[Nuclei] Scan timed out after {timeout}s for {domain}.")
            return findings

        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue

            sev_raw  = hit.get("info", {}).get("severity", "unknown").lower()
            cvss     = _nuclei_cvss(hit, sev_raw)
            cve_ids  = _extract_cve_ids(hit)
            template = hit.get("template-id", "nuclei-finding")
            desc     = (
                hit.get("info", {}).get("description", "")
                or f"Nuclei template {template} matched at {hit.get('matched-at', '')}"
            )

            findings.append({
                "vulnerability":  cve_ids[0] if cve_ids else template,
                "module":         "nuclei_scanner",
                "source":         "nuclei",
                "template_id":    template,
                "cve_refs":       cve_ids,
                "cvss":           cvss,
                "epss":           0.0,
                "severity":       sev_raw.capitalize(),
                "risk_score":     max(1, min(10, round(cvss))),
                "description":    desc[:300],
                "recommendation": (
                    hit.get("info", {}).get("remediation")
                    or f"Review and remediate nuclei finding: {template}."
                ),
                "matched_at":     hit.get("matched-at", ""),
                "domain":         domain,
                "discovered_at":  datetime.now(timezone.utc).isoformat(),
            })

    except FileNotFoundError:
        logger.error("[Nuclei] nuclei binary not found — ensure it is on PATH.")
    except Exception as e:
        logger.error(f"[Nuclei] Scan failed for {domain}: {type(e).__name__}: {e}")

    logger.info(f"[Nuclei] Found {len(findings)} finding(s) for {domain}.")
    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


async def gather_nuclei_scanner(domain: str) -> Dict[str, Any]:
    """Standard cy_asm module entry point. Returns {results, issues, summary}."""
    findings       = await run_nuclei_scan(domain)
    critical_count = sum(1 for f in findings if f["severity"].lower() == "critical")
    high_count     = sum(1 for f in findings if f["severity"].lower() == "high")

    issues = [
        f"{f['severity']} — {f['vulnerability']}: {f['description'][:80]}"
        for f in findings
        if f["severity"].lower() in ("critical", "high")
    ]
    summary = (
        f"Nuclei: {len(findings)} finding(s) "
        f"({critical_count} critical, {high_count} high)"
    )
    logger.info(f"[Nuclei] {summary}")

    return {
        "results": {
            "findings":       findings,
            "critical_count": critical_count,
            "high_count":     high_count,
            "total":          len(findings),
        },
        "issues":  issues,
        "summary": summary,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python modules/nuclei_scanner.py <domain>")
        sys.exit(1)
    result = asyncio.run(gather_nuclei_scanner(sys.argv[1].strip().lower()))
    print(json.dumps(result, indent=2, default=str))
