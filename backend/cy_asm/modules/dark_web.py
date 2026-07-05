# modules/dark_web.py
import asyncio
from typing import Dict, List, Any
from utils import setup_logging

logger = setup_logging()


async def gather_dark_web(domain: str, subdomains: List[str] = None) -> Dict[str, Any]:
    """
    Dark web scan for a domain via CyTIM centralized enrichment.
    Ahmia (Tor search) and HIBP (breach records) run inside CyTIM.
    Toggle-controlled via CyTIM's darkweb_enabled setting.
    """
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
        from core.helpers import is_darkweb_enabled, cytim_darkweb_enrich
    except ImportError:
        logger.warning("[DARKWEB] CyTIM helpers not importable — dark web scan skipped.")
        return {
            "results": {"ahmia": [], "hibp": [], "summary": "CyTIM not available."},
            "issues": [],
            "summary": "Dark web scan skipped — CyTIM not available.",
            "skipped": "cytim_unavailable",
        }

    if not is_darkweb_enabled():
        logger.info("[DARKWEB] Dark web enrichment disabled in CyTIM — skipping scan for %s.", domain)
        return {
            "results": {"ahmia": [], "hibp": [], "summary": "Dark web enrichment disabled in CyTIM."},
            "issues": [],
            "summary": "Dark web scan skipped — disabled in CyTIM settings.",
            "skipped": "dark_web_enrichment_disabled",
        }

    logger.info("[DARKWEB] Querying CyTIM dark web enrichment for %s", domain)

    loop = asyncio.get_running_loop()
    dw_response = await loop.run_in_executor(
        None, lambda: cytim_darkweb_enrich([{"type": "domain", "value": domain}])
    )

    if not dw_response.get("enabled", False):
        return {
            "results": {"ahmia": [], "hibp": [], "summary": "Dark web enrichment disabled in CyTIM."},
            "issues": [],
            "summary": "Dark web scan skipped — disabled in CyTIM settings.",
            "skipped": "dark_web_enrichment_disabled",
        }

    results_list = dw_response.get("results", [])
    findings = results_list[0].get("findings", {}) if results_list else {}

    ahmia: list = findings.get("ahmia", [])
    hibp:  list = findings.get("hibp",  [])

    risk_lvl = "High" if (ahmia or hibp) else "Low"
    summary  = f"Dark Web: {len(ahmia)} mentions, {len(hibp)} breaches. Risk: {risk_lvl}."
    if not (ahmia or hibp):
        summary += " No findings."

    logger.info(summary)
    return {
        "results": {"ahmia": ahmia, "hibp": hibp, "summary": summary},
        "issues": [
            f"Dark Web: {m.get('risk_level', 'medium')} risk mention — {m.get('title', '')}"
            for m in ahmia
        ] + [
            f"Dark Web breach: {b.get('title', 'unknown')} ({b.get('breach_date', 'unknown')})"
            for b in hibp
        ],
        "summary": summary,
    }
