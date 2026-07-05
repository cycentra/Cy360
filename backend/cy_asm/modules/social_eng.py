"""
modules/social_eng.py
CyCentra ASM — Social Engineering Vectors Module

Enumerates exposed employee contact information that could be used
for phishing, spear-phishing, or BEC attacks. Data sources:
  1. Hunter.io domain search (via CyTIM /api/cytim/recon emails module)
  2. Email pattern inference from any discovered names
  3. LinkedIn public profile enumeration via Google dork
  4. Common corporate email format guessing

All sources are passive — no direct interaction with target mail servers.
"""

import aiohttp
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import HTTP_TIMEOUT
from utils import setup_logging, create_async_session

logger = setup_logging()

# ---------------------------------------------------------------------------
# Hunter.io domain search
# ---------------------------------------------------------------------------

def find_emails_cytim(domain: str) -> List[Dict[str, Any]]:
    """
    Query CyTIM /api/cytim/recon (emails module) for known email addresses at *domain*.
    Returns list of {email, first_name, last_name, position, confidence, source}.
    Falls back to [] if CyTIM is unavailable or unconfigured.
    """
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))
        from core.helpers import cytim_recon
        results = cytim_recon(domain, ["emails"])
        emails = results.get("emails") or []
        logger.info(f"[SocialEng] CyTIM emails recon returned {len(emails)} email(s) for {domain}.")
        return emails
    except Exception as e:
        logger.warning(f"[SocialEng] CyTIM email recon failed: {e}")
        return []


# ---------------------------------------------------------------------------
# Common email format guesser
# ---------------------------------------------------------------------------

_EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{first}@{domain}",
    "{f}{last}@{domain}",
    "{first}{last}@{domain}",
    "{first}_{last}@{domain}",
    "{last}@{domain}",
    "{last}.{first}@{domain}",
]

def generate_email_patterns(
    first: str,
    last: str,
    domain: str,
) -> List[str]:
    """Generate likely corporate email addresses from a name + domain."""
    if not first or not last:
        return []
    f = first[0].lower() if first else ""
    return [
        p.format(
            first=first.lower(),
            last=last.lower(),
            f=f,
            domain=domain,
        )
        for p in _EMAIL_PATTERNS
    ]


# ---------------------------------------------------------------------------
# Google dork for LinkedIn profiles (passive, no LinkedIn API needed)
# ---------------------------------------------------------------------------

async def find_linkedin_profiles(
    domain: str,
    session: aiohttp.ClientSession,
) -> List[Dict[str, str]]:
    """
    Use a Google dork to find LinkedIn employee profiles for the company
    behind *domain*. Returns list of {name, title, url}.

    Note: Google may return a CAPTCHA for automated requests. This is a
    best-effort passive check — failures are logged, not raised.
    """
    company = domain.split(".")[0]
    dork    = f'site:linkedin.com/in "{company}" employee'
    url     = f"https://www.google.com/search?q={quote_plus(dork)}&num=10"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    profiles: List[Dict[str, str]] = []
    try:
        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=12),
            allow_redirects=True,
        ) as resp:
            if resp.status == 200:
                text = await resp.text()
                # Extract LinkedIn profile URLs
                li_urls = re.findall(r'https://[a-z]+\.linkedin\.com/in/[a-zA-Z0-9_%-]+', text)
                # Try to extract name from title tags adjacent to URLs
                for li_url in list(set(li_urls))[:10]:
                    slug = li_url.rstrip("/").split("/")[-1].replace("-", " ").title()
                    profiles.append({
                        "url":    li_url,
                        "name":   slug,
                        "source": "google_dork",
                    })
                logger.info(f"[SocialEng] Google dork found {len(profiles)} LinkedIn profile(s).")
            elif resp.status == 429:
                logger.warning("[SocialEng] Google rate-limited LinkedIn dork.")
            elif resp.status == 403:
                logger.info("[SocialEng] Google blocked dork request (CAPTCHA/bot detection).")
    except Exception as e:
        logger.debug(f"[SocialEng] LinkedIn dork failed: {type(e).__name__}: {e}")
    return profiles


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------

def _assess_risk(emails: List[Dict], profiles: List[Dict]) -> Dict[str, Any]:
    """
    Assess overall BEC/phishing risk based on exposed intel.
    Returns {level, score, reasons}.
    """
    reasons = []
    score   = 0

    if len(emails) >= 10:
        score += 3
        reasons.append(f"{len(emails)} employee email addresses publicly enumerable")
    elif len(emails) >= 3:
        score += 2
        reasons.append(f"{len(emails)} employee email addresses found")
    elif emails:
        score += 1
        reasons.append(f"{len(emails)} email address found")

    # High-value targets
    privileged_roles = ["ceo", "cfo", "cto", "ciso", "director", "head of", "vp", "president"]
    for e in emails:
        pos = e.get("position", "").lower()
        if any(r in pos for r in privileged_roles):
            score += 2
            reasons.append(f"Executive exposed: {e.get('first_name', '')} {e.get('last_name', '')} — {e.get('position', '')}")

    if profiles:
        score += 1
        reasons.append(f"{len(profiles)} LinkedIn profiles linkable to domain")

    level = "Critical" if score >= 5 else "High" if score >= 3 else "Medium" if score >= 1 else "Low"
    return {"level": level, "score": score, "reasons": reasons}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def gather_social_eng(domain: str) -> Dict[str, Any]:
    """
    Enumerate social engineering attack surface for *domain*.
    Returns standard cy_asm module dict: {results, issues, summary}
    """
    logger.info(f"[SocialEng] Starting social engineering intel for {domain}...")

    async with await create_async_session() as session:
        # CyTIM email recon (Hunter.io via CyTIM) + LinkedIn dork concurrently
        loop = asyncio.get_running_loop()
        cytim_results, li_profiles = await asyncio.gather(
            loop.run_in_executor(None, find_emails_cytim, domain),
            find_linkedin_profiles(domain, session),
            return_exceptions=True,
        )

    emails   = cytim_results if isinstance(cytim_results, list) else []
    profiles = li_profiles   if isinstance(li_profiles, list)   else []

    # Generate additional email pattern variants for discovered names
    pattern_emails: List[str] = []
    for e in emails:
        fn = e.get("first_name", "")
        ln = e.get("last_name", "")
        if fn and ln:
            variants = generate_email_patterns(fn, ln, domain)
            pattern_emails.extend(variants)

    risk = _assess_risk(emails, profiles)

    issues = []
    if risk["level"] in ("Critical", "High"):
        issues.extend([f"[SocialEng] {r}" for r in risk["reasons"]])

    email_list = [e["email"] for e in emails if e.get("email")]

    summary = (
        f"Social Eng: {len(email_list)} emails, "
        f"{len(profiles)} LinkedIn profiles — Risk: {risk['level']}"
    )
    if not emails and not profiles:
        summary = "Social Eng: No exposed employee data found (or API keys not configured)"

    logger.info(f"[SocialEng] {summary}")

    return {
        "results": {
            "emails":          emails,
            "email_list":      email_list,
            "email_patterns":  list(set(pattern_emails))[:20],
            "linkedin":        profiles,
            "risk_assessment": risk,
        },
        "issues":  issues,
        "summary": summary,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python modules/social_eng.py <domain>")
        sys.exit(1)
    target = sys.argv[1].strip().lower()
    result = asyncio.run(gather_social_eng(target))
    print(json.dumps(result, indent=2, default=str))
