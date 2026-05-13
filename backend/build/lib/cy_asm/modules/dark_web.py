# modules/dark_web.py
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from typing import Dict, List, Any
from utils import setup_logging, create_async_session
from config import HTTP_TIMEOUT, HIBP_API_KEY


logger = setup_logging()

async def scan_ahmia(domain: str, subdomains: List[str], session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    findings = []
    terms = [domain, f"@{domain}"] + [s for s in subdomains if s.startswith(("email.", "mail.", "webmail."))][:3]
    keywords = ["leak", "hack", "breach", "password", "credential", "data", "dump", "exposed"]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    for term in terms:
        try:
            await asyncio.sleep(2)
            url = "https://ahmia.fi/search/"
            async with session.get(url, params={"q": term}, headers=headers, timeout=15) as resp:
                if resp.status == 200:
                    soup = BeautifulSoup(await resp.text(), "html.parser")
                    for result in soup.find_all("li", class_="result")[:5]:
                        title = result.find("h4").get_text(strip=True) if result.find("h4") else ""
                        snippet = result.find("p").get_text(strip=True) if result.find("p") else ""
                        if any(k in title.lower() or k in snippet.lower() for k in keywords):
                            findings.append({
                                "title": title, "snippet": snippet,
                                "url": result.find("a")["href"] if result.find("a") else "",
                                "risk": "High-risk mention detected"
                            })
        except Exception as e: logger.error(f"Ahmia error {term}: {e}")
    return findings

async def scan_hibp(domain: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    results = []
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "CyCentra/1.0",
    }
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    try:
        async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT) as response:
            response.raise_for_status()
            breaches = await response.json()
            for breach in breaches[:10]:
                data_classes = breach.get("DataClasses", [])
                includes_emails = "Email addresses" in data_classes
                includes_passwords = "Passwords" in data_classes
                risk = f"Data breach detected ({breach.get('BreachDate', 'unknown')}). Check for compromised credentials."
                if includes_emails:
                    risk += " Breach includes email addresses."
                if includes_passwords:
                    risk += " Breach includes passwords."
                results.append(
                    {
                        "title": breach.get("Title", ""),
                        "breach_date": breach.get("BreachDate", "unknown"),
                        "url": f"https://haveibeenpwned.com/Breaches#{breach.get('Name', '')}",
                        "risk": risk,
                        "data_classes": data_classes,
                    }
                )
    except Exception as e:
        logger.error(f"HaveIBeenPwned scan failed for {domain}: {e}")
    return results

async def gather_dark_web(domain: str, subdomains: List[str] = None) -> Dict[str, Any]:
    logger.info(f"🌑 [DARKWEB] Starting dark web scan for {domain}")
    async with await create_async_session() as session:
        ahmia = await scan_ahmia(domain, subdomains or [], session)
        hibp = await scan_hibp(domain, session)

    risk_lvl = "High" if (ahmia or hibp) else "Low"
    summary = f"Dark Web: {len(ahmia)} mentions, {len(hibp)} breaches. Risk: {risk_lvl}."
    if not (ahmia or hibp): summary += " No findings."
    
    logger.info(summary)
    return {
        "results": {"ahmia": ahmia, "hibp": hibp, "summary": summary},
        "issues": [f"Dark Web: {f['risk']}" for f in ahmia],
        "summary": summary
    }
