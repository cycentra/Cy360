"""
modules/mobile_api.py
CyCentra ASM — Mobile App & API Security Module

Checks the mobile and API attack surface of a domain:
  1. APK/IPA link discovery from the domain's web pages
  2. API endpoint security checks (auth, rate-limiting, versioning)
  3. Mobile app store presence detection
  4. GraphQL introspection exposure
  5. REST API common misconfiguration checks
  6. CORS policy validation on API endpoints

No APK binary analysis (requires device/emulator) — this module checks
what is discoverable passively and via safe HTTP probes.
"""

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import HTTP_TIMEOUT
from utils import setup_logging, create_async_session

logger = setup_logging()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = {
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":      r"[a-z0-9-]+\.firebaseio\.com",
    "Firebase Key":      r"AAAA[A-Za-z0-9_-]{35}:",
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Stripe Live Key":   r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key":   r"sk_test_[0-9a-zA-Z]{24}",
    "GitHub PAT":        r"ghp_[0-9a-zA-Z]{36}",
    "JWT Token":         r"eyJ[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}",
    "Private Key":       r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
    "Slack Token":       r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Twilio SID":        r"AC[0-9a-fA-F]{32}",
    "SendGrid Key":      r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "Mapbox Token":      r"pk\.[A-Za-z0-9]+\.[A-Za-z0-9_-]+",
    "Cloudinary URL":    r"cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z0-9-]+",
}

_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/openapi.json",
    "/api-docs", "/api/docs",
    "/v1", "/v2", "/v3",
    "/.well-known/openid-configuration",
    "/oauth/token", "/oauth2/token",
    "/health", "/healthz", "/ping", "/status",
    "/metrics", "/actuator", "/actuator/health",
    "/debug", "/console",
]

_APP_STORE_PATTERNS = {
    "Google Play": r"play\.google\.com/store/apps/details\?id=([a-zA-Z0-9_.]+)",
    "Apple App Store": r"apps\.apple\.com/[a-z]+/app/[a-z0-9-]+/id(\d+)",
}


# ---------------------------------------------------------------------------
# APK/IPA link discovery
# ---------------------------------------------------------------------------

async def discover_app_links(
    domain: str,
    session: aiohttp.ClientSession,
) -> Dict[str, Any]:
    """
    Scrape domain homepage for links to APK/IPA files and app store pages.
    Returns {apk_links, ipa_links, store_links}.
    """
    apk_links: List[str]   = []
    ipa_links: List[str]   = []
    store_links: List[Dict[str, str]] = []

    for scheme in ("https", "http"):
        try:
            async with session.get(
                f"{scheme}://{domain}",
                timeout=aiohttp.ClientTimeout(total=12),
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    continue
                text = await resp.text()
                soup = BeautifulSoup(text, "html.parser")

                # Direct APK/IPA download links
                for tag in soup.find_all("a", href=True):
                    href = tag["href"]
                    if href.endswith(".apk"):
                        full = href if href.startswith("http") else urljoin(f"{scheme}://{domain}", href)
                        apk_links.append(full)
                    elif href.endswith(".ipa"):
                        full = href if href.startswith("http") else urljoin(f"{scheme}://{domain}", href)
                        ipa_links.append(full)

                # App store links
                for store, pattern in _APP_STORE_PATTERNS.items():
                    matches = re.findall(pattern, text)
                    for m in matches:
                        store_links.append({"store": store, "identifier": m})

                break  # Stop after first successful scheme
        except Exception as e:
            logger.debug(f"[MobileAPI] App link discovery failed ({scheme}): {e}")

    return {
        "apk_links":   list(set(apk_links)),
        "ipa_links":   list(set(ipa_links)),
        "store_links": store_links,
    }


# ---------------------------------------------------------------------------
# APK content scanning (if accessible URL)
# ---------------------------------------------------------------------------

async def scan_apk_url(
    apk_url: str,
    session: aiohttp.ClientSession,
) -> List[Dict[str, str]]:
    """
    Download APK and scan for hardcoded secrets via regex.
    APKs are zip files — we look for strings in the binary.
    Capped at 50MB to avoid memory issues.
    """
    secrets: List[Dict[str, str]] = []
    try:
        async with session.get(
            apk_url,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            if resp.status != 200:
                return []
            content_len = int(resp.headers.get("Content-Length", 0))
            if content_len > 50 * 1024 * 1024:
                logger.info(f"[MobileAPI] APK too large ({content_len} bytes) — skipping secret scan.")
                return []
            data = await resp.read()

        # Scan raw bytes as text (APK is a zip; dex/xml strings are readable)
        text = data.decode("latin-1", errors="replace")
        for secret_type, pattern in _SECRET_PATTERNS.items():
            for match in re.findall(pattern, text):
                value = match[0] if isinstance(match, tuple) else match
                secrets.append({
                    "type":   secret_type,
                    "value":  str(value)[:20] + "...",
                    "source": apk_url,
                })

        if secrets:
            logger.warning(f"[MobileAPI] Found {len(secrets)} secret(s) in APK: {apk_url}")
    except Exception as e:
        logger.debug(f"[MobileAPI] APK scan failed for {apk_url}: {e}")
    return secrets


# ---------------------------------------------------------------------------
# API endpoint security checks
# ---------------------------------------------------------------------------

async def check_api_endpoints(
    domain: str,
    session: aiohttp.ClientSession,
) -> List[Dict[str, Any]]:
    """
    Probe common API paths for security issues:
    - Unauthenticated access
    - GraphQL introspection enabled
    - Swagger/OpenAPI docs exposed
    - Missing rate limiting headers
    - Overly permissive CORS
    """
    findings: List[Dict[str, Any]] = []

    async def probe(path: str) -> Optional[Dict[str, Any]]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}{path}"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    if resp.status not in (200, 401, 403):
                        continue
                    ct   = resp.headers.get("Content-Type", "").lower()
                    cors = resp.headers.get("Access-Control-Allow-Origin", "")
                    rl   = resp.headers.get("X-RateLimit-Limit") or resp.headers.get("RateLimit-Limit")
                    text = await resp.text() if resp.status == 200 else ""

                    result: Dict[str, Any] = {
                        "url":            url,
                        "status":         resp.status,
                        "content_type":   ct,
                        "cors_wildcard":  cors == "*",
                        "rate_limited":   rl is not None,
                        "issues":         [],
                    }

                    if resp.status == 200:
                        # GraphQL introspection
                        if "graphql" in path.lower() or "graphiql" in path.lower():
                            gql_test_url = url
                            try:
                                async with session.post(
                                    gql_test_url,
                                    json={"query": "{ __schema { types { name } } }"},
                                    timeout=aiohttp.ClientTimeout(total=8),
                                ) as gql_resp:
                                    if gql_resp.status == 200:
                                        gql_data = await gql_resp.json()
                                        if "__schema" in str(gql_data):
                                            result["issues"].append("GraphQL introspection enabled — disable in production")
                            except Exception:
                                pass

                        # Swagger/OpenAPI docs exposed
                        if any(p in path for p in ("/swagger", "/openapi", "/api-docs")):
                            result["issues"].append(f"API documentation exposed at {path}")

                        # Debug/metrics endpoints
                        if any(p in path for p in ("/debug", "/console", "/actuator", "/metrics")):
                            result["issues"].append(f"Debug/metrics endpoint exposed at {path}")

                        # JSON response without auth
                        if ("json" in ct or text.strip().startswith("{") or text.strip().startswith("[")):
                            result["issues"].append(f"API endpoint {path} accessible without authentication")

                    # CORS issues
                    if cors == "*" and resp.status == 200:
                        result["issues"].append(f"Permissive CORS (Access-Control-Allow-Origin: *) on {path}")

                    if result["issues"] or resp.status == 200:
                        return result
            except Exception:
                pass
        return None

    tasks = [probe(p) for p in _API_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, dict) and r.get("issues"):
            findings.append(r)

    return findings


# ---------------------------------------------------------------------------
# Mobile deep-link / URL scheme discovery
# ---------------------------------------------------------------------------

async def discover_deeplinks(
    domain: str,
    session: aiohttp.ClientSession,
) -> List[str]:
    """
    Check /.well-known/assetlinks.json (Android) and
    apple-app-site-association (iOS) for registered deep-link schemes.
    These reveal app bundle IDs and linked domains.
    """
    deeplinks: List[str] = []
    checks = [
        f"https://{domain}/.well-known/assetlinks.json",
        f"https://{domain}/.well-known/apple-app-site-association",
        f"https://{domain}/apple-app-site-association",
    ]
    for url in checks:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status == 200:
                    deeplinks.append(url)
                    logger.info(f"[MobileAPI] Deep-link config found: {url}")
        except Exception:
            pass
    return deeplinks


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def gather_mobile_api(domain: str) -> Dict[str, Any]:
    """
    Enumerate mobile app and API security exposure for *domain*.
    Returns standard cy_asm module dict: {results, issues, summary}
    """
    logger.info(f"[MobileAPI] Starting mobile & API scan for {domain}...")

    async with await create_async_session() as session:
        app_links, api_findings, deeplinks = await asyncio.gather(
            discover_app_links(domain, session),
            check_api_endpoints(domain, session),
            discover_deeplinks(domain, session),
            return_exceptions=True,
        )

    app_links   = app_links   if isinstance(app_links, dict)   else {"apk_links": [], "ipa_links": [], "store_links": []}
    api_findings = api_findings if isinstance(api_findings, list) else []
    deeplinks   = deeplinks   if isinstance(deeplinks, list)   else []

    # Scan any discovered APKs for secrets
    apk_secrets: List[Dict[str, str]] = []
    if app_links.get("apk_links"):
        async with await create_async_session() as session:
            for apk_url in app_links["apk_links"][:3]:  # cap at 3 APKs
                secrets = await scan_apk_url(apk_url, session)
                apk_secrets.extend(secrets)

    # Aggregate issues
    issues: List[str] = []
    for finding in api_findings:
        issues.extend(finding.get("issues", []))
    for secret in apk_secrets:
        issues.append(f"APK secret exposed: {secret['type']} in {secret['source']}")

    exposed_api_count = len(api_findings)
    apk_count         = len(app_links.get("apk_links", []))
    store_count       = len(app_links.get("store_links", []))

    summary = (
        f"Mobile/API: {exposed_api_count} API issue(s), "
        f"{apk_count} APK link(s), "
        f"{store_count} app store listing(s), "
        f"{len(deeplinks)} deep-link config(s)"
    )
    if not issues:
        summary += " — No critical exposures found"

    logger.info(f"[MobileAPI] {summary}")

    return {
        "results": {
            "app_links":    app_links,
            "api_findings": api_findings,
            "apk_secrets":  apk_secrets,
            "deeplinks":    deeplinks,
        },
        "issues":  issues,
        "summary": summary,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python modules/mobile_api.py <domain>")
        sys.exit(1)
    target = sys.argv[1].strip().lower()
    result = asyncio.run(gather_mobile_api(target))
    print(json.dumps(result, indent=2, default=str))
