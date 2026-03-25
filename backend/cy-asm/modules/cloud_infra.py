# modules/cloud_infra.py
# CyCentra Cloud & Infrastructure Module (2025–2026)
# Detects potential public cloud storage buckets and very basic Kubernetes API exposure

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any, Optional

from utils import setup_logging, create_async_session
from config import HTTP_TIMEOUT

# Use hierarchical logger name – assumes setup_logging() was called once in main script
logger = logging.getLogger("cycentra.modules.cloud_infra")


def generate_candidates(domain: str) -> List[str]:
    """Generate realistic bucket name variations based on domain"""
    base = domain.split(".")[0].lower()
    full = domain.lower().replace(".", "-")

    patterns = [
        base,
        f"{base}-assets", f"{base}-prod", f"{base}-dev", f"{base}-staging",
        f"{base}-backup", f"{base}-files", f"{base}storage", f"{base}-media",
        f"{base}-public", f"{base}-uploads", f"{base}-static", f"{base}-content",
        f"{base}-app", f"{base}-web", f"{base}-cdn", f"{base}-images",
        full,
        f"{full}-assets", f"{full}-prod", f"{full}-backup",
        f"{base}2024", f"{base}2025", f"{base}-2024", f"{base}-2025",
        f"{base}-eu", f"{base}-us", f"{base}-asia", f"{base}-global",
        f"www{base}", f"cdn-{base}", f"storage-{base}", f"files-{base}",
    ]

    candidates = list(set(patterns))  # remove duplicates
    logger.debug(f"Generated {len(candidates)} bucket name candidates for domain {domain}")
    return candidates


PROVIDERS = [
    {
        "name": "AWS S3",
        "templates": [
            "https://{name}.s3.amazonaws.com",
            "https://{name}.s3.us-east-1.amazonaws.com",
            "https://{name}.s3.eu-west-1.amazonaws.com",
            "https://{name}.s3.ap-southeast-1.amazonaws.com",
        ],
        "public_keywords": [
            "listbucket", "allobject",
            "<listallmybucketsresult", "public",
        ],
    },
    {
        "name": "GCP Storage",
        "templates": [
            "https://storage.googleapis.com/{name}",
            "https://{name}.storage.googleapis.com",
        ],
        "public_keywords": ["listbucket", "accessdenied", "public"],
    },
    {
        "name": "Azure Blob",
        "templates": ["https://{name}.blob.core.windows.net"],
        "containers": ["", "/public", "/assets", "/files", "/uploads", "/wwwroot"],
        "public_keywords": ["listbucket", "blobs", "public"],
    },
    {
        "name": "DigitalOcean Spaces",
        "templates": [
            "https://{name}.nyc3.digitaloceanspaces.com",
            "https://{name}.sfo3.digitaloceanspaces.com",
        ],
        "public_keywords": ["listbucket", "public"],
    },
    {
        "name": "Oracle Cloud",
        "templates": ["https://{name}.compat.objectstorage.us-ashburn-1.oraclecloud.com"],
        "public_keywords": ["listbucket", "public"],
    },
]


async def check_bucket(
    url: str,
    session: aiohttp.ClientSession,
    keywords: List[str]
) -> Optional[Dict[str, Any]]:
    """Check single bucket URL for existence and public/listable status"""
    logger.debug(f"Probing bucket: {url}")

    try:
        async with session.head(url, timeout=12, allow_redirects=True) as head_resp:
            status = head_resp.status
            content_type = head_resp.headers.get("content-type", "").lower()

        # Early exit for clear negatives
        if status not in (200, 301, 403):
            logger.debug(f"→ {url:<65} → {status} (fast negative)")
            return None

        # Try to get body only when it might be useful
        text = ""
        if status in (200, 403) or "xml" in content_type or "html" in content_type:
            try:
                async with session.get(url, timeout=10) as get_resp:
                    text = (await get_resp.text()).lower()
            except Exception as get_err:
                logger.debug(f"→ GET body failed for {url}: {get_err.__class__.__name__}")

        # Evaluate findings
        if any(kw.lower() in text for kw in keywords):
            if any(kw in text for kw in ["listbucket", "allobject", "<listallmybucketsresult"]):
                logger.info(f"PUBLIC / LISTABLE BUCKET → {url}")
                return {
                    "url": url,
                    "status": status,
                    "risk": "PUBLIC/LISTABLE",
                    "details": "Bucket listing enabled",
                }
            else:
                logger.info(f"PUBLIC BUCKET → {url} (status {status})")
                return {
                    "url": url,
                    "status": status,
                    "risk": "PUBLIC",
                    "details": "Openly accessible",
                }

        if status == 403:
            logger.debug(f"→ {url:<65} → exists but private (403)")
            return {
                "url": url,
                "status": 403,
                "risk": "EXISTS",
                "details": "Private but exists",
            }

        logger.debug(f"→ {url:<65} → responded {status} (no clear public indicator)")
        return {
            "url": url,
            "status": status,
            "risk": "EXISTS",
            "details": f"Responded with status {status}",
        }

    except asyncio.TimeoutError:
        logger.debug(f"→ {url:<65} → timeout")
    except aiohttp.ClientError as e:
        logger.debug(f"→ {url:<65} → {e.__class__.__name__}")
    except Exception as unexpected:
        logger.warning(f"Unexpected error checking bucket {url}", exc_info=True)

    return None


async def scan_cloud_buckets(
    domain: str,
    session: aiohttp.ClientSession
) -> Dict[str, Any]:
    """Scan for cloud storage buckets across multiple providers"""
    candidates = generate_candidates(domain)
    logger.info(f"Bucket enumeration started → {len(candidates)} candidates × {len(PROVIDERS)} providers")

    tasks = []

    for name in candidates:
        for provider in PROVIDERS:
            if provider["name"] == "Azure Blob":
                base_url = provider["templates"][0].format(name=name)
                for container in provider.get("containers", [""]):
                    url = base_url + container
                    tasks.append(check_bucket(url, session, provider["public_keywords"]))
            else:
                for template in provider["templates"]:
                    url = template.format(name=name)
                    tasks.append(check_bucket(url, session, provider["public_keywords"]))

        # Small delay between candidate groups to be polite
        await asyncio.sleep(0.15)

    logger.debug(f"Dispatching {len(tasks)} bucket check tasks...")
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter valid findings (ignore exceptions)
    findings = [r for r in results if isinstance(r, dict)]
    error_count = sum(1 for r in results if isinstance(r, Exception))

    if error_count > 0:
        logger.warning(f"{error_count} bucket checks raised exceptions")

    # Sort by severity
    priority_map = {"PUBLIC/LISTABLE": 0, "PUBLIC": 1, "EXISTS": 2}
    findings.sort(key=lambda x: priority_map.get(x.get("risk", ""), 999))

    total_found = len(findings)
    public_count = sum(1 for f in findings if "PUBLIC" in f.get("risk", ""))

    summary_str = f"{total_found} buckets exist — {public_count} public/listable"
    logger.info(f"Bucket scan completed → {summary_str}")

    return {
        "total_potential_buckets_checked": len(tasks),
        "total_existing_buckets": total_found,
        "public_or_listable": public_count,
        "displayed_findings": findings[:50],
        "truncated": total_found > 50,
        "summary": summary_str,
    }


async def check_k8s_exposed(domain: str, session: aiohttp.ClientSession) -> bool:
    """Very basic check for exposed Kubernetes API server on port 6443"""
    url = f"https://{domain}:6443/api/v1"
    logger.debug(f"Probing for exposed K8s API → {url}")

    try:
        async with session.get(url, timeout=5) as resp:
            if resp.status == 200:
                text = await resp.text()
                if "api/v1" in text.lower():
                    logger.warning(f"→ POSSIBLE EXPOSED KUBERNETES API → {url}")
                    return True
    except Exception as e:
        logger.debug(f"K8s check failed (normal): {e.__class__.__name__}")

    logger.debug("→ No exposed Kubernetes API detected")
    return False


async def gather_cloud_infra(
    domain: str,
    ips: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Main entry point: gather cloud infrastructure intel
    - Bucket enumeration
    - Basic K8s exposure check
    - Cloud provider hints from IP list
    """
    logger.info(f"Cloud infrastructure scan started for domain: {domain}")

    # Try to enrich with DNS if no IPs provided
    if ips is None:
        logger.info("No IP list provided → attempting DNS enrichment")
        try:
            from modules.dns_recon import gather_dns_intel
            dns_result = await gather_dns_intel(domain)
            ips = dns_result.get("results", {}).get("ips", [])
            logger.info(f"Auto-enriched {len(ips)} IP records from DNS")
        except Exception as e:
            logger.warning(f"DNS enrichment failed: {e}", exc_info=False)
            ips = []

    # Collect detected cloud providers from IP metadata
    cloud_providers = {
        ip.get("cloud_provider")
        for ip in (ips or [])
        if ip.get("cloud_provider") and ip.get("cloud_provider") != "Unknown"
    }

    async with await create_async_session() as session:
        buckets_result, k8s_exposed = await asyncio.gather(
            scan_cloud_buckets(domain, session),
            check_k8s_exposed(domain, session)
        )

    issues = []
    if k8s_exposed:
        issues.append("Kubernetes API server appears exposed on port 6443 (high risk)")
    if buckets_result.get("public_or_listable", 0) > 0:
        issues.append(f"{buckets_result['public_or_listable']} public or listable cloud buckets detected")

    summary = (
        f"Cloud scan: {len(cloud_providers)} providers, "
        f"{buckets_result.get('total_existing_buckets', 0)} buckets "
        f"({buckets_result.get('public_or_listable', 0)} public/listable)"
    )
    logger.info(summary)

    return {
        "results": {
            "providers": list(cloud_providers),
            "buckets": buckets_result.get("displayed_findings", []),
            "k8s_exposed": k8s_exposed,
            "bucket_summary": buckets_result.get("summary", "No buckets found")
        },
        "issues": issues,
        "summary": summary
    }


if __name__ == "__main__":
    # Standalone test
    import asyncio
    test_domain = "example.com"  # ← change to real test domain
    result = asyncio.run(gather_cloud_infra(test_domain))
    print(result["summary"])
