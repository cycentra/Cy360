"""
CyCentra ASM — Configuration
All secrets loaded from environment variables.
Primary .env location: /opt/cycentra/.env  (shared with the full CyCentra stack)
Fallback locations checked in order if the primary is not found.
Never hardcode secrets here.
"""
import os
import logging
from pathlib import Path

# ---------------------------------------------------------------------------
# Load .env — priority order:
#   1. /opt/cycentra/.env          ← production install (shared stack .env)
#   2. <repo_root>/.env            ← developer checkout convenience
#   3. <cy_asm_dir>/.env           ← module-level override (not recommended)
#
# os.environ.setdefault() means already-set env vars always win —
# the .env file only fills gaps, never overwrites a running process's env.
# ---------------------------------------------------------------------------
def _load_dotenv():
    candidates = [
        Path("/opt/cycentra/.env"),                                  # production
        Path(__file__).resolve().parent.parent.parent / ".env",      # repo root
        Path(__file__).resolve().parent / ".env",                    # cy_asm dir
    ]
    for candidate in candidates:
        if candidate.exists():
            loaded = 0
            with open(candidate) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    os.environ.setdefault(
                        k.strip(),
                        v.strip().strip('"').strip("'"),
                    )
                    loaded += 1
            logging.getLogger("CyCentra").debug(
                f"[Config] Loaded {loaded} env var(s) from {candidate}"
            )
            return  # stop at first found — don't merge multiple files
    logging.getLogger("CyCentra").debug(
        "[Config] No .env file found — relying entirely on process environment"
    )

_load_dotenv()

# ── Azure Key Vault bootstrap ──────────────────────────────────────────────────
# Runs after dotenv so AZURE_KEYVAULT_URL is in env.  Fetches ASM API keys
# (Shodan, VT, NVD, etc.) from KV when configured.  No-op if KV not set up.
# When running inside the Flask process, core/config.py has already bootstrapped
# the FLASK_KV_MAP — this call fetches only the ASM-specific keys on top.
try:
    from core.kv_secrets import load_kv_secrets, ASM_KV_MAP
    load_kv_secrets(ASM_KV_MAP)
except Exception:
    pass

# ---------------------------------------------------------------------------
# API Keys — all from env, empty string = feature disabled
# ---------------------------------------------------------------------------
IPINFO_API_KEY          = os.environ.get("IPINFO_API_KEY", "")
SECURITYTRAILS_API_KEY  = os.environ.get("SECURITYTRAILS_API_KEY", "")
VIRUSTOTAL_API_KEY      = os.environ.get("VIRUSTOTAL_API_KEY", "")
NVD_API_KEY             = os.environ.get("NVD_API_KEY", "")
SHODAN_API_KEY          = os.environ.get("SHODAN_API_KEY", "")
GOOGLE_GEMINI_KEY       = os.environ.get("GOOGLE_GEMINI_KEY", "")
HUNTER_API_KEY          = os.environ.get("HUNTER_API_KEY", "")
HIBP_API_KEY            = os.environ.get("HIBP_API_KEY", "")

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
HTTP_TIMEOUT   = int(os.environ.get("HTTP_TIMEOUT", "10"))
MAX_RETRIES    = int(os.environ.get("MAX_RETRIES", "3"))
BACKOFF_FACTOR = int(os.environ.get("BACKOFF_FACTOR", "1"))

# ---------------------------------------------------------------------------
# Scanning constants
# ---------------------------------------------------------------------------
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "DS", "CAA"]
BRUTE_FORCE_WORDLIST = ["www", "mail", "ftp", "api", "test", "dev", "staging"]
EXPOSED_PATHS = ["/.git/", "/.env", "/admin", "/backup", "/db.dump"]
SAAS_PROVIDERS_FOR_TAKEOVER = [".s3.amazonaws.com", ".cloudfront.net", ".herokuapp.com"]

PQC_HYBRID_GROUPS = {
    0x0200: "X25519Kyber768Draft00",
    0x11B9: "X25519MLKEM768",
    0x11BA: "SecP384r1MLKEM768",
    0x11BB: "X25519MLKEM1024",
}

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail"]
QUICK_SCAN_PORTS      = "80,443,22,21,25,110,143,3389,8080,8443,3306,5432,6379,27017"
EXTENDED_PORT_RANGE   = "1-65535"
ENABLE_EXTENDED_PORT_SCAN = os.environ.get("ENABLE_EXTENDED_PORT_SCAN", "false").lower() == "true"
ENABLE_UDP_SCAN       = os.environ.get("ENABLE_UDP_SCAN", "false").lower() == "true"

ANON_CIPHERS       = {"ADH", "AECDH", "DH_anon", "EXP"}
WEAK_CIPHERS       = {"RC4", "3DES", "DES", "MD5", "NULL", "EXPORT"}
DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}

# ---------------------------------------------------------------------------
# EPSS API (Exploit Prediction Scoring System — free, no key required)
# ---------------------------------------------------------------------------
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# ---------------------------------------------------------------------------
# CVSSv3 severity thresholds
# ---------------------------------------------------------------------------
CVSS_CRITICAL = 9.0
CVSS_HIGH     = 7.0
CVSS_MEDIUM   = 4.0
