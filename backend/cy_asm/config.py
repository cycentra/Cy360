# CyCentra Config - Constants and API keys

# --- API Keys ---
# External threat-intel API keys (Shodan, SecurityTrails, VirusTotal, AlienVault)
# have been removed.  All passive OSINT and subdomain intel is now routed through
# the configured MISP instance — see System Settings → CyMISP in the portal.
#
# IPINFO_API_KEY  — still used by dns_recon.py for IP geolocation enrichment.
# NVD_API_KEY     — still used by web_analysis.py for CVE lookups against NVD.
# Both are optional: the respective modules skip the lookup when left empty.

# --- API Keys (Add yours here) ---
IPINFO_API_KEY = 'cb88ee41947f5e' 
SECURITYTRAILS_API_KEY = 'MTtPYhNEtxRN9pDseCoH10_SG2W6dgCZ' 
VIRUSTOTAL_API_KEY = 'd18a0f32b4c9ed0d4595d6863e3e72c22c0303bd11b4f9d8fa2bd37a4aeeef77' 
NVD_API_KEY = 'ca3e858c-3e96-4c08-9230-3f460900ffad' 
SHODAN_API_KEY = 'CX89uOeKYcWB5z2njXSmqcbncm6nbi37'

GOOGLE_GEMINI_KEY = "AIzaSyCW5toVZORcf8VJmDp3qNFQQlqnqBI_c3w"

# --- Network Settings ---
HTTP_TIMEOUT = 10
MAX_RETRIES = 3
BACKOFF_FACTOR = 1

# --- Scanning Constants (The missing piece!) ---
DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'DS', 'CAA']
BRUTE_FORCE_WORDLIST = ['www', 'mail', 'ftp', 'api', 'test', 'dev', 'staging']
EXPOSED_PATHS = ['/.git/', '/.env', '/admin', '/backup', '/db.dump']
SAAS_PROVIDERS_FOR_TAKEOVER = ['.s3.amazonaws.com', '.cloudfront.net', '.herokuapp.com']

PQC_HYBRID_GROUPS = {
    0x0200: "X25519Kyber768Draft00",
    0x11B9: "X25519MLKEM768",
    0x11BA: "SecP384r1MLKEM768",
    0x11BB: "X25519MLKEM1024",
}

COMMON_DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail']
QUICK_SCAN_PORTS = '80,443,22,21,25,110,143,3389'
EXTENDED_PORT_RANGE = '1-65535'
ENABLE_EXTENDED_PORT_SCAN = False
ENABLE_UDP_SCAN = False
ANON_CIPHERS = {"ADH", "AECDH", "DH_anon", "EXP"}
WEAK_CIPHERS = {"RC4", "3DES", "DES", "MD5", "NULL", "EXPORT"}
DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}
