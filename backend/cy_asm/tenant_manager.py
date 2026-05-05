import re
import requests
import sys

# Replace with your actual Wazuh Indexer (Elasticsearch/OpenSearch) details
INDEXER_URL = "https://localhost:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "your_admin_password"

def get_wazuh_tenants():
    """Fetches the list of existing tenants from the Indexer API."""
    endpoint = f"{INDEXER_URL}/_plugins/_security/api/tenants"
    try:
        response = requests.get(
            endpoint,
            auth=(INDEXER_USER, INDEXER_PASS),
            verify=False  # Set to True if you have valid SSL certs
        )
        if response.status_code == 200:
            # Returns a dictionary where keys are tenant names
            return response.json().keys()
        return []
    except Exception as e:
        print(f"Error connecting to Indexer: {e}")
        return []

def validate_tenant(input_tenant):
    """Return a filesystem-safe tenant identifier for this input.

    Priority:
    1. If the tenant already exists in Wazuh, return it unchanged.
    2. Otherwise sanitize the input (lowercase, replace unsafe chars with '_')
       so every SSO user gets their own isolated namespace.

    Never returns the shared "guests" holding area for authenticated users —
    that would allow one user's reports and NDJSON data to bleed into another
    user's directory.  The "guest" namespace (no trailing 's') is reserved
    exclusively for unauthenticated/guest_* scans and is set directly by
    the scan orchestrator rather than going through this function.
    """
    existing_tenants = get_wazuh_tenants()

    if input_tenant in existing_tenants:
        return input_tenant

    # Sanitize for filesystem safety — keep alphanumerics, dots, @, hyphens.
    # E.g. "user@example.com" → "user@example.com" (unchanged, all chars are safe)
    #      "User Name"        → "user_name"
    safe = re.sub(r"[^a-z0-9._@-]", "_", input_tenant.strip().lower())[:80]
    return safe or "unknown"
