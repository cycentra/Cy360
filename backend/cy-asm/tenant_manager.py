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
            verify=False # Set to True if you have valid SSL certs
        )
        if response.status_code == 200:
            # Returns a dictionary where keys are tenant names
            return response.json().keys()
        return []
    except Exception as e:
        print(f"Error connecting to Indexer: {e}")
        return []

def validate_tenant(input_tenant):
    """Checks if tenant exists; otherwise returns the 'holding' tenant name."""
    existing_tenants = get_wazuh_tenants()
    
    if input_tenant in existing_tenants:
        return input_tenant
    else:
        # This is your 'Holding Area' for new/unrecognized requests
        return "guests"
