from google import genai
import os

try:
    from core.kv_secrets import load_kv_secrets, ASM_KV_MAP
    load_kv_secrets(ASM_KV_MAP)
except Exception:
    pass

API_KEY = os.environ.get("GOOGLE_GEMINI_KEY", "")
if not API_KEY:
    raise RuntimeError("GOOGLE_GEMINI_KEY not set — add to Key Vault or /opt/cycentra/.env")
client = genai.Client(api_key=API_KEY)

print("--- Available Models for your API Key ---")
try:
    # client.models.list() returns a generator of model objects
    for m in client.models.list():
        # Filters for models that can actually generate text/JSON
        if "generateContent" in m.supported_actions:
            print(f"Model Name: {m.name}")
except Exception as e:
    print(f"Error listing models: {e}")
