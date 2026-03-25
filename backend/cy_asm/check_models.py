from google import genai
import os

# Replace with your actual key or ensure GOOGLE_GEMINI_KEY is in your environment
API_KEY = "AIzaSyCW5toVZORcf8VJmDp3qNFQQlqnqBI_c3w"
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
