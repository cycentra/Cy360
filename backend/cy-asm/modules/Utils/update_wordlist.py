import requests
import os

WORDLIST_URL = "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"
SAVE_PATH = "wordlists/subdomains.txt"
LIMIT = 5000  # Set your desired limit here

def refresh_wordlist():
    print(f"[*] Fetching wordlist from {WORDLIST_URL}...")
    try:
        response = requests.get(WORDLIST_URL, timeout=30)
        response.raise_for_status()

        # Split the raw text into a list of lines
        all_words = response.text.splitlines()
        
        # Take only the top X words
        top_words = all_words[:LIMIT]

        os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)

        # Save the limited list
        with open(SAVE_PATH, "w") as f:
            f.write("\n".join(top_words))

        print(f"[+] Successfully saved the top {len(top_words)} words to: {SAVE_PATH}")
    
    except Exception as e:
        print(f"[!] Update failed: {e}")

if __name__ == "__main__":
    refresh_wordlist()
