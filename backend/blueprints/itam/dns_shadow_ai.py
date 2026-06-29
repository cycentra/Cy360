"""
DNS-based Shadow AI detection.

Two components:
  1. AI_DOMAIN_WATCHLIST — 60+ known AI SaaS domains used in:
     a) Wazuh Sysmon EventID 22/3 rules (Windows)
     b) CyEDR agent journal-based DNS monitoring (Linux/macOS)
     c) NetworkDnsMonitor — optional forwarding resolver on CyCentra server
        that catches ALL devices on the network (no agent required)

  2. NetworkDnsMonitor — dnslib-based UDP forwarder listening on
     ITAM_DNS_MONITOR_PORT (default 5454). Forwards all queries upstream;
     matches AI domains and calls a callback to write shadow_ai_findings.
     Clients point their secondary DNS to CyCentra to get coverage.
"""
import logging
import threading
import time

log = logging.getLogger(__name__)

# ── Master AI SaaS domain watchlist ────────────────────────────────────────
AI_DOMAIN_WATCHLIST: list[str] = [
    # OpenAI / ChatGPT
    "openai.com", "api.openai.com", "chat.openai.com", "chatgpt.com",
    "oaiusercontent.com", "oai.azure.com", "openai.azure.com",
    # Anthropic / Claude
    "anthropic.com", "api.anthropic.com", "claude.ai",
    # Google Gemini / Vertex / AI Studio
    "gemini.google.com", "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com", "aistudio.google.com", "vertex.ai",
    "makersuite.google.com",
    # Meta / LLaMA
    "llama-api.com", "llamameta.net",
    # HuggingFace
    "huggingface.co", "api-inference.huggingface.co", "huggingface.com",
    # Mistral AI
    "mistral.ai", "api.mistral.ai", "console.mistral.ai",
    # Cohere
    "cohere.com", "cohere.ai", "api.cohere.ai", "api.cohere.com",
    # Perplexity AI
    "perplexity.ai", "api.perplexity.ai",
    # Together AI
    "together.ai", "api.together.ai", "api.together.xyz",
    # Groq
    "groq.com", "api.groq.com",
    # Fireworks AI
    "fireworks.ai", "api.fireworks.ai",
    # Anyscale
    "anyscale.com", "api.endpoints.anyscale.com",
    # Deep Infra
    "deepinfra.com", "api.deepinfra.com",
    # DeepSeek
    "deepseek.com", "api.deepseek.com", "chat.deepseek.com",
    # xAI / Grok
    "x.ai", "api.x.ai", "grok.x.ai",
    # Stability AI / image generation
    "stability.ai", "api.stability.ai", "platform.stability.ai",
    # Midjourney
    "midjourney.com", "cdn.midjourney.com",
    # Runway ML
    "runwayml.com", "runway.com", "api.runwayml.com",
    # ElevenLabs
    "elevenlabs.io", "api.elevenlabs.io",
    # Writing AI tools
    "writesonic.com", "api.writesonic.com",
    "jasper.ai", "api.jasper.ai",
    "copy.ai", "api.copy.ai",
    # Character AI
    "character.ai", "beta.character.ai", "neo.character.ai",
    # Poe / You / Phind
    "poe.com", "you.com", "phind.com",
    # Replicate
    "replicate.com", "api.replicate.com",
    # OpenRouter (aggregator)
    "openrouter.ai", "api.openrouter.ai",
    # Coze / ByteDance AI
    "coze.com", "api.coze.com",
    # Venice AI
    "venice.ai", "api.venice.ai",
    # Ollama hosted / cloud
    "ollama.ai", "ollama.com",
    # LM Studio cloud
    "lmstudio.ai",
    # Amazon Bedrock
    "bedrock.amazonaws.com",
    "bedrock-runtime.us-east-1.amazonaws.com",
    # IBM WatsonX
    "watsonx.ai", "us-south.ml.cloud.ibm.com",
    # GitHub Copilot (flag — let admin whitelist if approved)
    "copilot.microsoft.com", "api.githubcopilot.com",
    # Notion AI (embedded)
    "api.notion.so",
    # Grammarly AI
    "grammarly.com",
]

# Build suffix set for O(1) lookup
_AI_SUFFIXES: frozenset[str] = frozenset(d.lower().lstrip(".") for d in AI_DOMAIN_WATCHLIST)


def is_ai_domain(query: str) -> str | None:
    """Return the matched watchlist domain if query matches, else None."""
    q = query.lower().rstrip(".")
    # Exact match
    if q in _AI_SUFFIXES:
        return q
    # Subdomain match
    for suf in _AI_SUFFIXES:
        if q.endswith("." + suf):
            return suf
    return None


def check_journal_line(line: str) -> str | None:
    """
    Parse a single log line from systemd-resolved or mDNSResponder for AI domains.
    Returns matched domain or None.
    """
    for word in line.split():
        hit = is_ai_domain(word.strip("()[]<>,;"))
        if hit:
            return hit
    return None


def build_sysmon_pcre2() -> str:
    """Generate the PCRE2 alternation string for Wazuh Sysmon rules 101040/101041."""
    escaped = [d.replace(".", r"\.") for d in AI_DOMAIN_WATCHLIST]
    return "(?i)(" + "|".join(escaped) + ")"


# ── DNS journal monitoring for CyEDR agent (Linux / macOS) ─────────────────

def read_resolved_dns_linux(since_seconds: int = 70) -> list[str]:
    """
    Parse systemd-resolved journal for DNS queries in the last N seconds.
    Returns list of queried hostnames (unfiltered).
    """
    import subprocess
    try:
        result = subprocess.run(
            ["journalctl", "-u", "systemd-resolved",
             f"--since={since_seconds} seconds ago",
             "--no-pager", "--output=cat", "-q"],
            capture_output=True, text=True, timeout=8,
        )
        lines = []
        for line in result.stdout.splitlines():
            # systemd-resolved format: "QUERY_RESULT (NODATA) api.openai.com IN A"
            # or "lookup api.openai.com: ..."
            for part in line.split():
                stripped = part.strip("()[],.;:")
                if "." in stripped and len(stripped) > 4:
                    lines.append(stripped)
        return lines
    except Exception:
        return []


def read_mdns_dns_macos(since_seconds: int = 70) -> list[str]:
    """
    Parse mDNSResponder log stream for DNS queries on macOS.
    """
    import subprocess
    try:
        result = subprocess.run(
            ["log", "show",
             "--predicate", "process == \"mDNSResponder\"",
             "--last", f"{since_seconds}s",
             "--style", "syslog"],
            capture_output=True, text=True, timeout=10,
        )
        lines = []
        for line in result.stdout.splitlines():
            for part in line.split():
                stripped = part.strip("()[],.;:'\"")
                if "." in stripped and len(stripped) > 4:
                    lines.append(stripped)
        return lines
    except Exception:
        return []


def scan_dns_for_shadow_ai(os_type: str) -> list[str]:
    """
    Called from CyEDR agent heartbeat cycle.
    Returns list of AI domains detected in recent DNS activity.
    """
    queries: list[str] = []
    if os_type == "LINUX":
        queries = read_resolved_dns_linux()
    elif os_type == "MACOS":
        queries = read_mdns_dns_macos()
    # Windows handled by Sysmon EventID 22 — not needed here

    hits: list[str] = []
    seen: set[str] = set()
    for q in queries:
        domain = is_ai_domain(q)
        if domain and domain not in seen:
            seen.add(domain)
            hits.append(domain)
    return hits


# ── Optional network-level DNS forwarding resolver ─────────────────────────

class NetworkDnsMonitor:
    """
    Optional dnslib-based forwarding DNS resolver.
    Listens on ITAM_DNS_MONITOR_PORT (default 5454, non-privileged).
    Forwards ALL queries to upstream DNS — no blocking, observation-only.
    Calls callback(query_domain, client_ip, matched_watchlist_entry) for AI hits.

    Deployment: configure CyCentra server IP as secondary DNS on DHCP/router.
    For port 53 (requires root): set ITAM_DNS_MONITOR_PORT=53 and run Flask as root
    or add: setcap 'cap_net_bind_service=+ep' $(which python3)
    """

    def __init__(self, listen_port: int, upstream_dns: str, callback):
        self._port = listen_port
        self._upstream = upstream_dns
        self._callback = callback
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> bool:
        self._running = True
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="itam-dns-monitor"
        )
        self._thread.start()
        log.info("[ITAM-DNS] Resolver listening on 0.0.0.0:%d → upstream %s", self._port, self._upstream)
        return True

    def stop(self):
        self._running = False

    def _serve(self):
        try:
            from dnslib import DNSRecord         # type: ignore
            from dnslib.server import DNSServer  # type: ignore
            from dnslib.server import BaseResolver  # type: ignore
        except ImportError:
            log.warning("[ITAM-DNS] dnslib not installed — DNS monitor disabled. pip install dnslib")
            return

        monitor = self

        class _Resolver(BaseResolver):
            def resolve(self, request, handler):
                qname = str(request.q.qname).rstrip(".")
                client_ip = handler.client_address[0]
                hit = is_ai_domain(qname)
                if hit:
                    try:
                        monitor._callback(qname, client_ip, hit)
                    except Exception:
                        pass
                # Always forward — never block
                try:
                    proxy_r = DNSRecord.parse(
                        request.send(monitor._upstream, 53, timeout=5)
                    )
                    return proxy_r
                except Exception:
                    return request.reply()

        server = DNSServer(_Resolver(), port=self._port, address="0.0.0.0")
        server.start_thread()
        while self._running:
            time.sleep(1)
        server.stop()


_monitor_instance: NetworkDnsMonitor | None = None


def start_network_dns_monitor(listen_port: int, upstream_dns: str, ingest_fn) -> bool:
    """Start the background network DNS monitor if not already running."""
    global _monitor_instance
    if _monitor_instance is not None:
        return True
    _monitor_instance = NetworkDnsMonitor(listen_port, upstream_dns, ingest_fn)
    return _monitor_instance.start()


def get_watchlist() -> list[dict]:
    """Return the watchlist as a structured list for the API."""
    return [{"domain": d, "category": _categorise(d)} for d in AI_DOMAIN_WATCHLIST]


def _categorise(domain: str) -> str:
    cats = {
        "openai.com": "llm_api", "anthropic.com": "llm_api", "claude.ai": "llm_ui",
        "gemini.google.com": "llm_ui", "generativelanguage.googleapis.com": "llm_api",
        "mistral.ai": "llm_api", "groq.com": "llm_api", "together.ai": "llm_api",
        "huggingface.co": "model_hub", "replicate.com": "model_hub",
        "stability.ai": "image_gen", "midjourney.com": "image_gen", "runwayml.com": "video_gen",
        "elevenlabs.io": "voice_ai", "character.ai": "llm_ui", "poe.com": "llm_ui",
        "deepseek.com": "llm_api", "cohere.com": "llm_api", "perplexity.ai": "llm_ui",
        "copilot.microsoft.com": "coding_ai", "api.githubcopilot.com": "coding_ai",
        "bedrock.amazonaws.com": "llm_api", "watsonx.ai": "llm_api",
    }
    for k, v in cats.items():
        if k in domain:
            return v
    return "ai_saas"
