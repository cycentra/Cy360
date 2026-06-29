#!/usr/bin/env python3
"""
CyCentra 360 — CyEDR Phase 1 Bridge Agent

Cross-platform endpoint detection and response agent.
Reads kernel telemetry (auditd on Linux, log stream on macOS, Sysmon on Windows),
evaluates behavioral heuristics, streams telemetry to the CyCentra platform,
and executes response commands (isolate, kill_process, quarantine_file, run_scan).

Phase 1: Python bridge reading native OS event sources.
Phase 2: Native eBPF (Linux) / ESF (macOS) / ETW (Windows) agent replaces this.
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    import psutil
except ImportError:
    psutil = None

# ── Globals ────────────────────────────────────────────────────────────────────
VERSION       = "1.0.0"
OS_TYPE       = platform.system().upper()   # LINUX, DARWIN, WINDOWS
_RUNNING      = True
_STOP_EVENT   = threading.Event()
logger        = logging.getLogger("cyedr")

# ── Configuration ──────────────────────────────────────────────────────────────
class Config:
    def __init__(self, path: str):
        with open(path) as f:
            d = json.load(f)
        self.platform_url       = d["platform_url"].rstrip("/")
        self.deploy_token       = d["deploy_token"]
        self.agent_id           = d.get("agent_id", "")
        self.asset_type         = d.get("asset_type", "workstation")
        self.hostname           = d.get("hostname", socket.gethostname())
        self.os_type            = d.get("os_type", OS_TYPE)
        self.edr_home           = d.get("edr_home", "/opt/cycentra/edr")
        self.poll_interval      = int(d.get("poll_interval", 60))
        self.heartbeat_interval = int(d.get("heartbeat_interval", 60))
        self.telemetry_batch    = int(d.get("telemetry_batch", 20))
        self.yara_rules         = d.get("yara_rules", "")
        self.yara_binary        = d.get("yara_binary", "yara")
        self.quarantine_dir     = d.get("quarantine_dir", "/opt/cycentra/edr/quarantine")
        self.ioc_cache          = d.get("ioc_cache", "/opt/cycentra/edr/ioc_cache/ioc.json")
        self.log_file           = d.get("log_file", "/opt/cycentra/edr/logs/cyedr_agent.log")
        self.sysmon_channel     = d.get("sysmon_channel", "Microsoft-Windows-Sysmon/Operational")
        self._path              = path

    def save_agent_id(self, agent_id: str):
        self.agent_id = agent_id
        with open(self._path) as f:
            d = json.load(f)
        d["agent_id"] = agent_id
        with open(self._path, "w") as f:
            json.dump(d, f, indent=2)


# ── Logging ────────────────────────────────────────────────────────────────────
def setup_logging(log_file: str):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    handler = RotatingFileHandler(log_file, maxBytes=20 * 1024 * 1024, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("[CyEDR] %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler, console])


# ── HTTP client with retry ─────────────────────────────────────────────────────
def build_http_session(token: str) -> requests.Session:
    sess = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.mount("http://",  HTTPAdapter(max_retries=retry))
    sess.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "User-Agent":    f"CyEDR/{VERSION}",
    })
    return sess


# ── IOC Cache ─────────────────────────────────────────────────────────────────
class IOCCache:
    """Local cache of threat intel IOCs synced from the platform."""

    def __init__(self, cache_path: str):
        self._path   = cache_path
        self._hashes = set()
        self._ips    = set()
        self._domains = set()
        self._lock   = threading.Lock()
        self._load()

    def _load(self):
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path) as f:
                d = json.load(f)
            with self._lock:
                self._hashes  = set(d.get("hashes", []))
                self._ips     = set(d.get("ips", []))
                self._domains = set(d.get("domains", []))
            logger.info("IOC cache loaded: %d hashes, %d IPs, %d domains",
                        len(self._hashes), len(self._ips), len(self._domains))
        except Exception as e:
            logger.warning("IOC cache load failed: %s", e)

    def refresh(self, http: requests.Session, platform_url: str):
        try:
            resp = http.get(f"{platform_url}/api/edr/ioc-feed", timeout=30)
            if resp.ok:
                d = resp.json()
                os.makedirs(os.path.dirname(self._path), exist_ok=True)
                with open(self._path, "w") as f:
                    json.dump(d, f)
                self._load()
                logger.debug("IOC cache refreshed")
        except Exception as e:
            logger.warning("IOC cache refresh failed: %s", e)

    def match_hash(self, h: str) -> bool:
        with self._lock:
            return h.lower() in self._hashes

    def match_ip(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    def match_domain(self, d: str) -> bool:
        with self._lock:
            return d.lower() in self._domains


# ── Heuristic Engine (19 triggers, mirrors confidence_matrix.py) ───────────────
ASSET_MULTIPLIERS = {
    "domain_controller": 2.0,
    "database":          1.7,
    "api_gateway":       1.6,
    "jump_server":       1.8,
    "server":            1.3,
    "workstation":       1.0,
    "laptop":            1.0,
}

HEURISTIC_TRIGGERS = {
    # --- Process triggers ---
    "unsigned_binary_temp":    15,
    "unusual_parent_process":  35,
    "memory_injection":        40,
    "lsass_access":            45,
    "process_hollowing":       40,
    "process_tampering":       38,
    # --- Execution triggers ---
    "encoded_command":         30,
    "lolbas_execution":        25,
    "macro_execution":         25,
    "wmi_execution":           20,
    "script_from_browser":     30,
    # --- Network triggers ---
    "outbound_unusual_port":   15,
    "c2_pattern":              45,
    "tor_exit_node":           35,
    "dns_tunneling":           30,
    # --- Persistence triggers ---
    "new_service":             20,
    "startup_persistence":     20,
    # --- Credential triggers ---
    "credential_dump":         45,
    "password_spray":          25,
    # --- Shadow AI / governance triggers (low score — informational, not threat) ---
    "shadow_ai_process":       5,
}

# Regex patterns mapped to trigger names (evaluated against raw event text)
PATTERN_MAP = [
    (r"(?i)(memfd_create|process_vm_writev|process_vm_readv|ptrace)",     "memory_injection"),
    (r"(?i)(lsass\.exe)",                                                  "lsass_access"),
    (r"(?i)(sekurlsa|mimikatz|procdump.*lsass|wce\.exe)",                 "credential_dump"),
    (r"(?i)(-EncodedCommand|-enc .*==|FromBase64String|IEX\()",           "encoded_command"),
    (r"(?i)(certutil.*-urlcache|bitsadmin.*/transfer|mshta.*http|rundll32.*javascript|installutil\.exe)", "lolbas_execution"),
    (r"(?i)(WMI|wmiprvse|wmic.*Win32_Process)",                           "wmi_execution"),
    (r"(?i)(Auto_Open|Document_Open|winword.*cmd|excel.*powershell)",     "macro_execution"),
    (r"(?i)(cobalt.?strike|cs.?beacon|metasploit|sliver|havoc.*beacon|brute.?ratel)", "c2_pattern"),
    (r"(?i)(xmrig|stratum\+tcp|cryptonight|coinhive|minexmr)",           "c2_pattern"),
    (r"(?i)\/(etc\/cron|systemd\/system|rc\.local|LaunchDaemons|LaunchAgents)", "startup_persistence"),
    (r"(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled)", "process_hollowing"),
    (r"(?i)(cmd\.exe|powershell|wscript|cscript).*(chrome|firefox|winword|excel)\.exe", "script_from_browser"),
    (r"(?i)(sc\.exe.*(create|config)|PSEXESVC|PsExec.*\\\\)",            "new_service"),
]

# Known local/desktop AI processes to detect as Shadow AI
SHADOW_AI_PROCESSES = [
    "ollama", "lm_studio", "lmstudio", "jan", "gpt4all",
    "koboldcpp", "kobold_cpp", "text-generation-webui", "textgenwebui",
    "llamafile", "llama.cpp", "llama-server", "llama-cpp",
    "comfyui", "stable-diffusion-webui", "invokeai",
    "whisper", "localai", "localai-server",
    "open-webui", "msty", "chatbox",
]

# Regex to detect shadow AI process names in event text
_SHADOW_AI_RE = r"(?i)(" + "|".join(SHADOW_AI_PROCESSES) + r")[\s\"'\\\/]"


PATTERN_MAP.append((_SHADOW_AI_RE, "shadow_ai_process"))


def _check_shadow_ai_processes(cfg: "Config", http: "requests.Session") -> None:
    """
    Scan running process list for known local AI tool executables.
    Sends a shadow_ai telemetry event for each match found.
    Runs once per heartbeat cycle (every 60s).
    """
    if not psutil:
        return
    found: set[str] = set()
    try:
        for proc in psutil.process_iter(["name", "exe", "cmdline"]):
            try:
                pname = (proc.info.get("name") or "").lower()
                exe   = (proc.info.get("exe") or "").lower()
                cmd   = " ".join(proc.info.get("cmdline") or []).lower()
                for ai_proc in SHADOW_AI_PROCESSES:
                    if ai_proc in pname or ai_proc in exe or ai_proc in cmd:
                        found.add(ai_proc)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        logger.debug("shadow_ai_check error: %s", e)
        return

    for tool in found:
        try:
            envelope = {
                "timestamp":         datetime.utcnow().isoformat() + "Z",
                "endpoint_uuid":     cfg.agent_id,
                "os_type":           cfg.os_type,
                "hostname":          cfg.hostname,
                "event_uuid":        str(uuid.uuid4()),
                "event_category":    "shadow_ai",
                "confidence_score":  5,
                "triggered_heuristics": ["shadow_ai_process"],
                "asset_type":        cfg.asset_type,
                "raw":               {"process_name": tool, "ai_tool": tool},
            }
            http.post(
                f"{cfg.platform_url}/api/edr/telemetry",
                json=envelope, timeout=10,
            )
            logger.info("Shadow AI detected: %s", tool)
        except Exception as e:
            logger.debug("shadow_ai telemetry error: %s", e)


def _check_shadow_ai_dns(cfg: "Config", http: "requests.Session") -> None:
    """
    Monitor DNS query logs for SaaS AI domain access.
    Linux: parses systemd-resolved journal.
    macOS: parses mDNSResponder log stream.
    Windows: handled by Sysmon EventID 22 — skipped here.
    Sends dns-detection findings to /api/itam/shadow-ai/dns-ingest.
    """
    if cfg.os_type == "WINDOWS":
        return  # Windows coverage comes from Sysmon EventID 22

    AI_DNS_WATCHLIST = [
        "openai.com", "api.openai.com", "chatgpt.com", "anthropic.com", "api.anthropic.com",
        "claude.ai", "gemini.google.com", "generativelanguage.googleapis.com",
        "aiplatform.googleapis.com", "aistudio.google.com", "vertex.ai",
        "huggingface.co", "api-inference.huggingface.co", "mistral.ai", "api.mistral.ai",
        "cohere.com", "api.cohere.ai", "perplexity.ai", "api.perplexity.ai",
        "together.ai", "api.together.ai", "groq.com", "api.groq.com",
        "fireworks.ai", "deepinfra.com", "deepseek.com", "api.deepseek.com",
        "x.ai", "api.x.ai", "stability.ai", "api.stability.ai",
        "midjourney.com", "runwayml.com", "runway.com", "elevenlabs.io", "api.elevenlabs.io",
        "character.ai", "poe.com", "you.com", "replicate.com", "api.replicate.com",
        "openrouter.ai", "coze.com", "ollama.ai", "ollama.com", "lmstudio.ai",
        "watsonx.ai", "copilot.microsoft.com", "api.githubcopilot.com",
    ]

    def _is_ai(domain: str) -> str | None:
        d = domain.lower().rstrip(".")
        for suffix in AI_DNS_WATCHLIST:
            if d == suffix or d.endswith("." + suffix):
                return suffix
        return None

    def _read_linux() -> list[str]:
        try:
            import subprocess
            r = subprocess.run(
                ["journalctl", "-u", "systemd-resolved",
                 "--since=70 seconds ago", "--no-pager", "--output=cat", "-q"],
                capture_output=True, text=True, timeout=8,
            )
            return r.stdout.splitlines()
        except Exception:
            return []

    def _read_macos() -> list[str]:
        try:
            import subprocess
            r = subprocess.run(
                ["log", "show", "--predicate", 'process == "mDNSResponder"',
                 "--last", "70s", "--style", "syslog"],
                capture_output=True, text=True, timeout=10,
            )
            return r.stdout.splitlines()
        except Exception:
            return []

    lines = _read_linux() if cfg.os_type == "LINUX" else _read_macos()
    hits: set[str] = set()
    for line in lines:
        for part in line.split():
            stripped = part.strip("()[],.;:'\"")
            matched = _is_ai(stripped)
            if matched:
                hits.add(matched)

    for domain in hits:
        try:
            http.post(
                f"{cfg.platform_url}/api/itam/shadow-ai/dns-ingest",
                json={
                    "query_domain": domain,
                    "client_ip": cfg.agent_ip or "",
                    "matched_domain": domain,
                    "hostname": cfg.hostname,
                    "agent_id": cfg.agent_id,
                    "detection_method": "dns_journal",
                },
                timeout=8,
            )
            logger.info("Shadow AI DNS detected: %s", domain)
        except Exception as e:
            logger.debug("shadow_ai_dns ingest error: %s", e)


def _collect_arp_neighbors() -> list[dict]:
    """
    Collect local ARP table entries.
    Returns list of {ip, mac} dicts for all reachable neighbors.
    Cross-platform: uses `arp -a` output parsing.
    """
    import re as _re
    neighbors: list[dict] = []
    _SKIP = {"127.", "0.0.0.0", "255.", "224.", "<incomplete>", "ff:ff"}
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        )
        # Parse: Windows: "hostname (1.2.3.4) at aa-bb-cc-dd-ee-ff"
        #        Linux:   "1.2.3.4 ether aa:bb:cc:dd:ee:ff"
        #        macOS:   "hostname (1.2.3.4) at aa:bb:cc:dd:ee:ff"
        for line in result.stdout.splitlines():
            ip_match  = _re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", line)
            if not ip_match:
                ip_match = _re.search(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            mac_match = _re.search(r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                                   r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})", line)
            if not ip_match:
                continue
            ip  = ip_match.group(1)
            mac = mac_match.group(1).upper() if mac_match else ""
            if any(ip.startswith(s) for s in _SKIP) or any(s in mac for s in _SKIP):
                continue
            neighbors.append({"ip": ip, "mac": mac})
    except Exception as e:
        logger.debug("arp collection error: %s", e)
    return neighbors


def score_event(text: str, ioc: IOCCache, asset_type: str,
                extra_triggers: Optional[list] = None) -> tuple[int, list]:
    """
    Evaluate raw event text against heuristic patterns and IOC cache.
    Returns (confidence_score 0-100, list_of_triggered_heuristics).
    """
    triggered = set(extra_triggers or [])

    for pattern, trigger in PATTERN_MAP:
        if re.search(pattern, text):
            triggered.add(trigger)

    # IOC match bonus
    ti_bonus = 0
    for word in text.split():
        clean = word.strip("\"',;()[]{}\\")
        if len(clean) == 64 and re.fullmatch(r"[0-9a-fA-F]+", clean):
            if ioc.match_hash(clean):
                ti_bonus = 50
                triggered.add("threat_intel_match")
        elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", clean):
            if ioc.match_ip(clean):
                ti_bonus = 50
                triggered.add("threat_intel_match")

    if not triggered:
        return 0, []

    raw = sum(HEURISTIC_TRIGGERS.get(t, 10) for t in triggered) + ti_bonus
    multiplier = ASSET_MULTIPLIERS.get(asset_type, 1.0)
    score = min(100, int(raw * multiplier))
    return score, sorted(triggered)


# ── TelemetryEnvelope builder ─────────────────────────────────────────────────
def build_envelope(cfg: Config, event_category: str, raw_event: dict,
                   score: int, triggers: list) -> dict:
    return {
        "timestamp":       datetime.utcnow().isoformat() + "Z",
        "endpoint_uuid":   cfg.agent_id,
        "os_type":         cfg.os_type,
        "hostname":        cfg.hostname,
        "event_uuid":      str(uuid.uuid4()),
        "event_category":  event_category,
        "confidence_score": score,
        "triggered_heuristics": triggers,
        "asset_type":      cfg.asset_type,
        "raw":             raw_event,
    }


# ── Linux: auditd reader ───────────────────────────────────────────────────────
class AuditdReader(threading.Thread):
    """
    Reads from /var/log/audit/audit.log (or auditd socket) and emits events
    for CyEDR keys (cy360_edr_*). Wazuh reads the same log independently
    for its own keys (cy360_wazuh_tamper, FIM, etc.) — no conflict.
    """
    EDR_KEY_PREFIX = "cy360_edr_"

    def __init__(self, event_queue: queue.Queue, ioc: IOCCache, cfg: Config):
        super().__init__(daemon=True, name="AuditdReader")
        self._q   = event_queue
        self._ioc = ioc
        self._cfg = cfg

    def run(self):
        # Prefer audisp socket if CyEDR plugin configured; fallback to log tail
        audit_log = "/var/log/audit/audit.log"
        if os.path.exists("/var/run/cyedr_audit.sock"):
            self._read_socket()
        elif os.path.exists(audit_log):
            self._tail_log(audit_log)
        else:
            logger.warning("AuditdReader: no audit source found")

    def _tail_log(self, path: str):
        logger.info("AuditdReader: tailing %s", path)
        try:
            with open(path) as f:
                f.seek(0, 2)   # seek to end
                while not _STOP_EVENT.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    self._process_line(line.strip())
        except Exception as e:
            logger.error("AuditdReader tail error: %s", e)

    def _read_socket(self):
        import socket as sk
        logger.info("AuditdReader: reading from audisp socket")
        while not _STOP_EVENT.is_set():
            try:
                s = sk.socket(sk.AF_UNIX, sk.SOCK_STREAM)
                s.connect("/var/run/cyedr_audit.sock")
                buf = ""
                while not _STOP_EVENT.is_set():
                    chunk = s.recv(4096).decode("utf-8", errors="replace")
                    if not chunk:
                        break
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        self._process_line(line.strip())
            except Exception as e:
                logger.warning("AuditdReader socket error: %s — reconnecting in 5s", e)
                time.sleep(5)

    def _process_line(self, line: str):
        if not line or not re.search(r"key=\"cy360_edr_", line):
            return
        event = self._parse_audit_line(line)
        if not event:
            return

        score, triggers = score_event(line, self._ioc, self._cfg.asset_type)
        if score < 10:
            return

        key = event.get("key", "")
        category = "PROCESS" if "exec" in key else \
                   "NETWORK" if "net"  in key else \
                   "INJECT"  if "inject" in key else "KERNEL"

        env = build_envelope(self._cfg, category, event, score, triggers)
        env["raw"]["audit_key"] = key
        env["raw"]["syscall"]   = event.get("syscall", "")
        env["raw"]["exe"]       = event.get("exe", "")
        env["raw"]["uid"]       = event.get("uid", "")
        self._q.put(env)

    @staticmethod
    def _parse_audit_line(line: str) -> dict:
        parts = {}
        for m in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', line):
            k, v = m.group(1), m.group(2).strip('"')
            parts[k] = v
        return parts


# ── macOS: log stream reader ────────────────────────────────────────────────────
class MacOSLogReader(threading.Thread):
    """
    Subscribes to Apple Unified Log (oslog) for process creation and security events.
    Separate from the Wazuh apple-oslog subscription (different subsystem filter).
    CyEDR focuses on process lifecycle; Wazuh keeps auth/TCC/kext coverage.
    """

    EDR_SUBSYSTEMS = [
        "com.apple.kernel",
        "com.apple.security.sos",
        "com.apple.endpointsecurity",
        "com.apple.xpc.launchd",
        "com.apple.execve",
        "com.apple.process",
    ]

    def __init__(self, event_queue: queue.Queue, ioc: IOCCache, cfg: Config):
        super().__init__(daemon=True, name="MacOSLogReader")
        self._q   = event_queue
        self._ioc = ioc
        self._cfg = cfg

    def run(self):
        logger.info("MacOSLogReader: starting log stream subscription")
        pred_parts = " OR ".join(f'subsystem == "{s}"' for s in self.EDR_SUBSYSTEMS)
        pred = f'({pred_parts}) AND (messageType == "error" OR messageType == "fault" OR messageType == "info")'

        cmd = ["log", "stream", "--style", "json", "--predicate", pred]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, bufsize=1)
            buf = ""
            while not _STOP_EVENT.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        logger.warning("MacOSLogReader: log stream exited — restarting in 10s")
                        time.sleep(10)
                        self.run()
                        return
                    continue
                buf += line
                if buf.strip().endswith("}"):
                    self._process_entry(buf)
                    buf = ""
        except Exception as e:
            logger.error("MacOSLogReader error: %s", e)

    def _process_entry(self, raw: str):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return

        text = entry.get("eventMessage", "") + " " + entry.get("processImagePath", "")
        score, triggers = score_event(text, self._ioc, self._cfg.asset_type)
        if score < 10:
            return

        env = build_envelope(self._cfg, "PROCESS", {
            "message":    entry.get("eventMessage", ""),
            "process":    entry.get("processImagePath", ""),
            "pid":        entry.get("processID", 0),
            "subsystem":  entry.get("subsystem", ""),
        }, score, triggers)
        self._q.put(env)


# ── Windows: Sysmon event reader ───────────────────────────────────────────────
class WindowsSysmonReader(threading.Thread):
    """
    Reads Sysmon events from Windows Event Log channel.
    CyEDR now owns the Sysmon event channel; Wazuh no longer reads it
    (Sysmon localfile block removed from agent.conf).
    """

    SYSMON_EVENTIDS = {1, 3, 6, 7, 8, 10, 11, 12, 13, 22, 25}

    def __init__(self, event_queue: queue.Queue, ioc: IOCCache, cfg: Config):
        super().__init__(daemon=True, name="WindowsSysmonReader")
        self._q       = event_queue
        self._ioc     = ioc
        self._cfg     = cfg
        self._channel = cfg.sysmon_channel

    def run(self):
        logger.info("WindowsSysmonReader: subscribing to %s", self._channel)
        try:
            import win32evtlog
            import win32con
            self._read_via_win32evtlog(win32evtlog, win32con)
        except ImportError:
            logger.info("WindowsSysmonReader: win32evtlog not available, using Get-WinEvent fallback")
            self._read_via_powershell()

    def _read_via_win32evtlog(self, win32evtlog, win32con):
        hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        while not _STOP_EVENT.is_set():
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for ev in events:
                    if ev.EventID in self.SYSMON_EVENTIDS:
                        self._process_win32_event(ev)
            except Exception as e:
                logger.debug("win32evtlog read: %s", e)
            time.sleep(1)

    def _process_win32_event(self, ev):
        strings = ev.StringInserts or []
        text = " ".join(str(s) for s in strings if s)
        score, triggers = score_event(text, self._ioc, self._cfg.asset_type)
        if score < 15:
            return
        env = build_envelope(self._cfg, "PROCESS", {
            "event_id":  ev.EventID,
            "time":      str(ev.TimeGenerated),
            "fields":    list(strings),
        }, score, triggers)
        self._q.put(env)

    def _read_via_powershell(self):
        """Fallback: poll Get-WinEvent every 5 seconds for new Sysmon events."""
        last_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        while not _STOP_EVENT.is_set():
            try:
                ids = ",".join(str(i) for i in self.SYSMON_EVENTIDS)
                ps_cmd = (
                    f"Get-WinEvent -FilterHashtable @{{LogName='{self._channel}';"
                    f"Id={ids};StartTime='{last_time}'}} -ErrorAction SilentlyContinue | "
                    "Select-Object -ExpandProperty Message"
                )
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                    capture_output=True, text=True, timeout=20
                )
                last_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                if result.stdout:
                    for block in result.stdout.split("\n\n"):
                        text = block.strip()
                        if not text:
                            continue
                        score, triggers = score_event(text, self._ioc, self._cfg.asset_type)
                        if score >= 15:
                            env = build_envelope(self._cfg, "PROCESS",
                                                 {"raw_message": text}, score, triggers)
                            self._q.put(env)
            except Exception as e:
                logger.debug("Get-WinEvent poll error: %s", e)
            time.sleep(5)


# ── Telemetry sender ───────────────────────────────────────────────────────────
class TelemetrySender(threading.Thread):
    """Drains the event queue and POSTs batches to /api/edr/telemetry."""

    def __init__(self, event_queue: queue.Queue, http: requests.Session,
                 cfg: Config):
        super().__init__(daemon=True, name="TelemetrySender")
        self._q    = event_queue
        self._http = http
        self._cfg  = cfg
        self._url  = f"{cfg.platform_url}/api/edr/telemetry"

    def run(self):
        while not _STOP_EVENT.is_set():
            batch = []
            try:
                while len(batch) < self._cfg.telemetry_batch:
                    item = self._q.get(timeout=5)
                    batch.append(item)
            except queue.Empty:
                pass
            if batch:
                self._send(batch)

    def _send(self, batch: list):
        try:
            resp = self._http.post(self._url, json={"events": batch}, timeout=30)
            if not resp.ok:
                logger.warning("Telemetry send failed: %s %s", resp.status_code, resp.text[:200])
            else:
                logger.debug("Telemetry: sent %d events", len(batch))
        except Exception as e:
            logger.warning("Telemetry send exception: %s", e)
            # Re-queue events so they're not lost
            for item in batch:
                self._q.put(item)
            time.sleep(5)


# ── Response executor ──────────────────────────────────────────────────────────
class ResponseExecutor:
    """Executes commands issued by the platform (ISOLATE, KILL_PROCESS, QUARANTINE_FILE, etc.)."""

    def __init__(self, cfg: Config):
        self._cfg = cfg
        os.makedirs(cfg.quarantine_dir, exist_ok=True)

    def execute(self, cmd: dict) -> dict:
        name   = cmd.get("command_type", "")
        params = cmd.get("parameters", {})
        result = {"status": "failed", "output": ""}

        handlers = {
            "ISOLATE":        self._isolate,
            "UNISOLATE":      self._unisolate,
            "KILL_PROCESS":   self._kill_process,
            "QUARANTINE_FILE": self._quarantine_file,
            "ROLLBACK":       self._rollback,
            "RUN_SCAN":       self._run_scan,
            "COLLECT_FORENSICS": self._collect_forensics,
        }
        handler = handlers.get(name)
        if handler:
            try:
                output = handler(params)
                result = {"status": "completed", "output": output}
            except Exception as e:
                result = {"status": "failed", "output": str(e)}
                logger.error("Command %s failed: %s", name, e)
        else:
            result = {"status": "failed", "output": f"Unknown command: {name}"}

        return result

    # ── ISOLATE ──
    def _isolate(self, params: dict) -> str:
        reason = params.get("reason", "Platform command")
        mgmt_ip = params.get("management_ip", "")
        if OS_TYPE == "LINUX":
            return self._isolate_linux(mgmt_ip, reason)
        elif OS_TYPE == "DARWIN":
            return self._isolate_macos(mgmt_ip, reason)
        elif OS_TYPE == "WINDOWS":
            return self._isolate_windows(mgmt_ip, reason)
        raise RuntimeError(f"Unsupported OS: {OS_TYPE}")

    def _isolate_linux(self, mgmt_ip: str, reason: str) -> str:
        # Flush existing rules, then block all except loopback and EDR management channel
        cmds = [
            ["iptables", "-F"],
            ["iptables", "-P", "INPUT",   "DROP"],
            ["iptables", "-P", "OUTPUT",  "DROP"],
            ["iptables", "-P", "FORWARD", "DROP"],
            ["iptables", "-A", "INPUT",  "-i", "lo", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ]
        if mgmt_ip:
            cmds.append(["iptables", "-A", "OUTPUT", "-d", mgmt_ip, "-j", "ACCEPT"])
            cmds.append(["iptables", "-A", "INPUT",  "-s", mgmt_ip, "-j", "ACCEPT"])
        # Allow established connections to management (so agent can send telemetry)
        cmds.append(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED", "-j", "ACCEPT"])

        for c in cmds:
            subprocess.run(c, check=True, capture_output=True)
        logger.info("ISOLATE applied (Linux iptables). Reason: %s", reason)
        return f"Endpoint isolated via iptables. Reason: {reason}"

    def _isolate_macos(self, mgmt_ip: str, reason: str) -> str:
        # pf-based isolation
        pf_rules = "block all\npass on lo0\n"
        if mgmt_ip:
            pf_rules += f"pass out quick to {mgmt_ip} keep state\n"
            pf_rules += f"pass in quick from {mgmt_ip} keep state\n"

        pf_conf = "/tmp/cyedr_isolation.pf"
        with open(pf_conf, "w") as f:
            f.write(pf_rules)
        subprocess.run(["pfctl", "-f", pf_conf], check=True, capture_output=True)
        subprocess.run(["pfctl", "-e"], capture_output=True)
        logger.info("ISOLATE applied (macOS pf). Reason: %s", reason)
        return f"Endpoint isolated via pf. Reason: {reason}"

    def _isolate_windows(self, mgmt_ip: str, reason: str) -> str:
        # Windows Firewall: block all, allow loopback + management IP
        cmds = [
            ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
        ]
        if mgmt_ip:
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         "name=CyEDR-Management-Out", "dir=out", f"remoteip={mgmt_ip}",
                         "action=allow"])
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         "name=CyEDR-Management-In", "dir=in", f"remoteip={mgmt_ip}",
                         "action=allow"])
        for c in cmds:
            subprocess.run(c, capture_output=True)
        logger.info("ISOLATE applied (Windows Firewall). Reason: %s", reason)
        return f"Endpoint isolated via Windows Firewall. Reason: {reason}"

    # ── UNISOLATE ──
    def _unisolate(self, params: dict) -> str:
        if OS_TYPE == "LINUX":
            for rule in ["-P INPUT ACCEPT", "-P OUTPUT ACCEPT", "-P FORWARD ACCEPT", "-F"]:
                subprocess.run(["iptables"] + rule.split(), capture_output=True)
        elif OS_TYPE == "DARWIN":
            subprocess.run(["pfctl", "-d"], capture_output=True)
        elif OS_TYPE == "WINDOWS":
            subprocess.run(["netsh", "advfirewall", "set", "allprofiles",
                            "firewallpolicy", "blockinbound,allowoutbound"],
                           capture_output=True)
        logger.info("UNISOLATE applied")
        return "Network access restored"

    # ── KILL_PROCESS ──
    def _kill_process(self, params: dict) -> str:
        pid = params.get("pid")
        if not pid:
            raise ValueError("Missing pid parameter")
        pid = int(pid)
        if psutil:
            proc = psutil.Process(pid)
            proc.kill()
            return f"Process {pid} ({proc.name()}) terminated"
        os.kill(pid, signal.SIGKILL)
        return f"Process {pid} killed (SIGKILL)"

    # ── QUARANTINE_FILE ──
    def _quarantine_file(self, params: dict) -> str:
        path = params.get("file_path", "")
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")
        safe_name = hashlib.sha256(path.encode()).hexdigest()[:16]
        dest = os.path.join(self._cfg.quarantine_dir, safe_name)
        shutil.move(path, dest)
        os.chmod(dest, 0o000)   # deny all access
        logger.info("Quarantined: %s → %s", path, dest)
        return f"File quarantined: {path} → {dest}"

    # ── ROLLBACK ──
    def _rollback(self, params: dict) -> str:
        # Linux: restore from /var/lib/cycentra/journal/ if available
        # macOS: restore from APFS snapshot
        # Windows: restore from VSS snapshot
        journal_path = params.get("file_path", "")
        snapshot_id  = params.get("snapshot_id", "")

        if OS_TYPE == "LINUX" and journal_path:
            backup = f"/var/lib/cycentra/journal/{hashlib.sha256(journal_path.encode()).hexdigest()}"
            if os.path.exists(backup):
                shutil.copy2(backup, journal_path)
                return f"Restored: {journal_path}"
            return f"No journal backup found for {journal_path}"

        elif OS_TYPE == "DARWIN" and snapshot_id:
            result = subprocess.run(
                ["tmutil", "restore", "--source", snapshot_id, "--destination", journal_path],
                capture_output=True, text=True
            )
            return result.stdout or result.stderr

        elif OS_TYPE == "WINDOWS" and journal_path:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"], capture_output=True, text=True
            )
            return f"VSS rollback invoked for {journal_path}. Shadow state: {result.stdout[:200]}"

        return "No rollback action available for current configuration"

    # ── RUN_SCAN ──
    def _run_scan(self, params: dict) -> dict:
        path       = params.get("scan_path", "/")
        yara_bin   = self._cfg.yara_binary
        yara_rules = self._cfg.yara_rules

        if not shutil.which(yara_bin) and not os.path.exists(yara_bin):
            return {"output": "YARA binary not found — scan skipped", "matches": [], "source": "bundled"}

        # Collect rule files: bundled cycentra.yar + custom.yar (if present)
        rule_files = []
        if yara_rules and os.path.exists(yara_rules):
            rule_files.append(("bundled", yara_rules))
        custom_yar = os.path.join(self._cfg.edr_home, "custom.yar")
        if os.path.exists(custom_yar) and os.path.getsize(custom_yar) > 0:
            rule_files.append(("custom_yara", custom_yar))

        if not rule_files:
            return {"output": "No YARA rules available — scan skipped", "matches": [], "source": "none"}

        all_matches = []
        source_tag  = "bundled"
        for source, rules_path in rule_files:
            try:
                result = subprocess.run(
                    [yara_bin, "-r", rules_path, path],
                    capture_output=True, text=True, timeout=300,
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    all_matches.append({
                        "rule":   parts[0],
                        "path":   parts[1] if len(parts) > 1 else "unknown",
                        "source": source,
                    })
                    if source == "custom_yara":
                        source_tag = "custom_yara"
            except subprocess.TimeoutExpired:
                logger.warning("YARA scan timed out for %s with %s", path, rules_path)
            except Exception as exc:
                logger.warning("YARA scan error (%s): %s", source, exc)

        summary = f"YARA scan complete. {len(all_matches)} match(es) in {path}."
        return {"output": summary, "matches": all_matches, "source": source_tag}

    # ── COLLECT_FORENSICS ──
    def _collect_forensics(self, params: dict) -> str:
        out_dir = os.path.join(self._cfg.edr_home, "forensics")
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        artifacts = {}
        # Process list
        if psutil:
            procs = []
            for p in psutil.process_iter(["pid", "name", "exe", "username", "cmdline"]):
                try:
                    procs.append(p.info)
                except Exception:
                    pass
            artifacts["processes"] = procs

        # Network connections
        if psutil:
            try:
                artifacts["connections"] = [
                    {"laddr": str(c.laddr), "raddr": str(c.raddr),
                     "status": c.status, "pid": c.pid}
                    for c in psutil.net_connections(kind="inet")
                ]
            except Exception:
                pass

        # Write out
        out_file = os.path.join(out_dir, f"forensics_{ts}.json")
        with open(out_file, "w") as f:
            json.dump(artifacts, f, indent=2, default=str)

        return f"Forensics collected: {out_file} ({len(artifacts.get('processes', []))} processes)"


# ── Command poller ─────────────────────────────────────────────────────────────
class CommandPoller(threading.Thread):
    """Polls platform for pending response commands and executes them."""

    def __init__(self, http: requests.Session, cfg: Config, executor: ResponseExecutor):
        super().__init__(daemon=True, name="CommandPoller")
        self._http     = http
        self._cfg      = cfg
        self._executor = executor

    def run(self):
        while not _STOP_EVENT.is_set():
            try:
                self._poll()
            except Exception as e:
                logger.warning("CommandPoller error: %s", e)
            _STOP_EVENT.wait(self._cfg.poll_interval)

    def _poll(self):
        if not self._cfg.agent_id:
            return
        url = f"{self._cfg.platform_url}/api/edr/response/{self._cfg.agent_id}/pending"
        resp = self._http.get(url, timeout=15)
        if not resp.ok:
            return
        commands = resp.json().get("commands", [])
        if not commands:
            return
        logger.info("CommandPoller: %d pending command(s)", len(commands))
        for cmd in commands:
            cmd_id = cmd.get("id")
            result = self._executor.execute(cmd)
            self._ack(cmd_id, result)

    def _ack(self, cmd_id: Any, result: dict):
        try:
            self._http.post(
                f"{self._cfg.platform_url}/api/edr/response/{self._cfg.agent_id}/ack",
                json={"command_id": cmd_id, **result},
                timeout=15
            )
        except Exception as e:
            logger.warning("Command ACK failed: %s", e)


# ── Heartbeat ──────────────────────────────────────────────────────────────────
class Heartbeat(threading.Thread):

    def __init__(self, http: requests.Session, cfg: Config):
        super().__init__(daemon=True, name="Heartbeat")
        self._http = http
        self._cfg  = cfg

    def run(self):
        while not _STOP_EVENT.is_set():
            try:
                self._beat()
            except Exception as e:
                logger.debug("Heartbeat error: %s", e)
            _STOP_EVENT.wait(self._cfg.heartbeat_interval)

    def _beat(self):
        if not self._cfg.agent_id:
            return
        payload = {"version": VERSION, "os_type": self._cfg.os_type}
        if psutil:
            payload["cpu_percent"]  = psutil.cpu_percent(interval=1)
            payload["mem_percent"]  = psutil.virtual_memory().percent
            payload["disk_percent"] = psutil.disk_usage("/").percent

        # ARP neighbor discovery — feeds ITAM network_assets table
        neighbors = _collect_arp_neighbors()
        if neighbors:
            payload["arp_neighbors"] = neighbors

        self._http.post(
            f"{self._cfg.platform_url}/api/edr/agents/{self._cfg.agent_id}/heartbeat",
            json=payload, timeout=10
        )
        logger.debug("Heartbeat sent (neighbors=%d)", len(neighbors))

        # Shadow AI process scan — sends telemetry for each detected AI tool
        _check_shadow_ai_processes(self._cfg, self._http)
        # Shadow AI DNS journal scan — Linux/macOS journal-based SaaS AI detection
        _check_shadow_ai_dns(self._cfg, self._http)


# ── IOC refresh loop ───────────────────────────────────────────────────────────
class IOCRefresher(threading.Thread):
    INTERVAL = 3600  # refresh IOC cache + custom YARA rules every hour

    def __init__(self, ioc: IOCCache, http: requests.Session, platform_url: str,
                 edr_home: str, agent_id: str):
        super().__init__(daemon=True, name="IOCRefresher")
        self._ioc      = ioc
        self._http     = http
        self._url      = platform_url
        self._edr_home = edr_home
        self._agent_id = agent_id

    def _refresh_custom_yara(self):
        """Fetch active custom YARA rules from the platform and write to custom.yar."""
        try:
            resp = self._http.get(
                f"{self._url}/api/edr/installer/custom-yara",
                timeout=30,
            )
            if resp.ok:
                out_path = os.path.join(self._edr_home, "custom.yar")
                os.makedirs(self._edr_home, exist_ok=True)
                with open(out_path, "w") as f:
                    f.write(resp.text)
                logger.debug("Custom YARA rules refreshed (%d bytes)", len(resp.text))
            else:
                logger.debug("Custom YARA fetch returned %s", resp.status_code)
        except Exception as exc:
            logger.warning("Custom YARA refresh failed: %s", exc)

    def run(self):
        while not _STOP_EVENT.is_set():
            self._ioc.refresh(self._http, self._url)
            self._refresh_custom_yara()
            _STOP_EVENT.wait(self.INTERVAL)


# ── Self-enrollment (if no agent_id yet) ──────────────────────────────────────
def ensure_enrolled(cfg: Config, http: requests.Session):
    if cfg.agent_id:
        logger.info("Agent already enrolled: %s", cfg.agent_id)
        return

    logger.info("Enrolling with platform...")
    try:
        agent_ip = ""
        if psutil:
            for iface, addrs in psutil.net_if_addrs().items():
                if "lo" in iface.lower():
                    continue
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        agent_ip = addr.address
                        break
                if agent_ip:
                    break

        resp = http.post(
            f"{cfg.platform_url}/api/edr/agents/self-enroll",
            json={
                "hostname":   cfg.hostname,
                "os_type":    cfg.os_type,
                "asset_type": cfg.asset_type,
                "agent_ip":   agent_ip,
                "version":    VERSION,
            },
            timeout=30
        )
        if resp.ok:
            data = resp.json()
            agent_id = data.get("agent_id")
            if agent_id:
                cfg.save_agent_id(agent_id)
                logger.info("Enrolled — Agent ID: %s", agent_id)
            else:
                logger.error("Enrollment response missing agent_id: %s", resp.text)
        else:
            logger.error("Enrollment failed: %s %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.error("Enrollment exception: %s", e)


# ── Signal handler ─────────────────────────────────────────────────────────────
def handle_signal(signum, frame):
    global _RUNNING
    logger.info("Received signal %d — shutting down gracefully", signum)
    _RUNNING = False
    _STOP_EVENT.set()


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CyCentra 360 CyEDR Agent")
    parser.add_argument("--config", required=True, help="Path to config.json")
    args = parser.parse_args()

    cfg = Config(args.config)
    setup_logging(cfg.log_file)
    logger.info("CyEDR Agent v%s starting on %s (%s)", VERSION, cfg.hostname, cfg.os_type)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT,  handle_signal)

    http = build_http_session(cfg.deploy_token)
    ensure_enrolled(cfg, http)

    ioc      = IOCCache(cfg.ioc_cache)
    ev_queue = queue.Queue(maxsize=5000)
    executor = ResponseExecutor(cfg)

    # Build reader for this platform
    if OS_TYPE == "LINUX":
        reader = AuditdReader(ev_queue, ioc, cfg)
    elif OS_TYPE == "DARWIN":
        reader = MacOSLogReader(ev_queue, ioc, cfg)
    else:
        reader = WindowsSysmonReader(ev_queue, ioc, cfg)

    threads = [
        reader,
        TelemetrySender(ev_queue, http, cfg),
        CommandPoller(http, cfg, executor),
        Heartbeat(http, cfg),
        IOCRefresher(ioc, http, cfg.platform_url, cfg.edr_home, cfg.agent_id),
    ]

    for t in threads:
        t.start()
        logger.info("Started thread: %s", t.name)

    logger.info("CyEDR Agent fully operational — polling every %ds, heartbeat every %ds",
                cfg.poll_interval, cfg.heartbeat_interval)

    while _RUNNING:
        time.sleep(1)

    logger.info("CyEDR Agent shutting down")
    _STOP_EVENT.set()
    for t in threads:
        t.join(timeout=5)
    logger.info("CyEDR Agent stopped")


if __name__ == "__main__":
    main()
