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
import fnmatch
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
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta
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

try:
    # Verifies the tamper-protection admin password locally (bcrypt hash
    # only — the plaintext is typed by the local user and never leaves this
    # process). Already a transitive PyInstaller build dep via paramiko, see
    # agent-packages/build-edr-packages.sh.
    import bcrypt
except ImportError:
    bcrypt = None

# ── Globals ────────────────────────────────────────────────────────────────────
VERSION       = "1.0.0"
AGENT_VERSION = "1.0.238"           # bumped by hand only when this script itself changes
                                     # (NOT every platform release — see
                                     # _get_deployed_agent_version() in blueprints/edr/routes.py
                                     # for why: syncing this to the platform version caused every
                                     # agent to "self-update" to a byte-identical script on every
                                     # unrelated release, in a ~10s restart loop). Last real change
                                     # here shipped in v1.0.238 (tray Stop/Exit + watchdog fix);
                                     # this constant was left at 1.0.230 for 7 releases afterward.
OS_TYPE       = platform.system().upper()   # LINUX, DARWIN, WINDOWS
_RUNNING      = True
_STOP_EVENT   = threading.Event()
logger        = logging.getLogger("cyedr")

# ── Stable hardware UUID — survives reinstalls and hostname changes ────────────
def _get_hardware_uuid() -> str:
    """Return a hardware-stable identifier for this machine."""
    try:
        if platform.system() == "Darwin":
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
            ).decode(errors="replace")
            m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
            if m:
                return m.group(1).upper()
        elif platform.system() == "Linux":
            for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                if os.path.exists(path):
                    uid = open(path).read().strip()
                    if uid:
                        return uid.upper()
            try:
                uid = open("/sys/class/dmi/id/product_uuid").read().strip()
                if uid:
                    return uid.upper()
            except Exception:
                pass
        elif platform.system() == "Windows":
            out = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"],
                stderr=subprocess.DEVNULL,
            ).decode(errors="replace")
            for line in out.splitlines():
                line = line.strip()
                if line and line.upper() != "UUID":
                    return line.upper()
    except Exception:
        pass
    # Fallback: stable hash of primary MAC + initial hostname (written once to config)
    return hashlib.sha256(
        f"{uuid.getnode()}:{socket.gethostname()}".encode()
    ).hexdigest()[:32].upper()


# ── Policy enforcement constants ───────────────────────────────────────────────
_SINKHOLE_BEGIN  = "# BEGIN CyEDR-SINKHOLE"
_SINKHOLE_END    = "# END CyEDR-SINKHOLE"
_UDEV_USB_RULES  = "/etc/udev/rules.d/99-cyedr-usb.rules"
_CRON_DEEPSCAN   = "/etc/cron.d/cyedr-deepscan"
_CRON_UPDATE     = "/etc/cron.d/cyedr-update"
_PF_ANCHOR       = "/etc/pf.anchors/cyedr_policy"

# ── System-tray local IPC ───────────────────────────────────────────────────────
# The agent runs as a privileged headless service (root LaunchDaemon / SYSTEM
# service) with no GUI session of its own. cyedr_tray.py is a separate,
# unprivileged, per-user process that reaches the agent only through this
# local channel — Unix domain socket on Linux/macOS, named pipe on Windows.
_IPC_SOCKET_NAME = "agent.sock"
_IPC_PIPE_NAME   = r"\\.\pipe\CyEDRAgent"

# Shown to the local admin (agent log) after a tray-authorized stop — a
# stopped agent has no running process left to serve a "start" IPC command,
# so recovery is deliberately local-admin-only. See IPCListener._do_stop().
_RECOVERY_CMDS = {
    "LINUX":   "sudo systemctl start cyedr-agent",
    "DARWIN":  "sudo launchctl bootstrap system /Library/LaunchDaemons/com.cycentra.edr.plist",
    "WINDOWS": "sc start CyEDRAgent  (run from an elevated/Administrator prompt)",
}


def _verify_tamper_password_standalone(edr_home: str, password: str) -> tuple[bool, str]:
    """Same verification + lockout semantics as ResponseExecutor._verify_
    tamper_password, factored out so it can also run with no live agent
    process at all — see _cli_verify_and_start(), used by the tray's "Start
    CyEDR" action. Reads policy_state.json / tamper_lockout.json directly
    from disk instead of a live Config/ResponseExecutor object graph (there
    is nothing running yet to hold one). ResponseExecutor._verify_tamper_
    password delegates to this so the two call sites (live Stop over IPC,
    offline Start via elevated CLI) can never drift out of sync."""
    policy_state_path   = os.path.join(edr_home, "policy_state.json")
    tamper_lockout_path = os.path.join(edr_home, "tamper_lockout.json")

    policy_state = {}
    try:
        if os.path.exists(policy_state_path):
            with open(policy_state_path) as f:
                policy_state = json.load(f)
    except Exception:
        pass
    tp = policy_state.get("tamper_protection", {})

    if not tp.get("password_set") or not tp.get("protect_stop", True):
        return True, "no admin password configured"
    if bcrypt is None:
        return False, "bcrypt unavailable on this build — action blocked for safety"

    def _load_lockout() -> dict:
        try:
            if os.path.exists(tamper_lockout_path):
                with open(tamper_lockout_path) as f:
                    return json.load(f)
        except Exception:
            pass
        return {"failed_attempts": 0, "locked_until": ""}

    def _save_lockout(state: dict):
        try:
            with open(tamper_lockout_path, "w") as f:
                json.dump(state, f)
        except Exception:
            pass

    lockout = _load_lockout()
    locked_until = lockout.get("locked_until", "")
    if locked_until:
        try:
            if datetime.fromisoformat(locked_until) > datetime.utcnow():
                return False, f"locked out until {locked_until} (too many failed attempts)"
        except Exception:
            pass

    stored_hash = tp.get("password_hash", "")
    ok = False
    if stored_hash and password:
        try:
            ok = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except Exception:
            ok = False

    if ok:
        _save_lockout({"failed_attempts": 0, "locked_until": ""})
        return True, "password verified"

    max_attempts    = tp.get("lockout_attempts", 5)
    lockout_minutes = tp.get("lockout_minutes", 15)
    attempts = lockout.get("failed_attempts", 0) + 1
    new_state = {"failed_attempts": attempts, "locked_until": ""}
    if attempts >= max_attempts:
        new_state["locked_until"] = (datetime.utcnow() + timedelta(minutes=lockout_minutes)).isoformat()
    _save_lockout(new_state)
    return False, f"incorrect password (attempt {attempts}/{max_attempts})"


def _cli_verify_and_start(edr_home: str, password_file: str | None) -> None:
    """One-shot mode (--verify-and-start): no daemon startup, just verify the
    tamper password and, if allowed, start the underlying OS service. There
    is no running agent to ask over IPC — this offline path exists so the
    tray's "Start CyEDR" action has something to invoke. On macOS the tray
    calls this via `osascript ... with administrator privileges`, so this
    process is already running as root by the time it gets here — which is
    also what lets it read policy_state.json (root-only) and issue the
    launchctl/systemctl/sc start command. Always prints exactly one JSON line
    to stdout ({"ok": bool, "detail": str}) so the caller can parse the
    result; never raises.
    """
    password = ""
    if password_file:
        try:
            with open(password_file) as f:
                password = f.read()
        finally:
            try:
                os.remove(password_file)
            except OSError:
                pass

    allowed, detail = _verify_tamper_password_standalone(edr_home, password)
    result = {"ok": allowed, "detail": detail}

    if allowed:
        try:
            if OS_TYPE == "LINUX":
                subprocess.run(["systemctl", "start", "cyedr-agent"], check=True, timeout=15)
            elif OS_TYPE == "DARWIN":
                r = subprocess.run(
                    ["launchctl", "bootstrap", "system",
                     "/Library/LaunchDaemons/com.cycentra.edr.plist"],
                    capture_output=True, text=True, timeout=15,
                )
                # "already bootstrapped" means the end state the user asked
                # for (service loaded) already holds — treat as success, not
                # an error, rather than surfacing launchd's own wording.
                if r.returncode != 0 and "already bootstrapped" not in (r.stderr or "").lower():
                    result = {"ok": False, "detail": f"launchctl bootstrap failed: {r.stderr.strip()}"}
            elif OS_TYPE == "WINDOWS":
                subprocess.run(["sc", "start", "CyEDRAgent"], check=True, timeout=15)
        except Exception as e:
            result = {"ok": False, "detail": f"start command failed: {e}"}

    print(json.dumps(result))


def _ensure_ipc_token(cfg: "Config") -> str:
    """Low-value shared secret so the IPC socket isn't wide open to literally
    any local process — NOT the real security boundary (that's the admin
    password verified in ResponseExecutor._verify_tamper_password). World-
    readable by design: any locally logged-in user must be able to run the
    tray and request a scan; only STOP is gated behind the password."""
    try:
        os.makedirs(cfg.ipc_dir, exist_ok=True)
        os.chmod(cfg.ipc_dir, 0o755)
        path = os.path.join(cfg.ipc_dir, "ipc.token")
        if os.path.exists(path):
            tok = open(path).read().strip()
            if tok:
                return tok
        token = uuid.uuid4().hex + uuid.uuid4().hex
        with open(path, "w") as f:
            f.write(token)
        os.chmod(path, 0o644)
        return token
    except Exception as e:
        logger.warning("IPC token init failed: %s", e)
        return ""

# ── Configuration ──────────────────────────────────────────────────────────────
class Config:
    def __init__(self, path: str):
        with open(path) as f:
            d = json.load(f)
        self.platform_url       = d["platform_url"].rstrip("/")
        self.deploy_token       = d["deploy_token"]
        self.enrollment_token   = d.get("enrollment_token", d["deploy_token"])
        self.agent_id           = d.get("agent_id", "")
        self.hardware_uuid      = d.get("hardware_uuid", "")
        self.asset_type         = d.get("asset_type", "workstation")
        self.hostname           = d.get("hostname", socket.gethostname())
        self.os_type            = d.get("os_type", OS_TYPE)
        self.edr_home           = d.get("edr_home", "/opt/cycentra/edr")
        # Separate, world-traversable sibling directory for the tray IPC
        # socket/token. EDR_HOME itself is chmod 750 root-only (installer:
        # cyedr-install.sh) — config.json inside it holds the enrollment
        # token — so the IPC surface a regular desktop user must reach can't
        # live there without loosening that. See IPCListener in this file.
        self.ipc_dir            = d.get("ipc_dir", os.path.join(
            os.path.dirname(self.edr_home.rstrip("/")) or "/opt/cycentra", "edr-ipc"))
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
        # ARP network guard — persisted by heartbeat response
        _arp = d.get("arp_discovery", {})
        self.arp_enabled        = _arp.get("enabled", True)
        self.arp_enabled_until  = _arp.get("arp_enabled_until", "")
        # Active policy state — populated by ResponseExecutor on startup and after each APPLY_POLICY
        self.policy_state: dict = {}

    def save_agent_id(self, agent_id: str, hardware_uuid: str = ""):
        self.agent_id = agent_id
        if hardware_uuid:
            self.hardware_uuid = hardware_uuid
        with open(self._path) as f:
            d = json.load(f)
        d["agent_id"] = agent_id
        if hardware_uuid:
            d["hardware_uuid"] = hardware_uuid
        with open(self._path, "w") as f:
            json.dump(d, f, indent=2)

    def save_enrollment_token(self, token: str):
        """Persist the per-agent token returned by self-enroll — the initial
        deploy_token is shared/rotatable and is not valid for authenticated
        calls (heartbeat, telemetry) once the server has minted this one."""
        self.enrollment_token = token
        with open(self._path) as f:
            d = json.load(f)
        d["enrollment_token"] = token
        with open(self._path, "w") as f:
            json.dump(d, f, indent=2)

    def save_arp_state(self, enabled: bool, until_iso: str):
        """Persist arp_enabled + arp_enabled_until from heartbeat response."""
        self.arp_enabled       = enabled
        self.arp_enabled_until = until_iso
        with open(self._path) as f:
            d = json.load(f)
        d.setdefault("arp_discovery", {})["enabled"]           = enabled
        d["arp_discovery"]["arp_enabled_until"]                = until_iso
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

# Known local/desktop AI processes and AI coding assistant CLIs to detect as Shadow AI
SHADOW_AI_PROCESSES = [
    # Local LLM servers / UIs
    "ollama", "lm_studio", "lmstudio", "jan", "gpt4all",
    "koboldcpp", "kobold_cpp", "text-generation-webui", "textgenwebui",
    "llamafile", "llama.cpp", "llama-server", "llama-cpp",
    "comfyui", "stable-diffusion-webui", "invokeai",
    "whisper", "localai", "localai-server",
    "open-webui", "msty", "chatbox",
    # AI coding assistants / agent CLIs
    "claude",                   # Claude Code CLI (Anthropic)
    "cursor",                   # Cursor AI editor
    "windsurf",                 # Windsurf AI editor (Codeium)
    "aider",                    # Aider AI pair-programmer
    "continue",                 # Continue.dev extension server
    "codeium",                  # Codeium language server
    "copilot-language-server",  # GitHub Copilot LSP
    "tabnine-language-server",  # TabNine AI
    "supermaven",               # Supermaven AI
    "ghostwriter",              # Replit Ghostwriter
]

# OS system process names whose pname contains an AI tool substring but are NOT AI tools.
# Matching by process name (pname) first prevents false exe/cmd matches on the same process.
SHADOW_AI_PROC_EXCLUSIONS: set[str] = {
    "cursoruiviewservice",   # macOS AppKit accessibility daemon — not the Cursor IDE
}


def _self_update(cfg: "Config", http: "requests.Session", server_version: str) -> None:
    """
    Hot-swap the agent when the server reports a newer version.

    Script mode (*.py): downloads new script, atomic rename, sys.exit(0).
    Binary mode (Linux/macOS): downloads new binary from /installer/agent-binary,
      atomic POSIX rename over running binary (safe — kernel holds old inode open),
      sys.exit(0) → launchd/systemd restarts with new binary at same path.
    Binary mode (Windows): not supported via self-update; re-run cyedr-install.ps1.
    """
    import platform as _plat
    from pathlib import Path as _Path

    script_path = _Path(sys.argv[0]).resolve()
    tmp_path    = _Path(str(script_path) + ".update")

    # -------- Script mode (Python fallback install, any platform) --------
    if str(script_path).endswith(".py"):
        logger.info("Self-update: server=%s local=%s — downloading script update...",
                    server_version, AGENT_VERSION)
        try:
            resp = http.get(
                f"{cfg.platform_url}/api/edr/installer/agent-script",
                timeout=60, stream=True,
            )
            if not resp.ok:
                logger.warning("Self-update download failed: HTTP %s", resp.status_code)
                return
            with tmp_path.open("wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            tmp_path.chmod(script_path.stat().st_mode)
            tmp_path.replace(script_path)
            logger.info("Self-update: script applied %s — restarting", server_version)
            # _self_update() runs inside the Heartbeat background thread, not the
            # main thread — sys.exit() there only raises SystemExit in that thread
            # and silently leaves the process (and old in-memory code) running
            # forever. os._exit() terminates the whole process unconditionally so
            # systemd's Restart=always actually relaunches with the new script.
            os._exit(0)
        except Exception as exc:
            logger.error("Self-update (script) failed: %s", exc)
            try:
                tmp_path.unlink()
            except Exception:
                pass
        return

    # -------- Binary mode — Windows: not supported --------
    if cfg.os_type == "WINDOWS":
        logger.info(
            "Self-update: Windows binary — re-run cyedr-install.ps1 to upgrade to %s",
            server_version,
        )
        return

    # -------- Binary mode — Linux / macOS --------
    _machine = _plat.machine().lower()
    _arch = "x86_64" if _machine in ("x86_64", "amd64") else "aarch64"
    _os   = "macos" if cfg.os_type == "DARWIN" else "linux"
    bundle_url = (
        f"{cfg.platform_url}/api/edr/installer/agent-binary"
        f"?os={_os}&arch={_arch}"
    )
    logger.info(
        "Self-update: binary mode (%s/%s) — server=%s local=%s — downloading...",
        _os, _arch, server_version, AGENT_VERSION,
    )
    try:
        resp = http.get(bundle_url, timeout=120, stream=True)
        if not resp.ok:
            logger.warning(
                "Self-update binary download failed: HTTP %s — no bundle staged for %s/%s",
                resp.status_code, _os, _arch,
            )
            return
        with tmp_path.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
        tmp_path.chmod(script_path.stat().st_mode | 0o111)  # ensure executable
        tmp_path.replace(script_path)   # atomic POSIX rename — safe while binary is running
        logger.info("Self-update: binary %s applied — restarting via service manager", server_version)
        os._exit(0)  # see script-mode comment above — must exit the whole process, not this thread
    except Exception as exc:
        logger.error("Self-update (binary) failed: %s", exc)
        try:
            tmp_path.unlink()
        except Exception:
            pass

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
                if pname in SHADOW_AI_PROC_EXCLUSIONS:
                    continue  # known system process — skip before exe/cmd substring scan
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
                json={"events": [envelope]}, timeout=10,
            )
            logger.info("Shadow AI detected: %s", tool)
        except Exception as e:
            logger.debug("shadow_ai telemetry error: %s", e)


def _check_shadow_ai_dns(cfg: "Config", http: "requests.Session") -> None:
    """
    Monitor network connections for SaaS AI domain access — all platforms.

    Primary strategy (Linux / macOS):
      Forward-resolve all AI watchlist domains to build an IP→domain map, then
      match against established TCP:443 connections via psutil.  Works despite
      browser DoH (DNS-over-HTTPS) and CDN masking because we resolve from the
      same host that holds the connections — Cloudflare/Akamai IPs resolve to the
      same CDN IPs that the active connections use.

    Windows:
      Get-DnsClientCache (PowerShell) returns actual domain names directly, so no
      CDN masking issue.  Forward-DNS TCP scan supplements for DoH browsers.

    Why the old approach (DNS journals / dscacheutil) was replaced:
      - systemd-resolved only emits DNS query logs at DEBUG level; INFO (default)
        produces zero journal output → Linux journal scan always returned empty.
      - dscacheutil -cachedump is unreliable on macOS 13+ (Ventura/Sonoma) and
        returns nothing for cache entries in modern kernels.
      - Reverse-DNS on CDN IPs (Cloudflare 172.64.x.x / 104.18.x.x) returns
        NXDOMAIN — PTR records are absent — so the old TCP fallback was also blind.
    """
    import socket as _socket
    import time as _time

    AI_DNS_WATCHLIST = [
        # OpenAI / ChatGPT
        "openai.com", "api.openai.com", "chatgpt.com",
        "oaiusercontent.com", "oai.azure.com", "openai.azure.com",
        # Anthropic / Claude
        "anthropic.com", "api.anthropic.com", "claude.ai",
        # Google
        "gemini.google.com", "generativelanguage.googleapis.com",
        "aiplatform.googleapis.com", "aistudio.google.com", "vertex.ai",
        "makersuite.google.com",
        # Meta / HuggingFace
        "llama-api.com", "llamameta.net",
        "huggingface.co", "huggingface.com", "api-inference.huggingface.co",
        # Mistral / Cohere / Perplexity
        "mistral.ai", "api.mistral.ai", "console.mistral.ai",
        "cohere.com", "cohere.ai", "api.cohere.ai", "api.cohere.com",
        "perplexity.ai", "api.perplexity.ai",
        # Together / Groq / Fireworks / DeepInfra
        "together.ai", "api.together.ai", "api.together.xyz",
        "groq.com", "api.groq.com",
        "fireworks.ai", "api.fireworks.ai",
        "deepinfra.com", "api.deepinfra.com",
        # DeepSeek / xAI
        "deepseek.com", "api.deepseek.com", "chat.deepseek.com",
        "x.ai", "api.x.ai", "grok.x.ai",
        # Image / video / voice AI
        "stability.ai", "api.stability.ai", "platform.stability.ai",
        "midjourney.com", "cdn.midjourney.com",
        "runwayml.com", "runway.com", "api.runwayml.com",
        "elevenlabs.io", "api.elevenlabs.io",
        # Writing / chat AI
        "writesonic.com", "api.writesonic.com",
        "jasper.ai", "api.jasper.ai",
        "copy.ai", "api.copy.ai",
        "character.ai", "beta.character.ai", "neo.character.ai",
        "poe.com", "you.com", "phind.com",
        # Model hubs / aggregators
        "replicate.com", "api.replicate.com",
        "openrouter.ai", "api.openrouter.ai",
        "coze.com", "api.coze.com",
        "venice.ai", "api.venice.ai",
        "ollama.ai", "ollama.com",
        "lmstudio.ai",
        # Cloud AI platforms
        "bedrock.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com",
        "watsonx.ai", "us-south.ml.cloud.ibm.com",
        # Coding AI / enterprise
        "copilot.microsoft.com", "api.githubcopilot.com",
        "grammarly.com",
        "api.notion.so",
    ]

    def _is_ai(domain: str) -> str | None:
        d = domain.lower().rstrip(".")
        for suffix in AI_DNS_WATCHLIST:
            if d == suffix or d.endswith("." + suffix):
                return suffix
        return None

    # ── Forward-DNS cache: resolve AI domains → set of IPs (TTL = 10 min) ──────
    # Module-level cache so we don't resolve 60+ domains every heartbeat cycle.
    cache: dict[str, str]  = _check_shadow_ai_dns._ip_cache       # type: ignore[attr-defined]
    cache_ts: list[float]  = _check_shadow_ai_dns._ip_cache_ts    # type: ignore[attr-defined]
    cache_ttl = 600.0

    def _get_ip_to_domain() -> dict[str, str]:
        if _time.monotonic() - cache_ts[0] < cache_ttl and cache:
            return cache
        new_cache: dict[str, str] = {}
        for domain in AI_DNS_WATCHLIST:
            try:
                for info in _socket.getaddrinfo(domain, 443, type=_socket.SOCK_STREAM):
                    ip = info[4][0]
                    if ip not in new_cache:
                        new_cache[ip] = domain
            except Exception:
                pass
        cache.clear()
        cache.update(new_cache)
        cache_ts[0] = _time.monotonic()
        return cache

    # ── TCP/UDP connection scan using forward-DNS map (Linux / macOS primary) ────
    def _scan_tcp_forward_dns(ip_to_domain: dict[str, str]) -> dict[str, str]:
        found: dict[str, str] = {}
        if not psutil:
            return found
        try:
            for conn in psutil.net_connections(kind="inet"):
                # status=="ESTABLISHED" → TCP; status=="" → UDP/QUIC (HTTP3)
                if (conn.raddr
                        and conn.raddr.port in (443, 80, 8080, 8443)
                        and conn.status in ("ESTABLISHED", "")):
                    matched = ip_to_domain.get(conn.raddr.ip)
                    if matched and matched not in found:
                        found[matched] = "tcp_forward_dns"
        except Exception:
            pass
        return found

    # ── macOS: lsof scan (catches QUIC/UDP:443 that psutil misses) ───────────
    def _scan_lsof_macos(ip_to_domain: dict[str, str]) -> dict[str, str]:
        """
        lsof -i :443 lists every process socket bound to port 443, including
        QUIC/HTTP3 UDP sockets that psutil.net_connections() drops because they
        have no 'ESTABLISHED' status.  Works for Chrome, Safari, Firefox on macOS.
        """
        found: dict[str, str] = {}
        try:
            r = subprocess.run(
                ["lsof", "-i", ":443", "-n", "-P"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines()[1:]:   # skip header row
                parts = line.split()
                # NAME field contains "->"; TCP lines append "(ESTABLISHED)" after it
                # so we search for the part containing "->" rather than using parts[-1]
                name = next((p for p in parts if "->" in p), None)
                if not name:
                    continue
                remote = name.split("->")[-1]        # "104.18.32.47:443" or "[2a06::1]:443"
                ip = remote.rsplit(":", 1)[0].strip("[]")
                matched = ip_to_domain.get(ip)
                if matched and matched not in found:
                    found[matched] = "lsof_macos"
        except Exception:
            pass
        return found

    # ── macOS: AppleScript browser tab scanner ────────────────────────────────
    def _scan_browser_tabs_macos() -> dict[str, str]:
        """
        Enumerate all open tabs in Chrome-family browsers and Safari via
        Apple Events (osascript).  Timing-independent: catches chatgpt.com
        even when there is no active TCP/QUIC connection to port 443.
        Requires the agent's process to have Automation access (granted on
        first run via macOS Privacy dialog, or pre-approved via MDM profile).
        """
        found: dict[str, str] = {}

        def _extract_host(url: str) -> str:
            try:
                return url.split("//", 1)[1].split("/")[0].split("?")[0].lower()
            except Exception:
                return ""

        for browser, method in (
            ("Google Chrome", "browser_tabs_chrome"),
            ("Chromium",      "browser_tabs_chrome"),
            ("Arc",           "browser_tabs_chrome"),
            ("Brave Browser", "browser_tabs_chrome"),
        ):
            script = (
                f'tell application "{browser}"\n'
                f'  if it is running then\n'
                f'    set u to ""\n'
                f'    repeat with w in windows\n'
                f'      repeat with t in tabs of w\n'
                f'        set u to u & (URL of t) & linefeed\n'
                f'      end repeat\n'
                f'    end repeat\n'
                f'    return u\n'
                f'  end if\n'
                f'end tell'
            )
            try:
                r = subprocess.run(
                    ["osascript", "-e", script],
                    capture_output=True, text=True, timeout=5,
                )
                for line in r.stdout.splitlines():
                    host = _extract_host(line.strip())
                    if not host:
                        continue
                    matched = _is_ai(host)
                    if matched and matched not in found:
                        found[matched] = method
            except Exception:
                pass

        # Safari
        safari_script = (
            'tell application "Safari"\n'
            '  if it is running then\n'
            '    set u to ""\n'
            '    repeat with w in windows\n'
            '      repeat with t in tabs of w\n'
            '        try\n'
            '          set u to u & (URL of t) & linefeed\n'
            '        end try\n'
            '      end repeat\n'
            '    end repeat\n'
            '    return u\n'
            '  end if\n'
            'end tell'
        )
        try:
            r = subprocess.run(
                ["osascript", "-e", safari_script],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                host = _extract_host(line.strip())
                if not host:
                    continue
                matched = _is_ai(host)
                if matched and matched not in found:
                    found[matched] = "browser_tabs_safari"
        except Exception:
            pass

        return found

    # ── macOS: Chrome history reader (last 24 h) ──────────────────────────────
    def _scan_chrome_history_macos() -> dict[str, str]:
        """
        Copy Chrome's History SQLite to a temp file (bypasses the write lock)
        and query visits in the past 24 hours.  Catches AI domains even after
        the browser tab is closed or the QUIC session has ended.
        Handles root-service case by scanning all /Users/* home directories.
        """
        import sqlite3 as _sq3
        import shutil  as _sh
        import tempfile as _tf

        found: dict[str, str] = {}
        chrome_rel = os.path.join(
            "Library", "Application Support", "Google", "Chrome", "Default", "History"
        )

        homes: list[str] = []
        cur_home = os.path.expanduser("~")
        if cur_home not in ("/root", "/var/root"):
            homes.append(cur_home)
        for entry in (os.listdir("/Users") if os.path.isdir("/Users") else []):
            full = os.path.join("/Users", entry)
            if os.path.isdir(full) and full not in homes:
                homes.append(full)

        for home in homes:
            hist = os.path.join(home, chrome_rel)
            if not os.path.exists(hist):
                continue
            tmp = ""
            try:
                with _tf.NamedTemporaryFile(suffix=".db", delete=False) as tf:
                    tmp = tf.name
                _sh.copy2(hist, tmp)
                # Chrome stores times as µs since 1601-01-01; convert Unix epoch
                cutoff = (_time.time() - 86400) * 1_000_000 + 11_644_473_600 * 1_000_000
                con = _sq3.connect(tmp)
                for (url,) in con.execute(
                    "SELECT url FROM urls WHERE last_visit_time > ? LIMIT 500",
                    (cutoff,),
                ):
                    try:
                        host = url.split("//", 1)[1].split("/")[0].split("?")[0].lower()
                    except Exception:
                        continue
                    matched = _is_ai(host)
                    if matched and matched not in found:
                        found[matched] = "browser_history"
                con.close()
            except Exception:
                pass
            finally:
                if tmp:
                    try:
                        os.unlink(tmp)
                    except Exception:
                        pass
        return found

    # ── Windows: DNS Client Cache via PowerShell ──────────────────────────────
    def _read_windows() -> list[str]:
        lines: list[str] = []
        try:
            r = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command",
                 "Get-DnsClientCache | Select-Object -ExpandProperty Entry"],
                capture_output=True, text=True, timeout=12,
            )
            lines.extend(r.stdout.splitlines())
        except Exception:
            pass
        return lines

    # ── Collect hits by platform ──────────────────────────────────────────────
    all_hits: dict[str, str] = {}  # domain → detection_method

    if cfg.os_type == "WINDOWS":
        # PowerShell DNS cache gives exact domain names — no CDN issue
        for line in _read_windows():
            for part in line.split():
                matched = _is_ai(part.strip("()[],.;:'\""))
                if matched and matched not in all_hits:
                    all_hits[matched] = "dns_cache"
        # Supplement with forward-DNS TCP scan to catch DoH browsers
        for domain, method in _scan_tcp_forward_dns(_get_ip_to_domain()).items():
            if domain not in all_hits:
                all_hits[domain] = method
    else:
        ip_map = _get_ip_to_domain()
        all_hits.update(_scan_tcp_forward_dns(ip_map))
        if cfg.os_type == "DARWIN":
            # 1. Browser tabs (AppleScript) — timing-independent, most reliable for SaaS AI
            for domain, method in _scan_browser_tabs_macos().items():
                if domain not in all_hits:
                    all_hits[domain] = method
            # 2. Chrome history — catches recent visits even after tabs close
            for domain, method in _scan_chrome_history_macos().items():
                if domain not in all_hits:
                    all_hits[domain] = method
            # 3. lsof — catches QUIC/HTTP3 and any TCP that psutil missed
            for domain, method in _scan_lsof_macos(ip_map).items():
                if domain not in all_hits:
                    all_hits[domain] = method

    for domain, method in all_hits.items():
        try:
            http.post(
                f"{cfg.platform_url}/api/itam/shadow-ai/dns-ingest",
                json={
                    "query_domain": domain,
                    "client_ip": cfg.agent_ip or "",
                    "matched_domain": domain,
                    "hostname": cfg.hostname,
                    "agent_id": cfg.agent_id,
                    "detection_method": method,
                },
                timeout=8,
            )
            logger.info("Shadow AI DNS detected: %s [%s]", domain, method)
        except Exception as e:
            logger.debug("shadow_ai_dns ingest error: %s", e)


# Module-level cache storage for _check_shadow_ai_dns (avoids re-resolving every 60s)
_check_shadow_ai_dns._ip_cache    = {}     # type: ignore[attr-defined]
_check_shadow_ai_dns._ip_cache_ts = [0.0]  # type: ignore[attr-defined]


def _get_gateway_macs() -> list[dict]:
    """
    Return default gateway(s) as [{ip, mac}] for network-zone trust evaluation.

    Strategy:
      1. Detect all default-route gateway IPs from the routing table.
      2. Look up each gateway IP in the ARP cache to get its MAC.

    Cross-platform: Linux (ip route), macOS (netstat -rn), Windows (Get-NetRoute).
    Returns an empty list on any failure — never raises.
    """
    import re as _re
    gateways: list[dict] = []
    gw_ips: list[str] = []

    try:
        if OS_TYPE == "LINUX":
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=8)
            for line in r.stdout.splitlines():
                m = _re.search(r"via\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
                if m:
                    gw_ips.append(m.group(1))
        elif OS_TYPE == "MACOS":
            r = subprocess.run(["netstat", "-rn"],
                               capture_output=True, text=True, timeout=8)
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts and parts[0] in ("default", "0.0.0.0/0") and len(parts) >= 2:
                    gw_ips.append(parts[1])
        elif OS_TYPE == "WINDOWS":
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric)"
                 " | Select-Object -ExpandProperty NextHop"],
                capture_output=True, text=True, timeout=12
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if _re.match(r"\d{1,3}(\.\d{1,3}){3}", line):
                    gw_ips.append(line)
    except Exception as exc:
        logger.debug("_get_gateway_macs route detection: %s", exc)

    seen_ips: set[str] = set()
    for gw_ip in gw_ips:
        if gw_ip in seen_ips or gw_ip in ("0.0.0.0", ""):
            continue
        seen_ips.add(gw_ip)
        try:
            if OS_TYPE == "WINDOWS":
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-NetNeighbor -IPAddress '{gw_ip}' -ErrorAction SilentlyContinue)"
                     " | Select-Object -ExpandProperty LinkLayerAddress"],
                    capture_output=True, text=True, timeout=8
                )
                mac_raw = r.stdout.strip().replace("-", ":").upper()
            else:
                r = subprocess.run(
                    ["arp", "-n", gw_ip] if OS_TYPE == "LINUX" else ["arp", gw_ip],
                    capture_output=True, text=True, timeout=8
                )
                mac_raw = ""
                m = _re.search(
                    r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                    r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})",
                    r.stdout
                )
                if m:
                    mac_raw = m.group(1).upper().replace("-", ":")

            if mac_raw and mac_raw not in ("", "<incomplete>", "FF:FF:FF:FF:FF:FF"):
                gateways.append({"ip": gw_ip, "mac": mac_raw})
        except Exception as exc:
            logger.debug("_get_gateway_macs arp lookup %s: %s", gw_ip, exc)

    return gateways


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


# ── Self-inventory collectors (Host Security Profile — Asset Inventory) ────────
# Each function is best-effort and platform-dispatched: it must never raise, and
# returns an empty/partial result rather than aborting the whole snapshot if one
# collection step fails (e.g. a locked-down host without lsmod/wmic access).
# Output shapes intentionally mirror NetworkProbePoller._ssh_deep_scan()'s result
# dict so the server can feed both through the same ITAM ingest/CVE-match path.

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _local_run(cmd: str, timeout: int = 10) -> str:
    """Run a local shell command, return stdout (empty string on any failure)."""
    try:
        out = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return out.stdout.decode(errors="replace").strip()
    except Exception:
        return ""


def _collect_macs() -> list[str]:
    macs = []
    if not psutil:
        return macs
    try:
        for _iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if _MAC_RE.match(a.address or ""):
                    macs.append(a.address.upper())
    except Exception:
        pass
    return sorted(set(macs))


def _collect_bios_info() -> dict:
    bios: dict = {}
    try:
        system = platform.system()
        if system == "Linux":
            bios["vendor"]  = _local_run("cat /sys/class/dmi/id/bios_vendor 2>/dev/null")
            bios["version"] = _local_run("cat /sys/class/dmi/id/bios_version 2>/dev/null")
            bios["date"]    = _local_run("cat /sys/class/dmi/id/bios_date 2>/dev/null")
        elif system == "Darwin":
            bios["vendor"]  = "Apple"
            bios["model"]   = _local_run("sysctl -n hw.model")
            bios["version"] = _local_run("sysctl -n kern.osrelease")
        elif system == "Windows":
            raw = _local_run('wmic bios get manufacturer,smbiosbiosversion,releasedate /value')
            for line in raw.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    if v.strip():
                        bios[k.strip().lower()] = v.strip()
    except Exception:
        pass
    return bios


def _collect_hardware_info() -> dict:
    hw: dict = {"macs": _collect_macs(), "bios": _collect_bios_info()}
    try:
        hw["cpu_model"] = platform.processor()
        if psutil:
            hw["cpu_count"] = psutil.cpu_count(logical=True)
            try:
                freq = psutil.cpu_freq()
                if freq:
                    hw["cpu_freq_mhz"] = round(freq.current)
            except Exception:
                pass
            vm = psutil.virtual_memory()
            hw["memory_total_bytes"]     = vm.total
            hw["memory_available_bytes"] = vm.available
            hw["memory_percent"]         = vm.percent
            du = psutil.disk_usage("/")
            hw["disk_total_bytes"] = du.total
            hw["disk_used_bytes"]  = du.used
    except Exception as exc:
        logger.debug("Hardware inventory collection failed: %s", exc)
    return hw


def _collect_os_info() -> dict:
    info = {
        "platform":     platform.system(),
        "release":      platform.release(),
        "architecture": platform.machine(),
        "kernel":       platform.uname().release,
    }
    try:
        system = platform.system()
        if system == "Linux":
            raw = _local_run("cat /etc/os-release 2>/dev/null")
            info["raw"] = raw
            for line in raw.splitlines():
                if line.startswith("PRETTY_NAME="):
                    info["name"] = line.split("=", 1)[1].strip('"')
            info["patch_level"] = _local_run("uname -v")
        elif system == "Darwin":
            info["name"]  = "macOS " + _local_run("sw_vers -productVersion")
            info["build"] = _local_run("sw_vers -buildVersion")
            info["raw"]   = _local_run("sw_vers")
        elif system == "Windows":
            raw = _local_run("wmic os get Caption,Version,BuildNumber /value")
            info["raw"] = raw
            for line in raw.splitlines():
                if line.startswith("Caption="):
                    info["name"] = line.split("=", 1)[1].strip()
                elif line.startswith("BuildNumber="):
                    info["build"] = line.split("=", 1)[1].strip()
    except Exception as exc:
        logger.debug("OS inventory collection failed: %s", exc)
    return info


def _collect_installed_software() -> list[dict]:
    packages: list[dict] = []
    try:
        system = platform.system()
        if system == "Linux":
            raw = _local_run(
                "dpkg-query -W -f='${Package}|${Version}|${Maintainer}\\n' 2>/dev/null"
            )
            if not raw:
                raw = _local_run(
                    "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{VENDOR}|%{INSTALLTIME:date}\\n' 2>/dev/null"
                )
            for line in raw.splitlines():
                p = line.split("|")
                if p and p[0]:
                    packages.append({
                        "name":    p[0],
                        "version": p[1] if len(p) > 1 else "",
                        "vendor":  p[2] if len(p) > 2 else "",
                        "install_date": p[3] if len(p) > 3 else "",
                    })
        elif system == "Darwin":
            raw = _local_run("system_profiler SPApplicationsDataType -json 2>/dev/null", timeout=45)
            if raw:
                try:
                    data = json.loads(raw)
                    for app in data.get("SPApplicationsDataType", [])[:500]:
                        packages.append({
                            "name":         app.get("_name", ""),
                            "version":      app.get("version", ""),
                            "vendor":       app.get("obtained_from", ""),
                            "install_path": app.get("path", ""),
                            "install_date": app.get("lastModified", ""),
                        })
                except Exception:
                    pass
            for line in _local_run("brew list --versions 2>/dev/null").splitlines():
                p = line.split()
                if len(p) >= 2:
                    packages.append({"name": p[0], "version": p[1], "vendor": "Homebrew"})
        elif system == "Windows":
            raw = _local_run(
                'powershell -NoProfile -Command '
                '"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,'
                'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
                '-ErrorAction SilentlyContinue '
                '| Where-Object DisplayName '
                '| Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation '
                '| ConvertTo-Json -Compress"',
                timeout=30,
            )
            if raw:
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        data = [data]
                    for app in data[:500]:
                        packages.append({
                            "name":         app.get("DisplayName", "") or "",
                            "version":      app.get("DisplayVersion", "") or "",
                            "vendor":       app.get("Publisher", "") or "",
                            "install_path": app.get("InstallLocation", "") or "",
                            "install_date": app.get("InstallDate", "") or "",
                        })
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("Software inventory collection failed: %s", exc)
    return packages[:1000]


def _collect_running_services() -> list[dict]:
    services: list[dict] = []
    try:
        system = platform.system()
        if system == "Linux":
            raw = _local_run(
                "systemctl list-units --type=service --state=running "
                "--no-pager --no-legend 2>/dev/null | head -200"
            )
            for line in raw.splitlines():
                p = line.split()
                if p:
                    services.append({"name": p[0].replace(".service", ""), "state": "running"})
        elif system == "Darwin":
            for line in _local_run("launchctl list 2>/dev/null | tail -n +2 | head -200").splitlines():
                p = line.split("\t")
                if len(p) >= 3:
                    services.append({"name": p[2], "state": "running" if p[0] != "-" else "stopped"})
        elif system == "Windows":
            raw = _local_run(
                'powershell -NoProfile -Command '
                '"Get-Service | Where-Object Status -eq \'Running\' '
                '| Select-Object Name,Status | ConvertTo-Json -Compress"',
                timeout=20,
            )
            if raw:
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        data = [data]
                    for svc in data[:300]:
                        services.append({"name": svc.get("Name", ""), "state": "running"})
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("Service inventory collection failed: %s", exc)
    return services


def _collect_running_processes() -> list[dict]:
    procs: list[dict] = []
    if not psutil:
        return procs
    try:
        for p in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                info = p.info
                procs.append({
                    "pid":      info.get("pid"),
                    "name":     info.get("name", "") or "",
                    "exe":      info.get("exe", "") or "",
                    "username": info.get("username", "") or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if len(procs) >= 500:
                break
    except Exception as exc:
        logger.debug("Process inventory collection failed: %s", exc)
    return procs


def _collect_installed_drivers() -> list[dict]:
    drivers: list[dict] = []
    try:
        system = platform.system()
        if system == "Linux":
            for line in _local_run("lsmod 2>/dev/null | tail -n +2 | head -200").splitlines():
                p = line.split()
                if p:
                    drivers.append({"name": p[0], "size": p[1] if len(p) > 1 else ""})
        elif system == "Darwin":
            for line in _local_run("kextstat 2>/dev/null | tail -n +2 | head -200").splitlines():
                p = line.split()
                if len(p) >= 6:
                    drivers.append({"name": p[5]})
        elif system == "Windows":
            raw = _local_run(
                'powershell -NoProfile -Command '
                '"Get-CimInstance Win32_SystemDriver | Where-Object State -eq \'Running\' '
                '| Select-Object Name,DisplayName,PathName | ConvertTo-Json -Compress"',
                timeout=25,
            )
            if raw:
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        data = [data]
                    for d in data[:300]:
                        drivers.append({
                            "name": d.get("DisplayName") or d.get("Name", "") or "",
                            "path": d.get("PathName", "") or "",
                        })
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("Driver inventory collection failed: %s", exc)
    return drivers


def _collect_local_users() -> list[dict]:
    users: list[dict] = []
    try:
        system = platform.system()
        if system == "Linux":
            raw = _local_run(
                "getent passwd 2>/dev/null | "
                "awk -F: '$3>=1000 && $3<65534{print $1\"|\"$3\"|\"$6\"|\"$7}'"
            )
            for line in raw.splitlines():
                p = line.split("|")
                if p and p[0]:
                    users.append({
                        "username": p[0], "uid": p[1] if len(p) > 1 else "",
                        "home": p[2] if len(p) > 2 else "", "shell": p[3] if len(p) > 3 else "",
                    })
        elif system == "Darwin":
            for line in _local_run("dscl . list /Users 2>/dev/null | grep -v '^_'").splitlines():
                name = line.strip()
                if name and name not in ("daemon", "nobody", "root"):
                    users.append({"username": name})
        elif system == "Windows":
            raw = _local_run(
                'powershell -NoProfile -Command '
                '"Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json -Compress"',
                timeout=15,
            )
            if raw:
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        data = [data]
                    for u in data:
                        users.append({"username": u.get("Name", ""), "enabled": u.get("Enabled")})
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("User inventory collection failed: %s", exc)
    return users


def _collect_local_groups() -> list[dict]:
    groups: list[dict] = []
    try:
        system = platform.system()
        if system == "Linux":
            raw = _local_run(
                "getent group 2>/dev/null | awk -F: '$3>=1000 && $3<65534{print $1\"|\"$3}' | head -100"
            )
            for line in raw.splitlines():
                p = line.split("|")
                if p and p[0]:
                    groups.append({"name": p[0], "gid": p[1] if len(p) > 1 else ""})
        elif system == "Darwin":
            for line in _local_run(
                "dscl . list /Groups 2>/dev/null | grep -v '^_' | head -100"
            ).splitlines():
                name = line.strip()
                if name:
                    groups.append({"name": name})
        elif system == "Windows":
            raw = _local_run(
                'powershell -NoProfile -Command '
                '"Get-LocalGroup | Select-Object Name | ConvertTo-Json -Compress"',
                timeout=15,
            )
            if raw:
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        data = [data]
                    for g in data:
                        groups.append({"name": g.get("Name", "")})
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("Group inventory collection failed: %s", exc)
    return groups


def _collect_network_interfaces() -> list[dict]:
    interfaces: list[dict] = []
    if not psutil:
        return interfaces
    try:
        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            entry = {"name": iface, "addresses": [], "mac": "", "is_up": False}
            st = stats.get(iface)
            if st:
                entry["is_up"]      = bool(st.isup)
                entry["speed_mbps"] = st.speed
            for a in addrs:
                if _MAC_RE.match(a.address or ""):
                    entry["mac"] = a.address.upper()
                elif a.address:
                    entry["addresses"].append(a.address)
            interfaces.append(entry)
    except Exception as exc:
        logger.debug("Network interface collection failed: %s", exc)
    return interfaces


def _collect_listening_ports() -> list[dict]:
    ports: list[dict] = []
    if not psutil:
        return ports
    try:
        seen = set()
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_LISTEN or not c.laddr:
                continue
            key = (c.laddr.port, c.type)
            if key in seen:
                continue
            seen.add(key)
            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:
                    pass
            ports.append({
                "port":    c.laddr.port,
                "proto":   "tcp" if c.type == socket.SOCK_STREAM else "udp",
                "address": c.laddr.ip,
                "process": proc_name,
                "pid":     c.pid,
            })
    except Exception as exc:
        logger.debug("Listening port collection failed: %s", exc)
    return ports


def _collect_certificates() -> list[dict]:
    certs: list[dict] = []
    try:
        system = platform.system()
        if system == "Linux":
            raw = _local_run(
                "for f in /etc/ssl/certs/*.pem; do "
                "openssl x509 -noout -subject -enddate -in \"$f\" 2>/dev/null; done | head -400",
                timeout=20,
            )
            subject = ""
            for line in raw.splitlines():
                if line.startswith("subject="):
                    subject = line[len("subject="):].strip()
                elif line.startswith("notAfter=") and subject:
                    certs.append({"subject": subject, "expires": line[len("notAfter="):].strip()})
                    subject = ""
        elif system == "Darwin":
            raw = _local_run(
                "security find-certificate -a -c '' /Library/Keychains/System.keychain 2>/dev/null "
                "| grep '\"labl\"' | head -200",
                timeout=20,
            )
            for line in raw.splitlines():
                if "=" in line:
                    certs.append({"subject": line.split("=", 1)[1].strip().strip('"')})
        elif system == "Windows":
            raw = _local_run(
                'powershell -NoProfile -Command '
                '"Get-ChildItem Cert:\\LocalMachine\\My,Cert:\\LocalMachine\\Root '
                '-ErrorAction SilentlyContinue '
                '| Select-Object Subject,NotAfter | ConvertTo-Json -Compress"',
                timeout=20,
            )
            if raw:
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        data = [data]
                    for c in data[:300]:
                        certs.append({"subject": c.get("Subject", ""), "expires": c.get("NotAfter", "")})
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("Certificate inventory collection failed: %s", exc)
    return certs[:400]


def _collect_cloud_metadata() -> dict:
    """Best-effort, short-timeout IMDS probe — fails fast on non-cloud hosts."""
    try:
        r = requests.get("http://169.254.169.254/latest/meta-data/instance-id", timeout=0.3)
        if r.ok:
            return {"provider": "aws", "instance_id": r.text}
    except Exception:
        pass
    try:
        r = requests.get(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "true"}, timeout=0.3,
        )
        if r.ok:
            return {"provider": "azure", "raw": r.json()}
    except Exception:
        pass
    try:
        r = requests.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/id",
            headers={"Metadata-Flavor": "Google"}, timeout=0.3,
        )
        if r.ok:
            return {"provider": "gcp", "instance_id": r.text}
    except Exception:
        pass
    return {}


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

    def __init__(self, cfg: Config, http: "requests.Session | None" = None):
        self._cfg  = cfg
        self._http = http
        self._policy_state_path  = os.path.join(cfg.edr_home, "policy_state.json")
        os.makedirs(cfg.quarantine_dir, exist_ok=True)
        self._probe_poller: "NetworkProbePoller | None" = None
        self._load_policy_state()
        # Re-activate probe poller if policy was active before this restart
        probe_cfg = self._cfg.policy_state.get("network_probe", {})
        if probe_cfg.get("enabled") and self._http:
            self._start_probe_poller(probe_cfg)

    def execute(self, cmd: dict) -> dict:
        # DB/API returns field "action"; "command_type" was a legacy alias that no longer exists
        name   = cmd.get("action", cmd.get("command_type", ""))
        params = cmd.get("parameters", {})
        result = {"status": "failed", "output": ""}

        handlers = {
            "ISOLATE":           self._isolate,
            "UNISOLATE":         self._unisolate,
            "KILL_PROCESS":      self._kill_process,
            "QUARANTINE_FILE":   self._quarantine_file,
            "ROLLBACK":          self._rollback,
            "RUN_SCAN":          self._run_scan,
            "COLLECT_FORENSICS": self._collect_forensics,
            "APPLY_POLICY":      self._apply_policy,
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
        # Apply isolation_exceptions policy (allowed IPs, ports, DNS, DHCP)
        iex = self._cfg.policy_state.get("isolation_exceptions", {})
        for ip in iex.get("allowed_ips", []):
            cmds.append(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"])
            cmds.append(["iptables", "-A", "INPUT",  "-s", ip, "-j", "ACCEPT"])
        for port in iex.get("allowed_ports", []):
            cmds.append(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
            cmds.append(["iptables", "-A", "INPUT",  "-p", "tcp", "--sport", str(port), "-j", "ACCEPT"])
        if iex.get("allow_dns", True):
            cmds.append(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
            cmds.append(["iptables", "-A", "INPUT",  "-p", "udp", "--sport", "53", "-j", "ACCEPT"])
        if iex.get("allow_dhcp", True):
            cmds.append(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"])
            cmds.append(["iptables", "-A", "INPUT",  "-p", "udp", "--sport", "67:68", "-j", "ACCEPT"])

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
        # Apply isolation_exceptions policy
        iex = self._cfg.policy_state.get("isolation_exceptions", {})
        for ip in iex.get("allowed_ips", []):
            pf_rules += f"pass out quick to {ip} keep state\n"
            pf_rules += f"pass in quick from {ip} keep state\n"
        for port in iex.get("allowed_ports", []):
            pf_rules += f"pass out quick proto tcp to any port {port} keep state\n"
        if iex.get("allow_dns", True):
            pf_rules += "pass out quick proto udp to any port 53\n"
        if iex.get("allow_dhcp", True):
            pf_rules += "pass out quick proto udp to any port 67\n"

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
        # Apply isolation_exceptions policy
        iex = self._cfg.policy_state.get("isolation_exceptions", {})
        for ip in iex.get("allowed_ips", []):
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         "name=CyEDR-IsoEx-IP-Out", "dir=out", f"remoteip={ip}", "action=allow"])
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         "name=CyEDR-IsoEx-IP-In",  "dir=in",  f"remoteip={ip}", "action=allow"])
        for port in iex.get("allowed_ports", []):
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name=CyEDR-IsoEx-Port-{port}", "dir=out", "protocol=tcp",
                         f"remoteport={port}", "action=allow"])
        if iex.get("allow_dns", True):
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         "name=CyEDR-IsoEx-DNS", "dir=out", "protocol=udp",
                         "remoteport=53", "action=allow"])
        if iex.get("allow_dhcp", True):
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         "name=CyEDR-IsoEx-DHCP", "dir=out", "protocol=udp",
                         "remoteport=67", "action=allow"])
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

        # Resolve yara binary: config value → PATH lookup → common absolute fallbacks.
        # LaunchDaemons and systemd services run with a stripped PATH that excludes
        # Homebrew (/opt/homebrew/bin) and some distro paths (/usr/local/bin), so we
        # must probe absolute locations when shutil.which() returns nothing.
        _YARA_FALLBACKS = [
            "/opt/homebrew/bin/yara",   # macOS Apple Silicon (Homebrew)
            "/usr/local/bin/yara",       # macOS Intel (Homebrew) / Linux manual install
            "/usr/bin/yara",             # Linux package manager (apt/yum/dnf)
            "/bin/yara",                 # some minimal Linux distros
        ]
        resolved_bin = shutil.which(yara_bin) or (yara_bin if os.path.isfile(yara_bin) else None)
        if not resolved_bin:
            for fb in _YARA_FALLBACKS:
                if os.path.isfile(fb):
                    resolved_bin = fb
                    logger.info("yara binary resolved via fallback: %s", fb)
                    break
        if not resolved_bin:
            return {"output": "CyScan engine not found — scan skipped", "matches": [], "source": "bundled"}

        # Collect rule files: bundled cycentra.yar + custom.yar (if present)
        rule_files = []
        if yara_rules and os.path.exists(yara_rules):
            rule_files.append(("bundled", yara_rules))
        custom_yar = os.path.join(self._cfg.edr_home, "custom.yar")
        if os.path.exists(custom_yar) and os.path.getsize(custom_yar) > 0:
            rule_files.append(("custom_yara", custom_yar))

        if not rule_files:
            return {"output": "No CyScan rules available — scan skipped", "matches": [], "source": "none"}

        all_matches = []
        source_tag  = "bundled"
        for source, rules_path in rule_files:
            try:
                result = subprocess.run(
                    [resolved_bin, "-r", rules_path, path],
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

        # Filter matches against exclusions policy (paths and extensions)
        excl = self._cfg.policy_state.get("exclusions", {})
        excl_paths = excl.get("paths", [])
        excl_exts  = excl.get("extensions", [])
        excl_hashes_set = {h.lower() for h in excl.get("hashes", [])}
        if excl_paths or excl_exts or excl_hashes_set:
            filtered = []
            for m in all_matches:
                match_path = m.get("path", "")
                if excl_paths and any(match_path.startswith(ep) for ep in excl_paths):
                    continue
                if excl_exts and any(match_path.endswith(ext) for ext in excl_exts):
                    continue
                filtered.append(m)
            excluded_count = len(all_matches) - len(filtered)
            all_matches    = filtered
            if excluded_count:
                logger.debug("YARA: %d match(es) suppressed by exclusions policy", excluded_count)

        summary = f"CyScan complete. {len(all_matches)} match(es) in {path}."
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

    # ═══════════════════════════════════════════════════════════════════════════
    # POLICY ENFORCEMENT
    # Each policy_type delivered via APPLY_POLICY is enforced here and persisted
    # in policy_state.json so that settings survive agent restarts.
    # All threads hold a reference to cfg, so cfg.policy_state updates are
    # immediately visible to heuristic readers and the telemetry sender.
    # ═══════════════════════════════════════════════════════════════════════════

    # ── Policy state I/O ──────────────────────────────────────────────────────

    def _load_policy_state(self):
        if os.path.exists(self._policy_state_path):
            try:
                with open(self._policy_state_path) as f:
                    self._cfg.policy_state = json.load(f)
                logger.info("Policy state loaded: %d policy type(s) active",
                            len(self._cfg.policy_state))
            except Exception as e:
                logger.warning("Policy state load failed: %s", e)
                self._cfg.policy_state = {}
        else:
            self._cfg.policy_state = {}

    def _save_policy_state(self):
        try:
            os.makedirs(os.path.dirname(self._policy_state_path), exist_ok=True)
            with open(self._policy_state_path, "w") as f:
                json.dump(self._cfg.policy_state, f, indent=2)
        except Exception as e:
            logger.warning("Policy state save failed: %s", e)

    # ── APPLY_POLICY dispatcher ───────────────────────────────────────────────

    def _apply_policy(self, params: dict) -> str:
        policy_type = params.get("policy_type", "")
        config      = params.get("config", {})
        policy_id   = params.get("policy_id", "?")

        _dispatch = {
            "threat_prevention":    self._apply_threat_prevention,
            "device_control":       self._apply_device_control,
            "app_control":          self._apply_app_control,
            "network_control":      self._apply_network_control,
            "exclusions":           self._apply_exclusions,
            "update_policy":        self._apply_update_policy,
            "isolation_exceptions": self._apply_isolation_exceptions,
            "network_probe":        self._apply_network_probe_policy,
            "tamper_protection":    self._apply_tamper_protection,
        }

        fn = _dispatch.get(policy_type)
        if not fn:
            raise ValueError(f"Unknown policy_type: {policy_type}")

        result = fn(config)
        self._cfg.policy_state[policy_type] = config
        self._save_policy_state()
        logger.info("Policy applied: type=%s id=%s", policy_type, policy_id)
        return result

    # ── threat_prevention ─────────────────────────────────────────────────────

    def _apply_threat_prevention(self, cfg: dict) -> str:
        parts = []

        yara_enabled = cfg.get("yara_enabled", True)
        parts.append(f"yara={'enabled' if yara_enabled else 'disabled'}")

        auto_q = cfg.get("auto_quarantine", True)
        parts.append(f"auto_quarantine={'on' if auto_q else 'off'}")

        sched = cfg.get("deep_scan_schedule", "off")
        parts.append(self._schedule_deep_scan(sched))

        script_ctrl = cfg.get("script_control", "audit")
        if script_ctrl == "block":
            parts.append("script_engines: " + self._block_script_engines())
        else:
            parts.append(f"script_control={script_ctrl}")

        ai_sens = cfg.get("ai_sensitivity", "medium")
        parts.append(f"ai_sensitivity={ai_sens} (stored)")

        return "threat_prevention: " + "; ".join(parts)

    def _schedule_deep_scan(self, schedule: str) -> str:
        agent_bin    = sys.executable
        agent_script = os.path.abspath(sys.argv[0])
        cfg_path     = self._cfg._path

        cron_map = {"daily": "0 2 * * *", "weekly": "0 2 * * 0", "monthly": "0 2 1 * *"}

        if OS_TYPE == "LINUX":
            if schedule == "off":
                if os.path.exists(_CRON_DEEPSCAN):
                    os.remove(_CRON_DEEPSCAN)
                return "deep_scan=off (cron removed)"
            interval = cron_map.get(schedule, "0 2 * * 0")
            try:
                with open(_CRON_DEEPSCAN, "w") as f:
                    f.write(f"# CyEDR deep scan — auto-generated\n"
                            f"{interval} root {agent_bin} {agent_script} "
                            f"--config {cfg_path} --run-scan /\n")
                return f"deep_scan={schedule} ({interval} cron)"
            except Exception as e:
                return f"deep_scan={schedule} (cron error: {e})"

        elif OS_TYPE == "DARWIN":
            plist_path = "/Library/LaunchDaemons/com.cycentra.edr.deepscan.plist"
            if schedule == "off":
                if os.path.exists(plist_path):
                    subprocess.run(["launchctl", "unload", plist_path], capture_output=True)
                    try:
                        os.remove(plist_path)
                    except Exception:
                        pass
                return "deep_scan=off (LaunchDaemon removed)"
            hour = 2
            try:
                plist = (
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                    "<plist version=\"1.0\"><dict>\n"
                    "  <key>Label</key><string>com.cycentra.edr.deepscan</string>\n"
                    "  <key>ProgramArguments</key><array>\n"
                    f"    <string>{agent_bin}</string><string>{agent_script}</string>\n"
                    f"    <string>--config</string><string>{cfg_path}</string>\n"
                    "    <string>--run-scan</string><string>/</string>\n"
                    "  </array>\n"
                    "  <key>StartCalendarInterval</key><dict>\n"
                    f"    <key>Hour</key><integer>{hour}</integer>\n"
                    "    <key>Minute</key><integer>0</integer>\n"
                    "  </dict>\n"
                    "  <key>RunAtLoad</key><false/>\n"
                    "</dict></plist>\n"
                )
                with open(plist_path, "w") as f:
                    f.write(plist)
                subprocess.run(["launchctl", "load", plist_path], capture_output=True)
                return f"deep_scan={schedule} (LaunchDaemon)"
            except Exception as e:
                return f"deep_scan={schedule} (plist error: {e})"

        elif OS_TYPE == "WINDOWS":
            task_name = "CyEDR-DeepScan"
            if schedule == "off":
                subprocess.run(["schtasks", "/Delete", "/TN", task_name, "/F"],
                               capture_output=True)
                return "deep_scan=off (scheduled task removed)"
            sc_type = {"daily": "DAILY", "weekly": "WEEKLY", "monthly": "MONTHLY"}.get(
                schedule, "WEEKLY")
            try:
                subprocess.run([
                    "schtasks", "/Create", "/F",
                    "/TN", task_name, "/SC", sc_type, "/ST", "02:00",
                    "/TR", f'"{agent_bin}" "{agent_script}" --config "{cfg_path}" --run-scan C:\\',
                    "/RU", "SYSTEM",
                ], capture_output=True, check=True)
                return f"deep_scan={schedule} (Windows scheduled task)"
            except Exception as e:
                return f"deep_scan={schedule} (schtasks error: {e})"

        return f"deep_scan={schedule} (stored)"

    def _block_script_engines(self) -> str:
        if not psutil:
            return "psutil unavailable"
        if OS_TYPE != "WINDOWS":
            return "block mode stored (Linux/macOS: requires kernel driver)"
        targets = {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
        killed  = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if (proc.info.get("name") or "").lower() in targets:
                    proc.kill()
                    killed.append(proc.info["name"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return f"terminated: {killed or 'none'}"

    # ── device_control ────────────────────────────────────────────────────────

    def _apply_device_control(self, cfg: dict) -> str:
        parts = []

        usb_policy   = cfg.get("usb_policy", "allow")
        approved_ids = cfg.get("usb_approved_ids", []) if cfg.get("usb_corporate_only") else []
        parts.append(self._enforce_usb_policy(usb_policy, approved_ids))

        parts.append(self._enforce_bluetooth(cfg.get("bluetooth_policy", "allow")))
        parts.append(self._enforce_wifi(cfg.get("wifi_policy", "allow"),
                                         cfg.get("wifi_approved_ssids", [])))

        for key in ("camera_policy", "microphone_policy", "clipboard_policy", "screenshot_policy"):
            val = cfg.get(key, "allow")
            if val != "allow":
                parts.append(f"{key}={val} (stored; MDM/kernel driver required)")

        return "device_control: " + "; ".join(parts)

    def _enforce_usb_policy(self, policy: str, approved_ids: list) -> str:
        if OS_TYPE == "LINUX":
            if policy == "allow":
                if os.path.exists(_UDEV_USB_RULES):
                    os.remove(_UDEV_USB_RULES)
                    subprocess.run(["udevadm", "control", "--reload-rules"], capture_output=True)
                return "usb=allow"
            lines = ["# CyEDR USB Policy — auto-generated, do not edit"]
            for dev_id in approved_ids:
                if ":" in dev_id:
                    vendor, product = dev_id.split(":", 1)
                    lines.append(
                        f'ACTION=="add", SUBSYSTEM=="usb", '
                        f'ATTR{{idVendor}}=="{vendor}", ATTR{{idProduct}}=="{product}", '
                        f'GOTO="cyedr_usb_end"'
                    )
            if policy == "block":
                lines.append('ACTION=="add", SUBSYSTEM=="usb", ATTR{authorized}="0"')
            elif policy == "read_only":
                lines.append(
                    'ACTION=="add", SUBSYSTEM=="block", ATTRS{removable}=="1", '
                    'RUN+="/sbin/blockdev --setro /dev/%k"'
                )
            lines.append('LABEL="cyedr_usb_end"')
            try:
                with open(_UDEV_USB_RULES, "w") as f:
                    f.write("\n".join(lines) + "\n")
                subprocess.run(["udevadm", "control", "--reload-rules"], capture_output=True)
                subprocess.run(["udevadm", "trigger"], capture_output=True)
                return f"usb={policy} (udev)"
            except Exception as e:
                return f"usb={policy} (udev error: {e})"

        elif OS_TYPE == "WINDOWS":
            try:
                import winreg
                usb_key = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usb_key,
                                    0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD,
                                      4 if policy == "block" else 3)
                if policy == "read_only":
                    stor_key = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
                    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, stor_key) as k:
                        winreg.SetValueEx(k, "WriteProtect", 0, winreg.REG_DWORD, 1)
                elif policy == "allow":
                    stor_key = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, stor_key,
                                            0, winreg.KEY_SET_VALUE) as k:
                            winreg.SetValueEx(k, "WriteProtect", 0, winreg.REG_DWORD, 0)
                    except FileNotFoundError:
                        pass
                return f"usb={policy} (registry)"
            except Exception as e:
                return f"usb={policy} (registry error: {e})"

        return f"usb={policy} (stored; macOS USB blocking requires MDM)"

    def _enforce_bluetooth(self, policy: str) -> str:
        if OS_TYPE == "LINUX":
            cmd = ["rfkill", "block" if policy == "block" else "unblock", "bluetooth"]
            subprocess.run(cmd, capture_output=True)
            return f"bluetooth={'blocked' if policy == 'block' else 'allow'} (rfkill)"

        elif OS_TYPE == "DARWIN":
            val = "0" if policy == "block" else "1"
            try:
                subprocess.run(
                    ["defaults", "write", "/Library/Preferences/com.apple.Bluetooth",
                     "ControllerPowerState", val], capture_output=True)
                subprocess.run(["killall", "-HUP", "bluetoothd"], capture_output=True)
                return f"bluetooth={'blocked' if policy == 'block' else 'allow'} (macOS defaults)"
            except Exception as e:
                return f"bluetooth={policy} (error: {e})"

        elif OS_TYPE == "WINDOWS":
            try:
                if policy == "block":
                    subprocess.run(["sc", "stop",   "bthserv"], capture_output=True)
                    subprocess.run(["sc", "config",  "bthserv", "start=disabled"],
                                   capture_output=True)
                    return "bluetooth=blocked (bthserv disabled)"
                else:
                    subprocess.run(["sc", "config",  "bthserv", "start=auto"],
                                   capture_output=True)
                    subprocess.run(["sc", "start",   "bthserv"], capture_output=True)
                    return "bluetooth=allow (bthserv)"
            except Exception as e:
                return f"bluetooth={policy} (error: {e})"

        return f"bluetooth={policy} (stored)"

    def _enforce_wifi(self, policy: str, approved_ssids: list) -> str:
        if OS_TYPE == "LINUX":
            try:
                if policy == "block":
                    subprocess.run(["nmcli", "radio", "wifi", "off"], capture_output=True)
                    return "wifi=blocked (nmcli)"
                elif policy == "allow":
                    subprocess.run(["nmcli", "radio", "wifi", "on"], capture_output=True)
                    return "wifi=allow (nmcli)"
                elif policy == "managed" and approved_ssids:
                    cur = subprocess.run(
                        ["nmcli", "-t", "-f", "NAME,TYPE,STATE", "connection", "show", "--active"],
                        capture_output=True, text=True)
                    for line in cur.stdout.splitlines():
                        parts = line.split(":")
                        if len(parts) >= 3 and "wifi" in parts[1] and parts[0] not in approved_ssids:
                            subprocess.run(["nmcli", "connection", "down", parts[0]],
                                           capture_output=True)
                    return f"wifi=managed (approved: {approved_ssids})"
            except Exception as e:
                return f"wifi={policy} (nmcli error: {e})"

        elif OS_TYPE == "DARWIN":
            try:
                state = "off" if policy == "block" else "on"
                subprocess.run(
                    ["networksetup", "-setnetworkserviceenabled", "Wi-Fi", state],
                    capture_output=True)
                return f"wifi={'blocked' if policy == 'block' else 'allow'} (networksetup)"
            except Exception as e:
                return f"wifi={policy} (error: {e})"

        elif OS_TYPE == "WINDOWS":
            try:
                state = "disabled" if policy == "block" else "enabled"
                subprocess.run(
                    ["netsh", "interface", "set", "interface", "Wi-Fi", state],
                    capture_output=True)
                return f"wifi={'blocked' if policy == 'block' else 'allow'} (netsh)"
            except Exception as e:
                return f"wifi={policy} (error: {e})"

        return f"wifi={policy} (stored)"

    # ── app_control ───────────────────────────────────────────────────────────

    def _apply_app_control(self, cfg: dict) -> str:
        mode         = cfg.get("mode", "audit")
        blocked_apps = cfg.get("blocked_apps", [])
        allowed_apps = cfg.get("allowed_apps", [])
        hash_rules   = cfg.get("hash_rules", [])
        path_rules   = cfg.get("path_rules", [])

        parts = [f"mode={mode}"]
        if mode in ("blacklist", "whitelist") or blocked_apps or hash_rules or path_rules:
            parts.append(self._app_control_sweep(
                mode, blocked_apps, allowed_apps, hash_rules, path_rules))
        else:
            parts.append("monitoring (audit mode — telemetry only)")

        return "app_control: " + "; ".join(parts)

    def _app_control_sweep(self, mode: str, blocked_apps: list, allowed_apps: list,
                            hash_rules: list, path_rules: list) -> str:
        if not psutil:
            return "sweep skipped (psutil unavailable)"

        blocked_names = {b.lower() for b in blocked_apps}
        allowed_names = {a.lower() for a in allowed_apps}
        block_hashes  = {r["hash"].lower() for r in hash_rules if r.get("action") == "block"}
        block_paths   = [(r["path_pattern"], ) for r in path_rules if r.get("action") == "block"]

        killed = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid  = proc.info.get("pid", 0)
                name = (proc.info.get("name") or "").lower()
                exe  = proc.info.get("exe") or ""
                if pid <= 10:
                    continue
                kill_it = False
                if mode == "blacklist" and name in blocked_names:
                    kill_it = True
                elif mode == "whitelist" and allowed_names and name not in allowed_names:
                    kill_it = True
                if not kill_it and exe and block_hashes:
                    try:
                        digest = hashlib.sha256(
                            open(exe, "rb").read(4 * 1024 * 1024)).hexdigest()
                        if digest in block_hashes:
                            kill_it = True
                    except Exception:
                        pass
                if not kill_it and exe and block_paths:
                    for (pattern,) in block_paths:
                        if fnmatch.fnmatch(exe, pattern):
                            kill_it = True
                            break
                if kill_it:
                    proc.kill()
                    killed.append(f"{name}({pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return f"sweep: {len(killed)} terminated ({', '.join(killed[:5]) or 'none'})"

    # ── network_control ───────────────────────────────────────────────────────

    def _apply_network_control(self, cfg: dict) -> str:
        parts = []

        parts.append(self._set_host_firewall(cfg.get("host_firewall_enabled", True)))

        fw_rules = cfg.get("firewall_rules", [])
        if fw_rules:
            parts.append(self._apply_firewall_rules(
                fw_rules,
                cfg.get("default_inbound", "allow"),
                cfg.get("default_outbound", "allow"),
            ))
        else:
            parts.append(
                f"inbound={cfg.get('default_inbound', 'allow')} "
                f"outbound={cfg.get('default_outbound', 'allow')} (stored)"
            )

        # Build sinkhole domain list
        sinkhole_domains: list = []
        if cfg.get("dns_sinkhole", False):
            sinkhole_domains = list(cfg.get("dns_sinkhole_domains", []))
        if cfg.get("block_malicious_dns", True):
            ioc_domains = self._get_ioc_domains()
            # Merge without duplicates, preserving order
            existing = set(sinkhole_domains)
            sinkhole_domains += [d for d in ioc_domains if d not in existing]
        parts.append(self._update_hosts_sinkhole(sinkhole_domains))

        if cfg.get("proxy_enforcement", False) and cfg.get("proxy_host", ""):
            parts.append(self._set_system_proxy(cfg["proxy_host"]))
        else:
            parts.append(self._clear_system_proxy())

        conn_log = cfg.get("connection_logging", "anomalies")
        if conn_log == "all":
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        parts.append(f"connection_logging={conn_log}")

        return "network_control: " + "; ".join(parts)

    def _set_host_firewall(self, enabled: bool) -> str:
        if OS_TYPE == "LINUX":
            try:
                if not enabled:
                    for rule in ["-F", "-P INPUT ACCEPT", "-P OUTPUT ACCEPT",
                                 "-P FORWARD ACCEPT"]:
                        subprocess.run(["iptables"] + rule.split(), capture_output=True)
                    return "host_firewall=disabled (iptables flushed)"
                return "host_firewall=enabled"
            except Exception as e:
                return f"host_firewall={enabled} (iptables error: {e})"

        elif OS_TYPE == "DARWIN":
            subprocess.run(["pfctl", "-e" if enabled else "-d"], capture_output=True)
            return f"host_firewall={'enabled' if enabled else 'disabled'} (pf)"

        elif OS_TYPE == "WINDOWS":
            state = "on" if enabled else "off"
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", state],
                capture_output=True)
            return f"host_firewall={'enabled' if enabled else 'disabled'} (Windows Firewall)"

        return f"host_firewall={enabled} (stored)"

    def _apply_firewall_rules(self, rules: list, default_inbound: str,
                               default_outbound: str) -> str:
        applied, errors = 0, []

        if OS_TYPE == "LINUX":
            # Remove previous CyEDR-Policy iptables rules
            subprocess.run(
                "iptables-save 2>/dev/null | grep -v 'CyEDR-Policy' | iptables-restore",
                shell=True, capture_output=True)
            for rule in rules:
                name      = rule.get("name", "unnamed")
                direction = rule.get("direction", "out").upper()
                protocol  = rule.get("protocol", "tcp").lower()
                port_rng  = str(rule.get("port_range", ""))
                action    = "ACCEPT" if rule.get("action", "allow") == "allow" else "DROP"
                src_ip    = rule.get("src_ip", "")
                chain     = "INPUT" if direction == "IN" else "OUTPUT"
                cmd       = ["iptables", "-A", chain, "-p", protocol]
                if src_ip:
                    cmd += ["-s" if direction == "IN" else "-d", src_ip]
                if port_rng:
                    cmd += ["--dport", port_rng]
                cmd += ["-m", "comment", "--comment", f"CyEDR-Policy-{name}", "-j", action]
                try:
                    subprocess.run(cmd, check=True, capture_output=True)
                    applied += 1
                except Exception:
                    errors.append(name)
            if default_inbound == "block":
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-m", "comment",
                     "--comment", "CyEDR-Policy-default-in", "-j", "DROP"],
                    capture_output=True)
            if default_outbound == "block":
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-m", "comment",
                     "--comment", "CyEDR-Policy-default-out", "-j", "DROP"],
                    capture_output=True)

        elif OS_TYPE == "WINDOWS":
            subprocess.run(
                'netsh advfirewall firewall delete rule name="CyEDR-Policy"',
                shell=True, capture_output=True)
            for rule in rules:
                name     = rule.get("name", "unnamed")
                dirn     = "in" if rule.get("direction", "out").upper() == "IN" else "out"
                protocol = rule.get("protocol", "tcp").lower()
                port_rng = str(rule.get("port_range", "")) or "any"
                action   = "allow" if rule.get("action", "allow") == "allow" else "block"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=CyEDR-Policy-{name}",
                    f"dir={dirn}", f"protocol={protocol}",
                    f"localport={port_rng}", f"action={action}",
                ]
                if rule.get("src_ip"):
                    cmd.append(f"remoteip={rule['src_ip']}")
                try:
                    subprocess.run(cmd, capture_output=True, check=True)
                    applied += 1
                except Exception:
                    errors.append(name)

        elif OS_TYPE == "DARWIN":
            pf_lines = []
            for rule in rules:
                dirn     = "in" if rule.get("direction", "out").upper() == "IN" else "out"
                protocol = rule.get("protocol", "tcp").lower()
                port_rng = rule.get("port_range", "")
                action   = "pass" if rule.get("action", "allow") == "allow" else "block"
                line     = f"{action} {dirn} proto {protocol}"
                if port_rng:
                    line += f" to any port {port_rng}"
                pf_lines.append(line)
            if default_inbound == "block":
                pf_lines.append("block in all")
            if default_outbound == "block":
                pf_lines.append("block out all")
            try:
                os.makedirs(os.path.dirname(_PF_ANCHOR), exist_ok=True)
                with open(_PF_ANCHOR, "w") as f:
                    f.write("\n".join(pf_lines) + "\n")
                subprocess.run(
                    ["pfctl", "-a", "cyedr_policy", "-f", _PF_ANCHOR],
                    capture_output=True)
                applied = len(pf_lines)
            except Exception as e:
                errors.append(str(e))

        err_str = f" (errors: {errors})" if errors else ""
        return f"{applied} firewall rule(s) applied{err_str}"

    def _get_ioc_domains(self) -> list:
        try:
            if os.path.exists(self._cfg.ioc_cache):
                with open(self._cfg.ioc_cache) as f:
                    return list(json.load(f).get("domains", []))
        except Exception:
            pass
        return []

    def _hosts_file_path(self) -> str:
        if OS_TYPE == "WINDOWS":
            return r"C:\Windows\System32\drivers\etc\hosts"
        return "/etc/hosts"

    def _update_hosts_sinkhole(self, domains: list) -> str:
        hosts_path = self._hosts_file_path()
        try:
            with open(hosts_path, "r") as f:
                content = f.read()
        except Exception as e:
            return f"sinkhole error (read: {e})"

        # Remove any existing CyEDR block (clean slate before re-applying)
        content = re.sub(
            rf"{re.escape(_SINKHOLE_BEGIN)}.*?{re.escape(_SINKHOLE_END)}\n?",
            "",
            content,
            flags=re.DOTALL,
        )

        if domains:
            block = f"\n{_SINKHOLE_BEGIN}\n"
            for domain in sorted(set(d.strip().lower() for d in domains if d.strip())):
                block += f"0.0.0.0 {domain}\n"
                if not domain.startswith("www."):
                    block += f"0.0.0.0 www.{domain}\n"
            block += f"{_SINKHOLE_END}\n"
            content = content.rstrip("\n") + "\n" + block

        try:
            with open(hosts_path, "w") as f:
                f.write(content)
        except PermissionError:
            if OS_TYPE in ("LINUX", "DARWIN"):
                try:
                    with tempfile.NamedTemporaryFile(
                            mode="w", suffix=".hosts", delete=False) as tf:
                        tf.write(content)
                        tf_path = tf.name
                    subprocess.run(
                        ["sudo", "cp", tf_path, hosts_path],
                        check=True, capture_output=True)
                    os.unlink(tf_path)
                except Exception as e:
                    return f"sinkhole error (sudo cp failed: {e})"
            else:
                return f"sinkhole error (permission denied — run agent as Administrator)"
        except Exception as e:
            return f"sinkhole error (write: {e})"

        self._flush_dns_cache()
        count = len(domains)
        return (f"sinkhole=applied ({count} domain(s) → 0.0.0.0)"
                if count else "sinkhole=cleared")

    def _flush_dns_cache(self):
        try:
            if OS_TYPE == "LINUX":
                for svc in ("systemd-resolved", "nscd", "dnsmasq"):
                    r = subprocess.run(
                        ["systemctl", "is-active", "--quiet", svc], capture_output=True)
                    if r.returncode == 0:
                        if svc == "systemd-resolved":
                            subprocess.run(["resolvectl", "flush-caches"], capture_output=True)
                        else:
                            subprocess.run(["systemctl", "restart", svc], capture_output=True)
                        break
            elif OS_TYPE == "DARWIN":
                subprocess.run(["dscacheutil", "-flushcache"], capture_output=True)
                subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True)
            elif OS_TYPE == "WINDOWS":
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
        except Exception as e:
            logger.debug("DNS cache flush: %s", e)

    def _set_system_proxy(self, proxy_host: str) -> str:
        try:
            if OS_TYPE == "LINUX":
                with open("/etc/profile.d/cyedr_proxy.sh", "w") as f:
                    f.write(f'export http_proxy="{proxy_host}"\n'
                            f'export https_proxy="{proxy_host}"\n')
                os.environ.update({"http_proxy": proxy_host, "https_proxy": proxy_host})
                return f"proxy={proxy_host} (/etc/profile.d)"
            elif OS_TYPE == "DARWIN":
                iface = "Wi-Fi"
                host_port = proxy_host.replace("http://", "").replace("https://", "").split(":")
                subprocess.run(
                    ["networksetup", "-setwebproxy", iface] + host_port,
                    capture_output=True)
                subprocess.run(
                    ["networksetup", "-setwebproxystate", iface, "on"], capture_output=True)
                return f"proxy={proxy_host} (macOS networksetup)"
            elif OS_TYPE == "WINDOWS":
                reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                subprocess.run(
                    ["reg", "add", reg_path, "/v", "ProxyServer", "/t", "REG_SZ",
                     "/d", proxy_host, "/f"], capture_output=True)
                subprocess.run(
                    ["reg", "add", reg_path, "/v", "ProxyEnable", "/t", "REG_DWORD",
                     "/d", "1", "/f"], capture_output=True)
                return f"proxy={proxy_host} (Windows registry)"
        except Exception as e:
            return f"proxy={proxy_host} (error: {e})"
        return f"proxy={proxy_host} (stored)"

    def _clear_system_proxy(self) -> str:
        try:
            if OS_TYPE == "LINUX":
                proxy_file = "/etc/profile.d/cyedr_proxy.sh"
                if os.path.exists(proxy_file):
                    os.remove(proxy_file)
                for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
                    os.environ.pop(k, None)
            elif OS_TYPE == "DARWIN":
                subprocess.run(
                    ["networksetup", "-setwebproxystate", "Wi-Fi", "off"],
                    capture_output=True)
            elif OS_TYPE == "WINDOWS":
                reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                subprocess.run(
                    ["reg", "add", reg_path, "/v", "ProxyEnable", "/t", "REG_DWORD",
                     "/d", "0", "/f"], capture_output=True)
        except Exception as e:
            return f"proxy clear error: {e}"
        return "proxy=cleared"

    # ── exclusions ────────────────────────────────────────────────────────────

    def _apply_exclusions(self, cfg: dict) -> str:
        # Persisted in cfg.policy_state["exclusions"].
        # _run_scan reads paths/extensions/hashes to filter YARA matches.
        # Heuristic readers read processes/network_ips to skip telemetry.
        paths  = len(cfg.get("paths", []))
        procs  = len(cfg.get("processes", []))
        exts   = len(cfg.get("extensions", []))
        hashes = len(cfg.get("hashes", []))
        ips    = len(cfg.get("network_ips", []))
        return (f"exclusions stored: {paths} path(s), {procs} process(es), "
                f"{exts} extension(s), {hashes} hash(es), {ips} network IP(s)")

    # ── update_policy ─────────────────────────────────────────────────────────

    def _apply_update_policy(self, cfg: dict) -> str:
        auto_update  = cfg.get("auto_update", True)
        channel      = cfg.get("channel", "stable")
        maint_start  = cfg.get("maintenance_window_start", "02:00")
        maint_days   = cfg.get("maintenance_days", ["saturday", "sunday"])
        parts        = [f"channel={channel}",
                        f"window={maint_start} ({','.join(maint_days)})"]

        if not auto_update:
            # Remove any existing schedules
            if OS_TYPE == "LINUX" and os.path.exists(_CRON_UPDATE):
                os.remove(_CRON_UPDATE)
            elif OS_TYPE == "WINDOWS":
                subprocess.run(
                    ["schtasks", "/Delete", "/TN", "CyEDR-AutoUpdate", "/F"],
                    capture_output=True)
            parts.append("auto_update=off")
            return "update_policy: " + "; ".join(parts)

        if OS_TYPE == "LINUX":
            try:
                h, m = maint_start.split(":")
                day_nums = {
                    "monday": 1, "tuesday": 2, "wednesday": 3,
                    "thursday": 4, "friday": 5, "saturday": 6, "sunday": 0,
                }
                days_str = ",".join(
                    str(day_nums[d]) for d in maint_days if d in day_nums) or "6,0"
                with open(_CRON_UPDATE, "w") as f:
                    f.write(f"# CyEDR auto-update — auto-generated\n"
                            f"{m} {h} * * {days_str} root "
                            f"systemctl restart cyedr-agent 2>/dev/null || true\n")
                parts.append(f"cron written ({m} {h} * * {days_str})")
            except Exception as e:
                parts.append(f"cron error: {e}")

        elif OS_TYPE == "WINDOWS":
            try:
                day_abbr = {
                    "monday": "MON", "tuesday": "TUE", "wednesday": "WED",
                    "thursday": "THU", "friday": "FRI",
                    "saturday": "SAT", "sunday": "SUN",
                }
                day_str = ",".join(
                    day_abbr[d] for d in maint_days if d in day_abbr) or "SAT,SUN"
                subprocess.run([
                    "schtasks", "/Create", "/F",
                    "/TN", "CyEDR-AutoUpdate",
                    "/SC", "WEEKLY", "/D", day_str, "/ST", maint_start,
                    "/TR", "sc stop CyEDR-Agent && sc start CyEDR-Agent",
                    "/RU", "SYSTEM",
                ], capture_output=True)
                parts.append(f"scheduled ({day_str} {maint_start})")
            except Exception as e:
                parts.append(f"schtasks error: {e}")

        else:
            parts.append("update_policy stored (macOS: use MDM or launchd for restarts)")

        return "update_policy: " + "; ".join(parts)

    # ── isolation_exceptions ──────────────────────────────────────────────────

    def _apply_isolation_exceptions(self, cfg: dict) -> str:
        # Persisted in cfg.policy_state["isolation_exceptions"].
        # _isolate_linux/darwin/windows read this on every ISOLATE command.
        allowed_ips   = cfg.get("allowed_ips", [])
        allowed_ports = cfg.get("allowed_ports", [443, 8443])
        allow_dns     = cfg.get("allow_dns", True)
        allow_dhcp    = cfg.get("allow_dhcp", True)
        return (f"isolation_exceptions stored: {len(allowed_ips)} IP(s), "
                f"ports={allowed_ports}, dns={allow_dns}, dhcp={allow_dhcp}")

    # ── network_probe ─────────────────────────────────────────────────────────

    def _apply_network_probe_policy(self, cfg: dict) -> str:
        enabled = cfg.get("enabled", False)
        if enabled:
            if not self._http:
                return "network_probe: cannot start — HTTP session not available (upgrade agent)"
            self._start_probe_poller(cfg)
            subnet = cfg.get("subnet", "auto")
            interval = cfg.get("scan_interval_minutes", 60)
            return f"network_probe: started (subnet={subnet}, interval={interval}min)"
        else:
            self._stop_probe_poller()
            return "network_probe: stopped"

    def _start_probe_poller(self, cfg: dict):
        self._stop_probe_poller()
        self._probe_poller = NetworkProbePoller(self._http, self._cfg, cfg)
        self._probe_poller.start()
        logger.info("NetworkProbePoller started for subnet=%s", cfg.get("subnet", "auto"))

    def _stop_probe_poller(self):
        if self._probe_poller and self._probe_poller.is_alive():
            self._probe_poller.stop()
            self._probe_poller.join(timeout=5)
            logger.info("NetworkProbePoller stopped")
        self._probe_poller = None

    # ── tamper_protection ─────────────────────────────────────────────────────
    # Gates the system-tray app's Stop/Exit CyEDR action. Only password_hash
    # (bcrypt) is ever stored here — see policy_engine.py POLICY_DEFAULTS and
    # routes.py's _reconcile_tamper_password() for where the hash is produced
    # server-side. Nothing here ever sees the plaintext admin password except
    # what the local user types into the tray's password prompt at verify time.

    def _apply_tamper_protection(self, cfg: dict) -> str:
        password_set = cfg.get("password_set", False)
        protect_stop = cfg.get("protect_stop", True)
        return f"tamper_protection stored: password_set={password_set}, protect_stop={protect_stop}"

    def _verify_tamper_password(self, password: str) -> tuple[bool, str]:
        """Delegates to the module-level standalone version so the live
        (Stop, over IPC) and offline (Start, via elevated CLI — see
        _cli_verify_and_start) verification paths share one implementation.
        Reads policy_state.json fresh from disk rather than self._cfg.
        policy_state — APPLY_POLICY already persists every in-memory update
        to that same file, so this is equivalent, not stale."""
        return _verify_tamper_password_standalone(self._cfg.edr_home, password)


# ── System-tray IPC listener ────────────────────────────────────────────────────
class IPCListener(threading.Thread):
    """Local control channel for the per-user system-tray app (cyedr_tray.py).

    Protocol: one JSON object per connection, newline-terminated, request then
    a single JSON response, then the connection closes. Requests:
      {"op": "status", "token": "..."}
      {"op": "scan",   "token": "...", "path": "/"}
      {"op": "stop",   "token": "...", "password": "..."}

    SCAN only requires the shared ipc_token (low-value, see _ensure_ipc_token) —
    it's a read-mostly action. STOP additionally requires the admin password
    set in Cy360 → EDR Policies → Tamper Protection, verified locally via
    ResponseExecutor._verify_tamper_password(); the plaintext never reaches
    the platform. Note this only gates the tray's own menu action — an OS
    admin can always stop the underlying service directly (systemctl /
    launchctl / sc), same limitation every EDR's tray-level tamper protection
    has.
    """

    def __init__(self, cfg: Config, executor: ResponseExecutor,
                 http: "requests.Session | None", ipc_token: str):
        super().__init__(daemon=True, name="IPCListener")
        self._cfg      = cfg
        self._executor = executor
        self._http     = http
        self._token    = ipc_token

    def run(self):
        if not self._token:
            logger.warning("IPCListener: no ipc token — tray control channel disabled")
            return
        if OS_TYPE == "WINDOWS":
            self._run_windows_pipe()
        else:
            self._run_unix_socket()

    # ── Linux / macOS ──
    def _run_unix_socket(self):
        os.makedirs(self._cfg.ipc_dir, exist_ok=True)
        os.chmod(self._cfg.ipc_dir, 0o755)
        sock_path = os.path.join(self._cfg.ipc_dir, _IPC_SOCKET_NAME)
        try:
            if os.path.exists(sock_path):
                os.remove(sock_path)
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            os.chmod(sock_path, 0o666)  # any local user must be able to reach the tray, see class docstring
            srv.listen(4)
            srv.settimeout(1.0)
        except Exception as e:
            logger.error("IPCListener: failed to bind %s: %s", sock_path, e)
            return
        logger.info("IPCListener: listening on %s", sock_path)
        while not _STOP_EVENT.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except Exception as e:
                logger.warning("IPCListener accept error: %s", e)
                continue
            threading.Thread(target=self._handle_unix_conn, args=(conn,), daemon=True).start()
        try:
            srv.close()
            os.remove(sock_path)
        except Exception:
            pass

    def _handle_unix_conn(self, conn):
        try:
            conn.settimeout(10)
            data = b""
            while b"\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            req  = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
            resp = self._dispatch(req)
        except Exception as e:
            resp = {"ok": False, "error": str(e)}
        try:
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        except Exception:
            pass
        finally:
            conn.close()

    # ── Windows ──
    def _run_windows_pipe(self):
        try:
            import win32pipe, win32file
        except ImportError:
            logger.error("IPCListener: pywin32 not available — tray IPC disabled on this build")
            return
        while not _STOP_EVENT.is_set():
            try:
                pipe = win32pipe.CreateNamedPipe(
                    _IPC_PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, None,
                )
                win32pipe.ConnectNamedPipe(pipe, None)
                threading.Thread(target=self._handle_pipe_conn, args=(pipe, win32file), daemon=True).start()
            except Exception as e:
                if not _STOP_EVENT.is_set():
                    logger.warning("IPCListener pipe error: %s", e)
                time.sleep(1)

    def _handle_pipe_conn(self, pipe, win32file):
        try:
            _, data = win32file.ReadFile(pipe, 65536)
            req  = json.loads(data.decode("utf-8"))
            resp = self._dispatch(req)
        except Exception as e:
            resp = {"ok": False, "error": str(e)}
        try:
            win32file.WriteFile(pipe, (json.dumps(resp) + "\n").encode("utf-8"))
        except Exception:
            pass
        finally:
            try:
                win32file.CloseHandle(pipe)
            except Exception:
                pass

    # ── Protocol ──
    def _dispatch(self, req: dict) -> dict:
        if req.get("token") != self._token:
            return {"ok": False, "error": "unauthorized"}
        op = req.get("op", "")

        if op == "status":
            tp = self._cfg.policy_state.get("tamper_protection", {})
            return {
                "ok": True, "running": True,
                "hostname": self._cfg.hostname, "agent_id": self._cfg.agent_id,
                "protected": bool(tp.get("password_set") and tp.get("protect_stop", True)),
            }

        if op == "scan":
            threading.Thread(target=self._run_scan_async, args=(req.get("path", "/"),), daemon=True).start()
            self._report_tamper_event("scan_requested", True, "triggered from system tray")
            return {"ok": True, "status": "scan_started"}

        if op == "stop":
            allowed, detail = self._executor._verify_tamper_password(req.get("password", ""))
            self._report_tamper_event("stop_authorized" if allowed else "stop_denied", allowed, detail)
            if allowed:
                threading.Thread(target=self._do_stop, daemon=True).start()
                return {"ok": True, "status": "stopping"}
            return {"ok": False, "error": detail}

        return {"ok": False, "error": f"unknown op: {op}"}

    def _run_scan_async(self, path: str):
        cmd_id = f"tray-{uuid.uuid4().hex[:12]}"
        try:
            result = self._executor._run_scan({"scan_path": path})
            if self._http and self._cfg.agent_id:
                self._http.post(
                    f"{self._cfg.platform_url}/api/edr/response/{self._cfg.agent_id}/commands/{cmd_id}/complete",
                    json={"success": True, "result": result, "action": "RUN_SCAN"},
                    timeout=30,
                )
        except Exception as e:
            logger.warning("Tray on-demand scan failed: %s", e)

    def _report_tamper_event(self, action: str, success: bool, detail: str):
        if not self._http or not self._cfg.agent_id:
            return
        try:
            self._http.post(
                f"{self._cfg.platform_url}/api/edr/tamper-events",
                json={"action": action, "success": success, "detail": detail},
                timeout=10,
            )
        except Exception as e:
            logger.debug("tamper-event report failed: %s", e)

    def _do_stop(self):
        """Stop the underlying service properly (systemctl/launchctl/sc), not
        just exit this process — Restart=always in the systemd unit would
        otherwise bring the agent straight back up within seconds. This is a
        deliberate, hard stop: once stopped, restarting requires local admin
        access to this machine (see _RECOVERY_CMDS) — nothing in the tray can
        undo it, by design, or the password gate on this action would be
        meaningless. Writes a marker file so cyedr-watchdog.timer (Linux)
        knows this downtime was authorized and must not auto-revert it."""
        recovery = _RECOVERY_CMDS.get(OS_TYPE, "restart the CyEDR service manually")
        logger.warning(
            "Tray-authorized STOP — CyEDR protection is now OFFLINE on this host "
            "until a local admin restarts it. To restart: %s", recovery)
        try:
            marker = os.path.join(self._cfg.edr_home, ".tray_stopped")
            with open(marker, "w") as f:
                f.write(datetime.utcnow().isoformat())
        except Exception as e:
            logger.warning("Could not write stop marker: %s", e)
        time.sleep(0.5)  # let the IPC response reach the tray first
        try:
            if OS_TYPE == "LINUX":
                subprocess.Popen(["systemctl", "stop", "cyedr-agent"])
            elif OS_TYPE == "DARWIN":
                subprocess.Popen(["launchctl", "bootout", "system/com.cycentra.edr"])
            elif OS_TYPE == "WINDOWS":
                subprocess.Popen(["sc", "stop", "CyEDRAgent"])
        except Exception as e:
            logger.error("Service stop command failed: %s", e)
        global _RUNNING
        _RUNNING = False
        _STOP_EVENT.set()


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
            cmd_id     = cmd.get("id")
            cmd_action = cmd.get("action", "")
            result     = self._executor.execute(cmd)
            self._complete(cmd_id, cmd_action, result)

    def _complete(self, cmd_id: Any, cmd_action: str, result: dict):
        """Report command execution result to the platform via the correct completion endpoint."""
        success = result.get("status") == "completed"
        payload = {
            "success": success,
            "result":  result.get("output", {}),
            "action":  cmd_action,
        }
        try:
            resp = self._http.post(
                f"{self._cfg.platform_url}/api/edr/response/{self._cfg.agent_id}/commands/{cmd_id}/complete",
                json=payload,
                timeout=15,
            )
            if not resp.ok:
                logger.warning("Command complete returned %s for cmd %s", resp.status_code, cmd_id)
        except Exception as e:
            logger.warning("Command complete failed for cmd %s: %s", cmd_id, e)


# ── Heartbeat ──────────────────────────────────────────────────────────────────
class Heartbeat(threading.Thread):

    _RECOVERY_COOLDOWN = 300  # seconds — avoid hammering self-enroll if deploy_token is also bad

    def __init__(self, http: requests.Session, cfg: Config):
        super().__init__(daemon=True, name="Heartbeat")
        self._http = http
        self._cfg  = cfg
        self._last_recovery_attempt = 0.0

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
        probe_cfg = self._cfg.policy_state.get("network_probe", {})
        payload = {
            "version":       VERSION,
            "agent_version": AGENT_VERSION,
            "os_type":       self._cfg.os_type,
            "probe_active":  bool(probe_cfg.get("enabled")),
            "probe_subnet":  probe_cfg.get("subnet", "") if probe_cfg.get("enabled") else "",
        }
        if psutil:
            payload["cpu_percent"]  = psutil.cpu_percent(interval=1)
            payload["mem_percent"]  = psutil.virtual_memory().percent
            payload["disk_percent"] = psutil.disk_usage("/").percent

        # Gateway MACs — always sent so server can update zone trust
        gateways = _get_gateway_macs()
        if gateways:
            payload["gateway_macs"] = gateways

        # ARP network guard: check arp_enabled (with offline grace-period)
        arp_ok = self._cfg.arp_enabled
        if arp_ok and self._cfg.arp_enabled_until:
            try:
                from datetime import datetime, timezone
                exp = datetime.fromisoformat(self._cfg.arp_enabled_until.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > exp:
                    arp_ok = False
                    logger.info("ARP trust expired — roaming assumed; skipping neighbor collection")
            except Exception:
                pass

        if arp_ok:
            neighbors = _collect_arp_neighbors()
            if neighbors:
                payload["arp_neighbors"] = neighbors
        else:
            neighbors = []
            logger.debug("ARP collection skipped (zone not trusted)")

        try:
            resp = self._http.post(
                f"{self._cfg.platform_url}/api/edr/agents/{self._cfg.agent_id}/heartbeat",
                json=payload, timeout=10
            )
            if resp.ok:
                data = resp.json()
                new_enabled = data.get("arp_enabled", True)
                new_until   = data.get("arp_enabled_until", "")
                if new_enabled != self._cfg.arp_enabled or new_until != self._cfg.arp_enabled_until:
                    self._cfg.save_arp_state(new_enabled, new_until)
                    logger.info("ARP state updated: enabled=%s zone=%s",
                                new_enabled, data.get("network_zone", "unknown"))
                # Self-update: if server reports a newer agent version, hot-swap and restart
                server_ver = data.get("agent_version", "")
                if server_ver and server_ver != AGENT_VERSION:
                    _self_update(self._cfg, self._http, server_ver)
            elif resp.status_code in (401, 403):
                # Bearer token is stale/rotated — self-heal by re-enrolling with the
                # still-valid deploy_token, rather than 401-ing forever until someone
                # notices the agent went offline. Cooldown avoids hammering the server
                # if deploy_token itself has since been revoked/expired.
                now = time.time()
                if now - self._last_recovery_attempt >= self._RECOVERY_COOLDOWN:
                    self._last_recovery_attempt = now
                    logger.warning(
                        "Heartbeat auth failed (%s) — attempting enrollment recovery",
                        resp.status_code,
                    )
                    ensure_enrolled(self._cfg, self._http, force=True)
            else:
                logger.debug("Heartbeat returned %s", resp.status_code)
        except Exception as exc:
            logger.debug("Heartbeat error: %s", exc)

        logger.debug("Heartbeat sent (neighbors=%d gateways=%d arp_ok=%s)",
                     len(neighbors), len(gateways), arp_ok)

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


# ── Self-Inventory Reporter (Host Security Profile — Asset Inventory) ──────────
class InventoryReporter(threading.Thread):
    """
    Periodically collects a full local CMDB snapshot of this host — hardware,
    OS, installed software, running services/processes, drivers, users, groups,
    network interfaces, listening ports, certificates, and cloud metadata — and
    POSTs it to POST /api/edr/inventory.

    The payload shape mirrors NetworkProbePoller._ssh_deep_scan()'s result dict
    on purpose: the server ingests both self-reported and agentless-scanned
    inventory through the same ITAM ingest/CVE-match path (_ingest_deep_scan_result),
    so there is exactly one inventory + CVE pipeline, not two.
    """

    INTERVAL      = 21600  # 6 hours
    STARTUP_DELAY = 30     # let enrollment/heartbeat settle before first collection

    def __init__(self, http: requests.Session, cfg: Config):
        super().__init__(daemon=True, name="InventoryReporter")
        self._http = http
        self._cfg  = cfg

    def run(self):
        _STOP_EVENT.wait(self.STARTUP_DELAY)
        while not _STOP_EVENT.is_set():
            try:
                self._collect_and_send()
            except Exception as exc:
                logger.warning("InventoryReporter error: %s", exc)
            _STOP_EVENT.wait(self.INTERVAL)

    def _collect_and_send(self):
        if not self._cfg.agent_id:
            return
        t0 = time.time()
        payload = {
            "hostname":            self._cfg.hostname,
            "hardware_uuid":       self._cfg.hardware_uuid,
            "os_info":             _collect_os_info(),
            "hardware":            _collect_hardware_info(),
            "packages":            _collect_installed_software(),
            "services":            _collect_running_services(),
            "processes":           _collect_running_processes(),
            "drivers":             _collect_installed_drivers(),
            "local_users":         _collect_local_users(),
            "local_groups":        _collect_local_groups(),
            "network_interfaces":  _collect_network_interfaces(),
            "listening_ports":     _collect_listening_ports(),
            "certificates":        _collect_certificates(),
            "cloud_metadata":      _collect_cloud_metadata(),
        }
        try:
            resp = self._http.post(
                f"{self._cfg.platform_url}/api/edr/inventory",
                json=payload, timeout=60,
            )
            if resp.ok:
                logger.info(
                    "Inventory reported in %.1fs: %d packages, %d processes, %d services",
                    time.time() - t0, len(payload["packages"]),
                    len(payload["processes"]), len(payload["services"]),
                )
            else:
                logger.debug("Inventory report returned %s", resp.status_code)
        except Exception as exc:
            logger.debug("Inventory report failed: %s", exc)


# ── File Integrity Monitoring (Host Security Profile — FIM, Phase 2) ───────────
_DEFAULT_FIM_PATHS = {
    "Linux": [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
        "/etc/ssh/sshd_config", "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
        "/root/.ssh",
    ],
    "Darwin": [
        "/etc/passwd", "/etc/sudoers", "/etc/hosts", "/etc/ssh/sshd_config",
        "/private/etc/crontab", "/Library/LaunchDaemons", "/Library/LaunchAgents",
    ],
    "Windows": [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\config",
        r"C:\Windows\System32\Tasks",
    ],
}

_FIM_CRITICAL_RE = re.compile(
    r"(passwd|shadow|sudoers|sshd_config|authorized_keys|crontab|LaunchDaemons|"
    r"drivers.etc.hosts|System32.config)",
    re.IGNORECASE,
)


def _fim_hash_file(path: str, cap_bytes: int = 64 * 1024 * 1024) -> Optional[str]:
    try:
        if os.path.getsize(path) > cap_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _fim_file_meta(path: str) -> dict:
    meta = {"path": path, "size": None, "owner": "", "permissions": "", "sha256": None}
    try:
        st = os.stat(path)
        meta["size"] = st.st_size
        meta["permissions"] = oct(st.st_mode & 0o777)
        if platform.system() != "Windows":
            try:
                import pwd
                meta["owner"] = pwd.getpwuid(st.st_uid).pw_name
            except Exception:
                meta["owner"] = str(st.st_uid)
        if os.path.isfile(path):
            meta["sha256"] = _fim_hash_file(path)
    except Exception:
        pass
    return meta


class FimMonitor(threading.Thread):
    """
    File Integrity Monitoring — watches a default set of security-critical
    paths per OS using the `watchdog` library (inotify on Linux, FSEvents on
    macOS, ReadDirectoryChangesW on Windows — the exact platform primitives
    the Host Security Profile spec calls for, via a well-tested cross-platform
    wrapper instead of hand-rolled ctypes bindings for three separate OS APIs).

    Diffing against the previously known hash happens server-side (see
    POST /api/edr/fim/events in blueprints/edr/routes.py, which reads
    edr_fim_baseline) — this thread only reports current on-disk facts (path,
    hash, size, owner, permissions, event_type); it holds no local baseline.
    """

    FLUSH_INTERVAL    = 15     # seconds between batched event POSTs
    BASELINE_INTERVAL = 86400  # 24h between full baseline snapshots
    STARTUP_DELAY     = 45

    def __init__(self, http: requests.Session, cfg: Config):
        super().__init__(daemon=True, name="FimMonitor")
        self._http  = http
        self._cfg   = cfg
        self._queue: dict = {}   # path -> latest pending event dict
        self._lock  = threading.Lock()
        self._last_baseline = 0.0
        self._observer = None

    def _on_event(self, event_type: str, path: str, old_path: Optional[str] = None):
        with self._lock:
            self._queue[path] = {"event_type": event_type, "path": path, "old_path": old_path}

    def _build_observer(self, watch_paths: list):
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        outer = self

        class _Handler(FileSystemEventHandler):
            def __init__(self, only_file: Optional[str] = None):
                self._only_file = only_file

            def _allowed(self, path: str) -> bool:
                return self._only_file is None or os.path.basename(path) == self._only_file

            def on_created(self, event):
                if not event.is_directory and self._allowed(event.src_path):
                    outer._on_event("created", event.src_path)

            def on_deleted(self, event):
                if not event.is_directory and self._allowed(event.src_path):
                    outer._on_event("deleted", event.src_path)

            def on_modified(self, event):
                if not event.is_directory and self._allowed(event.src_path):
                    outer._on_event("modified", event.src_path)

            def on_moved(self, event):
                if not event.is_directory and self._allowed(event.dest_path):
                    outer._on_event("renamed", event.dest_path, old_path=event.src_path)

        observer = Observer()
        for p in watch_paths:
            if not os.path.exists(p):
                continue
            try:
                if os.path.isdir(p):
                    observer.schedule(_Handler(), p, recursive=True)
                else:
                    observer.schedule(
                        _Handler(only_file=os.path.basename(p)),
                        os.path.dirname(p) or ".", recursive=False,
                    )
            except Exception as exc:
                logger.debug("FIM: could not watch %s: %s", p, exc)
        return observer

    def run(self):
        try:
            import watchdog  # noqa: F401 — availability probe, lazy import
        except ImportError:
            logger.warning("FIM disabled: watchdog not installed in this agent build")
            return

        watch_paths = _DEFAULT_FIM_PATHS.get(platform.system(), [])
        try:
            self._observer = self._build_observer(watch_paths)
            self._observer.start()
            logger.info("FimMonitor watching %d path(s)", len(watch_paths))
        except Exception as exc:
            logger.warning("FimMonitor failed to start: %s", exc)
            return

        _STOP_EVENT.wait(self.STARTUP_DELAY)
        while not _STOP_EVENT.is_set():
            if time.time() - self._last_baseline >= self.BASELINE_INTERVAL:
                try:
                    self._send_baseline(watch_paths)
                except Exception as exc:
                    logger.debug("FIM baseline send failed: %s", exc)
                self._last_baseline = time.time()
            try:
                self._flush_events()
            except Exception as exc:
                logger.debug("FIM event flush failed: %s", exc)
            _STOP_EVENT.wait(self.FLUSH_INTERVAL)

        if self._observer:
            self._observer.stop()

    def _flush_events(self):
        with self._lock:
            if not self._queue:
                return
            pending = list(self._queue.values())
            self._queue.clear()

        events = []
        for item in pending:
            path = item["path"]
            if item["event_type"] == "deleted":
                meta = {"size": None, "owner": "", "permissions": "", "sha256": None}
            else:
                meta = _fim_file_meta(path)
            events.append({
                "event_type":  item["event_type"],
                "path":        path,
                "old_path":    item.get("old_path"),
                "sha256":      meta["sha256"],
                "size":        meta["size"],
                "owner":       meta["owner"],
                "permissions": meta["permissions"],
                "critical":    bool(_FIM_CRITICAL_RE.search(path)),
            })
        if not events:
            return
        try:
            resp = self._http.post(
                f"{self._cfg.platform_url}/api/edr/fim/events",
                json={"events": events}, timeout=30,
            )
            if resp.ok:
                logger.info("FIM: reported %d event(s)", len(events))
            else:
                logger.debug("FIM event POST returned %s", resp.status_code)
        except Exception as exc:
            logger.debug("FIM event POST failed: %s", exc)

    def _send_baseline(self, watch_paths: list):
        entries = []
        for root in watch_paths:
            if not os.path.exists(root):
                continue
            if os.path.isfile(root):
                entries.append(_fim_file_meta(root))
                continue
            count = 0
            for dirpath, _dirs, files in os.walk(root):
                for fname in files:
                    if count >= 2000:
                        break
                    entries.append(_fim_file_meta(os.path.join(dirpath, fname)))
                    count += 1
                if count >= 2000:
                    break
        if not entries:
            return
        try:
            resp = self._http.post(
                f"{self._cfg.platform_url}/api/edr/fim/baseline",
                json={"entries": entries}, timeout=60,
            )
            if resp.ok:
                logger.info("FIM: baseline sent (%d files)", len(entries))
            else:
                logger.debug("FIM baseline POST returned %s", resp.status_code)
        except Exception as exc:
            logger.debug("FIM baseline POST failed: %s", exc)


# ── SCA / CIS Benchmark Check Engine (Host Security Profile — SCA, Phase 3) ────
# Policy-as-code: each check is {id, title, rationale, remediation, severity,
# check} where `check` is a callable returning True (pass) / False (fail) /
# None (not applicable on this host). Kept as embedded Python data rather than
# parsed YAML files — same declarative shape the spec describes, without
# bundling a YAML parser into a hardened security-agent binary. Swappable for
# real YAML policy packs later without changing the ingest contract.

def _sca_ps_bool(expr: str, timeout: int = 15) -> Optional[bool]:
    out = _local_run(f'powershell -NoProfile -Command "{expr}"', timeout=timeout).strip().lower()
    if out == "true":
        return True
    if out == "false":
        return False
    return None


def _sca_ps_reg_dword(hive_path: str, name: str, timeout: int = 15) -> Optional[int]:
    expr = (
        f"(Get-ItemProperty -Path '{hive_path}' -Name '{name}' "
        f"-ErrorAction SilentlyContinue).{name}"
    )
    out = _local_run(f'powershell -NoProfile -Command "{expr}"', timeout=timeout).strip()
    try:
        return int(out)
    except Exception:
        return None


def _sca_sshd_config_value(key: str) -> str:
    out = _local_run(f"sshd -T 2>/dev/null | grep -i '^{key} '")
    parts = out.strip().split()
    return parts[1].lower() if len(parts) >= 2 else ""


def _sca_check_linux_firewall() -> Optional[bool]:
    out = _local_run("ufw status 2>/dev/null; firewall-cmd --state 2>/dev/null").lower()
    if "active" in out or "running" in out:
        return True
    if "inactive" in out or "not running" in out:
        return False
    return None


def _sca_check_linux_selinux_apparmor() -> Optional[bool]:
    se = _local_run("getenforce 2>/dev/null").strip().lower()
    if se:
        return se == "enforcing"
    aa = _local_run("aa-status --enabled 2>/dev/null; echo $?").strip()
    if aa:
        return aa.splitlines()[-1].strip() == "0"
    return None


_SCA_CHECKS_LINUX = [
    {"id": "CY-LNX-001", "title": "Host firewall active (ufw/firewalld)",
     "rationale": "An active host firewall reduces exposure to network-based attacks.",
     "remediation": "Enable ufw (`ufw enable`) or firewalld (`systemctl enable --now firewalld`).",
     "severity": "high", "check": _sca_check_linux_firewall},
    {"id": "CY-LNX-002", "title": "SSH PermitRootLogin disabled",
     "rationale": "Direct root SSH login bypasses per-user audit trails and MFA.",
     "remediation": "Set `PermitRootLogin no` in /etc/ssh/sshd_config and restart sshd.",
     "severity": "high", "check": lambda: (
         _sca_sshd_config_value("permitrootlogin") == "no"
         if _sca_sshd_config_value("permitrootlogin") else None)},
    {"id": "CY-LNX-003", "title": "SSH password authentication disabled",
     "rationale": "Key-based auth resists credential-stuffing and brute-force attacks.",
     "remediation": "Set `PasswordAuthentication no` in /etc/ssh/sshd_config and restart sshd.",
     "severity": "medium", "check": lambda: (
         _sca_sshd_config_value("passwordauthentication") == "no"
         if _sca_sshd_config_value("passwordauthentication") else None)},
    {"id": "CY-LNX-004", "title": "Password max age <= 90 days",
     "rationale": "Bounded password lifetime limits the window a leaked credential stays valid.",
     "remediation": "Set `PASS_MAX_DAYS 90` in /etc/login.defs.",
     "severity": "low", "check": lambda: (
         (lambda v: int(v) <= 90 if v.isdigit() else None)(
             _local_run("grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}'")))},
    {"id": "CY-LNX-005", "title": "Kernel ASLR enabled",
     "rationale": "Address space randomization raises the bar for memory-corruption exploits.",
     "remediation": "Set `kernel.randomize_va_space=2` via sysctl.",
     "severity": "medium", "check": lambda: (
         _local_run("sysctl -n kernel.randomize_va_space 2>/dev/null").strip() == "2")},
    {"id": "CY-LNX-006", "title": "IPv4 forwarding disabled",
     "rationale": "A workstation/server that isn't a router shouldn't forward packets between interfaces.",
     "remediation": "Set `net.ipv4.ip_forward=0` via sysctl unless this host is an intended gateway.",
     "severity": "low", "check": lambda: (
         _local_run("sysctl -n net.ipv4.ip_forward 2>/dev/null").strip() == "0")},
    {"id": "CY-LNX-007", "title": "Mandatory access control enforcing (SELinux/AppArmor)",
     "rationale": "MAC confines compromised processes even after code execution.",
     "remediation": "Set SELinux to Enforcing or ensure AppArmor profiles are enabled.",
     "severity": "medium", "check": _sca_check_linux_selinux_apparmor},
    {"id": "CY-LNX-008", "title": "auditd running",
     "rationale": "System call auditing is required for incident forensics.",
     "remediation": "`systemctl enable --now auditd`.",
     "severity": "medium", "check": lambda: (
         _local_run("systemctl is-active auditd 2>/dev/null").strip() == "active")},
    {"id": "CY-LNX-009", "title": "Cron restricted to authorized users",
     "rationale": "Unrestricted cron access is a common persistence mechanism.",
     "remediation": "Create /etc/cron.allow listing only authorized users.",
     "severity": "low", "check": lambda: os.path.isfile("/etc/cron.allow") or None},
    {"id": "CY-LNX-010", "title": "/etc/passwd not world-writable",
     "rationale": "A world-writable passwd file allows any local user to escalate privileges.",
     "remediation": "`chmod 644 /etc/passwd`.",
     "severity": "critical", "check": lambda: (
         (lambda m: (m & 0o022) == 0)(os.stat("/etc/passwd").st_mode & 0o777)
         if os.path.exists("/etc/passwd") else None)},
]

_SCA_CHECKS_DARWIN = [
    {"id": "CY-MAC-001", "title": "Gatekeeper enabled",
     "rationale": "Gatekeeper blocks execution of unsigned/unnotarized applications.",
     "remediation": "`sudo spctl --master-enable`.",
     "severity": "high", "check": lambda: (
         "enabled" in _local_run("spctl --status 2>&1").lower())},
    {"id": "CY-MAC-002", "title": "Application firewall enabled",
     "rationale": "The application firewall blocks unsolicited inbound connections.",
     "remediation": "System Settings → Network → Firewall → On, or `socketfilterfw --setglobalstate on`.",
     "severity": "high", "check": lambda: (
         (lambda v: v != "0" if v else None)(
             _local_run("defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null").strip()))},
    {"id": "CY-MAC-003", "title": "FileVault disk encryption enabled",
     "rationale": "Full-disk encryption protects data at rest if the device is lost or stolen.",
     "remediation": "`sudo fdesetup enable`.",
     "severity": "critical", "check": lambda: (
         "filevault is on" in _local_run("fdesetup status 2>&1").lower())},
    {"id": "CY-MAC-004", "title": "System Integrity Protection enabled",
     "rationale": "SIP prevents modification of protected system files even by root.",
     "remediation": "Re-enable via Recovery Mode: `csrutil enable`.",
     "severity": "critical", "check": lambda: (
         "enabled" in _local_run("csrutil status 2>&1").lower())},
    {"id": "CY-MAC-005", "title": "Remote Login (SSH) disabled unless required",
     "rationale": "Remote Login exposes an SSH attack surface if not intentionally required.",
     "remediation": "`sudo systemsetup -setremotelogin off` if SSH access isn't needed on this host.",
     "severity": "low", "check": lambda: (
         "off" in _local_run("systemsetup -getremotelogin 2>&1").lower())},
]

_SCA_CHECKS_WINDOWS = [
    {"id": "CY-WIN-001", "title": "Windows Firewall enabled (all profiles)",
     "rationale": "A disabled firewall profile removes host-level network filtering.",
     "remediation": "Enable all profiles: `Set-NetFirewallProfile -All -Enabled True`.",
     "severity": "high", "check": lambda: _sca_ps_bool(
         "(Get-NetFirewallProfile).Enabled -notcontains $false")},
    {"id": "CY-WIN-002", "title": "Microsoft Defender real-time protection enabled",
     "rationale": "Real-time protection is the primary on-access malware defense layer.",
     "remediation": "`Set-MpPreference -DisableRealtimeMonitoring $false`.",
     "severity": "critical", "check": lambda: _sca_ps_bool(
         "(Get-MpComputerStatus).RealTimeProtectionEnabled")},
    {"id": "CY-WIN-003", "title": "BitLocker enabled on system drive",
     "rationale": "Full-disk encryption protects data at rest if the device is lost or stolen.",
     "remediation": "`Enable-BitLocker -MountPoint $env:SystemDrive`.",
     "severity": "critical", "check": lambda: _sca_ps_bool(
         "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'On'")},
    {"id": "CY-WIN-004", "title": "LSA Protection (RunAsPPL) enabled",
     "rationale": "LSA Protection blocks unsigned code from injecting into lsass.exe, a common "
                  "credential-theft technique.",
     "remediation": "Set `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL` = 1 (DWORD) and reboot.",
     "severity": "high", "check": lambda: (
         (lambda v: v == 1 if v is not None else None)(
             _sca_ps_reg_dword(r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")))},
    {"id": "CY-WIN-005", "title": "PowerShell Script Block Logging enabled",
     "rationale": "Script block logging is essential for detecting obfuscated PowerShell attacks.",
     "remediation": "Enable via Group Policy: Administrative Templates → Windows PowerShell → "
                     "Turn on PowerShell Script Block Logging.",
     "severity": "medium", "check": lambda: (
         (lambda v: v == 1 if v is not None else None)(
             _sca_ps_reg_dword(
                 r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                 "EnableScriptBlockLogging")))},
    {"id": "CY-WIN-006", "title": "SMBv1 disabled",
     "rationale": "SMBv1 is legacy and was the vector for WannaCry/NotPetya (EternalBlue).",
     "remediation": "`Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`.",
     "severity": "critical", "check": lambda: _sca_ps_bool(
         "(Get-SmbServerConfiguration).EnableSMB1Protocol -eq $false")},
    {"id": "CY-WIN-007", "title": "Credential Guard running",
     "rationale": "Credential Guard isolates LSA secrets in a VBS-protected container, blocking "
                  "pass-the-hash/pass-the-ticket even after admin-level compromise.",
     "remediation": "Enable via Group Policy or `DG_Readiness_Tool.ps1 -Enable`.",
     "severity": "medium", "check": lambda: _sca_ps_bool(
         "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard "
         "-ErrorAction SilentlyContinue).SecurityServicesRunning -contains 1")},
    {"id": "CY-WIN-008", "title": "RDP requires Network Level Authentication",
     "rationale": "NLA requires authentication before a full RDP session is established, reducing "
                  "pre-auth attack surface.",
     "remediation": "Set `UserAuthentication` = 1 (DWORD) under the RDP-Tcp WinStations key.",
     "severity": "high", "check": lambda: (
         (lambda v: v == 1 if v is not None else None)(
             _sca_ps_reg_dword(
                 r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                 "UserAuthentication")))},
]

_SCA_CHECKS = {"Linux": _SCA_CHECKS_LINUX, "Darwin": _SCA_CHECKS_DARWIN, "Windows": _SCA_CHECKS_WINDOWS}
_SCA_POLICY_META = {
    "Linux":   ("CY-CIS-LINUX",   "CyCentra Baseline Hardening — Linux"),
    "Darwin":  ("CY-CIS-MACOS",   "CyCentra Baseline Hardening — macOS"),
    "Windows": ("CY-CIS-WINDOWS", "CyCentra Baseline Hardening — Windows"),
}


def _run_sca_checks() -> list:
    checks = _SCA_CHECKS.get(platform.system(), [])
    results = []
    for c in checks:
        try:
            outcome = c["check"]()
        except Exception as exc:
            logger.debug("SCA check %s errored: %s", c["id"], exc)
            outcome = None
        result = "not_applicable" if outcome is None else ("passed" if outcome else "failed")
        results.append({
            "check_id":    c["id"],
            "title":       c["title"],
            "description": c.get("description", c["title"]),
            "rationale":   c.get("rationale", ""),
            "remediation": c.get("remediation", ""),
            "severity":    c.get("severity", "medium"),
            "result":      result,
        })
    return results


class ScaScanner(threading.Thread):
    """
    Security Configuration Assessment — runs the bundled CIS-style hardening
    checks locally every INTERVAL and reports pass/fail/not_applicable results.
    A re-scan overwrites the server's edr_sca_results in place (see
    POST /api/edr/sca/results) — the table always reflects the latest scan.
    """

    INTERVAL      = 21600  # 6h — same cadence as InventoryReporter
    STARTUP_DELAY = 60

    def __init__(self, http: requests.Session, cfg: Config):
        super().__init__(daemon=True, name="ScaScanner")
        self._http = http
        self._cfg  = cfg

    def run(self):
        _STOP_EVENT.wait(self.STARTUP_DELAY)
        while not _STOP_EVENT.is_set():
            try:
                self._scan_and_send()
            except Exception as exc:
                logger.warning("ScaScanner error: %s", exc)
            _STOP_EVENT.wait(self.INTERVAL)

    def _scan_and_send(self):
        if not self._cfg.agent_id:
            return
        results = _run_sca_checks()
        if not results:
            return
        policy_id, policy_name = _SCA_POLICY_META.get(
            platform.system(), ("CY-CIS-GENERIC", "CyCentra Baseline Hardening"))
        payload = {"policy_id": policy_id, "policy_name": policy_name, "checks": results}
        try:
            resp = self._http.post(
                f"{self._cfg.platform_url}/api/edr/sca/results", json=payload, timeout=30,
            )
            if resp.ok:
                passed = sum(1 for r in results if r["result"] == "passed")
                logger.info("SCA scan reported: %d/%d checks passed", passed, len(results))
            else:
                logger.debug("SCA report returned %s", resp.status_code)
        except Exception as exc:
            logger.debug("SCA report failed: %s", exc)


# ── Network Probe Poller ───────────────────────────────────────────────────────
class NetworkProbePoller(threading.Thread):
    """
    Activated only when the 'network_probe' policy is deployed to this agent.
    Polls /api/itam/probe/jobs for on-demand scan requests and executes them
    locally using nmap, then POSTs raw XML results back to the server.
    Also fires scheduled auto-scans at the configured interval.

    All scan traffic originates from inside the customer LAN — the cloud
    Cy360 server never needs a route to private subnets.
    """

    POLL_INTERVAL = 30   # seconds between job queue polls

    def __init__(self, http: "requests.Session", cfg: Config, policy: dict):
        super().__init__(daemon=True, name="NetworkProbePoller")
        self._http   = http
        self._cfg    = cfg
        self._policy = policy
        self._stop   = threading.Event()
        self._last_auto_scan: float = 0.0

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info("NetworkProbePoller running — polling every %ds", self.POLL_INTERVAL)
        while not self._stop.is_set():
            try:
                self._poll_jobs()
                self._maybe_auto_scan()
            except Exception as exc:
                logger.warning("NetworkProbePoller error: %s", exc)
            self._stop.wait(self.POLL_INTERVAL)

    # ── Job queue poll ────────────────────────────────────────────────────────

    def _poll_jobs(self):
        if not self._cfg.agent_id:
            return
        try:
            resp = self._http.get(
                f"{self._cfg.platform_url}/api/itam/probe/jobs",
                params={"agent_id": self._cfg.agent_id},
                timeout=15,
            )
            if not resp.ok:
                return
            jobs = resp.json().get("jobs", [])
        except Exception as exc:
            logger.debug("Probe job poll failed: %s", exc)
            return

        for job in jobs:
            # Run each job in its own daemon thread — SSH/WinRM can take 30-90s
            # without blocking the poll loop or the auto-scan timer.
            job_id = job.get("id")
            t = threading.Thread(
                target=self._run_job_thread,
                args=(job,),
                daemon=True,
                name=f"ProbeJob-{job_id}",
            )
            t.start()

    def _run_job_thread(self, job: dict):
        job_id = job.get("id")
        try:
            result = self._execute_job(job)
            self._post_result(job_id, result, error=None)
        except Exception as exc:
            logger.warning("Probe job %s failed: %s", job_id, exc)
            self._post_result(job_id, {}, error=str(exc))

    def _execute_job(self, job: dict) -> dict:
        scan_type = job.get("scan_type", "subnet")
        if scan_type == "subnet":
            subnet = job.get("subnet") or self._resolve_subnet()
            ports  = job.get("ports") or self._policy.get("ports",
                "22,23,80,443,554,631,8080,8883,9100,161,502,47808")
            return self._run_nmap(subnet, ports)
        if scan_type == "snmp":
            params    = job.get("params") or {}
            if isinstance(params, str):
                try:
                    import json as _json
                    params = _json.loads(params)
                except Exception:
                    params = {}
            target_ip = job.get("target_ip") or params.get("target_ip", "")
            community = params.get("community", self._policy.get("snmp_community", "public"))
            port      = int(params.get("port") or self._policy.get("snmp_port", 161))
            asset_id  = params.get("asset_id")
            return self._run_snmp(target_ip, community, port, asset_id)
        if scan_type == "deep_scan":
            params = job.get("params") or {}
            if isinstance(params, str):
                try:
                    import json as _json
                    params = _json.loads(params)
                except Exception:
                    params = {}
            target_ip = params.get("target_ip", job.get("target_ip", ""))
            asset_id  = params.get("asset_id")
            return self._run_deep_scan(target_ip, asset_id)
        raise ValueError(f"Unsupported scan_type: {scan_type}")

    def _post_result(self, job_id: str, result: dict, error: "str | None"):
        try:
            self._http.post(
                f"{self._cfg.platform_url}/api/itam/probe/jobs/{job_id}/result",
                json={"result": result, "error": error},
                timeout=30,
            )
        except Exception as exc:
            logger.warning("Probe result post failed for job %s: %s", job_id, exc)

    # ── Auto-scan on interval ─────────────────────────────────────────────────

    def _maybe_auto_scan(self):
        interval_min = int(self._policy.get("scan_interval_minutes", 60))
        if interval_min <= 0:
            return
        elapsed_min = (time.time() - self._last_auto_scan) / 60
        if elapsed_min < interval_min:
            return
        subnet = self._resolve_subnet()
        if not subnet:
            logger.warning("NetworkProbePoller: no subnet configured for auto-scan")
            return
        ports = self._policy.get("ports", "22,23,80,443,554,631,8080,8883,9100,161,502,47808")
        logger.info("NetworkProbePoller: starting auto-scan of %s", subnet)
        try:
            result = self._run_nmap(subnet, ports)
            self._http.post(
                f"{self._cfg.platform_url}/api/itam/probe/auto-result",
                json={"agent_id": self._cfg.agent_id, "subnet": subnet, "result": result},
                timeout=30,
            )
            self._last_auto_scan = time.time()
            logger.info("NetworkProbePoller: auto-scan complete for %s", subnet)
        except Exception as exc:
            logger.warning("NetworkProbePoller: auto-scan failed: %s", exc)

    # ── nmap execution ────────────────────────────────────────────────────────

    def _run_nmap(self, subnet: str, ports: str) -> dict:
        nmap_bin = shutil.which("nmap")
        if not nmap_bin:
            for candidate in ("/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"):
                if os.path.isfile(candidate):
                    nmap_bin = candidate
                    break
        if not nmap_bin:
            raise RuntimeError("nmap not found — install nmap on this host to use Network Probe")

        cmd = [
            nmap_bin, "-sn", "-PS22,80,443", "--open",
            "-p", ports, "-oX", "-",
            "--host-timeout", "5s",
            subnet,
        ]
        logger.debug("Probe nmap: %s", " ".join(cmd))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {"scan_type": "subnet", "subnet": subnet, "raw_nmap_xml": proc.stdout}
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"nmap timed out scanning {subnet}")

    # ── SNMP execution ────────────────────────────────────────────────────────

    def _run_snmp(self, ip: str, community: str, port: int, asset_id) -> dict:
        """
        Poll one device via SNMP v2c using snmpget/snmpwalk CLI tools.
        Returns a dict that the server's _ingest_snmp_result() understands.
        Requires net-snmp tools (snmpget + snmpwalk) on the probe agent host.
        """
        snmpget  = shutil.which("snmpget")
        snmpwalk = shutil.which("snmpwalk")

        result = {
            "scan_type": "snmp",
            "ip": ip,
            "asset_id": asset_id,
            "snmp_data": {},
        }

        if not snmpget or not snmpwalk:
            result["error"] = (
                "snmpget/snmpwalk not found on probe agent — "
                "install net-snmp: apt install snmp / yum install net-snmp-utils"
            )
            return result

        _OID_DESCR    = "1.3.6.1.2.1.1.1.0"
        _OID_NAME     = "1.3.6.1.2.1.1.5.0"
        _OID_LOCATION = "1.3.6.1.2.1.1.6.0"
        _OID_OBJ_ID   = "1.3.6.1.2.1.1.2.0"
        _OID_UPTIME   = "1.3.6.1.2.1.1.3.0"

        def _get(oid: str) -> str:
            try:
                out = subprocess.check_output(
                    [snmpget, "-v2c", f"-c{community}", f"-t3", "-r1", "-Oqn",
                     f"{ip}:{port}", oid],
                    stderr=subprocess.DEVNULL, timeout=8,
                )
                val = out.decode(errors="replace").strip()
                for prefix in ("STRING:", "INTEGER:", "OID:", "Timeticks:", "Gauge32:",
                               "Counter32:", "IpAddress:", "Hex-STRING:"):
                    if val.startswith(prefix):
                        val = val[len(prefix):].strip()
                return val.strip('"')
            except Exception:
                return ""

        description = _get(_OID_DESCR)
        hostname    = _get(_OID_NAME)
        location    = _get(_OID_LOCATION)
        object_id   = _get(_OID_OBJ_ID)
        uptime_raw  = _get(_OID_UPTIME)

        try:
            centiseconds = int("".join(filter(str.isdigit, uptime_raw.split(" ")[0])) or "0")
            uptime_sec = centiseconds // 100
        except Exception:
            uptime_sec = 0

        result["snmp_data"] = {
            "status":         "ok",
            "description":    description,
            "hostname":       hostname,
            "location":       location,
            "object_id":      object_id,
            "uptime_seconds": uptime_sec,
            "interfaces":     [],  # interface walk omitted for brevity
        }
        logger.info("Probe SNMP: %s → hostname=%s", ip, hostname or "(none)")
        return result

    # ── SSH/WinRM deep scan ───────────────────────────────────────────────────

    def _run_deep_scan(self, target_ip: str, asset_id) -> dict:
        """Fetch credentials from server, then try SSH (paramiko) then WinRM."""
        base = {"scan_type": "deep_scan", "asset_id": asset_id, "ip": target_ip}
        if not target_ip:
            base.update({"status": "error", "error": "No target IP in job"})
            return base
        try:
            cred_resp = self._http.get(
                f"{self._cfg.platform_url}/api/itam/probe/creds",
                timeout=10,
            )
            if not cred_resp.ok:
                base.update({"status": "error", "error": "Failed to fetch scan credentials"})
                return base
            creds = cred_resp.json()
        except Exception as exc:
            base.update({"status": "error", "error": f"Credential fetch failed: {exc}"})
            return base

        result = self._ssh_deep_scan(
            ip=target_ip,
            port=int(creds.get("ssh_port", 22)),
            username=creds.get("username", ""),
            password=creds.get("password", ""),
            key_path=creds.get("key_path", ""),
        )
        if result.get("status") != "ok":
            # SSH failed — try WinRM
            winrm_result = self._winrm_deep_scan(
                ip=target_ip,
                port=int(creds.get("winrm_port", 5985)),
                username=creds.get("winrm_username", ""),
                password=creds.get("winrm_password", ""),
                use_ssl=bool(creds.get("winrm_ssl", False)),
            )
            if winrm_result.get("status") == "ok":
                result = winrm_result
        result.update({"scan_type": "deep_scan", "asset_id": asset_id, "ip": target_ip})
        logger.info("Probe deep-scan %s: status=%s method=%s", target_ip,
                    result.get("status"), result.get("method"))
        return result

    def _ssh_deep_scan(self, ip: str, port: int, username: str,
                       password: str, key_path: str) -> dict:
        """SSH deep inventory via paramiko (lazy import — zero overhead unless used)."""
        result = {"status": "error", "method": "ssh", "ip": ip, "error": ""}
        try:
            import paramiko  # noqa: PLC0415 — lazy import keeps cold-start fast
        except ImportError:
            result["error"] = "paramiko not available in this agent build"
            return result
        if not username:
            result["error"] = "No SSH username configured in ITAM settings"
            return result
        if not password and not (key_path and os.path.isfile(key_path)):
            result["error"] = "No SSH password or key_path configured in ITAM settings"
            return result
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs: dict = {"hostname": ip, "port": port, "username": username, "timeout": 12}
            if key_path and os.path.isfile(key_path):
                kwargs["key_filename"] = key_path
            else:
                kwargs["password"] = password
            ssh.connect(**kwargs)

            def _run(cmd: str) -> str:
                try:
                    _, out, _ = ssh.exec_command(cmd, timeout=20)
                    return out.read().decode(errors="replace").strip()
                except Exception:
                    return ""

            hostname  = _run("hostname")
            os_raw    = _run("cat /etc/os-release 2>/dev/null || uname -a")
            cpu_info  = _run("lscpu 2>/dev/null | head -20 || sysctl -n machdep.cpu.brand_string 2>/dev/null")
            mem_raw   = _run("free -b 2>/dev/null || vm_stat 2>/dev/null")
            disk_raw  = _run("df -h / 2>/dev/null")
            pkgs_raw  = _run(
                "dpkg -l 2>/dev/null | tail -n +6 || "
                "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{ARCH}|%{SUMMARY}\\n' 2>/dev/null || "
                "brew list --versions 2>/dev/null"
            )
            svcs_raw  = _run(
                "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -60 || "
                "launchctl list 2>/dev/null | head -40"
            )
            ports_raw = _run("ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null | head -40")
            users_raw = _run(
                "getent passwd 2>/dev/null | awk -F: '$3>=1000{print $1\"|\"$6\"|\"$7}' || "
                "dscl . list /Users 2>/dev/null | grep -v '^_'"
            )
            ssh.close()

            # Parse packages
            packages = []
            for line in pkgs_raw.splitlines():
                if "|" in line:
                    p = line.split("|")
                    packages.append({"name": p[0], "version": p[1] if len(p) > 1 else "",
                                     "arch": p[2] if len(p) > 2 else "",
                                     "description": p[3] if len(p) > 3 else ""})
                elif line[:3] in ("ii ", "hi ", "rc "):
                    p = line.split()
                    if len(p) >= 3:
                        packages.append({"name": p[1], "version": p[2],
                                         "arch": p[3] if len(p) > 3 else "",
                                         "description": " ".join(p[4:])})
                elif " " in line and not line.startswith(" "):
                    p = line.split(None, 1)
                    packages.append({"name": p[0], "version": p[1] if len(p) > 1 else ""})

            # Parse services
            services = []
            for line in svcs_raw.splitlines()[:60]:
                p = line.split()
                if not p:
                    continue
                name  = p[0].replace(".service", "")
                state = "running" if len(p) > 2 and p[2] == "running" else "unknown"
                services.append({"name": name, "state": state})

            # Parse listening ports
            listening_ports = []
            for line in ports_raw.splitlines():
                p = line.split()
                if len(p) < 4:
                    continue
                addr = p[3]
                if ":" in addr:
                    port_part = addr.rsplit(":", 1)[-1]
                    try:
                        listening_ports.append({
                            "port": int(port_part),
                            "proto": p[0].lower(),
                            "address": addr,
                        })
                    except ValueError:
                        pass

            # Parse local users
            local_users = []
            for line in users_raw.splitlines():
                if "|" in line:
                    p = line.split("|")
                    local_users.append({"username": p[0],
                                        "home": p[1] if len(p) > 1 else "",
                                        "shell": p[2] if len(p) > 2 else ""})
                elif line.strip():
                    local_users.append({"username": line.strip()})

            result.update({
                "status":         "ok",
                "hostname":       hostname,
                "os_info":        {"raw": os_raw},
                "hardware":       {"cpu_info": cpu_info, "memory_raw": mem_raw, "disk": disk_raw},
                "packages":       packages[:500],
                "services":       services,
                "listening_ports": listening_ports,
                "local_users":    local_users,
            })
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def _winrm_deep_scan(self, ip: str, port: int, username: str,
                         password: str, use_ssl: bool = False) -> dict:
        """WinRM deep inventory via pywinrm (lazy import)."""
        result = {"status": "error", "method": "winrm", "ip": ip, "error": ""}
        try:
            import winrm  # noqa: PLC0415
        except ImportError:
            result["error"] = "pywinrm not available in this agent build"
            return result
        if not username or not password:
            result["error"] = "No WinRM credentials configured in ITAM settings"
            return result
        try:
            import json as _json
            protocol = "https" if use_ssl else "http"
            s = winrm.Session(
                f"{protocol}://{ip}:{port}/wsman",
                auth=(username, password),
                transport="basic",
                server_cert_validation="ignore",
            )

            def _ps(script: str) -> str:
                try:
                    r = s.run_ps(script)
                    return r.std_out.decode(errors="replace").strip() if r.std_out else ""
                except Exception:
                    return ""

            def _parse(raw: str):
                try:
                    return _json.loads(raw) if raw else None
                except Exception:
                    return None

            def _listify(v):
                if v is None:
                    return []
                return v if isinstance(v, list) else [v]

            hostname  = _ps("hostname")
            os_data   = _parse(_ps(
                "Get-WmiObject Win32_OperatingSystem | "
                "Select-Object Caption,Version,OSArchitecture | ConvertTo-Json"
            )) or {}
            cpu_data  = _parse(_ps(
                "Get-WmiObject Win32_Processor | "
                "Select-Object Name,NumberOfCores | ConvertTo-Json"
            )) or {}
            svcs_raw  = _listify(_parse(_ps(
                "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
                "Select-Object Name,DisplayName | ConvertTo-Json"
            )))
            ports_raw = _listify(_parse(_ps(
                "Get-NetTCPConnection -State Listen | "
                "Select-Object LocalPort,LocalAddress | ConvertTo-Json"
            )))
            users_raw = _listify(_parse(_ps(
                "Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json"
            )))
            pkgs_raw  = _listify(_parse(_ps(
                "Get-Package | Select-Object Name,Version | ConvertTo-Json"
            )))

            if isinstance(os_data, list) and os_data:
                os_data = os_data[0]
            if isinstance(cpu_data, list) and cpu_data:
                cpu_data = cpu_data[0]

            result.update({
                "status":   "ok",
                "hostname": hostname,
                "os_info":  {
                    "name":    os_data.get("Caption", "Windows") if isinstance(os_data, dict) else "Windows",
                    "version": os_data.get("Version", "") if isinstance(os_data, dict) else "",
                    "arch":    os_data.get("OSArchitecture", "") if isinstance(os_data, dict) else "",
                },
                "hardware": {"cpu_info": str(cpu_data)},
                "services": [
                    {"name": s.get("Name", ""), "state": "running",
                     "display_name": s.get("DisplayName", "")}
                    for s in svcs_raw if isinstance(s, dict)
                ],
                "listening_ports": [
                    {"port": p.get("LocalPort", 0), "proto": "tcp",
                     "address": p.get("LocalAddress", "")}
                    for p in ports_raw if isinstance(p, dict)
                ],
                "local_users": [
                    {"username": u.get("Name", ""), "enabled": u.get("Enabled", True)}
                    for u in users_raw if isinstance(u, dict)
                ],
                "packages": [
                    {"name": pk.get("Name", ""), "version": pk.get("Version", "")}
                    for pk in pkgs_raw if isinstance(pk, dict)
                ][:500],
            })
        except Exception as exc:
            result["error"] = str(exc)
        return result

    # ── Subnet resolution ─────────────────────────────────────────────────────

    def _resolve_subnet(self) -> str:
        configured = self._policy.get("subnet", "").strip()
        if configured:
            return configured
        # Auto-detect from the agent's own IP — derive /24 CIDR
        try:
            if psutil:
                for iface, addrs in psutil.net_if_addrs().items():
                    if "lo" in iface.lower():
                        continue
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            parts = addr.address.split(".")
                            if len(parts) == 4 and parts[0] not in ("127", "169"):
                                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass
        return ""


# ── Self-enrollment (if no agent_id yet) ──────────────────────────────────────
def ensure_enrolled(cfg: Config, http: requests.Session, force: bool = False):
    """`force=True` re-enrolls even if cfg.agent_id is already set — used by the
    heartbeat self-heal path (see Heartbeat._beat) to recover from a rotated or
    stale enrollment_token using the still-valid, never-rotated deploy_token.
    The server matches the existing row by hardware_uuid/hostname and UPDATEs
    it, so this never creates a duplicate agent."""
    if cfg.agent_id and not force:
        logger.info("Agent already enrolled: %s", cfg.agent_id)
        return

    logger.info("Enrolling with platform...")
    try:
        # Collect hardware UUID once — persisted so future starts skip re-enroll
        hardware_uuid = cfg.hardware_uuid or _get_hardware_uuid()

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

        # Capture default gateway at enrollment time (trusted corporate environment)
        gateways = _get_gateway_macs()
        enroll_gw = gateways[0] if gateways else {}

        resp = http.post(
            f"{cfg.platform_url}/api/edr/agents/self-enroll",
            json={
                "hostname":       cfg.hostname,
                "os_type":        cfg.os_type,
                "asset_type":     cfg.asset_type,
                "agent_ip":       agent_ip,
                "version":        VERSION,
                "hardware_uuid":  hardware_uuid,
                "gateway_ip":     enroll_gw.get("ip", ""),
                "gateway_mac":    enroll_gw.get("mac", ""),
            },
            timeout=30
        )
        if resp.ok:
            data = resp.json()
            agent_id = data.get("agent_id")
            token    = data.get("enrollment_token")
            if agent_id:
                cfg.save_agent_id(agent_id, hardware_uuid=hardware_uuid)
                if token:
                    cfg.save_enrollment_token(token)
                    http.headers["Authorization"] = f"Bearer {token}"
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
    parser.add_argument("--config", help="Path to config.json")
    parser.add_argument("--verify-and-start", metavar="EDR_HOME",
                         help="One-shot mode: verify the tamper password and start the "
                              "service, no long-running agent. Used by the tray's Start "
                              "action (see _cli_verify_and_start); run elevated.")
    parser.add_argument("--password-file",
                         help="Path to a file holding the tamper password, used with "
                              "--verify-and-start; the file is deleted after being read.")
    args = parser.parse_args()

    if args.verify_and_start:
        _cli_verify_and_start(args.verify_and_start, args.password_file)
        return

    if not args.config:
        parser.error("--config is required unless --verify-and-start is given")

    cfg = Config(args.config)
    setup_logging(cfg.log_file)
    logger.info("CyEDR Agent v%s starting on %s (%s)", VERSION, cfg.hostname, cfg.os_type)

    # Clear any stale tray-stop marker — this process running at all means an
    # admin (or the OS) has already authorized this start; the marker's only
    # job is telling cyedr-watchdog.timer not to auto-revert an intentional
    # stop, and a fresh startup should re-arm normal crash-recovery behavior.
    try:
        os.remove(os.path.join(cfg.edr_home, ".tray_stopped"))
    except OSError:
        pass

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT,  handle_signal)

    http = build_http_session(cfg.enrollment_token)
    ensure_enrolled(cfg, http)

    ioc      = IOCCache(cfg.ioc_cache)
    ev_queue = queue.Queue(maxsize=5000)
    executor = ResponseExecutor(cfg, http)
    ipc_token = _ensure_ipc_token(cfg)

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
        InventoryReporter(http, cfg),
        FimMonitor(http, cfg),
        ScaScanner(http, cfg),
        IPCListener(cfg, executor, http, ipc_token),
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
