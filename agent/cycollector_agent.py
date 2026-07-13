#!/usr/bin/env python3
"""
CyCentra 360 — CyCollector Agent (Phase 1 of the CyDataLake initiative)

Generic host log collector. Ships raw OS log events (journald/syslog on
Linux, Unified Log on macOS, Event Log on Windows) to the CyCentra platform
for centralised, source-agnostic ingestion — the intended replacement path
for the Wazuh agent's log-shipping role.

Phase 1 scope only: collection + transport. Events are ingested as
low-severity/undifferentiated "system" alerts (see backend/cysiemstack/
collector_bridge.py) — there is no decode/rule engine here yet. Do not
expect Wazuh rule-engine parity from this agent alone; that is later,
separate work.

This agent intentionally follows the same structural conventions as
agent/cyedr_agent.py (Config/self-enrollment/HTTP session/threaded readers)
so the two can eventually be merged into a single endpoint agent rather
than running side-by-side indefinitely.
"""
import argparse
import hashlib
import json
import logging
import os
import platform
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from logging.handlers import RotatingFileHandler
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("Missing dependency: pip install requests")

VERSION       = "0.1.0"
AGENT_VERSION = "0.1.0"
OS_TYPE       = platform.system().upper()   # LINUX, DARWIN, WINDOWS
_STOP_EVENT   = threading.Event()
logger        = logging.getLogger("cycollector")


# ── Stable hardware UUID — same derivation as CyEDR, so a host enrolled in
#    both systems can eventually be correlated/merged by hardware identity ──
def _get_hardware_uuid() -> str:
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
    return hashlib.sha256(
        f"{uuid.getnode()}:{socket.gethostname()}".encode()
    ).hexdigest()[:32].upper()


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
        self.hostname           = d.get("hostname", socket.gethostname())
        self.os_type            = d.get("os_type", OS_TYPE)
        self.collector_home     = d.get("collector_home", "/opt/cycentra/collector")
        self.heartbeat_interval = int(d.get("heartbeat_interval", 60))
        self.ship_interval      = int(d.get("ship_interval", 5))
        self.ship_batch_max     = int(d.get("ship_batch_max", 500))
        self.log_file           = d.get("log_file", "/opt/cycentra/collector/logs/cycollector_agent.log")
        self.sources            = d.get("sources", ["journald" if OS_TYPE == "LINUX" else
                                                     "oslog" if OS_TYPE == "DARWIN" else "eventlog"])
        self._path              = path

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


def setup_logging(log_file: str):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    handler = RotatingFileHandler(log_file, maxBytes=20 * 1024 * 1024, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("[CyCollector] %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler, console])


def build_http_session(token: str) -> requests.Session:
    sess = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.mount("http://",  HTTPAdapter(max_retries=retry))
    sess.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "User-Agent":    f"CyCollector/{VERSION}",
    })
    return sess


def ensure_enrolled(cfg: Config, http: requests.Session):
    if cfg.agent_id:
        logger.info("Agent already enrolled: %s", cfg.agent_id)
        return

    logger.info("Enrolling with platform...")
    try:
        hardware_uuid = cfg.hardware_uuid or _get_hardware_uuid()

        agent_ip = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            agent_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        resp = http.post(
            f"{cfg.platform_url}/api/collector/agents/self-enroll",
            json={
                "deployment_token": cfg.deploy_token,
                "hostname":         cfg.hostname,
                "os_type":          cfg.os_type,
                "agent_ip":         agent_ip,
                "version":          AGENT_VERSION,
                "hardware_uuid":    hardware_uuid,
            },
            timeout=30,
        )
        if resp.ok:
            data = resp.json()
            agent_id = data.get("agent_id")
            token    = data.get("enrollment_token")
            if agent_id:
                cfg.save_agent_id(agent_id, hardware_uuid=hardware_uuid)
                if token:
                    http.headers["Authorization"] = f"Bearer {token}"
                logger.info("Enrolled — Agent ID: %s", agent_id)
            else:
                logger.error("Enrollment response missing agent_id: %s", resp.text)
        else:
            logger.error("Enrollment failed: %s %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.error("Enrollment exception: %s", e)


# ── Source readers ─────────────────────────────────────────────────────────────

class JournaldReader(threading.Thread):
    """Tails `journalctl -f` (structured JSON output) — Linux only.
    Falls back to plain-text tail of /var/log/syslog or /var/log/messages
    if journalctl is unavailable (minimal/container images)."""

    def __init__(self, event_queue: queue.Queue):
        super().__init__(daemon=True, name="JournaldReader")
        self._q = event_queue

    def run(self):
        if shutil_which("journalctl"):
            self._run_journalctl()
        else:
            self._run_file_fallback()

    def _run_journalctl(self):
        logger.info("JournaldReader: starting `journalctl -f -o json`")
        cmd = ["journalctl", "-f", "-n", "0", "-o", "json"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, bufsize=1)
            while not _STOP_EVENT.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        logger.warning("JournaldReader: journalctl exited — restarting in 10s")
                        time.sleep(10)
                        return self._run_journalctl()
                    continue
                self._process_journal_line(line)
        except Exception as e:
            logger.error("JournaldReader error: %s", e)

    def _process_journal_line(self, line: str):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return
        self._q.put({
            "source_type": "journald",
            "program":     entry.get("SYSLOG_IDENTIFIER", entry.get("_COMM", "")),
            "message":     entry.get("MESSAGE", ""),
            "metadata": {
                "priority": entry.get("PRIORITY"),
                "unit":     entry.get("_SYSTEMD_UNIT", ""),
                "pid":      entry.get("_PID", ""),
            },
            "raw": entry,
        })

    def _run_file_fallback(self):
        for path in ("/var/log/syslog", "/var/log/messages"):
            if os.path.exists(path):
                return self._tail_file(path)
        logger.warning("JournaldReader: no journalctl and no syslog file found — reader idle")

    def _tail_file(self, path: str):
        logger.info("JournaldReader: tailing %s", path)
        try:
            with open(path) as f:
                f.seek(0, 2)
                while not _STOP_EVENT.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    self._q.put({
                        "source_type": "syslog",
                        "program":     "",
                        "message":     line.strip(),
                        "metadata":    {},
                        "raw":         {"line": line.strip()},
                    })
        except Exception as e:
            logger.error("JournaldReader tail error: %s", e)


class MacOSLogReader(threading.Thread):
    """Generic Unified Log stream — Darwin only. Unlike CyEDR's MacOSLogReader
    (which filters to security/process subsystems), this reader collects
    broadly since CyCollector's job is generic ingestion, not detection."""

    def __init__(self, event_queue: queue.Queue):
        super().__init__(daemon=True, name="MacOSLogReader")
        self._q = event_queue

    def run(self):
        logger.info("MacOSLogReader: starting `log stream --style ndjson`")
        cmd = ["log", "stream", "--style", "ndjson"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, bufsize=1)
            while not _STOP_EVENT.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        logger.warning("MacOSLogReader: log stream exited — restarting in 10s")
                        time.sleep(10)
                        return self.run()
                    continue
                self._process_line(line)
        except Exception as e:
            logger.error("MacOSLogReader error: %s", e)

    def _process_line(self, line: str):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return
        if "eventMessage" not in entry:
            return
        self._q.put({
            "source_type": "oslog",
            "program":     entry.get("process", ""),
            "message":     entry.get("eventMessage", ""),
            "metadata": {
                "subsystem": entry.get("subsystem", ""),
                "pid":       entry.get("processID", ""),
            },
            "raw": entry,
        })


class WindowsEventLogReader(threading.Thread):
    """Polls System + Application Event Log channels — Windows only."""

    CHANNELS = ["System", "Application"]

    def __init__(self, event_queue: queue.Queue):
        super().__init__(daemon=True, name="WindowsEventLogReader")
        self._q = event_queue

    def run(self):
        try:
            import win32evtlog
        except ImportError:
            logger.warning("WindowsEventLogReader: pywin32 not installed — reader idle")
            return

        handles = {}
        bookmarks = {}
        for chan in self.CHANNELS:
            try:
                handles[chan] = win32evtlog.OpenEventLog(None, chan)
                bookmarks[chan] = win32evtlog.GetNumberOfEventLogRecords(handles[chan])
            except Exception as e:
                logger.warning("WindowsEventLogReader: cannot open channel %s: %s", chan, e)

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        logger.info("WindowsEventLogReader: polling channels %s", list(handles))
        while not _STOP_EVENT.is_set():
            for chan, handle in handles.items():
                try:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    for ev in events:
                        self._q.put({
                            "source_type": "windows_eventlog",
                            "program":     ev.SourceName,
                            "message":     " ".join(str(s) for s in (ev.StringInserts or [])),
                            "metadata": {
                                "channel":    chan,
                                "event_id":   ev.EventID & 0xFFFF,
                                "event_type": ev.EventType,
                            },
                            "raw": {"record_number": ev.RecordNumber},
                        })
                except Exception:
                    pass
            time.sleep(5)


def shutil_which(cmd: str) -> Optional[str]:
    import shutil
    return shutil.which(cmd)


# ── Shipping + heartbeat ───────────────────────────────────────────────────────

class ShipperThread(threading.Thread):
    def __init__(self, event_queue: queue.Queue, http: requests.Session, cfg: Config):
        super().__init__(daemon=True, name="ShipperThread")
        self._q   = event_queue
        self._http = http
        self._cfg  = cfg

    def run(self):
        while not _STOP_EVENT.is_set():
            batch = []
            deadline = time.time() + self._cfg.ship_interval
            while time.time() < deadline and len(batch) < self._cfg.ship_batch_max:
                try:
                    batch.append(self._q.get(timeout=max(0.1, deadline - time.time())))
                except queue.Empty:
                    break
            if not batch:
                continue
            self._ship(batch)

    def _ship(self, batch: list):
        try:
            resp = self._http.post(
                f"{self._cfg.platform_url}/api/collector/logs",
                json={"events": batch},
                timeout=30,
            )
            if not resp.ok:
                logger.warning("ShipperThread: ingest failed %s %s", resp.status_code, resp.text[:200])
        except Exception as e:
            logger.warning("ShipperThread: ingest exception: %s — %d event(s) dropped", e, len(batch))


class HeartbeatThread(threading.Thread):
    def __init__(self, http: requests.Session, cfg: Config):
        super().__init__(daemon=True, name="HeartbeatThread")
        self._http = http
        self._cfg  = cfg

    def run(self):
        while not _STOP_EVENT.is_set():
            try:
                self._http.post(
                    f"{self._cfg.platform_url}/api/collector/heartbeat",
                    json={"source_types": self._cfg.sources, "version": AGENT_VERSION},
                    timeout=15,
                )
            except Exception as e:
                logger.debug("HeartbeatThread: heartbeat failed: %s", e)
            _STOP_EVENT.wait(self._cfg.heartbeat_interval)


def handle_signal(signum, frame):
    logger.info("Received signal %d — shutting down gracefully", signum)
    _STOP_EVENT.set()


def main():
    parser = argparse.ArgumentParser(description="CyCentra 360 CyCollector Agent")
    parser.add_argument("--config", required=True, help="Path to config.json")
    args = parser.parse_args()

    cfg = Config(args.config)
    setup_logging(cfg.log_file)
    logger.info("CyCollector Agent v%s starting on %s (%s)", VERSION, cfg.hostname, cfg.os_type)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT,  handle_signal)

    http = build_http_session(cfg.enrollment_token)
    ensure_enrolled(cfg, http)

    ev_queue = queue.Queue(maxsize=20000)

    if OS_TYPE == "LINUX":
        reader = JournaldReader(ev_queue)
    elif OS_TYPE == "DARWIN":
        reader = MacOSLogReader(ev_queue)
    else:
        reader = WindowsEventLogReader(ev_queue)

    threads = [reader, ShipperThread(ev_queue, http, cfg), HeartbeatThread(http, cfg)]
    for t in threads:
        t.start()
        logger.info("Started thread: %s", t.name)

    logger.info("CyCollector Agent fully operational")
    while not _STOP_EVENT.is_set():
        time.sleep(1)

    logger.info("CyCollector Agent shutting down")
    for t in threads:
        t.join(timeout=5)
    logger.info("CyCollector Agent stopped")


if __name__ == "__main__":
    main()
