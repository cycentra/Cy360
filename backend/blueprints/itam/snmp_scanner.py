"""
blueprints/itam/snmp_scanner.py
================================
SNMP v1/v2c polling for network devices (routers, switches, printers, firewalls)
that lack SSH access or a CyEDR agent.

Primary: pysnmp-lextudio (pip dep, synchronous v4/v5 hlapi).
Fallback: system snmpget/snmpwalk (net-snmp-utils / snmp package) via subprocess.
Error reported only when neither is available.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

log = logging.getLogger(__name__)

# ── Primary: pysnmp synchronous hlapi (pysnmp-lextudio < 6.0) ─────────────────
try:
    from pysnmp.hlapi import (
        getCmd,
        nextCmd,
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
    )
    _PYSNMP_AVAILABLE = True
except ImportError:
    _PYSNMP_AVAILABLE = False

# ── Fallback: system snmpget / snmpwalk CLI ────────────────────────────────────
_SNMPGET_BIN  = shutil.which("snmpget")
_SNMPWALK_BIN = shutil.which("snmpwalk")
_SUBPROCESS_SNMP = bool(_SNMPGET_BIN and _SNMPWALK_BIN)

_OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
_OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"
_OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
_OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
_OID_SYS_UPTIME   = "1.3.6.1.2.1.1.3.0"
_OID_IF_DESCR     = "1.3.6.1.2.1.2.2.1.2"
_OID_IF_SPEED     = "1.3.6.1.2.1.2.2.1.5"
_OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"

_IF_STATUS_MAP = {1: "up", 2: "down", 3: "testing"}
_MAX_INTERFACES = 24


# ── pysnmp helpers ─────────────────────────────────────────────────────────────

def _get_scalars(engine, community_data, transport, oids: list[str]) -> dict[str, str]:
    result = {}
    objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]
    error_indication, error_status, error_index, var_binds = next(
        getCmd(engine, community_data, transport, ContextData(), *objects)
    )
    if error_indication or error_status:
        return result
    for var_bind in var_binds:
        oid_str = str(var_bind[0])
        val = var_bind[1]
        result[oid_str] = str(val).strip()
    return result


def _walk_table(engine, community_data, transport, base_oid: str, max_rows: int) -> dict[int, str]:
    rows: dict[int, str] = {}
    for error_indication, error_status, _, var_binds in nextCmd(
        engine,
        community_data,
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,
    ):
        if error_indication or error_status:
            break
        for var_bind in var_binds:
            oid_str = str(var_bind[0])
            if not oid_str.startswith(base_oid):
                break
            suffix = oid_str[len(base_oid):]
            suffix = suffix.lstrip(".")
            try:
                index = int(suffix.split(".")[0])
            except (ValueError, IndexError):
                continue
            rows[index] = str(var_bind[1]).strip()
        if len(rows) >= max_rows:
            break
    return rows


# ── subprocess (net-snmp CLI) helpers ─────────────────────────────────────────

def _parse_snmp_value(raw: str) -> str:
    """Strip type prefix (STRING:, INTEGER:, OID:, etc.) from snmpget -Oqn output."""
    raw = raw.strip()
    for prefix in ("STRING:", "INTEGER:", "OID:", "Timeticks:", "Gauge32:",
                   "Counter32:", "Counter64:", "IpAddress:", "Hex-STRING:"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):].strip()
            break
    return raw.strip('"')


def _snmpget_cmd(ip: str, community: str, port: int, timeout: int,
                 oids: list[str]) -> dict[str, str]:
    """Retrieve scalar OIDs via snmpget CLI. Returns {oid: value}."""
    cmd = [
        _SNMPGET_BIN, "-v2c", f"-c{community}",
        f"-t{timeout}", "-r1", "-Oqn",
        f"{ip}:{port}",
    ] + oids
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      timeout=timeout + 2)
        result: dict[str, str] = {}
        lines = out.decode(errors="replace").splitlines()
        for i, line in enumerate(lines):
            if "=" in line:
                oid_part, _, val_part = line.partition("=")
                oid = oid_part.strip()
                result[oid] = _parse_snmp_value(val_part)
            elif i < len(oids):
                # line with no '=' means no response for this OID
                result[oids[i]] = ""
        return result
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return {}


def _snmpwalk_cmd(ip: str, community: str, port: int, timeout: int,
                  base_oid: str, max_rows: int) -> dict[int, str]:
    """Walk a table OID via snmpwalk CLI. Returns {index: value}."""
    cmd = [
        _SNMPWALK_BIN, "-v2c", f"-c{community}",
        f"-t{timeout}", "-r1", "-Oqn",
        f"{ip}:{port}", base_oid,
    ]
    rows: dict[int, str] = {}
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      timeout=(timeout + 2) * 2)
        for line in out.decode(errors="replace").splitlines():
            if "=" not in line:
                continue
            oid_part, _, val_part = line.partition("=")
            oid_str = oid_part.strip()
            if not oid_str.startswith("." + base_oid) and not oid_str.startswith(base_oid):
                continue
            # extract last numeric component as row index
            suffix = oid_str.lstrip(".")[len(base_oid.lstrip(".")):]
            suffix = suffix.lstrip(".")
            try:
                index = int(suffix.split(".")[0])
            except (ValueError, IndexError):
                continue
            rows[index] = _parse_snmp_value(val_part)
            if len(rows) >= max_rows:
                break
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        pass
    return rows


def _snmp_scan_subprocess(ip: str, community: str, port: int, timeout: int) -> dict:
    """Perform an SNMP scan using system snmpget/snmpwalk binaries."""
    base: dict = {
        "ip": ip, "status": "error", "error": None,
        "hostname": "", "description": "", "location": "",
        "object_id": "", "uptime_seconds": 0, "interfaces": [],
    }
    try:
        scalar_oids = [
            _OID_SYS_DESCR, _OID_SYS_NAME, _OID_SYS_LOCATION,
            _OID_SYS_OBJECT_ID, _OID_SYS_UPTIME,
        ]
        scalars = _snmpget_cmd(ip, community, port, timeout, scalar_oids)

        base["description"] = scalars.get(_OID_SYS_DESCR, "").strip()
        base["hostname"]    = scalars.get(_OID_SYS_NAME, "").strip()
        base["location"]    = scalars.get(_OID_SYS_LOCATION, "").strip()
        base["object_id"]   = scalars.get(_OID_SYS_OBJECT_ID, "").strip()

        uptime_raw = scalars.get(_OID_SYS_UPTIME, "0")
        try:
            centiseconds = int("".join(filter(str.isdigit, uptime_raw.split(" ")[0])) or "0")
            base["uptime_seconds"] = centiseconds // 100
        except (ValueError, IndexError):
            base["uptime_seconds"] = 0

        if_descr  = _snmpwalk_cmd(ip, community, port, timeout, _OID_IF_DESCR, _MAX_INTERFACES)
        if_speed  = _snmpwalk_cmd(ip, community, port, timeout, _OID_IF_SPEED, _MAX_INTERFACES)
        if_status = _snmpwalk_cmd(ip, community, port, timeout, _OID_IF_OPER_STATUS, _MAX_INTERFACES)

        interfaces = []
        for idx in sorted(if_descr.keys())[:_MAX_INTERFACES]:
            speed_bps = 0
            try:
                speed_bps = int(if_speed.get(idx, 0))
            except (ValueError, TypeError):
                pass
            status_code = 0
            try:
                status_code = int(if_status.get(idx, 0))
            except (ValueError, TypeError):
                pass
            interfaces.append({
                "index": idx,
                "name": if_descr.get(idx, ""),
                "speed_mbps": speed_bps // 1_000_000,
                "status": _IF_STATUS_MAP.get(status_code, "unknown"),
            })

        base["interfaces"] = interfaces
        base["status"] = "ok"

    except Exception as exc:
        log.warning("snmp_scan (subprocess) failed for %s: %s", ip, exc)
        base["error"] = str(exc)

    return base


# ── Public API ─────────────────────────────────────────────────────────────────

def snmp_scan(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: int = 3,
    scan_timeout: int = 20,
) -> dict:
    """Poll a single device via SNMP v2c and return inventory data.

    scan_timeout is the hard wall-clock cap on the entire pysnmp path.
    If pysnmp hangs past scan_timeout seconds, falls back to subprocess.
    """
    if _PYSNMP_AVAILABLE:
        with ThreadPoolExecutor(max_workers=1) as _ex:
            _fut = _ex.submit(_snmp_scan_pysnmp, ip, community, port, timeout)
            try:
                return _fut.result(timeout=scan_timeout)
            except FuturesTimeoutError:
                log.warning("snmp_scan pysnmp timed out after %ds for %s; trying subprocess", scan_timeout, ip)
            except Exception as exc:
                log.warning("snmp_scan pysnmp raised %s for %s; trying subprocess", exc, ip)

    if _SUBPROCESS_SNMP:
        log.debug("Using snmpget/snmpwalk CLI for %s", ip)
        return _snmp_scan_subprocess(ip, community, port, timeout)

    return {"error": (
        "SNMP unavailable: install pysnmp-lextudio (pip install 'pysnmp-lextudio>=4.4.12,<6.0.0') "
        "or net-snmp-utils (apt install snmp / yum install net-snmp-utils)"
    )}


def _snmp_scan_pysnmp(ip: str, community: str, port: int, timeout: int) -> dict:
    """Perform SNMP scan using pysnmp synchronous hlapi."""
    base: dict = {
        "ip": ip, "status": "error", "error": None,
        "hostname": "", "description": "", "location": "",
        "object_id": "", "uptime_seconds": 0, "interfaces": [],
    }
    try:
        engine = SnmpEngine()
        community_data = CommunityData(community, mpModel=1)
        transport = UdpTransportTarget((ip, port), timeout=timeout, retries=1)

        scalar_oids = [
            _OID_SYS_DESCR, _OID_SYS_NAME, _OID_SYS_LOCATION,
            _OID_SYS_OBJECT_ID, _OID_SYS_UPTIME,
        ]
        scalars = _get_scalars(engine, community_data, transport, scalar_oids)

        base["description"] = scalars.get(_OID_SYS_DESCR, "").strip()
        base["hostname"]    = scalars.get(_OID_SYS_NAME, "").strip()
        base["location"]    = scalars.get(_OID_SYS_LOCATION, "").strip()
        base["object_id"]   = scalars.get(_OID_SYS_OBJECT_ID, "").strip()

        uptime_raw = scalars.get(_OID_SYS_UPTIME, "0")
        try:
            centiseconds = int("".join(filter(str.isdigit, uptime_raw.split(" ")[0])) or "0")
            base["uptime_seconds"] = centiseconds // 100
        except (ValueError, IndexError):
            base["uptime_seconds"] = 0

        if_descr  = _walk_table(engine, community_data, transport, _OID_IF_DESCR, _MAX_INTERFACES)
        if_speed  = _walk_table(engine, community_data, transport, _OID_IF_SPEED, _MAX_INTERFACES)
        if_status = _walk_table(engine, community_data, transport, _OID_IF_OPER_STATUS, _MAX_INTERFACES)

        interfaces = []
        for idx in sorted(if_descr.keys())[:_MAX_INTERFACES]:
            speed_bps = 0
            try:
                speed_bps = int(if_speed.get(idx, 0))
            except ValueError:
                pass
            status_code = 0
            try:
                status_code = int(if_status.get(idx, 0))
            except ValueError:
                pass
            interfaces.append({
                "index": idx,
                "name": if_descr.get(idx, ""),
                "speed_mbps": speed_bps // 1_000_000,
                "status": _IF_STATUS_MAP.get(status_code, "unknown"),
            })

        base["interfaces"] = interfaces
        base["status"] = "ok"

    except Exception as exc:
        log.warning("snmp_scan (pysnmp) failed for %s: %s", ip, exc)
        base["error"] = str(exc)

    return base


def bulk_snmp_scan(
    ips: list[str],
    community: str = "public",
    port: int = 161,
    timeout: int = 3,
    max_workers: int = 20,
) -> list[dict]:
    """Scan multiple IPs in parallel via SNMP and return a list of results."""
    if not _PYSNMP_AVAILABLE and not _SUBPROCESS_SNMP:
        return [{"error": (
            "SNMP unavailable: install pysnmp-lextudio (pip install 'pysnmp-lextudio>=4.4.12,<6.0.0') "
            "or net-snmp-utils (apt install snmp / yum install net-snmp-utils)"
        )}]

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(snmp_scan, ip, community, port, timeout): ip
            for ip in ips
        }
        for future in as_completed(future_to_ip):
            try:
                results.append(future.result())
            except Exception as exc:
                ip = future_to_ip[future]
                log.warning("bulk_snmp_scan worker error for %s: %s", ip, exc)
                results.append({"ip": ip, "status": "error", "error": str(exc)})
    return results


def infer_device_type(description: str, object_id: str) -> str:
    """Infer the device category from sysDescr and sysObjectID strings."""
    combined = (description + " " + object_id).lower()

    _ROUTER_PATTERNS = ["cisco ios", "cisco router", "juniper", "junos", "mikrotik", "routeros", "vyos"]
    _SWITCH_PATTERNS = ["catalyst", "hp procurve", "procurve", "hpe aruba", "cisco nx-os", "nexus",
                        "extreme networks", "dell powerconnect", "brocade", "netgear gs"]
    _FIREWALL_PATTERNS = ["fortigate", "fortinet", "palo alto", "panos", "checkpoint",
                          "asa", "cisco asa", "netscreen", "sophos", "sonicwall", "opnsense", "pfsense"]
    _PRINTER_PATTERNS = ["jetdirect", "laserjet", "hp color laserjet", "xerox", "lexmark",
                         "brother", "ricoh", "konica minolta", "epson", "canon printer", "kyocera"]
    _UPS_PATTERNS = ["apc", "ups", "uninterruptible", "eaton", "cyberpower"]
    _AP_PATTERNS = ["aruba", "arubaos", "ubiquiti", "unifi", "cisco aironet", "meraki", "ruckus",
                    "aerohive", "meru", "cisco wlc", "wireless access point"]
    _CAMERA_PATTERNS = ["axis", "hikvision", "dahua", "hanwha", "vivotek", "pelco", "bosch camera",
                        "ip camera", "network camera"]
    _SERVER_PATTERNS = ["linux", "ubuntu", "debian", "centos", "rhel", "windows server",
                        "freebsd", "vmware esxi", "proxmox", "hp proliant", "dell poweredge"]

    for pattern in _FIREWALL_PATTERNS:
        if pattern in combined:
            return "firewall"
    for pattern in _ROUTER_PATTERNS:
        if pattern in combined:
            return "router"
    for pattern in _SWITCH_PATTERNS:
        if pattern in combined:
            return "switch"
    for pattern in _AP_PATTERNS:
        if pattern in combined:
            return "access_point"
    for pattern in _PRINTER_PATTERNS:
        if pattern in combined:
            return "printer"
    for pattern in _UPS_PATTERNS:
        if pattern in combined:
            return "ups"
    for pattern in _CAMERA_PATTERNS:
        if pattern in combined:
            return "camera"
    for pattern in _SERVER_PATTERNS:
        if pattern in combined:
            return "server"
    if combined.strip():
        return "network_device"
    return "unknown"
