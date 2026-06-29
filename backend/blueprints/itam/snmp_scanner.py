"""
blueprints/itam/snmp_scanner.py
================================
SNMP v1/v2c polling for network devices (routers, switches, printers, firewalls)
that lack SSH access or a CyEDR agent. Uses pysnmp-lextudio (the maintained pysnmp fork).
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

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


def snmp_scan(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: int = 3,
) -> dict:
    """Poll a single device via SNMP v2c and return inventory data."""
    if not _PYSNMP_AVAILABLE:
        return {"error": "pysnmp-lextudio not installed"}

    base: dict = {
        "ip": ip,
        "status": "error",
        "error": None,
        "hostname": "",
        "description": "",
        "location": "",
        "object_id": "",
        "uptime_seconds": 0,
        "interfaces": [],
    }

    try:
        engine = SnmpEngine()
        community_data = CommunityData(community, mpModel=1)
        transport = UdpTransportTarget((ip, port), timeout=timeout, retries=1)

        scalar_oids = [
            _OID_SYS_DESCR,
            _OID_SYS_NAME,
            _OID_SYS_LOCATION,
            _OID_SYS_OBJECT_ID,
            _OID_SYS_UPTIME,
        ]
        scalars = _get_scalars(engine, community_data, transport, scalar_oids)

        def _get(oid: str) -> str:
            for key, val in scalars.items():
                if key.endswith(oid.lstrip("0123456789.")) or oid in key:
                    return val
            return scalars.get(oid, "")

        base["description"] = scalars.get(_OID_SYS_DESCR, "").strip()
        base["hostname"] = scalars.get(_OID_SYS_NAME, "").strip()
        base["location"] = scalars.get(_OID_SYS_LOCATION, "").strip()
        base["object_id"] = scalars.get(_OID_SYS_OBJECT_ID, "").strip()

        uptime_raw = scalars.get(_OID_SYS_UPTIME, "0")
        try:
            centiseconds = int("".join(filter(str.isdigit, uptime_raw.split(" ")[0])) or "0")
            base["uptime_seconds"] = centiseconds // 100
        except (ValueError, IndexError):
            base["uptime_seconds"] = 0

        if_descr = _walk_table(engine, community_data, transport, _OID_IF_DESCR, _MAX_INTERFACES)
        if_speed = _walk_table(engine, community_data, transport, _OID_IF_SPEED, _MAX_INTERFACES)
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
        log.warning("snmp_scan failed for %s: %s", ip, exc)
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
    if not _PYSNMP_AVAILABLE:
        return [{"error": "pysnmp-lextudio not installed"}]

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
