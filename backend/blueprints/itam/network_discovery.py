"""
blueprints/itam/network_discovery.py
======================================
Network discovery utilities for ITAM.

Three discovery sources — all write into network_assets table:
  1. CMDB CSV import   — manual, highest priority (source='manual')
  2. ARP neighbor merge — from CyEDR heartbeat reports (source='arp_report')
  3. nmap subnet scan  — active on-demand sweep (source='nmap')

All sources use upsert on ip_address so they merge cleanly.
"""
from __future__ import annotations
import csv
import io
import ipaddress
import logging
import socket
import subprocess
import json
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Generator

_log = logging.getLogger(__name__)

# ── CMDB CSV Import ───────────────────────────────────────────────────────────

CMDB_REQUIRED_COLS = {"ip_address"}
CMDB_OPTIONAL_COLS = {"hostname", "mac_address", "asset_type", "vendor", "notes", "tags"}

_VALID_ASSET_TYPES = {
    "workstation", "laptop", "server", "domain_controller", "database",
    "api_gateway", "jump_server", "ci_cd_node", "iot_device", "network_device",
    "printer", "camera", "smart_device", "industrial", "hvac_bms", "embedded",
    "mobile", "unknown",
}


def parse_cmdb_csv(file_content: bytes) -> tuple[list[dict], list[str]]:
    """
    Parse a CMDB CSV upload. Returns (rows, errors).

    Accepted columns (case-insensitive header):
      ip_address* | hostname | mac_address | asset_type | vendor | notes | tags

    tags: comma-separated string → stored as array
    """
    errors: list[str] = []
    rows: list[dict] = []

    try:
        text = file_content.decode("utf-8-sig")  # handle BOM
    except UnicodeDecodeError:
        text = file_content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))

    # Normalise column names
    if not reader.fieldnames:
        return [], ["CSV has no header row"]

    col_map = {c.strip().lower(): c for c in reader.fieldnames}

    if "ip_address" not in col_map:
        return [], ["CSV missing required column: ip_address"]

    for line_no, raw_row in enumerate(reader, start=2):
        row = {k.strip().lower(): (v or "").strip() for k, v in raw_row.items()}

        ip_str = row.get("ip_address", "").strip()
        if not ip_str:
            continue
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            errors.append(f"Row {line_no}: invalid IP '{ip_str}' — skipped")
            continue

        asset_type = row.get("asset_type", "unknown").lower()
        if asset_type and asset_type not in _VALID_ASSET_TYPES:
            errors.append(f"Row {line_no}: unknown asset_type '{asset_type}' — set to 'unknown'")
            asset_type = "unknown"

        tags_raw = row.get("tags", "")
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

        rows.append({
            "ip_address":  ip_str,
            "hostname":    row.get("hostname", ""),
            "mac_address": row.get("mac_address", ""),
            "asset_type":  asset_type or "unknown",
            "vendor":      row.get("vendor", ""),
            "notes":       row.get("notes", ""),
            "tags":        tags,
            "source":      "manual",
        })

    return rows, errors


def upsert_assets(conn, assets: list[dict], source: str = "manual") -> int:
    """
    Upsert a list of asset dicts into network_assets.
    'manual' source overwrites all fields; other sources only fill blanks.
    Returns count of rows upserted.
    """
    if not assets:
        return 0
    count = 0
    with conn.cursor() as cur:
        for a in assets:
            tags = a.get("tags") or []
            if source == "manual":
                cur.execute("""
                    INSERT INTO network_assets
                      (ip_address, mac_address, hostname, vendor, asset_type,
                       source, discovery_source, notes, tags, last_seen, first_seen)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())
                    ON CONFLICT (ip_address) DO UPDATE SET
                      mac_address      = COALESCE(NULLIF(EXCLUDED.mac_address,''), network_assets.mac_address),
                      hostname         = COALESCE(NULLIF(EXCLUDED.hostname,''),    network_assets.hostname),
                      vendor           = COALESCE(NULLIF(EXCLUDED.vendor,''),      network_assets.vendor),
                      asset_type       = CASE WHEN EXCLUDED.asset_type <> 'unknown'
                                             THEN EXCLUDED.asset_type
                                             ELSE network_assets.asset_type END,
                      notes            = COALESCE(NULLIF(EXCLUDED.notes,''),       network_assets.notes),
                      tags             = EXCLUDED.tags,
                      source           = 'manual',
                      discovery_source = 'manual',
                      last_seen        = NOW()
                """, (
                    a["ip_address"],
                    a.get("mac_address") or None,
                    a.get("hostname") or None,
                    a.get("vendor") or None,
                    a.get("asset_type", "unknown"),
                    "manual",
                    "manual",
                    a.get("notes") or None,
                    tags,
                ))
            else:
                # Non-manual: only fill fields that are currently empty.
                # When a MAC is present, try to update the existing row for that
                # MAC first (handles devices that changed IP due to roaming/DHCP).
                # Only move the IP if the new IP is not already claimed by a
                # different device — otherwise fall through to the IP-based upsert.
                mac = a.get("mac_address") or None
                if mac:
                    cur.execute("""
                        UPDATE network_assets SET
                          ip_address       = %s::inet,
                          hostname         = COALESCE(hostname, NULLIF(%s, '')),
                          vendor           = COALESCE(vendor,   NULLIF(%s, '')),
                          asset_type       = CASE WHEN asset_type IN ('unknown','')
                                                  THEN %s ELSE asset_type END,
                          source           = CASE WHEN source = 'manual' THEN 'manual'
                                                  ELSE %s END,
                          discovery_source = CASE WHEN discovery_source IN ('manual','')
                                                  THEN %s ELSE discovery_source END,
                          last_seen        = NOW()
                        WHERE mac_address = %s
                          AND ip_address IS DISTINCT FROM %s::inet
                          AND NOT EXISTS (
                            SELECT 1 FROM network_assets
                            WHERE ip_address = %s::inet
                              AND mac_address IS DISTINCT FROM %s
                          )
                        RETURNING id
                    """, (
                        a["ip_address"],
                        a.get("hostname") or None,
                        a.get("vendor") or None,
                        a.get("asset_type", "unknown"),
                        source, source,
                        mac,
                        a["ip_address"],
                        a["ip_address"],
                        mac,
                    ))
                    if cur.fetchone():
                        count += 1
                        continue

                cur.execute("""
                    INSERT INTO network_assets
                      (ip_address, mac_address, hostname, vendor, asset_type,
                       source, discovery_source, last_seen, first_seen)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())
                    ON CONFLICT (ip_address) DO UPDATE SET
                      mac_address      = COALESCE(network_assets.mac_address, NULLIF(EXCLUDED.mac_address,'')),
                      hostname         = COALESCE(network_assets.hostname,    NULLIF(EXCLUDED.hostname,'')),
                      vendor           = COALESCE(network_assets.vendor,      NULLIF(EXCLUDED.vendor,'')),
                      asset_type       = CASE WHEN network_assets.asset_type IN ('unknown','')
                                             THEN EXCLUDED.asset_type
                                             ELSE network_assets.asset_type END,
                      source           = CASE WHEN network_assets.source = 'manual'
                                             THEN 'manual' ELSE EXCLUDED.source END,
                      discovery_source = CASE WHEN network_assets.discovery_source IN ('manual','')
                                             THEN EXCLUDED.discovery_source
                                             ELSE network_assets.discovery_source END,
                      last_seen        = NOW()
                """, (
                    a["ip_address"],
                    mac,
                    a.get("hostname") or None,
                    a.get("vendor") or None,
                    a.get("asset_type", "unknown"),
                    source,
                    source,
                ))
            count += 1
        conn.commit()
    return count


# ── ARP Neighbor Merge ────────────────────────────────────────────────────────

def _rdns_batch(ips: list[str], timeout: float = 0.8) -> dict[str, str]:
    """
    Concurrent reverse-DNS lookup for a list of IPs.
    Returns {ip: hostname}; missing = empty string.
    Each lookup races against `timeout` seconds.
    """
    def _lookup(ip: str) -> tuple[str, str]:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return ip, host
        except OSError:
            return ip, ""

    result: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(len(ips), 20)) as ex:
        futures = {ex.submit(_lookup, ip): ip for ip in ips}
        for fut in futures:
            ip = futures[fut]
            try:
                _, host = fut.result(timeout=timeout)
                result[ip] = host
            except (FutureTimeoutError, Exception):
                result[ip] = ""
    return result


def parse_arp_neighbors(raw: list[dict]) -> list[dict]:
    """
    Parse the arp_neighbors list from a CyEDR heartbeat payload.
    Each entry: {ip, mac, iface?}
    Filters out link-local, loopback, broadcast, multicast.
    Enriches vendor + asset_type via OUI lookup and resolves hostnames via rDNS.
    """
    from .iot_classifier import oui_lookup

    _SKIP = {"127.", "169.254.", "0.0.0.0", "255.", "224.", "ff02"}

    entries = []
    for entry in raw:
        ip = str(entry.get("ip", "")).strip()
        if not ip or any(ip.startswith(s) for s in _SKIP):
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        mac = str(entry.get("mac", "")).strip().upper()
        entries.append({"ip": ip, "mac": mac})

    if not entries:
        return []

    # Resolve hostnames concurrently
    hostnames = _rdns_batch([e["ip"] for e in entries])

    result = []
    for e in entries:
        ip, mac = e["ip"], e["mac"]
        vendor_name, oui_cat = oui_lookup(mac) if mac else ("", "unknown")
        vendor = vendor_name if vendor_name and vendor_name != "Unknown" else None
        asset_type = oui_cat if oui_cat != "unknown" else "unknown"
        result.append({
            "ip_address":  ip,
            "mac_address": mac or None,
            "hostname":    hostnames.get(ip) or None,
            "vendor":      vendor,
            "asset_type":  asset_type,
            "source":      "arp_report",
        })
    return result


# ── nmap Subnet Scan ──────────────────────────────────────────────────────────

def run_nmap_discovery(subnet: str, ports: str = "22,23,80,443,554,631,8080,8883,9100,161,502,47808") -> list[dict]:
    """
    Run an nmap ping + light port scan against subnet.
    Returns list of asset dicts suitable for upsert_assets().

    Requires nmap installed on the Cy360 server.
    Runs as the Flask process user — ensure sudo or cap_net_raw if needed.
    """
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        _log.error("nmap_discovery: invalid subnet %s", subnet)
        return []

    cmd = [
        "nmap", "-sn", "-PS22,80,443", "--open",
        "-p", ports, "-oX", "-",
        "--host-timeout", "5s",
        subnet,
    ]
    _log.info("nmap_discovery: scanning %s", subnet)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        _log.warning("nmap not installed — skipping subnet scan")
        return []
    except subprocess.TimeoutExpired:
        _log.warning("nmap scan timed out for %s", subnet)
        return []

    return _parse_nmap_xml(result.stdout)


def _parse_nmap_xml(xml_output: str) -> list[dict]:
    """Parse nmap XML output into asset dicts."""
    import xml.etree.ElementTree as ET
    assets = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return []

    for host in root.findall("host"):
        if host.find("status") is None or host.find("status").get("state") != "up":
            continue

        ip, hostname, mac, vendor = "", "", "", ""
        open_ports = []

        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "").upper()
                vendor = addr.get("vendor", "")

        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        ports_elem = host.find("ports")
        if ports_elem:
            for port_elem in ports_elem.findall("port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port_elem.find("service")
                open_ports.append({
                    "port":    int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "service": svc.get("name", "") if svc is not None else "",
                    "banner":  svc.get("product", "") if svc is not None else "",
                })

        if not ip:
            continue

        from .iot_classifier import oui_lookup, classify_ports, is_iot_candidate
        if not vendor and mac:
            vendor_name, cat = oui_lookup(mac)
            vendor = vendor_name
        else:
            _, cat = classify_ports(open_ports) if open_ports else ("", "unknown")

        asset_type = cat if cat != "unknown" else "unknown"

        assets.append({
            "ip_address":  ip,
            "mac_address": mac or None,
            "hostname":    hostname or None,
            "vendor":      vendor or None,
            "asset_type":  asset_type,
            "open_ports":  open_ports,
            "source":      "nmap",
        })

    return assets
