"""
blueprints/itam/iot_classifier.py
==================================
IoT device classification engine.

Classifies discovered network assets as IoT based on:
  - OUI (MAC vendor prefix) lookup against known IoT manufacturer table
  - Open port / service fingerprinting (RTSP, MQTT, SNMP, IPP, etc.)
  - mDNS / Bonjour service type hints
  - Banner grabbing heuristics

Risk scoring (0-100):
  - Default-credential reachability    +40
  - No TLS on management port          +20
  - Known-vulnerable firmware banner   +20
  - Open telnet (port 23)              +15
  - Outbound non-standard traffic      +5
"""
from __future__ import annotations
import socket
import logging

_log = logging.getLogger(__name__)

# ── OUI → vendor mapping (top IoT/OT vendors by MAC prefix) ──────────────────
# Format: first 3 octets (uppercase, no separators) → (vendor, device_category)
OUI_TABLE: dict[str, tuple[str, str]] = {
    # Cameras
    "001A07": ("Hikvision",       "camera"),
    "C0EAE4": ("Hikvision",       "camera"),
    "44191A": ("Hikvision",       "camera"),
    "485B39": ("Hikvision",       "camera"),
    "D083BE": ("Dahua",           "camera"),
    "402693": ("Dahua",           "camera"),
    "001D6C": ("Axis",            "camera"),
    "ACCC8E": ("Axis",            "camera"),
    "00408C": ("Axis",            "camera"),
    "B8273B": ("Bosch Security",  "camera"),
    "000B5D": ("Hanwha (Samsung Techwin)", "camera"),
    "5C8D4E": ("Avigilon",        "camera"),
    # Printers
    "000E8F": ("Xerox",           "printer"),
    "000085": ("HP",              "printer"),
    "001B78": ("HP",              "printer"),
    "3C2AF4": ("HP",              "printer"),
    "E80688": ("HP",              "printer"),
    "005056": ("Brother",         "printer"),
    "0000F0": ("Samsung",         "printer"),
    "0021B7": ("Ricoh",           "printer"),
    "00004E": ("Ricoh",           "printer"),
    "00E019": ("Canon",           "printer"),
    # Network / switches / APs
    "00059A": ("Cisco",           "network_device"),
    "0050F0": ("Cisco",           "network_device"),
    "001E13": ("Cisco",           "network_device"),
    "14E6E4": ("Ubiquiti",        "network_device"),
    "F09FC2": ("Ubiquiti",        "network_device"),
    "24A43C": ("Ubiquiti",        "network_device"),
    "788A20": ("Ubiquiti",        "network_device"),
    "DC9FDB": ("Ubiquiti",        "network_device"),
    "F4E2C6": ("TP-Link",         "network_device"),
    "50C7BF": ("TP-Link",         "network_device"),
    "E894F6": ("Aruba",           "network_device"),
    "94B40F": ("Aruba",           "network_device"),
    # Smart home / IoT hubs
    "18B430": ("Nest (Google)",   "smart_device"),
    "641666": ("Nest (Google)",   "smart_device"),
    "D8EB46": ("Philips Hue",     "smart_device"),
    "001788": ("Philips Hue",     "smart_device"),
    "68A7BC": ("Amazon Echo",     "smart_device"),
    "F0272D": ("Amazon Echo",     "smart_device"),
    "74C246": ("Ring",            "smart_device"),
    "B4EE96": ("Ring",            "smart_device"),
    "AC63BE": ("Apple HomeKit",   "smart_device"),
    "AC3C0B": ("Google Chromecast", "smart_device"),
    "54607E": ("Google Chromecast", "smart_device"),
    # HVAC / BMS / Industrial
    "000227": ("Siemens Building Tech", "hvac_bms"),
    "001AEF": ("Schneider Electric",    "hvac_bms"),
    "0000A2": ("Honeywell",             "hvac_bms"),
    "B82754": ("Bosch Rexroth",         "industrial"),
    "0006C7": ("Beckhoff",              "industrial"),
    "001D9A": ("Rockwell Automation",   "industrial"),
    "0050C2": ("Moxa",                  "industrial"),
    # Thin clients / embedded
    "00E04C": ("Raspberry Pi Foundation", "embedded"),
    "B827EB": ("Raspberry Pi Foundation", "embedded"),
    "DCA632": ("Raspberry Pi Foundation", "embedded"),
    "E45F01": ("Raspberry Pi Foundation", "embedded"),
    # Virtualization hosts (VM NICs)
    "000C29": ("VMware",          "workstation"),
    "000569": ("VMware",          "workstation"),
    "001C14": ("VMware",          "workstation"),
    "005056": ("VMware",          "workstation"),
    "080027": ("VirtualBox",      "workstation"),
    "52540C": ("QEMU/KVM",        "workstation"),
    "001C42": ("Parallels",       "workstation"),
    "00155D": ("Microsoft Hyper-V", "workstation"),
    # Apple computers & mobile
    "001124": ("Apple",           "workstation"),
    "001451": ("Apple",           "workstation"),
    "001636": ("Apple",           "workstation"),
    "001B63": ("Apple",           "workstation"),
    "001D4F": ("Apple",           "workstation"),
    "001EC2": ("Apple",           "workstation"),
    "001F5B": ("Apple",           "workstation"),
    "002312": ("Apple",           "workstation"),
    "003065": ("Apple",           "workstation"),
    "003EE1": ("Apple",           "workstation"),
    "040CCE": ("Apple",           "workstation"),
    "049269": ("Apple",           "workstation"),
    "04F7E4": ("Apple",           "workstation"),
    "6CF049": ("Apple",           "workstation"),
    "70CD60": ("Apple",           "workstation"),
    "78CAF7": ("Apple",           "workstation"),
    "88C9E8": ("Apple",           "workstation"),
    "8C7B9D": ("Apple",           "workstation"),
    "94E96A": ("Apple",           "workstation"),
    "A4B197": ("Apple",           "workstation"),
    "ACDE48": ("Apple",           "workstation"),
    "BC52B7": ("Apple",           "workstation"),
    "C82A14": ("Apple",           "workstation"),
    "D0E140": ("Apple",           "workstation"),
    "D49A20": ("Apple",           "workstation"),
    "F0D1A9": ("Apple",           "workstation"),
    "F4F15A": ("Apple",           "workstation"),
    # Dell servers & workstations
    "001143": ("Dell",            "workstation"),
    "001422": ("Dell",            "workstation"),
    "001A4B": ("Dell",            "workstation"),
    "001E4F": ("Dell",            "workstation"),
    "001EC9": ("Dell",            "workstation"),
    "0026B9": ("Dell",            "workstation"),
    "14187A": ("Dell",            "workstation"),
    "18037D": ("Dell",            "workstation"),
    "18DB F5": ("Dell",            "server"),
    "2477BA": ("Dell",            "workstation"),
    "50E0E0": ("Dell",            "workstation"),
    "BC5FF4": ("Dell",            "workstation"),
    "EC9BF4": ("Dell",            "server"),
    "F48E38": ("Dell",            "server"),
    # HP / HPE workstations & servers
    "001635": ("HP",              "workstation"),
    "001708": ("HP",              "workstation"),
    "001CC4": ("HP",              "workstation"),
    "00248C": ("HP",              "server"),
    "0030C1": ("HP",              "server"),
    "3C4A92": ("HP",              "server"),
    "40B034": ("HP",              "server"),
    "64517E": ("HP",              "workstation"),
    "706D15": ("HP",              "workstation"),
    "785EF7": ("HP",              "workstation"),
    "9CD21E": ("HP",              "server"),
    "A0D3C1": ("HP",              "workstation"),
    "B0593C": ("HP",              "server"),
    "EC8EB5": ("HP",              "server"),
    # Lenovo / IBM workstations & laptops
    "001F16": ("Lenovo",          "workstation"),
    "002170": ("Lenovo",          "workstation"),
    "002322": ("Lenovo",          "workstation"),
    "0025B3": ("Lenovo",          "laptop"),
    "002608": ("Lenovo",          "laptop"),
    "404A03": ("Lenovo",          "workstation"),
    "6CF387": ("Lenovo",          "laptop"),
    "747548": ("Lenovo",          "laptop"),
    "9CF387": ("Lenovo",          "laptop"),
    "C8D9D2": ("Lenovo",          "workstation"),
    # Intel NICs (common in all brands)
    "001111": ("Intel",           "workstation"),
    "001567": ("Intel",           "workstation"),
    "001734": ("Intel",           "workstation"),
    "001C7B": ("Intel",           "workstation"),
    "001EE5": ("Intel",           "workstation"),
    "00236C": ("Intel",           "workstation"),
    "002618": ("Intel",           "workstation"),
    "0027F4": ("Intel",           "workstation"),
    "40F201": ("Intel",           "workstation"),
    "748693": ("Intel",           "workstation"),
    "A4C3F0": ("Intel",           "workstation"),
    # More Cisco (routers/switches/firewalls)
    "000F66": ("Cisco",           "network_device"),
    "001189": ("Cisco",           "network_device"),
    "001589": ("Cisco",           "network_device"),
    "0016C7": ("Cisco",           "network_device"),
    "001839": ("Cisco",           "network_device"),
    "0019E7": ("Cisco",           "network_device"),
    "001AA1": ("Cisco",           "network_device"),
    "001C41": ("Cisco",           "network_device"),
    "001C58": ("Cisco",           "network_device"),
    "001D71": ("Cisco",           "network_device"),
    "001F9E": ("Cisco",           "network_device"),
    "002155": ("Cisco",           "network_device"),
    "002497": ("Cisco",           "network_device"),
    "0050BD": ("Cisco",           "network_device"),
    "00904D": ("Cisco",           "network_device"),
    # Juniper Networks
    "0010DB": ("Juniper",         "network_device"),
    "001868": ("Juniper",         "network_device"),
    "2C6BF5": ("Juniper",         "network_device"),
    "5C695C": ("Juniper",         "network_device"),
    # Palo Alto / Fortinet / Check Point (firewalls)
    "000DAE": ("Palo Alto",       "network_device"),
    "00090F": ("Fortinet",        "network_device"),
    "0011F0": ("Fortinet",        "network_device"),
    "001C7F": ("Check Point",     "network_device"),
    # Netgear routers / switches
    "001B2F": ("Netgear",         "network_device"),
    "0026F2": ("Netgear",         "network_device"),
    "0034DF": ("Netgear",         "network_device"),
    "20E52A": ("Netgear",         "network_device"),
    "6CB0CE": ("Netgear",         "network_device"),
    "9C3DCF": ("Netgear",         "network_device"),
    # D-Link routers
    "001195": ("D-Link",          "network_device"),
    "1CAFF7": ("D-Link",          "network_device"),
    "34D270": ("D-Link",          "network_device"),
    "90947F": ("D-Link",          "network_device"),
    # ASUS routers / motherboards
    "001A92": ("ASUS",            "network_device"),
    "002354": ("ASUS",            "workstation"),
    "107B44": ("ASUS",            "workstation"),
    "2C4D54": ("ASUS",            "workstation"),
    "6045CB": ("ASUS",            "network_device"),
    "74D435": ("ASUS",            "workstation"),
    # Mikrotik
    "4C5E0C": ("MikroTik",        "network_device"),
    "6C3B6B": ("MikroTik",        "network_device"),
    "B8690E": ("MikroTik",        "network_device"),
    "CC2DE0": ("MikroTik",        "network_device"),
    "D4CA6D": ("MikroTik",        "network_device"),
    "DC2C6E": ("MikroTik",        "network_device"),
    "E48D8C": ("MikroTik",        "network_device"),
    # Samsung (mobile / tablets / TVs)
    "001477": ("Samsung",         "workstation"),
    "001D5A": ("Samsung",         "workstation"),
    "002339": ("Samsung",         "workstation"),
    "00264D": ("Samsung",         "smart_device"),
    "CCF9E8": ("Samsung",         "smart_device"),
    # Microsoft Surface / Xbox
    "7845C4": ("Microsoft",       "workstation"),
    "C869CD": ("Microsoft",       "workstation"),
}

# ── Port → service fingerprints ───────────────────────────────────────────────
# Maps open port to (service_name, likely_device_category, risk_contribution)
PORT_SIGNATURES: dict[int, tuple[str, str, int]] = {
    23:   ("telnet",       "iot_device",      15),  # high risk: no encryption
    69:   ("tftp",         "network_device",  10),
    80:   ("http-mgmt",    "iot_device",       5),
    161:  ("snmp",         "network_device",   8),
    162:  ("snmp-trap",    "network_device",   5),
    443:  ("https-mgmt",   "iot_device",       0),
    502:  ("modbus",       "industrial",      20),  # OT protocol — very high risk
    554:  ("rtsp",         "camera",           5),  # RTSP = IP camera
    631:  ("ipp",          "printer",          3),  # IPP print protocol
    1883: ("mqtt",         "smart_device",     8),  # MQTT unencrypted
    4840: ("opc-ua",       "industrial",      12),  # OPC-UA industrial
    5353: ("mdns",         "smart_device",     0),
    8080: ("http-alt",     "iot_device",       5),
    8443: ("https-alt",    "iot_device",       0),
    8883: ("mqtt-ssl",     "smart_device",     0),  # MQTT encrypted — ok
    9100: ("raw-print",    "printer",          3),
    47808:("bacnet",       "hvac_bms",        15),  # BACnet building automation
}

# ── mDNS service type → device category ──────────────────────────────────────
MDNS_SERVICE_MAP: dict[str, str] = {
    "_ipp._tcp":        "printer",
    "_ipps._tcp":       "printer",
    "_printer._tcp":    "printer",
    "_pdl-datastream._tcp": "printer",
    "_rtsp._tcp":       "camera",
    "_hap._tcp":        "smart_device",      # HomeKit Accessory Protocol
    "_googlecast._tcp": "smart_device",      # Chromecast
    "_airplay._tcp":    "smart_device",      # Apple AirPlay
    "_mqtt._tcp":       "smart_device",
    "_http._tcp":       "iot_device",
    "_https._tcp":      "iot_device",
    "_smb._tcp":        "server",
    "_ssh._tcp":        "server",
    "_vnc._tcp":        "workstation",
}

# ── Known default credential pairs by vendor ─────────────────────────────────
DEFAULT_CREDS: dict[str, list[tuple[str, str]]] = {
    "Hikvision":  [("admin", "12345"), ("admin", "admin"), ("admin", "")],
    "Dahua":      [("admin", "admin"), ("admin", "123456")],
    "Axis":       [("root", "pass"), ("root", "root")],
    "TP-Link":    [("admin", "admin"), ("admin", "")],
    "Ubiquiti":   [("ubnt", "ubnt"), ("admin", "admin")],
    "Cisco":      [("cisco", "cisco"), ("admin", "admin")],
    "D-Link":     [("admin", "admin"), ("admin", "")],
    "_default_":  [("admin", "admin"), ("admin", "password"), ("root", "root"),
                   ("root", ""), ("admin", ""), ("guest", "guest")],
}


def oui_lookup(mac: str) -> tuple[str, str]:
    """
    Given a MAC address (any separator), return (vendor, device_category).
    Returns ('Unknown', 'unknown') if not found.
    """
    if not mac:
        return "Unknown", "unknown"
    clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    prefix = clean[:6]
    return OUI_TABLE.get(prefix, ("Unknown", "unknown"))


def classify_ports(open_ports: list[dict]) -> tuple[str, int]:
    """
    Given a list of {port, protocol, service} dicts, infer device category
    and calculate port-based risk contribution.
    Returns (device_category, risk_score_addition).
    """
    best_category = "unknown"
    risk_add = 0
    category_priority = {
        "camera": 10, "printer": 9, "industrial": 8, "hvac_bms": 7,
        "smart_device": 6, "network_device": 5, "iot_device": 4,
        "server": 3, "workstation": 2, "embedded": 1, "unknown": 0,
    }

    for p in open_ports:
        port = int(p.get("port", 0))
        sig = PORT_SIGNATURES.get(port)
        if not sig:
            continue
        _, cat, risk = sig
        risk_add += risk
        if category_priority.get(cat, 0) > category_priority.get(best_category, 0):
            best_category = cat

    return best_category, min(risk_add, 40)


def compute_risk_score(
    vendor: str,
    device_category: str,
    open_ports: list[dict],
    has_default_creds: bool = False,
    has_telnet: bool = False,
    no_tls_on_mgmt: bool = False,
) -> tuple[int, list[str]]:
    """
    Compute a 0-100 risk score and a list of contributing risk factor descriptions.
    """
    score = 20  # baseline for any IoT/unmanaged device
    factors: list[str] = []

    if has_default_creds:
        score += 40
        factors.append("Default credentials detected")

    if has_telnet:
        score += 15
        factors.append("Telnet (port 23) open — unencrypted management")

    if no_tls_on_mgmt:
        score += 20
        factors.append("Management interface accessible over HTTP (no TLS)")

    _, port_risk = classify_ports(open_ports)
    if port_risk:
        score += port_risk
        factors.append(f"Risky services exposed ({port_risk} pts)")

    # High-risk categories
    if device_category in ("industrial", "hvac_bms"):
        score += 10
        factors.append(f"OT/ICS device type ({device_category}) — critical infrastructure risk")

    # Known-risky vendors
    if vendor in ("Hikvision", "Dahua") and not has_default_creds:
        score += 5
        factors.append("Vendor has known CVE history — verify firmware version")

    return min(score, 100), factors


def probe_default_creds(ip: str, port: int = 80, vendor: str = "_default_") -> bool:
    """
    Attempt a quick HTTP Basic Auth probe with known default credentials.
    Returns True if any default credential pair succeeds.
    Only attempted when ITAM_PROBE_DEFAULT_CREDS is enabled.
    Timeout: 2s per attempt.
    """
    import urllib.request
    import base64
    creds = DEFAULT_CREDS.get(vendor, []) + DEFAULT_CREDS["_default_"]
    for user, passwd in creds[:4]:  # limit to first 4 pairs
        try:
            token = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            req = urllib.request.Request(
                f"http://{ip}:{port}/",
                headers={"Authorization": f"Basic {token}"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status in (200, 302):
                    _log.warning("Default creds found on %s port %s (%s:%s)", ip, port, user, passwd)
                    return True
        except Exception:
            pass
    return False


def is_iot_candidate(asset: dict) -> bool:
    """
    Quick pre-filter: is this asset likely IoT based on OUI or ports alone?
    Used to avoid scanning every asset with full fingerprinting.
    """
    mac = asset.get("mac_address", "")
    vendor, cat = oui_lookup(mac)
    if cat not in ("unknown", "server", "workstation"):
        return True
    open_ports = asset.get("open_ports") or []
    iot_ports = {554, 1883, 8883, 47808, 502, 4840, 9100, 631}
    return any(int(p.get("port", 0)) in iot_ports for p in open_ports)
