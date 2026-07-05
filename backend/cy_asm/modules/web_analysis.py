# modules/web_analysis.py
# CyCentra Web/HTTP Analysis — Enhanced 2026
# True protocol-specific handshaking for every port; extended HTTP header audit;
# SMB signing, RDP NLA, SSH KEX, Docker/K8s exposure checks.
# All checks use Python stdlib + existing deps — no new packages required.

import nmap
import aiohttp
import asyncio
import re
import socket
import struct
import ftplib
import smtplib
import ssl
import dns.resolver
from typing import Dict, List, Any
from bs4 import BeautifulSoup
from config import (
    HTTP_TIMEOUT, EXPOSED_PATHS, QUICK_SCAN_PORTS,
    EXTENDED_PORT_RANGE, INFRA_EXPOSURE_PORTS,
    ENABLE_EXTENDED_PORT_SCAN, ENABLE_UDP_SCAN,
    PROTO_PROBE_TIMEOUT,
)
from utils import setup_logging, create_async_session

try:
    from modules.crypto_checks import check_ssl_status
except ImportError:
    async def check_ssl_status(domain):
        return {"ssl_enabled": False, "issues": ["SSL check unavailable"]}

logger = setup_logging()

# ── Required security headers (missing = finding) ─────────────────────────────
REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]


# ── Port scanner ───────────────────────────────────────────────────────────────

def scan_ports_with_nmap(domain: str) -> List[int]:
    open_ports = []
    nm = nmap.PortScanner()
    if ENABLE_EXTENDED_PORT_SCAN:
        ports_arg = EXTENDED_PORT_RANGE
        nmap_args = "-p {ports} -T4 -sV --open"
        if ENABLE_UDP_SCAN:
            ports_arg = f"{EXTENDED_PORT_RANGE},U:{EXTENDED_PORT_RANGE}"
            nmap_args += " -sU"
    else:
        # Quick scan: standard services + infra-exposure ports
        ports_arg = f"{QUICK_SCAN_PORTS},{INFRA_EXPOSURE_PORTS}"
        nmap_args = f"-p {ports_arg} -T4 --open"
    logger.info(f"Port scanning {domain}")
    try:
        nm.scan(domain, arguments=nmap_args.format(ports=ports_arg))
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port]["state"] == "open":
                        open_ports.append(port)
        open_ports.sort()
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
    return open_ports


# ── Protocol-specific probes ───────────────────────────────────────────────────

def _probe_http_banner(host: str, port: int) -> Dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return {"banner": banner or "HTTP service", "protocol": "http"}
    except Exception:
        return {"banner": "Unknown", "protocol": "http"}


def _probe_ssh(host: str, port: int = 22) -> Dict[str, Any]:
    """Read SSH version banner and parse KEX INIT for algorithm lists."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "ssh", "issues": []}
    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            # SSH sends its version line immediately
            banner_raw = s.recv(256).decode(errors="ignore").strip()
            result["banner"] = banner_raw

            # Reply with our own version to advance the handshake
            s.send(b"SSH-2.0-CyCentra_Probe\r\n")

            # Read KEX INIT packet: 4-byte length, 1-byte pad, 1-byte type(20), payload
            raw = s.recv(2048)
            if len(raw) >= 6 and raw[5] == 20:  # SSH_MSG_KEXINIT
                offset = 6 + 16  # skip pkt_len(4)+pad_len(1)+type(1)+cookie(16)
                algo_lists = []
                for _ in range(10):  # 10 name-list fields in KEXINIT
                    if offset + 4 > len(raw):
                        break
                    length = struct.unpack(">I", raw[offset:offset + 4])[0]
                    offset += 4
                    field = raw[offset:offset + length].decode(errors="ignore")
                    algo_lists.append(field)
                    offset += length

                if algo_lists:
                    kex_algos = algo_lists[0] if len(algo_lists) > 0 else ""
                    host_key_types = algo_lists[1] if len(algo_lists) > 1 else ""
                    enc_client = algo_lists[2] if len(algo_lists) > 2 else ""

                    result["kex_algorithms"] = kex_algos
                    result["host_key_types"] = host_key_types
                    result["encryption_algos"] = enc_client

                    # Flag weak/deprecated algorithms
                    weak_kex = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
                    if any(w in kex_algos for w in weak_kex):
                        result["issues"].append(f"SSH weak KEX algorithm in use: {kex_algos}")

                    if "ssh-dss" in host_key_types:
                        result["issues"].append("SSH DSA host key (deprecated)")

                    if "arcfour" in enc_client or "3des" in enc_client.lower():
                        result["issues"].append("SSH weak encryption algorithm offered")

    except Exception as e:
        result["banner"] = f"SSH probe error: {e}"
    return result


def _probe_ftp(host: str, port: int = 21) -> Dict[str, Any]:
    """Check FTP banner and anonymous login."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "ftp", "anonymous_login": False, "issues": []}
    try:
        with ftplib.FTP(timeout=PROTO_PROBE_TIMEOUT) as ftp:
            welcome = ftp.connect(host, port)
            result["banner"] = welcome.strip()
            try:
                ftp.login("anonymous", "probe@cycentra.local")
                result["anonymous_login"] = True
                result["issues"].append("FTP anonymous login permitted — unauthenticated access to file system")
            except ftplib.error_perm:
                pass
    except Exception as e:
        result["banner"] = f"FTP probe error: {e}"
    return result


def _probe_smtp(host: str, port: int = 25) -> Dict[str, Any]:
    """Grab SMTP banner and test for open relay."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "smtp", "open_relay": False, "issues": [], "auth_methods": []}
    try:
        with smtplib.SMTP(timeout=PROTO_PROBE_TIMEOUT) as smtp:
            code, banner = smtp.connect(host, port)
            result["banner"] = banner.decode(errors="ignore").strip() if isinstance(banner, bytes) else str(banner)

            try:
                smtp.ehlo("probe.cycentra.local")
                feats = smtp.esmtp_features
                if "auth" in feats:
                    result["auth_methods"] = feats["auth"].split()
            except Exception:
                pass

            # Open relay test: attempt to relay a message between two external domains
            try:
                smtp.mail("probe@external1.com")
                code2, _ = smtp.rcpt("probe@external2.com")
                if code2 == 250:
                    result["open_relay"] = True
                    result["issues"].append("SMTP open relay detected — server will forward email for unauthenticated senders")
            except smtplib.SMTPRecipientsRefused:
                pass
            except Exception:
                pass
    except Exception as e:
        result["banner"] = f"SMTP probe error: {e}"
    return result


def _probe_rdp_nla(host: str, port: int = 3389) -> Dict[str, Any]:
    """
    Send an RDP X.224 Connection Request and inspect the response to determine
    whether Network Level Authentication (NLA / CredSSP) is required.

    X.224 TPKT layout:
      [0]    version=3
      [1]    reserved=0
      [2-3]  length (big-endian uint16)
      [4]    LI (length indicator for TPDU header)
      [5]    CR TPDU code = 0xE0
      [6-7]  dst-ref
      [8-9]  src-ref
      [10]   class/option
      Followed by RDP Negotiation Request TLV (type=0x01, flags, length=8, protocols bitmask)

    Protocols bitmask: 0x00000001 = TLS, 0x00000003 = NLA (CredSSP+TLS)
    """
    result: Dict[str, Any] = {
        "banner": "RDP",
        "protocol": "rdp",
        "nla_required": None,
        "ssl_required": None,
        "rdp_protocol": None,
        "issues": [],
    }
    # X.224 CR TPDU with RDP Negotiation Request (request NLA + TLS)
    rdp_neg_req = (
        b"\x03\x00\x00\x13"   # TPKT header: version=3, reserved=0, length=19
        b"\x0e"               # LI=14
        b"\xe0"               # CR TPDU code
        b"\x00\x00"           # dst-ref
        b"\x00\x00"           # src-ref
        b"\x00"               # class 0
        # RDP Negotiation Request
        b"\x01"               # type=TYPE_RDP_NEG_REQ
        b"\x00"               # flags
        b"\x08\x00"           # length=8
        b"\x03\x00\x00\x00"  # protocols: PROTOCOL_SSL(1) | PROTOCOL_HYBRID(2)
    )
    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            s.send(rdp_neg_req)
            resp = s.recv(64)
            if len(resp) >= 19:
                # Parse TPKT + TPDU
                tpdu_code = resp[5] if len(resp) > 5 else 0
                if tpdu_code == 0xD0:  # CC TPDU (Connection Confirm)
                    # RDP Negotiation Response starts at byte 11
                    if len(resp) >= 19:
                        neg_type  = resp[11]
                        neg_flags = resp[12]
                        selected  = struct.unpack("<I", resp[15:19])[0] if len(resp) >= 19 else 0
                        result["rdp_protocol"] = selected
                        if neg_type == 0x02:  # TYPE_RDP_NEG_RSP
                            # selected_protocol: 0=classic RDP, 1=TLS only, 2=NLA (CredSSP)
                            result["ssl_required"] = bool(selected & 0x01)
                            result["nla_required"] = bool(selected & 0x02)
                            if not result["nla_required"]:
                                result["issues"].append(
                                    "RDP NLA (Network Level Authentication) is NOT enforced — "
                                    "brute-force and credential exposure risk"
                                )
                        elif neg_type == 0x03:  # TYPE_RDP_NEG_FAILURE
                            result["issues"].append("RDP Negotiation failure — server may be using legacy encryption")
    except Exception as e:
        result["banner"] = f"RDP probe error: {e}"
    return result


def _probe_redis(host: str, port: int = 6379) -> Dict[str, Any]:
    """Send a PING. An unauthenticated +PONG is a critical exposure."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "redis", "no_auth": False, "issues": []}
    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            s.send(b"*1\r\n$4\r\nPING\r\n")
            resp = s.recv(256).decode(errors="ignore").strip()
            result["banner"] = resp
            if resp.startswith("+PONG"):
                result["no_auth"] = True
                result["issues"].append(
                    "Redis is accessible without authentication — "
                    "full database read/write/config access by any client"
                )
            elif resp.startswith("-NOAUTH") or resp.startswith("-ERR"):
                result["issues"].append("Redis requires AUTH (correctly configured)")
    except Exception as e:
        result["banner"] = f"Redis probe error: {e}"
    return result


def _probe_mongodb(host: str, port: int = 27017) -> Dict[str, Any]:
    """
    Send a MongoDB OP_QUERY for isMaster on admin.$cmd.
    If we get a valid response without authenticating, auth is disabled.
    """
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "mongodb", "no_auth": False, "issues": []}
    try:
        # Build minimal OP_QUERY: isMaster on admin.$cmd
        query_bson = (
            b"\x13\x00\x00\x00"   # document length = 19
            b"\x01"               # type: Double
            b"isMaster\x00"       # key
            b"\x00\x00\x00\x00\x00\x00\xf0\x3f"  # value: 1.0
            b"\x00"               # document terminator
        )
        # OP_QUERY header
        full_collection = b"admin.$cmd\x00"
        op_query = struct.pack("<i", 0)             # flags
        op_query += full_collection
        op_query += struct.pack("<i", 0)             # numberToSkip
        op_query += struct.pack("<i", -1)            # numberToReturn
        op_query += query_bson
        msg_len = 16 + len(op_query)
        header = struct.pack("<iiii", msg_len, 1, 0, 2004)  # opCode=2004 OP_QUERY
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            s.send(header + op_query)
            resp = s.recv(512)
            if len(resp) > 20:
                result["banner"] = f"MongoDB responded ({len(resp)} bytes)"
                # If we got a document back we're unauthenticated
                result["no_auth"] = True
                result["issues"].append(
                    "MongoDB is accessible without authentication — "
                    "full database access by unauthenticated clients"
                )
    except Exception as e:
        result["banner"] = f"MongoDB probe error: {e}"
    return result


def _probe_smb(host: str, port: int = 445) -> Dict[str, Any]:
    """
    Send SMB2 NEGOTIATE to determine SMB version and signing enforcement.
    Parses SecurityMode field: bit 0 = signing enabled, bit 1 = signing required.
    """
    result: Dict[str, Any] = {
        "banner": "SMB",
        "protocol": "smb",
        "smb_version": None,
        "signing_enabled": None,
        "signing_required": False,
        "issues": [],
    }
    # SMB2 NEGOTIATE packet (minimal)
    smb2_header = (
        b"\xfeSMB"            # ProtocolId
        + struct.pack("<H", 64)  # StructureSize=64
        + b"\x00\x00"         # CreditCharge
        + b"\x00\x00\x00\x00" # Status
        + struct.pack("<H", 0) # Command=NEGOTIATE(0)
        + b"\x1f\x00"         # CreditRequest
        + b"\x00\x00\x00\x00" # Flags
        + b"\x00\x00\x00\x00" # NextCommand
        + b"\x00" * 8         # MessageId
        + b"\x00" * 4         # Reserved
        + b"\x00" * 4         # TreeId
        + b"\x00" * 8         # SessionId
        + b"\x00" * 16        # Signature
    )
    negotiate_body = (
        struct.pack("<H", 36)   # StructureSize=36
        + struct.pack("<H", 4)   # DialectCount=4
        + b"\x00\x00"           # SecurityMode (client side)
        + b"\x00\x00"           # Reserved
        + b"\x00\x00\x00\x00"   # Capabilities
        + b"\x00" * 16          # ClientGuid
        + b"\x00" * 8           # ClientStartTime
        # Dialects: SMB 2.0.2, 2.1, 3.0, 3.1.1
        + struct.pack("<HHHH", 0x0202, 0x0210, 0x0300, 0x0311)
    )
    payload = smb2_header + negotiate_body
    netbios = struct.pack(">I", len(payload)) + payload  # NetBIOS session service header

    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            s.send(netbios)
            resp = s.recv(512)
            # NetBIOS header is 4 bytes, then SMB2 header 64 bytes, then NEGOTIATE response body
            if len(resp) >= 72:
                proto_id = resp[4:8]
                if proto_id == b"\xfeSMB":
                    # Parse SecurityMode from NEGOTIATE response body (offset 68+2 from NetBIOS)
                    body_start = 68  # 4 (NetBIOS) + 64 (SMB2 header)
                    struct_size = struct.unpack("<H", resp[body_start:body_start + 2])[0]
                    security_mode = struct.unpack("<H", resp[body_start + 2:body_start + 4])[0]
                    dialect = struct.unpack("<H", resp[body_start + 4:body_start + 6])[0]

                    result["smb_version"] = f"SMB {dialect >> 8}.{dialect & 0xff}"
                    result["signing_enabled"]  = bool(security_mode & 0x0001)
                    result["signing_required"] = bool(security_mode & 0x0002)
                    result["banner"] = f"SMB {hex(dialect)} signing={'required' if result['signing_required'] else ('enabled' if result['signing_enabled'] else 'disabled')}"

                    if not result["signing_required"]:
                        result["issues"].append(
                            f"SMB signing NOT required ({result['smb_version']}) — "
                            "relay attacks (NTLM relay, Pass-the-Hash) are possible"
                        )
                    if dialect <= 0x0202:  # SMBv2.0.2 only
                        result["issues"].append("SMBv2.0.2 dialect in use — upgrade to SMB 3.1.1")
    except Exception as e:
        result["banner"] = f"SMB probe error: {e}"
    return result


def _probe_docker(host: str, port: int = 2375) -> Dict[str, Any]:
    """Check if Docker daemon API is accessible without TLS."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "docker", "exposed": False, "issues": []}
    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            s.send(b"GET /version HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            resp = s.recv(512).decode(errors="ignore")
            if '"ApiVersion"' in resp or "Docker" in resp:
                result["exposed"] = True
                result["banner"] = resp.split("\r\n\r\n", 1)[-1][:200]
                result["issues"].append(
                    "Docker daemon API exposed without TLS (port 2375) — "
                    "full container control by any client (Critical)"
                )
    except Exception:
        pass
    return result


def _probe_kubernetes(host: str, port: int = 6443) -> Dict[str, Any]:
    """Check if Kubernetes API server is reachable and returns info without auth."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "kubernetes", "exposed": False, "issues": []}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.send(b"GET /version HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                resp = s.recv(512).decode(errors="ignore")
                if '"gitVersion"' in resp or '"major"' in resp:
                    result["exposed"] = True
                    result["banner"] = resp.split("\r\n\r\n", 1)[-1][:200]
                    result["issues"].append(
                        "Kubernetes API server accessible without authentication — "
                        "cluster takeover risk (Critical)"
                    )
    except Exception:
        pass
    return result


def _probe_elasticsearch(host: str, port: int = 9200) -> Dict[str, Any]:
    """Check if Elasticsearch HTTP API is open without auth."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "elasticsearch", "exposed": False, "issues": []}
    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            s.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            resp = s.recv(512).decode(errors="ignore")
            if '"cluster_name"' in resp or '"version"' in resp:
                result["exposed"] = True
                result["banner"] = resp.split("\r\n\r\n", 1)[-1][:200]
                result["issues"].append(
                    "Elasticsearch accessible without authentication — "
                    "full index read/write access (Critical)"
                )
    except Exception:
        pass
    return result


def _probe_memcached(host: str, port: int = 11211) -> Dict[str, Any]:
    """Send 'stats' command. Unauthenticated stats = exposure."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "memcached", "exposed": False, "issues": []}
    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            s.send(b"stats\r\n")
            resp = s.recv(512).decode(errors="ignore")
            if resp.startswith("STAT"):
                result["exposed"] = True
                result["banner"] = resp[:150]
                result["issues"].append(
                    "Memcached accessible without authentication — "
                    "cache poisoning and DDoS amplification risk"
                )
    except Exception:
        pass
    return result


def _probe_vnc(host: str, port: int = 5900) -> Dict[str, Any]:
    """Grab VNC protocol version banner."""
    result: Dict[str, Any] = {"banner": "Unknown", "protocol": "vnc", "issues": []}
    try:
        with socket.create_connection((host, port), timeout=PROTO_PROBE_TIMEOUT) as s:
            banner = s.recv(12).decode(errors="ignore").strip()
            result["banner"] = banner
            if banner.startswith("RFB"):
                result["issues"].append(
                    f"VNC service exposed ({banner}) — "
                    "remote desktop access may be unauthenticated or weakly protected"
                )
    except Exception:
        pass
    return result


# ── Protocol dispatch ──────────────────────────────────────────────────────────

_PROTO_MAP: Dict[int, Any] = {
    21:   _probe_ftp,
    22:   _probe_ssh,
    25:   _probe_smtp,
    80:   lambda h, p: _probe_http_banner(h, p),
    110:  lambda h, p: _probe_http_banner(h, p),
    143:  lambda h, p: _probe_http_banner(h, p),
    443:  lambda h, p: _probe_http_banner(h, p),
    445:  _probe_smb,
    2375: _probe_docker,
    2376: _probe_docker,
    3306: lambda h, p: _probe_http_banner(h, p),   # MySQL banner grab fallback
    3389: _probe_rdp_nla,
    5432: lambda h, p: _probe_http_banner(h, p),   # PostgreSQL banner fallback
    5900: _probe_vnc,
    6379: _probe_redis,
    6443: _probe_kubernetes,
    8080: lambda h, p: _probe_http_banner(h, p),
    8443: lambda h, p: _probe_http_banner(h, p),
    9090: lambda h, p: _probe_http_banner(h, p),   # Prometheus
    9200: _probe_elasticsearch,
    9300: _probe_elasticsearch,
    11211: _probe_memcached,
    27017: _probe_mongodb,
}


async def fingerprint_services(host: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
    results: Dict[int, Dict[str, Any]] = {}
    loop = asyncio.get_event_loop()

    async def _probe(port: int):
        probe_fn = _PROTO_MAP.get(port, lambda h, p: _probe_http_banner(h, p))
        try:
            fp = await loop.run_in_executor(None, probe_fn, host, port)
        except Exception as e:
            fp = {"banner": f"Probe error: {e}", "protocol": "unknown"}

        vulns: List[str] = []
        banner = fp.get("banner", "")
        if banner and len(banner) > 4:
            try:
                import sys as _sys, os as _os
                _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))
                from core.helpers import cytim_recon
                _host = host if isinstance(host, str) else str(host)
                _r = await loop.run_in_executor(
                    None,
                    lambda: cytim_recon(_host, ["cve"], cve_keywords=[banner[:100]])
                )
                vulns = [f["cve_id"] for f in (_r.get("cve") or {}).get("findings", [])[:5]]
            except Exception:
                pass

        fp["vulns"] = vulns
        results[port] = fp

    await asyncio.gather(*[_probe(p) for p in ports])
    return results


# ── Secret scanning ────────────────────────────────────────────────────────────

async def find_secrets_in_js(url: str, session: aiohttp.ClientSession) -> List[Dict[str, str]]:
    patterns = {
        "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key":    r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})",
        "Stripe Live Key":   r"sk_live_[0-9a-zA-Z]{24}",
        "Stripe Test Key":   r"sk_test_[0-9a-zA-Z]{24}",
        "GitHub PAT":        r"ghp_[0-9a-zA-Z]{36}",
        "GitHub OAuth":      r"gho_[0-9a-zA-Z]{36}",
        "Firebase URL":      r"[a-z0-9-]+\.firebaseio\.com",
        "Firebase Key":      r"AAAA[A-Za-z0-9_-]{35}:",
        "Private Key":       r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        "Google API Key":    r"AIza[0-9A-Za-z\\-_]{35}",
        "Slack Token":       r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
        "Slack Webhook":     r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "Twilio SID":        r"SK[0-9a-fA-F]{32}",
        "JWT Token":         r"eyJ[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}",
        "SendGrid API Key":  r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "Mailgun Key":       r"key-[0-9a-zA-Z]{32}",
    }
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status != 200:
                return []
            soup = BeautifulSoup(await resp.text(), "html.parser")
            js_urls = []
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if not src.endswith(".js"):
                    continue
                full = src if src.startswith("http") else url.rstrip("/") + "/" + src.lstrip("/")
                js_urls.append(full)
            js_urls = js_urls[:15]
        found = []
        for js_url in js_urls:
            try:
                async with session.get(js_url, timeout=12) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text()
                    for name, regex in patterns.items():
                        for match in re.findall(regex, text):
                            value = match[0] if isinstance(match, tuple) else match
                            found.append({"type": name, "value": value.strip(), "source": js_url.split("/")[-1]})
                    await asyncio.sleep(0.3)
            except Exception:
                pass
        return [dict(t) for t in {tuple(d.items()) for d in found}]
    except Exception:
        return []


# ── Exposed path analysis ──────────────────────────────────────────────────────

async def analyze_exposed_paths(domain: str, session: aiohttp.ClientSession, schemes: List[str]) -> List[Dict[str, Any]]:
    paths = set(EXPOSED_PATHS)
    # Only probe HTTPS for path discovery — HTTP is redundant and doubles findings
    for file in ["/robots.txt", "/sitemap.xml"]:
        try:
            async with session.get(f"https://{domain}{file}", timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "robots" in file:
                        paths.update(re.findall(r"Disallow:\s*([^\s#]+)", text))
                    elif "sitemap" in file:
                        paths.update(re.findall(r"<loc>[^<]*" + re.escape(domain) + r"([^<]+)</loc>", text))
        except Exception:
            pass

    results = []

    async def check(p):
        p = p.rstrip("/") + "/"
        # HTTPS only — HTTP is always a redirect to HTTPS, not a separate surface
        url = f"https://{domain}{p}"
        try:
            async with session.head(url, allow_redirects=False, timeout=8) as resp:
                # Only 200 and 401/403 are meaningful — 301 means "nothing here, go to HTTPS"
                if resp.status not in (200, 401, 403):
                    return
                # Content-type gate: sensitive files (.git, .env, db.dump) should NOT
                # return text/html. A text/html 200 is almost certainly a SPA soft-404.
                content_type = resp.headers.get("content-type", "").lower()
                is_sensitive = any(x in p for x in [".env", ".git", "db.dump", "backup", "config"])
                if is_sensitive and "text/html" in content_type:
                    # Likely SPA soft-404 — do a GET to check content signature before flagging
                    try:
                        async with session.get(url, allow_redirects=False, timeout=8) as get_resp:
                            if get_resp.status != 200:
                                return
                            ct = get_resp.headers.get("content-type", "").lower()
                            if "text/html" in ct:
                                return  # Still HTML -> soft-404, skip entirely
                    except Exception:
                        return
                sev = "Critical" if any(x in p for x in [".env", ".git", "backup", "admin", "config"]) else "High"
                results.append({"path": p, "url": url, "status": resp.status, "severity": sev})
        except Exception:
            pass

    await asyncio.gather(*[check(p) for p in paths])
    # Deduplicate by path — keep highest-severity entry per unique path
    seen_paths = {}
    for r in results:
        key = r["path"]
        if key not in seen_paths or (r["severity"] == "Critical" and seen_paths[key]["severity"] != "Critical"):
            seen_paths[key] = r
    deduped = sorted(seen_paths.values(), key=lambda x: (x["severity"] == "Critical", x["severity"] == "High"), reverse=True)
    return deduped[:50]


async def discover_api_endpoints(domain: str, session: aiohttp.ClientSession, schemes: List[str]) -> List[str]:
    found = []
    for scheme in schemes:
        for endpoint in ["/api", "/graphql", "/v1", "/api/v1", "/rest", "/jsonapi"]:
            url = f"{scheme}://{domain}{endpoint}"
            try:
                async with session.get(url, timeout=HTTP_TIMEOUT) as resp:
                    if resp.status == 200 and any(t in resp.headers.get("content-type", "").lower() for t in ["json", "text"]):
                        found.append(url)
            except Exception:
                pass
    return found


# ── HTTP header audit ──────────────────────────────────────────────────────────

async def web_analyzer(domain: str, dns_records: Dict, session) -> Dict[str, Any]:
    result = {
        "http_headers": [],
        "redirects_to_https": False,
        "cors_issues": [],
        "exposed_api_routes": [],
        "header_detail": {},
    }
    try:
        async with session.get(f"http://{domain}", allow_redirects=True, timeout=HTTP_TIMEOUT) as resp:
            result["redirects_to_https"] = str(resp.url).startswith("https://")
            headers = resp.headers

            # Check all required security headers
            for h in REQUIRED_HEADERS:
                val = headers.get(h, "")
                if not val:
                    result["http_headers"].append(f"Missing {h}")
                else:
                    result["header_detail"][h] = val

            # Cache-Control on sensitive-ish paths
            cc = headers.get("Cache-Control", "")
            if not cc or "no-store" not in cc.lower():
                result["http_headers"].append("Cache-Control: no-store not set on root response")

            # CORS wildcard
            acao = headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                result["cors_issues"].append("Permissive CORS (Access-Control-Allow-Origin: *)")
            acam = headers.get("Access-Control-Allow-Methods", "")
            if acam and any(m in acam.upper() for m in ["DELETE", "PUT", "PATCH"]):
                result["cors_issues"].append(f"CORS allows mutating methods: {acam}")

    except Exception:
        pass
    return result


# ── Orchestration ──────────────────────────────────────────────────────────────

async def gather_web_analysis(domain: str, dns_records: Dict[str, Any] = None) -> Dict[str, Any]:
    if dns_records is None:
        dns_records = {}
    ports = scan_ports_with_nmap(domain)
    fingerprints = await fingerprint_services(domain, ports)
    ssl_result = check_ssl_status(domain) if 443 in ports else {"ssl_enabled": False, "issues": []}
    async with await create_async_session() as session:
        js_secrets = await find_secrets_in_js(f"https://{domain}", session)
        schemes = ["https", "http"]
        exposed = await analyze_exposed_paths(domain, session, schemes)
        apis = await discover_api_endpoints(domain, session, schemes)
        http_analysis = await web_analyzer(domain, dns_records, session)

    # Aggregate issues
    issues = ssl_result.get("issues", [])
    for p, fp in fingerprints.items():
        for issue in fp.get("issues", []):
            issues.append(f"Port {p}: {issue}")
        if fp.get("vulns"):
            issues.append(f"Port {p}: CVE references found")
    if js_secrets:
        issues.append(f"{len(js_secrets)} leaked secrets found in JS files")
    if any(e["severity"] == "Critical" for e in exposed):
        issues.append("Critical path exposures detected")
    issues.extend(http_analysis.get("cors_issues", []))
    issues.extend([f"Header: {h}" for h in http_analysis.get("http_headers", [])])

    summary = f"Web: {len(ports)} ports | {len(js_secrets)} secrets | {len(exposed)} paths | {len(apis)} APIs"

    return {
        "results": {
            "ports": ports,
            "fingerprints": fingerprints,
            "ssl": ssl_result,
            "js_secrets": js_secrets,
            "exposed_paths": exposed,
            "api_endpoints": apis,
            "http_analysis": http_analysis,
        },
        "issues": issues,
        "summary": summary,
    }


if __name__ == "__main__":
    from . import run_standalone
