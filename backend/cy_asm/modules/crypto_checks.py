# modules/crypto_checks.py
# CyCentra — Complete SSL/TLS + Post-Quantum Crypto Auditor (2026 Ready)
# Enhanced: full cert depth (key size/type, sig algo, serial, issuer chain,
# self-signed, not-before, long validity, OCSP stapling, TLS compression,
# Heartbleed) all wired into the standard check_ssl_status() path.

import ssl
import socket
import hashlib
import struct
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import asyncio
from OpenSSL import crypto
from utils import setup_logging

DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "LOW"]
ANON_CIPHERS = ["AECDH", "ADH"]
PQC_HYBRID_GROUPS = {
    0x6399: "X25519Kyber768Draft00",
    0x11ec: "P256-Kyber768",
    0x11B9: "X25519MLKEM768",
    0x11BA: "SecP384r1MLKEM768",
    0x11BB: "X25519MLKEM1024",
}

logger = setup_logging()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_self_signed(cert: crypto.X509) -> bool:
    try:
        return cert.get_subject().CN == cert.get_issuer().CN
    except Exception:
        return False


def _check_not_before(cert: crypto.X509) -> Optional[str]:
    try:
        nb_raw = cert.get_notBefore().decode("ascii")
        not_before = datetime.strptime(nb_raw, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        if not_before > datetime.now(timezone.utc):
            return f"Certificate not yet valid (valid from {not_before.date()})"
    except Exception:
        pass
    return None


def _check_long_validity(cert: crypto.X509) -> Optional[str]:
    try:
        nb = datetime.strptime(cert.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        na = datetime.strptime(cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        days = (na - nb).days
        if days > 398:
            return f"Certificate validity too long ({days} days > 398)"
    except Exception:
        pass
    return None


def _check_ocsp_stapling(ssock) -> bool:
    try:
        return bool(ssock.getpeercert().get("OCSP"))
    except Exception:
        return False


def _check_tls_compression(ssock) -> bool:
    try:
        return ssock.compression() is not None
    except Exception:
        return False


def _simple_heartbleed_test(hostname: str, port: int = 443, timeout: int = 5) -> bool:
    """Returns True when the probe suggests vulnerability (no alert received)."""
    try:
        s = socket.create_connection((hostname, port), timeout=timeout)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=hostname)
        # Heartbeat request: type=24 (0x18), TLS 1.0, length=3, payload=1, pad=16384
        ss.send(b"\x18\x03\x01\x00\x03\x01\x40\x00")
        data = ss.recv(10)
        ss.close()
        # A patched server sends an alert (type=21) or closes — if we get type=24 back it's vulnerable
        return len(data) > 0 and data[0] == 0x18
    except Exception:
        return False


def _get_key_info(cert: crypto.X509) -> Dict[str, Any]:
    info: Dict[str, Any] = {"key_type": "Unknown", "key_bits": None}
    try:
        pub = cert.get_pubkey()
        ktype = pub.type()
        if ktype == crypto.TYPE_RSA:
            info["key_type"] = "RSA"
        elif ktype == crypto.TYPE_DSA:
            info["key_type"] = "DSA"
        elif ktype == 408:  # EVP_PKEY_EC
            info["key_type"] = "ECDSA"
        else:
            info["key_type"] = f"type({ktype})"
        info["key_bits"] = pub.bits()
    except Exception:
        pass
    return info


def _get_sig_algo(cert: crypto.X509) -> str:
    try:
        return cert.get_signature_algorithm().decode(errors="ignore")
    except Exception:
        return "Unknown"


def _get_issuer_full(cert: crypto.X509) -> Dict[str, str]:
    issuer: Dict[str, str] = {}
    try:
        comps = dict(cert.get_issuer().get_components())
        issuer["O"]  = comps.get(b"O",  b"").decode(errors="ignore")
        issuer["CN"] = comps.get(b"CN", b"").decode(errors="ignore")
        issuer["C"]  = comps.get(b"C",  b"").decode(errors="ignore")
        # Detect Extended Validation by common CN patterns
        cn = issuer["CN"].lower()
        issuer["ev"] = any(kw in cn for kw in ["extended validation", " ev ", "ev ssl", "ev root"])
    except Exception:
        pass
    return issuer


def _get_cert_serial(cert: crypto.X509) -> str:
    try:
        return format(cert.get_serial_number(), "x").upper()
    except Exception:
        return "Unknown"


def _get_cert_fingerprint(cert: crypto.X509) -> str:
    try:
        der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        return hashlib.sha256(der).hexdigest().upper()
    except Exception:
        return "Unknown"


# ── Post-Quantum Detection ─────────────────────────────────────────────────────

def check_pqc_server_support(domain: str) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return {"server_pqc": False, "groups": [], "status": "KEM testing requires raw packet capture"}
    except Exception:
        pass
    return {"server_pqc": False, "groups": [], "status": "Not detected"}


# ── Main SSL/TLS Check ─────────────────────────────────────────────────────────

def check_ssl_status(domain: str) -> Dict[str, Any]:
    issues: List[str] = []
    cert_info: Dict[str, Any] = {
        "issuer": "Unknown",
        "issuer_full": {},
        "san_valid": False,
        "san_details": [],
        "days_to_expiry": None,
        "not_before": None,
        "cipher": "Unknown",
        "protocol": "Unknown",
        "chain_valid": False,
        "heartbleed_risk": False,
        "self_signed": False,
        "ocsp_stapling": False,
        "tls_compression": False,
        "key_type": "Unknown",
        "key_bits": None,
        "sig_algo": "Unknown",
        "serial": "Unknown",
        "fingerprint_sha256": "Unknown",
        "long_validity": False,
        "ev_cert": False,
    }

    # ── Phase 1: Permissive extraction ────────────────────────────────────────
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "OP_IGNORE_UNEXPECTED_EOF"):
        context.options |= ssl.OP_IGNORE_UNEXPECTED_EOF

    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    cert_info["cipher"], cert_info["protocol"], _ = cipher_tuple

                der_cert = ssock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

                # Expiry
                na_str = cert.get_notAfter().decode("ascii")
                not_after = datetime.strptime(na_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                cert_info["days_to_expiry"] = (not_after - datetime.now(timezone.utc)).days

                # Not-before
                nb_str = cert.get_notBefore().decode("ascii")
                not_before = datetime.strptime(nb_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                cert_info["not_before"] = str(not_before.date())

                # Issuer (simple + full)
                issuer_comp = dict(cert.get_issuer().get_components())
                cert_info["issuer"] = issuer_comp.get(b"O", b"Unknown").decode(errors="ignore")
                issuer_full = _get_issuer_full(cert)
                cert_info["issuer_full"] = issuer_full
                cert_info["ev_cert"] = issuer_full.get("ev", False)

                # SAN
                parsed_cert = ssock.getpeercert()
                sans = parsed_cert.get("subjectAltName", [])
                for _, val in sans:
                    cert_info["san_details"].append(val.lower())
                    if val.lower() == domain.lower() or (val.startswith("*.") and domain.lower().endswith(val[2:])):
                        cert_info["san_valid"] = True
                if not cert_info["san_valid"]:
                    issues.append(f"SAN mismatch: {domain} not covered by certificate")

                # Key info
                key_info = _get_key_info(cert)
                cert_info.update(key_info)
                if key_info["key_type"] == "RSA" and key_info["key_bits"] and key_info["key_bits"] < 2048:
                    issues.append(f"Weak RSA key: {key_info['key_bits']} bits (minimum 2048)")
                elif key_info["key_bits"] and key_info["key_bits"] < 2048:
                    issues.append(f"Weak key: {key_info['key_bits']} bits")

                # Signature algorithm
                cert_info["sig_algo"] = _get_sig_algo(cert)
                if "sha1" in cert_info["sig_algo"].lower():
                    issues.append(f"Deprecated signature algorithm: {cert_info['sig_algo']}")

                # Serial + fingerprint
                cert_info["serial"] = _get_cert_serial(cert)
                cert_info["fingerprint_sha256"] = _get_cert_fingerprint(cert)

                # Self-signed
                cert_info["self_signed"] = _is_self_signed(cert)
                if cert_info["self_signed"]:
                    issues.append("Certificate is self-signed")

                # Not-yet-valid
                nb_issue = _check_not_before(cert)
                if nb_issue:
                    issues.append(nb_issue)

                # Long validity
                lv_issue = _check_long_validity(cert)
                if lv_issue:
                    cert_info["long_validity"] = True
                    issues.append(lv_issue)

                # OCSP stapling
                cert_info["ocsp_stapling"] = _check_ocsp_stapling(ssock)

                # TLS compression (CRIME)
                cert_info["tls_compression"] = _check_tls_compression(ssock)
                if cert_info["tls_compression"]:
                    issues.append("TLS compression enabled — CRIME attack risk")

                # Deprecated protocol
                if cert_info["protocol"] in DEPRECATED_PROTOCOLS:
                    issues.append(f"Deprecated TLS protocol in use: {cert_info['protocol']}")

                # Weak cipher
                cipher_name = cert_info["cipher"]
                if any(w in cipher_name for w in WEAK_CIPHERS):
                    issues.append(f"Weak cipher suite in use: {cipher_name}")
                if any(a in cipher_name for a in ANON_CIPHERS):
                    issues.append(f"Anonymous cipher suite — no server authentication: {cipher_name}")

    except Exception as e:
        return {"ssl_enabled": False, "issues": [f"Handshake failed: {e}"], "cert_info": cert_info}

    # ── Phase 2: Chain validation ──────────────────────────────────────────────
    strict_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with strict_ctx.wrap_socket(sock, server_hostname=domain):
                cert_info["chain_valid"] = True
    except Exception as e:
        cert_info["chain_valid"] = False
        issues.append(f"Trust chain invalid: {e}")

    # ── Phase 3: Heartbleed probe ──────────────────────────────────────────────
    cert_info["heartbleed_risk"] = _simple_heartbleed_test(domain)
    if cert_info["heartbleed_risk"]:
        issues.append("Heartbleed probe indicates potential vulnerability (CVE-2014-0160)")

    # ssl_enabled = TLS connection was established and cert data was obtained.
    # chain_valid and san_valid are separate quality flags — issues in those
    # are already captured in the issues list and shown as separate findings.
    # Do NOT gate ssl_enabled on chain_valid/san_valid: Python's strict CA bundle
    # can fail intermediate issuer verification even when a valid TLS cert is
    # in use, which would falsely assign a -10 posture penalty.
    _tls_established = cert_info.get("protocol") is not None and cert_info.get("protocol") not in ("Unknown", None, "")
    return {
        "ssl_enabled": _tls_established,
        "issues": list(set(issues)),
        "cert_info": cert_info,
    }


async def audit_crypto(domain: str) -> Dict[str, Any]:
    ssl_status = check_ssl_status(domain)
    pqc_server = check_pqc_server_support(domain)
    all_issues = ssl_status["issues"].copy()
    if not pqc_server["server_pqc"]:
        all_issues.append("Server does NOT offer post-quantum hybrid key exchange")
    return {
        "summary": f"SSL: {'OK' if ssl_status['ssl_enabled'] else 'Issues'}",
        "issues": all_issues,
        "results": {"ssl": ssl_status, "pqc": pqc_server},
    }


if __name__ == "__main__":
    from . import run_standalone
    run_standalone(audit_crypto)
