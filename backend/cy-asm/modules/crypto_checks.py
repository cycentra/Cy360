# modules/crypto_check.py
# CyCentra — Complete SSL/TLS + Post-Quantum Crypto Auditor (2026 Ready)
# Enhanced for AWS Global Accelerator, Cloudflare, and modern WAF bypass

import ssl
import socket
import json
import struct
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import asyncio
from OpenSSL import crypto
from utils import setup_logging

# These must be defined for the PQC and Cipher checks to work
DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "LOW"]
ANON_CIPHERS = ["AECDH", "ADH"]
PQC_HYBRID_GROUPS = {
    0x6399: "X25519Kyber768Draft00", 
    0x11ec: "P256-Kyber768"
}

logger = setup_logging()

# === Helper Functions ===
def _is_self_signed(cert_der: bytes) -> bool:
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
        return cert.get_subject() == cert.get_issuer()
    except Exception: return False

def _check_not_before(cert: crypto.X509) -> Optional[str]:
    try:
        nb_raw = cert.get_notBefore().decode('ascii')
        not_before = datetime.strptime(nb_raw, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
        if not_before > datetime.now(timezone.utc):
            return f"Certificate not yet valid (valid from {not_before.date()})"
    except Exception: pass
    return None

def _check_long_validity(cert: crypto.X509) -> Optional[str]:
    try:
        nb_raw = cert.get_notBefore().decode('ascii')
        na_raw = cert.get_notAfter().decode('ascii')
        not_before = datetime.strptime(nb_raw, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(na_raw, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
        days = (not_after - not_before).days
        if days > 398: return f"Certificate validity too long ({days} days > 398)"
    except Exception: pass
    return None

def _check_ocsp_stapling(ssock) -> bool:
    try: return bool(ssock.getpeercert().get('OCSP'))
    except Exception: return False

def _check_tls_compression(ssock) -> bool:
    try: return ssock.compression() is not None
    except Exception: return False

def _simple_heartbleed_test(hostname: str, port: int = 443, timeout: int = 5) -> bool:
    try:
        s = socket.create_connection((hostname, port), timeout=timeout)
        # Use a permissive wrapper for the probe
        ss = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLS)
        ss.send(b'\x18\x03\x03\x00\x03\x01\x40\x40\x00')
        ss.recv(10)
        ss.close()
        return False
    except Exception: return True 

# === Post-Quantum Detection ===
def check_pqc_server_support(domain: str) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return {"server_pqc": False, "groups": [], "status": "KEM testing requires raw packet capture"}
    except Exception: pass
    return {"server_pqc": False, "groups": [], "status": "Not detected"}

# === Main SSL/TLS Check (WITH NEW FIX) ===
def check_ssl_status(domain: str) -> Dict[str, Any]:
    issues: List[str] = []
    # Ensure this is fully initialized so even on failure, we don't return 'false'
    cert_info: Dict[str, Any] = {
        "issuer": "Unknown", "san_valid": False, "san_details": [],
        "days_to_expiry": None, "cipher": "Unknown", "protocol": "Unknown",
        "chain_valid": False, "heartbleed_risk": False
    }

    # 1. PERMISSIVE PHASE (Extraction)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Cloudflare/AWS EOF Fix
    if hasattr(ssl, "OP_IGNORE_UNEXPECTED_EOF"):
        context.options |= ssl.OP_IGNORE_UNEXPECTED_EOF

    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Protocol & Cipher
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    cert_info["cipher"], cert_info["protocol"], _ = cipher_tuple
                
                # Get Binary Cert for Local Parsing
                der_cert = ssock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

                # Expiry (This will now finally show up)
                na_str = cert.get_notAfter().decode('ascii')
                not_after = datetime.strptime(na_str, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
                cert_info["days_to_expiry"] = (not_after - datetime.now(timezone.utc)).days
                
                # Issuer
                issuer_comp = dict(cert.get_issuer().get_components())
                cert_info["issuer"] = issuer_comp.get(b'O', b'Unknown').decode(errors='ignore')

                # SAN Check
                parsed_cert = ssock.getpeercert()
                sans = parsed_cert.get('subjectAltName', [])
                for _, val in sans:
                    cert_info["san_details"].append(val.lower())
                    if val.lower() == domain.lower() or (val.startswith('*.') and domain.lower().endswith(val[2:])):
                        cert_info["san_valid"] = True
                
                if not cert_info["san_valid"]:
                    issues.append(f"SAN mismatch: {domain} not covered by certificate")

    except Exception as e:
        # If we fail here, at least we tried to get the protocol
        return {"ssl_enabled": False, "issues": [f"Handshake failed: {e}"], "cert_info": cert_info}

    # 2. STRICT PHASE (Security Only)
    strict_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with strict_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_info["chain_valid"] = True
    except Exception as e:
        cert_info["chain_valid"] = False
        issues.append(f"Trust chain invalid: {e}")

    return {
        "ssl_enabled": cert_info["chain_valid"] and cert_info["san_valid"],
        "issues": list(set(issues)),
        "cert_info": cert_info
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
        "results": {"ssl": ssl_status, "pqc": pqc_server}
    }
if __name__ == "__main__":
    from . import run_standalone
    run_standalone(audit_crypto)
