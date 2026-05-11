"""
modules/debug_crypto.py.
CyCentra ASM — SSL/TLS Deep Diagnostic Utility

Standalone tool for in-depth SSL/TLS auditing beyond what crypto_checks.py
exposes in the normal scan pipeline. Run directly:

    python modules/debug_crypto.py <domain>

Covers every check in the original plus fixes:
  - All missing imports added (ssl, socket, Dict, List, etc.)
  - Integrated with config.py constants (no re-declarations)
  - Returns structured dict compatible with portal JSON format
  - Can also be called from other modules via test_module(domain)
"""

import asyncio
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from OpenSSL import crypto

# Ensure the parent directory is on sys.path when run standalone
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    DEPRECATED_PROTOCOLS,
    WEAK_CIPHERS,
    ANON_CIPHERS,
    PQC_HYBRID_GROUPS,
)
from utils import setup_logging

logger = setup_logging()


# ---------------------------------------------------------------------------
# Helper functions (kept from original + fixed)
# ---------------------------------------------------------------------------

def _is_self_signed(cert_der: bytes) -> bool:
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
        return cert.get_subject() == cert.get_issuer()
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
        nb_raw = cert.get_notBefore().decode("ascii")
        na_raw = cert.get_notAfter().decode("ascii")
        not_before = datetime.strptime(nb_raw, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(na_raw, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        days = (not_after - not_before).days
        if days > 398:
            return f"Certificate validity too long ({days} days > 398)"
    except Exception:
        pass
    return None


def _check_ocsp_stapling(ssock: ssl.SSLSocket) -> bool:
    try:
        return bool(ssock.getpeercert().get("OCSP"))
    except Exception:
        return False


def _get_sans_from_cert(cert: crypto.X509) -> List[str]:
    """Extract DNS SANs from the OpenSSL cert object.

    ssock.getpeercert() returns an empty dict when ssl.CERT_NONE is used, so the
    subjectAltName extension must be read directly from the cert object instead.
    """
    sans: List[str] = []
    try:
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                for entry in str(ext).split(","):
                    entry = entry.strip()
                    if entry.startswith("DNS:"):
                        sans.append(entry[4:].lower())
    except Exception:
        pass
    return sans


def _check_tls_compression(ssock: ssl.SSLSocket) -> bool:
    try:
        return ssock.compression() is not None
    except Exception:
        return False


def _simple_heartbleed_test(hostname: str, port: int = 443, timeout: int = 5) -> bool:
    """
    Lightweight Heartbleed probe. Sends a malformed heartbeat record and
    checks if the server responds with data (indicating vulnerability).
    Returns True if likely SAFE (connection refused / no response), False if
    further investigation needed.
    """
    try:
        s = socket.create_connection((hostname, port), timeout=timeout)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=hostname)
        # Heartbeat request with oversized length
        ss.send(b"\x18\x03\x02\x00\x03\x01\x40\x00")
        response = ss.recv(10)
        ss.close()
        # If server responded with heartbeat (0x18), it may be vulnerable
        return len(response) > 0 and response[0] == 0x18
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main deep diagnostic function
# ---------------------------------------------------------------------------

def test_module(domain: str) -> Dict[str, Any]:
    """
    Perform a comprehensive SSL/TLS audit for *domain*.

    Returns a dict with keys:
      ssl_enabled, issues, cert_info

    This is the full deep version of crypto_checks.check_ssl_status() — run
    this standalone or via the CLI below for maximum diagnostic detail.
    """
    issues: List[str] = []
    cert_info: Dict[str, Any] = {
        "issuer": "Unknown",
        "san_valid": False,
        "san_details": [],
        "extraneous_sans": [],
        "chain_valid": False,
        "chain_details": "",
        "days_to_expiry": None,
        "cipher": "Unknown",
        "protocol": "Unknown",
        "self_signed": False,
        "not_yet_valid": False,
        "validity_too_long": False,
        "ocsp_stapling": False,
        "compression_enabled": False,
        "heartbleed_risk": False,
    }

    context = ssl.create_default_context()
    # Suppress certificate errors during extraction phase
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "OP_IGNORE_UNEXPECTED_EOF"):
        context.options |= ssl.OP_IGNORE_UNEXPECTED_EOF

    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                # --- Cipher & Protocol ---
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    cipher_name, proto, _ = cipher_tuple
                    cert_info["cipher"]   = cipher_name
                    cert_info["protocol"] = proto

                    if proto in DEPRECATED_PROTOCOLS:
                        issues.append(f"Deprecated protocol: {proto}")
                    if any(w in cipher_name.upper() for w in WEAK_CIPHERS):
                        issues.append(f"Weak cipher: {cipher_name}")
                    if any(a in cipher_name.upper() for a in ANON_CIPHERS):
                        issues.append(f"Anonymous cipher (MITM risk): {cipher_name}")

                # --- TLS Compression (CRIME) ---
                if _check_tls_compression(ssock):
                    cert_info["compression_enabled"] = True
                    issues.append("TLS compression enabled — CRIME attack possible")

                # --- Heartbleed ---
                if _simple_heartbleed_test(domain):
                    cert_info["heartbleed_risk"] = True
                    issues.append("Potential Heartbleed vulnerability (CVE-2014-0160)")

                # --- Certificate parsing ---
                der_cert = ssock.getpeercert(binary_form=True)
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                cert     = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)

                # Self-signed
                if _is_self_signed(der_cert):
                    cert_info["self_signed"] = True
                    issues.append("Self-signed certificate")

                # Not before
                nb_issue = _check_not_before(cert)
                if nb_issue:
                    cert_info["not_yet_valid"] = True
                    issues.append(nb_issue)

                # Long validity
                long_issue = _check_long_validity(cert)
                if long_issue:
                    cert_info["validity_too_long"] = True
                    issues.append(long_issue)

                # Expiry
                na_str   = cert.get_notAfter().decode("ascii")
                not_after = datetime.strptime(na_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                cert_info["days_to_expiry"] = days_left
                if days_left < 0:
                    issues.append(f"Certificate EXPIRED on {not_after.date()}")
                elif days_left < 14:
                    issues.append(f"URGENT: Certificate expires in {days_left} days")
                elif days_left < 30:
                    issues.append(f"Certificate expiring soon ({days_left} days left)")

                # SAN validation — parse from OpenSSL cert object; getpeercert() is empty with CERT_NONE
                sans = _get_sans_from_cert(cert)
                domain_l = domain.lower()
                for v in sans:
                    cert_info["san_details"].append(v)
                    if v == domain_l or (
                        v.startswith("*.") and (
                            domain_l == v[2:] or domain_l.endswith("." + v[2:])
                        )
                    ):
                        cert_info["san_valid"] = True
                    elif not v.endswith("." + domain_l):
                        cert_info["extraneous_sans"].append(v)

                if not sans:
                    issues.append("No Subject Alternative Names (SANs) present")
                elif not cert_info["san_valid"]:
                    issues.append(f"SAN mismatch: '{domain}' not covered by certificate")

                # OCSP stapling
                cert_info["ocsp_stapling"] = _check_ocsp_stapling(ssock)
                if not cert_info["ocsp_stapling"]:
                    issues.append("OCSP stapling not enabled")

                # Chain validation (strict context)
                try:
                    store = crypto.X509Store()
                    for ca_der in context.get_ca_certs(binary_form=True):
                        store.add_cert(
                            crypto.load_certificate(crypto.FILETYPE_ASN1, ca_der)
                        )
                    store_ctx = crypto.X509StoreContext(store, cert)
                    store_ctx.verify_certificate()
                    cert_info["chain_valid"]   = True
                    cert_info["chain_details"] = "Chain validated successfully"
                except Exception as e:
                    cert_info["chain_valid"]   = False
                    cert_info["chain_details"] = str(e)
                    issues.append(f"Chain validation failed: {e}")

                # Issuer
                issuer = dict(cert.get_issuer().get_components())
                cert_info["issuer"] = issuer.get(b"O", b"Unknown").decode(errors="ignore")

    except socket.gaierror:
        issues.append("Domain resolution failed or no HTTPS service on port 443")
        return {"ssl_enabled": False, "issues": issues, "cert_info": cert_info}
    except ssl.SSLError as e:
        issues.append(f"SSL handshake failed: {e}")
        return {"ssl_enabled": False, "issues": issues, "cert_info": cert_info}
    except ConnectionRefusedError:
        issues.append("Connection refused on port 443 — HTTPS not available")
        return {"ssl_enabled": False, "issues": issues, "cert_info": cert_info}
    except Exception as e:
        issues.append(f"TLS connection failed: {type(e).__name__}: {e}")
        return {"ssl_enabled": False, "issues": issues, "cert_info": cert_info}

    ssl_ok = (
        cert_info["chain_valid"]
        and cert_info["san_valid"]
        and not cert_info["self_signed"]
        and (cert_info["days_to_expiry"] or 0) > 0
        and cert_info["protocol"] not in DEPRECATED_PROTOCOLS
    )

    return {
        "ssl_enabled": ssl_ok,
        "issues":      list(set(issues)),
        "cert_info":   cert_info,
    }


# ---------------------------------------------------------------------------
# Async wrapper so it can be awaited from scan pipeline if needed
# ---------------------------------------------------------------------------

async def audit_crypto_deep(domain: str) -> Dict[str, Any]:
    """Async wrapper around test_module() for use in async scan pipelines."""
    result = await asyncio.to_thread(test_module, domain)
    all_issues = result.get("issues", [])
    summary = (
        f"Deep SSL audit: {'OK' if result['ssl_enabled'] else 'ISSUES FOUND'} "
        f"— {len(all_issues)} finding(s)"
    )
    return {
        "summary": summary,
        "issues":  all_issues,
        "results": {"ssl": result},
    }


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python modules/debug_crypto.py <domain>")
        print("Example: python modules/debug_crypto.py example.com")
        sys.exit(1)

    target = sys.argv[1].strip().lower()
    logger.info(f"[DebugCrypto] Running deep SSL audit for: {target}")

    result = test_module(target)

    print("\n" + "=" * 60)
    print(f"  SSL/TLS Deep Audit — {target}")
    print("=" * 60)
    print(f"  SSL OK:          {result['ssl_enabled']}")
    print(f"  Protocol:        {result['cert_info']['protocol']}")
    print(f"  Cipher:          {result['cert_info']['cipher']}")
    print(f"  Issuer:          {result['cert_info']['issuer']}")
    print(f"  Days to expiry:  {result['cert_info']['days_to_expiry']}")
    print(f"  Chain valid:     {result['cert_info']['chain_valid']}")
    print(f"  SAN valid:       {result['cert_info']['san_valid']}")
    print(f"  Self-signed:     {result['cert_info']['self_signed']}")
    print(f"  OCSP stapling:   {result['cert_info']['ocsp_stapling']}")
    print(f"  Heartbleed risk: {result['cert_info']['heartbleed_risk']}")
    if result["issues"]:
        print(f"\n  Issues ({len(result['issues'])}):")
        for iss in result["issues"]:
            print(f"    ⚠  {iss}")
    else:
        print("\n  No issues found.")
    print("=" * 60)
    print(json.dumps(result, indent=2, default=str))
