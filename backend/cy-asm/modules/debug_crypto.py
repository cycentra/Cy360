import asyncio
import json
from modules.crypto_checks import audit_crypto

def test_module(domain: str) -> Dict[str, Any]:
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

    try:
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Cipher & Protocol
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    cipher_name, proto, _ = cipher_tuple
                    cert_info["cipher"] = cipher_name
                    cert_info["protocol"] = proto

                    if proto in DEPRECATED_PROTOCOLS:
                        issues.append(f"Deprecated protocol: {proto}")
                    if any(w in cipher_name.upper() for w in WEAK_CIPHERS):
                        issues.append(f"Weak cipher: {cipher_name}")
                    if any(a in cipher_name.upper() for a in ANON_CIPHERS):
                        issues.append(f"Anonymous cipher (MITM risk): {cipher_name}")

                # Compression (CRIME)
                if _check_tls_compression(ssock):
                    cert_info["compression_enabled"] = True
                    issues.append("TLS compression enabled → CRIME attack possible")

                # Heartbleed probe
                if _simple_heartbleed_test(domain):
                    cert_info["heartbleed_risk"] = True
                    issues.append("Potential Heartbleed vulnerability (CVE-2014-0160)")

                # Certificate parsing
                der_cert = ssock.getpeercert(binary_form=True)
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)

                # Self-signed
                if _is_self_signed(der_cert):
                    cert_info["self_signed"] = True
                    issues.append("Self-signed certificate")

                # Not Before
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
                na_str = cert.get_notAfter().decode('ascii')
                not_after = datetime.strptime(na_str, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                cert_info["days_to_expiry"] = days_left
                if days_left < 0:
                    issues.append(f"Certificate expired on {not_after.date()}")
                elif days_left < 30:
                    issues.append(f"Certificate expiring soon ({days_left} days left)")

                # SAN validation
                sans = ssock.getpeercert().get('subjectAltName', [])
                domain_l = domain.lower()
                for typ, val in sans:
                    if typ == 'DNS':
                        v = val.lower()
                        cert_info["san_details"].append(v)
                        if v == domain_l or (v.startswith('*.') and (domain_l == v[2:] or domain_l.endswith('.' + v[2:]))):
                            cert_info["san_valid"] = True
                        elif not v.endswith('.' + domain_l):
                            cert_info["extraneous_sans"].append(v)
                            issues.append(f"Extraneous SAN entry: {v}")

                if not sans:
                    issues.append("No Subject Alternative Names (SANs)")
                elif not cert_info["san_valid"]:
                    issues.append(f"SAN mismatch: '{domain}' not covered by certificate")

                # OCSP Stapling
                cert_info["ocsp_stapling"] = _check_ocsp_stapling(ssock)
                if not cert_info["ocsp_stapling"]:
                    issues.append("OCSP stapling not supported")

                # Chain validation
                try:
                    store = crypto.X509Store()
                    for ca_der in context.get_ca_certs(binary_form=True):
                        store.add_cert(crypto.load_certificate(crypto.FILETYPE_ASN1, ca_der))
                    store_ctx = crypto.X509StoreContext(store, cert)
                    store_ctx.verify_certificate()
                    cert_info["chain_valid"] = True
                    cert_info["chain_details"] = "Chain validated successfully"
                except Exception as e:
                    cert_info["chain_valid"] = False
                    cert_info["chain_details"] = str(e)
                    issues.append(f"Chain validation failed: {e}")

                # Issuer
                issuer = dict(cert.get_issuer().get_components())
                cert_info["issuer"] = issuer.get(b'O', b'Unknown').decode(errors='ignore')

    except socket.gaierror:
        issues.append("Domain resolution failed or no HTTPS service")
    except ssl.SSLError as e:
        issues.append(f"SSL handshake failed: {e}")
    except Exception as e:
        issues.append(f"TLS connection failed: {e}")

    return {
        "ssl_enabled": len(issues) == 0 and "TLS" in cert_info["protocol"],
        "issues": issues,
        "cert_info": cert_info
    }





if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "secupulse.com"
    asyncio.run(test_module(target))
