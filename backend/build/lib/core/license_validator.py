#!/usr/bin/env python3
"""
CyCentra 360 — License Validator
=================================
Validates a .lic file and prints a machine-readable result.
Called by setup.sh and the license watchdog.

Exit codes:
  0  — valid full license
  1  — valid demo license
  2  — license expired
  3  — invalid / tampered license
  4  — no license file found (auto-demo mode)

Stdout (JSON):
  {"valid": true/false, "type": "full"|"demo"|"none",
   "days_remaining": N, "customer": "...", "features": [...],
   "message": "..."}
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path

# ── Embedded public key (vendor public key — safe to distribute) ──────────────
CYCENTRA_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqrIIRpBVaAxSaOr7IxfA
mQOvYL4MRQm6sCiCt7hn0QjsNLIOM6vrvs59bLbXVwdJWqNA05TBVrQIM5ttx8mE
MmajaYt3MYJ436x85209kJUaql98FNqRxdYowrcTBW28OZKQb1eLaSlpa7NtX19p
vvPP4nLYCab5wTIAcQ02qMaEGfmAXvkB6c2GoMTbK1ToeOj2vOuqEJU7jVzvfXt7
r+hE2MJGDY4z3CZY4i4fpx5X1w6JnGcaVy5Z97syeIM9WbRgsq3Z8WdEWgLBiKrQ
OK1Jv0PDOgn/1/cP2TpktXXk+6nxqaE0K3zxPVPqNlKg1iNlrumMo0JL8UU+7gzQ
WQIDAQAB
-----END PUBLIC KEY-----
"""

DEMO_MAX_DAYS  = 15
DEMO_STATE     = Path("/opt/cycentra/.demo_start")
LICENSE_PATH   = Path("/opt/cycentra/cycentra.lic")

# v3 subscription types; v2 aliases: full→enterprise, trial→starter
_V3_TYPES      = {"starter", "professional", "enterprise", "demo"}
_V2_ALIAS      = {"full": "enterprise", "trial": "starter"}

# ── Core validation ───────────────────────────────────────────────────────────

def _verify_signature(payload_str: str, sig_b64: str) -> bool:
    """Verify RSA-SHA256 signature using the embedded public key."""
    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception:
        return False

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(CYCENTRA_PUBLIC_KEY)
        kf_path = kf.name

    with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as sf:
        sf.write(sig_bytes)
        sf_path = sf.name

    try:
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", kf_path,
             "-signature", sf_path],
            input=payload_str.encode(),
            capture_output=True,
        )
        return proc.returncode == 0
    except FileNotFoundError:
        return False
    finally:
        os.unlink(kf_path)
        os.unlink(sf_path)


def _parse_lic_file(path: Path) -> tuple[dict | None, str | None]:
    """Parse a .lic file → (payload_dict, signature_b64) or (None, None)."""
    try:
        text = path.read_text()
    except Exception:
        return None, None

    try:
        payload_b64 = text.split("-----BEGIN CYCENTRA LICENSE-----")[1] \
                          .split("-----END CYCENTRA LICENSE-----")[0].strip()
        sig_b64     = text.split("-----BEGIN CYCENTRA SIGNATURE-----")[1] \
                          .split("-----END CYCENTRA SIGNATURE-----")[0].strip()
        payload_str = base64.b64decode(payload_b64).decode()
        payload     = json.loads(payload_str)
        return payload, sig_b64, payload_str
    except Exception:
        return None, None, None


def _days_remaining(expires_str: str) -> int:
    expires = date.fromisoformat(expires_str)
    return (expires - date.today()).days


def _demo_days_remaining() -> int:
    if not DEMO_STATE.exists():
        # First run — stamp it
        DEMO_STATE.parent.mkdir(parents=True, exist_ok=True)
        DEMO_STATE.write_text(date.today().isoformat())
        # Make immutable so the clock cannot be reset without root + chattr -i
        try:
            import subprocess as _sp
            _sp.run(["chattr", "+i", str(DEMO_STATE)], capture_output=True, timeout=5)
        except Exception:
            pass
        return DEMO_MAX_DAYS
    start = date.fromisoformat(DEMO_STATE.read_text().strip())
    elapsed = (date.today() - start).days
    return max(0, DEMO_MAX_DAYS - elapsed)


# ── Main ──────────────────────────────────────────────────────────────────────

def validate(lic_path: Path = LICENSE_PATH) -> dict:
    if not lic_path.exists():
        # No license file → auto-demo mode
        days = _demo_days_remaining()
        if days <= 0:
            return {"valid": False, "type": "demo", "days_remaining": 0,
                    "features": [], "customer": "Demo",
                    "message": "Demo period expired. Purchase a license at cycentra.com"}
        return {"valid": True, "type": "demo", "days_remaining": days,
                "features": ["cysiem"],
                "customer": "Demo",
                "message": f"Demo mode — {days} day(s) remaining"}

    result = _parse_lic_file(lic_path)
    if len(result) == 2:
        return {"valid": False, "type": "none", "days_remaining": 0,
                "features": [], "customer": "unknown",
                "message": "License file is corrupt or unreadable"}
    payload, sig_b64, payload_str = result

    if payload is None:
        return {"valid": False, "type": "none", "days_remaining": 0,
                "features": [], "customer": "unknown",
                "message": "License file could not be parsed"}

    if not _verify_signature(payload_str, sig_b64):
        return {"valid": False, "type": "none", "days_remaining": 0,
                "features": [], "customer": payload.get("customer", "unknown"),
                "message": "License signature is invalid — file may have been tampered"}

    expiry_str = payload.get("subscription_end") or payload.get("expires", "")
    if not expiry_str:
        return {"valid": False, "type": payload.get("type", "none"), "days_remaining": 0,
                "features": [], "customer": payload.get("customer", "unknown"),
                "message": "License file missing expiry date"}
    days = _days_remaining(expiry_str)

    # For demo-type signed licenses: the expiry date is calculated from the
    # GENERATION date, not the installation date.  A demo .lic file generated
    # weeks before the customer installs it would expire almost immediately.
    # Fix: for type="demo" lics, the effective days remaining is the MAX of
    # (lic expiry days, installation-clock days from .demo_start).  This
    # guarantees the customer always gets DEMO_MAX_DAYS from the day they
    # installed, regardless of when the .lic file was generated.
    if payload["type"] == "demo":
        install_days = _demo_days_remaining()
        if install_days > days:
            days = install_days

    # ── v3 / v2 normalisation ────────────────────────────────────────────────
    # v3 uses subscription_end; v2 uses expires. Support both.
    expiry_date   = payload.get("subscription_end") or payload.get("expires", "")
    # v3 uses max_users; v2 uses users. Support both.
    max_users     = payload.get("max_users", payload.get("users", 0))
    billing_cycle = payload.get("billing_cycle", "annual")
    # Normalise type aliases (full → enterprise, trial → starter)
    lic_type      = _V2_ALIAS.get(payload["type"], payload["type"])

    if days < 0:
        return {"valid": False, "type": lic_type, "days_remaining": 0,
                "features": payload.get("features", []),
                "customer": payload["customer"],
                "billing_cycle": billing_cycle, "max_users": max_users,
                "subscription_end": expiry_date,
                "message": f"License expired on {expiry_date}"}

    return {"valid": True, "type": lic_type, "days_remaining": days,
            "features": payload.get("features", []),
            "customer": payload["customer"],
            "billing_cycle": billing_cycle, "max_users": max_users,
            "subscription_end": expiry_date,
            "message": f"License valid — {days} day(s) remaining (expires {expiry_date})"}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--license", default=str(LICENSE_PATH),
                    help="Path to .lic file")
    ap.add_argument("--quiet", action="store_true",
                    help="Only exit code, no output")
    args = ap.parse_args()

    result = validate(Path(args.license))

    if not args.quiet:
        print(json.dumps(result, indent=2))

    # Map to exit code
    if not result["valid"]:
        if "expired" in result["message"]:
            sys.exit(2)
        elif result["type"] == "none":
            sys.exit(3)
        elif result["type"] == "demo":
            sys.exit(2)   # demo expired
        sys.exit(4)
    elif result["type"] == "demo":
        sys.exit(1)
    else:
        sys.exit(0)
