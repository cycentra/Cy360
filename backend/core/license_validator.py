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
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3PWTGpjM9/RTMTA4FMmj
coYBxAEtckGxiv/Vf9vtZHbZBsoqaZk+Fx30DeiHCD2x0P//xkLxb/+yhY4vGsx5
cYEJpUHCxlskxFaBlBOQmZGIqgq6BHicfEnAiRCmmX6GznmCNPzqIIgXXtTOVILz
ez/oTDQkfNp5z3qrHK9XAqleqHehyJR3genS9XAPB8sNey6RfjYPa4FZixm4O7DI
i0nQeWeGjhPeZLaWo+BIGeMzCZQZpLOg4HBvsdNQZ9Jp4ktHnPKAFqyLzI+4BctE
o6cG5hWtmCcvUXWwzB+5YTPmMDp28kRNNOyMLo9DPsS6LHcW5R96uEXsyE8G1lZo
oQIDAQAB
-----END PUBLIC KEY-----
"""

DEMO_MAX_DAYS  = 15
DEMO_STATE     = Path("/opt/cycentra/.demo_start")
LICENSE_PATH   = Path("/opt/cycentra/cycentra.lic")

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

    days = _days_remaining(payload["expires"])
    if days < 0:
        return {"valid": False, "type": payload["type"], "days_remaining": 0,
                "features": payload.get("features", []),
                "customer": payload["customer"],
                "message": f"License expired on {payload['expires']}"}

    return {"valid": True, "type": payload["type"], "days_remaining": days,
            "features": payload.get("features", []),
            "customer": payload["customer"],
            "message": f"License valid — {days} day(s) remaining (expires {payload['expires']})"}


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
