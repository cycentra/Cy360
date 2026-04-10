#!/usr/bin/env python3
"""
CyCentra 360 — License Generator (VENDOR TOOL — NEVER DISTRIBUTE)
=================================================================
Generates signed license files for CyCentra 360 installations.

Usage:
    python3 cy-license-gen.py --customer "Acme Corp" \
        --email admin@acme.com \
        --type full \
        --days 365 \
        --features cysiem,cyiris,cysoar,cymind

    python3 cy-license-gen.py --demo --customer "Trial User" --email trial@example.com

Output: cycentra_<customer_slug>_<date>.lic
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

PRIVATE_KEY = Path(__file__).parent / "cycentra_license_private.pem"
ALL_FEATURES = ["cysiem", "cyiris", "cysoar", "cymind", "cymisp"]
DEMO_FEATURES = ["cysiem"]        # demo only unlocks SIEM
DEMO_DAYS    = 15

# ── Helpers ───────────────────────────────────────────────────────────────────

def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def sign_payload(payload_str: str) -> str:
    """Sign payload using RSA-SHA256 with the vendor private key. Returns base64."""
    if not PRIVATE_KEY.exists():
        sys.exit(f"[ERROR] Private key not found at {PRIVATE_KEY}\n"
                 "Run from the cycentra360/tools/ directory.")
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(PRIVATE_KEY)],
        input=payload_str.encode(),
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.exit(f"[ERROR] Signing failed: {proc.stderr.decode()}")
    return base64.b64encode(proc.stdout).decode()


def build_license(customer: str, email: str, lic_type: str,
                  days: int, features: list) -> dict:
    issued  = date.today().isoformat()
    expires = (date.today() + timedelta(days=days)).isoformat()
    return {
        "version":  "1",
        "customer": customer,
        "email":    email,
        "issued":   issued,
        "expires":  expires,
        "type":     lic_type,       # "full" | "demo"
        "features": features,
    }


def write_license_file(lic: dict, out_path: Path) -> None:
    # Canonical payload = sorted JSON (no whitespace) — what we sign
    payload = json.dumps(lic, sort_keys=True, separators=(",", ":"))
    signature = sign_payload(payload)

    content = (
        "-----BEGIN CYCENTRA LICENSE-----\n"
        f"{base64.b64encode(payload.encode()).decode()}\n"
        "-----END CYCENTRA LICENSE-----\n"
        "-----BEGIN CYCENTRA SIGNATURE-----\n"
        f"{signature}\n"
        "-----END CYCENTRA SIGNATURE-----\n"
    )
    out_path.write_text(content)
    print(f"[OK] License written → {out_path}")
    print(f"     Customer : {lic['customer']}")
    print(f"     Email    : {lic['email']}")
    print(f"     Type     : {lic['type']}")
    print(f"     Issued   : {lic['issued']}")
    print(f"     Expires  : {lic['expires']}")
    print(f"     Features : {', '.join(lic['features'])}")

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="CyCentra 360 License Generator")
    p.add_argument("--customer", required=True,  help="Customer / company name")
    p.add_argument("--email",    required=True,  help="Contact email address")
    p.add_argument("--type",     default="full", choices=["full", "demo"],
                   help="License type (default: full)")
    p.add_argument("--days",     type=int, default=365,
                   help="Validity in days from today (default: 365)")
    p.add_argument("--features", default=",".join(ALL_FEATURES),
                   help=f"Comma-separated feature list (default: all). "
                        f"Available: {', '.join(ALL_FEATURES)}")
    p.add_argument("--demo",     action="store_true",
                   help=f"Shortcut: generate {DEMO_DAYS}-day demo license (overrides --days/--features/--type)")
    p.add_argument("--out",      default=None,
                   help="Output file path (default: auto-named .lic file)")
    args = p.parse_args()

    if args.demo:
        lic_type = "demo"
        days     = DEMO_DAYS
        features = DEMO_FEATURES
    else:
        lic_type = args.type
        days     = args.days
        features = [f.strip() for f in args.features.split(",") if f.strip()]
        unknown  = set(features) - set(ALL_FEATURES)
        if unknown:
            sys.exit(f"[ERROR] Unknown features: {unknown}. Valid: {ALL_FEATURES}")

    lic = build_license(args.customer, args.email, lic_type, days, features)

    if args.out:
        out_path = Path(args.out)
    else:
        date_str = date.today().strftime("%Y%m%d")
        out_path = Path(f"cycentra_{slug(args.customer)}_{date_str}.lic")

    write_license_file(lic, out_path)


if __name__ == "__main__":
    main()
