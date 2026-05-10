# ASM Engine & Portal Enhancements

**Version:** v1.0.387+
**Date:** 2026-05-10
**Scope:** cy-asm scanner engine, portal frontend, DevOps setup script

---

## Overview

This document covers the full set of enhancements delivered to the CyCentra 360 ASM (Attack Surface Management) system. The work spans four areas: the Python scanner engine, the React portal, the JavaScript adapter bridge, and the deployment setup script.

---

## 1. ASM Scanner Engine

### 1.1 `cy_asm/config.py`

- Added **SMB port 445** to `QUICK_SCAN_PORTS` so SMB signing status is checked in all scan tiers.
- Added **`INFRA_EXPOSURE_PORTS`** constant covering infrastructure exposure ports used in Deep scans:
  - `2375, 2376` — Docker daemon (plain + TLS)
  - `6443` — Kubernetes API server
  - `9200, 9300` — Elasticsearch (HTTP + transport)
  - `11211` — Memcached
  - `5900` — VNC
  - `9090, 9091` — Prometheus / exporters
  - `8161` — ActiveMQ
- Added **`PROTO_PROBE_TIMEOUT`** constant (default `5` seconds) — per-probe timeout for all protocol-specific handshake probes, configurable via `PROTO_PROBE_TIMEOUT` environment variable.

---

### 1.2 `cy_asm/modules/crypto_checks.py` — Full Rewrite

**Problem:** Helper functions for certificate analysis were defined but never called inside `check_ssl_status()`.

**Resolution:** Complete rewrite wiring all helpers into the main function. Two-phase connection approach (permissive extraction first, strict chain validation second) to maximise data collected even when the chain is incomplete.

**New certificate fields collected:**

| Field | Description |
|---|---|
| `key_type` | RSA / EC / DSA |
| `key_bits` | Key size in bits (flags < 2048 RSA, < 256 EC) |
| `sig_algo` | Signature algorithm (flags MD5/SHA-1 as weak) |
| `serial` | Certificate serial number (hex) |
| `fingerprint_sha256` | SHA-256 fingerprint |
| `issuer_full` | Full issuer string (O, CN, C) |
| `ev_cert` | Boolean — Extended Validation certificate detected |
| `self_signed` | Boolean |
| `ocsp_stapling` | Boolean |
| `tls_compression` | Boolean — CRIME-vulnerable if true |
| `not_before` | Certificate validity start date |
| `long_validity` | Boolean — validity period > 398 days (CA/Browser Forum limit) |

**New probes added:**

- **Deprecated protocol check** — flags TLS 1.0 / TLS 1.1 / SSLv3 negotiation
- **Weak cipher check** — flags RC4, DES, 3DES, EXPORT, NULL cipher suites
- **Heartbleed probe** — raw TLS heartbeat request (type `0x18`); detects vulnerable server response

---

### 1.3 `cy_asm/modules/web_analysis.py` — Full Rewrite

**Protocol-Specific Handshaking**

Replaced generic banner grabbing with true protocol handshakes dispatched via `_PROTO_MAP`. Each probe runs in a thread-pool executor (`asyncio.get_event_loop().run_in_executor`) for concurrency.

| Port(s) | Probe | What it detects |
|---|---|---|
| 22 | `_probe_ssh()` | SSH banner + KEX INIT response; extracts server version, preferred kex/cipher/mac algorithms |
| 21 | `_probe_ftp()` | `ftplib.FTP` anonymous login attempt; flags anonymous access enabled |
| 25, 587 | `_probe_smtp()` | `smtplib.SMTP` EHLO + AUTH; flags open relay / no-auth required |
| 3389 | `_probe_rdp_nla()` | X.224 TPKT + RDP Negotiation Request; parses CC TPDU SecurityMode bitmask — **bit 1 = NLA/CredSSP required** |
| 6379 | `_probe_redis()` | RESP PING command; flags unauthenticated access |
| 27017 | `_probe_mongodb()` | OP_QUERY `isMaster`; flags no-auth access |
| 445 | `_probe_smb()` | SMB2 NEGOTIATE packet; parses SecurityMode — **bit 0 = signing enabled, bit 1 = signing required** |
| 2375, 2376 | `_probe_docker()` | HTTP GET `/version`; flags exposed Docker daemon |
| 6443 | `_probe_kubernetes()` | HTTPS GET `/version`; flags unauthenticated Kubernetes API |
| 9200 | `_probe_elasticsearch()` | HTTP GET `/`; flags unauthenticated Elasticsearch |
| 11211 | `_probe_memcached()` | Raw `stats` command; flags unauthenticated Memcached |
| 5900 | `_probe_vnc()` | RFB handshake; flags no-auth VNC |

**RDP NLA Detection Detail**

```
→ Send: TPKT header + X.224 CR TPDU + RDP Negotiation Request (protocols: SSL|NLA)
← Recv: TPKT + CC TPDU; read RDP_NEG_RSP type byte
   If type == 0x02 and securityMode bit 1 set → NLA/CredSSP required
   If type == 0x03 → RDP_NEG_FAILURE (server rejected NLA)
```

**SMB2 Signing Detection Detail**

```
→ Send: NetBIOS session + SMB2 NEGOTIATE (dialects: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
← Recv: SMB2 NEGOTIATE response; read SecurityMode field
   Bit 0 set → signing enabled
   Bit 1 set → signing required (compliant)
   Neither set → signing disabled (finding raised)
```

**Extended HTTP Security Headers**

`REQUIRED_HEADERS` expanded from 4 to 9 headers:

| Header | Risk if absent |
|---|---|
| `Strict-Transport-Security` | Downgrade / MITM |
| `X-Content-Type-Options` | MIME sniffing |
| `X-Frame-Options` | Clickjacking |
| `Content-Security-Policy` | XSS |
| `Referrer-Policy` | Information leakage |
| `Permissions-Policy` | Feature abuse |
| `Cross-Origin-Opener-Policy` | Cross-origin attacks |
| `Cross-Origin-Embedder-Policy` | Spectre-class side channels |
| `Cross-Origin-Resource-Policy` | Cross-origin data theft |

---

### 1.4 `cy_asm/cycentra_scan.py` — Unified Vulnerability Indexing

**ASM-XXXXX deterministic IDs**

Every vulnerability finding now carries a stable, deterministic `asm_id` generated from the `(domain, module, finding)` triplet using SHA-256:

```python
def _asm_finding_id(domain: str, module: str, finding: str) -> str:
    raw = f"{domain}|{module}|{finding}".lower().encode()
    digest = hashlib.sha256(raw).hexdigest()
    return f"ASM-{digest[:5].upper()}"
```

- IDs are stable across scans of the same target — the same finding always produces the same ID.
- Format aligns with the SIEM Correlation Engine's `INC-NNNNN` namespace (prefix-padded).
- All NDJSON vulnerability entries and `_normalise_issue()` output include `asm_id`.

---

## 2. Portal — JavaScript Adapter

### 2.1 `portal/src/core/adapter.js`

**Client-side ASM ID generation** (FNV-1a 32-bit, 5 hex chars):

```javascript
function _asmFindingId(domain, module, finding) {
  const raw = `${domain}|${module}|${finding}`.toLowerCase();
  let h = 0x811c9dc5 >>> 0;
  for (let i = 0; i < raw.length; i++) {
    h = Math.imul(h ^ raw.charCodeAt(i), 0x01000193) >>> 0;
  }
  return `ASM-${h.toString(16).toUpperCase().slice(0, 5).padStart(5, "0")}`;
}
```

**SIEM Bridge updated:** Critical/High findings forwarded to CySIEM now use `ASM-XXXXX` as `rule_id`, replacing the previous sequential `CC-NNNNNN` placeholder. When the backend-generated `asm_id` is present in the scan JSON it is used directly; the client-side hash is a fallback.

---

## 3. Portal — Frontend Pages

### 3.1 `portal/src/pages/scan/ScanPage.jsx` — "Scan Operations"

**Three-Tier Scan Comparison Matrix**

| Tier | Color | Description |
|---|---|---|
| Passive | `#a78bfa` | OSINT-only — no direct target contact |
| Standard | `#4d9eff` | Active TCP/banner/header scan |
| Deep | `#00e5a0` | Full protocol probes + infra exposure + Nuclei |

- Bubble selector buttons switch the active tier; selected tier features display inline below the grid.
- Progress ring accent color matches the selected tier color.
- Button label updates: "Launch Passive Scan →" / "Launch Standard Scan →" / "Launch Deep Scan →".

**CTEM Continuous Sync Panel**

- Toggle to enable continuous monitoring (Continuous Threat Exposure Management).
- Interval options: 1 hour, 2 hours, 4 hours, 6 hours, 12 hours, 24 hours, Weekly.
- Minimum interval enforced: **1 hour** (3600 seconds).
- On Apply: deletes any existing scheduler job for the target, then `POST /api/scheduler/jobs` with `{type: "interval", seconds: N}`.
- Preview bar shows next-run estimate and selected interval label.

---

### 3.2 `portal/src/pages/guest-scan/GuestScanPage.jsx` — Guest UX Cleanup

**Removed:** "FULL ACCESS REQUIRED" / "LIMITED ACCESS" overlay banners.

**Added:** Educational three-tier comparison table (read-only, no interaction):

| Feature | Passive | Standard | Deep |
|---|---|---|---|
| OSINT / DNS / WHOIS | ✓ | ✓ | ✓ |
| Port Scan | — | ✓ | ✓ |
| SSL/TLS Analysis | — | ✓ | ✓ |
| HTTP Security Headers | — | ✓ | ✓ |
| Protocol Handshaking | — | — | ✓ |
| RDP NLA / SMB Signing | — | — | ✓ |
| Infra Exposure (Docker/K8s) | — | — | ✓ |
| Nuclei CVE Scanning | — | — | ✓ |
| Posture Score & Report | — | — | ✓ |

Passive and Deep tiers rendered at reduced opacity to indicate the guest scan runs Standard tier.

**Upsell language updated:**

- Locked widget overlay: *"For deeper access and full vulnerability analysis, generate a Deep Scan report from the Licensed Portal."*
- CTA button: **"Request Licensed Portal →"** (was "Get Full Access →")
- Trust badge: *"For continuous monitoring, use the Licensed Portal."*

---

### 3.3 `portal/src/pages/dashboard/DashboardPage.jsx` — ASM Posture Widget

New **`ASMPostureWidget`** component added to the main dashboard, sourcing data from `data.meta.posture_score` and `data.meta.posture_grade` (embedded by `posture_score.py` at scan time — no extra API call).

**Visual design:**

- Half-circle SVG gauge (180° arc, 0–100 scale).
- Needle positioned at the posture score.
- Grade color map:

| Grade | Color |
|---|---|
| A+ / A | `#00e5a0` (green) |
| B | `#4d9eff` (blue) |
| C | `#f5c518` (amber) |
| D | `#ff8c00` (orange) |
| F | `#ff3b3b` (red) |

- Grade band legend displayed below the gauge (A+≥90, A≥80, B≥70, C≥55, D≥35, F<35).
- Scan type badge (Passive / Standard / Deep) shown alongside the score, using existing `scanTypeColor` palette.

---

## 4. DevOps — `cycentra-setup.sh`

### 4.1 New ASM Scanner Tuning Variables

Added to **both** the fresh-install `.env` heredoc and the `--update` surgical patch block:

| Variable | Default | Description |
|---|---|---|
| `ENABLE_EXTENDED_PORT_SCAN` | `false` | Scan all 65535 ports (slower, more thorough) |
| `ENABLE_UDP_SCAN` | `false` | Add UDP scan layer (requires root; significantly slower) |
| `PROTO_PROBE_TIMEOUT` | `5` | Seconds per protocol-specific handshake probe |
| `INFRA_EXPOSURE_PORTS` | `2375,2376,6443,9200,9300,11211,5900,9090,9091,8161` | Extra ports checked for infrastructure exposure in Deep scans |

Existing installs running `--update` will have these vars appended automatically if absent.

### 4.2 No New Python Packages Required

All protocol-specific handshake probes (`_probe_ssh`, `_probe_rdp_nla`, `_probe_smb`, etc.) are implemented using Python standard library only:

```
ftplib, smtplib, struct, socket, hashlib, ssl
```

No changes to `requirements.txt` or `cycentra-setup.sh` pip install blocks were needed.

---

## 5. Scan Tier Capability Reference

| Capability | Passive | Standard | Deep |
|---|---|---|---|
| OSINT / DNS enumeration | ✓ | ✓ | ✓ |
| WHOIS / registrar data | ✓ | ✓ | ✓ |
| Subdomain discovery | ✓ | ✓ | ✓ |
| Port scan (TCP) | — | ✓ | ✓ |
| SSL/TLS certificate analysis | — | ✓ | ✓ |
| HTTP security headers | — | ✓ | ✓ |
| Web technology fingerprinting | — | ✓ | ✓ |
| SSH KEX negotiation probe | — | ✓ | ✓ |
| FTP anonymous access probe | — | ✓ | ✓ |
| SMTP relay probe | — | ✓ | ✓ |
| Redis unauthenticated probe | — | ✓ | ✓ |
| MongoDB unauthenticated probe | — | ✓ | ✓ |
| RDP NLA / CredSSP detection | — | — | ✓ |
| SMB2 signing enforcement check | — | — | ✓ |
| Docker daemon exposure | — | — | ✓ |
| Kubernetes API exposure | — | — | ✓ |
| Elasticsearch unauthenticated | — | — | ✓ |
| Memcached unauthenticated | — | — | ✓ |
| VNC no-auth probe | — | — | ✓ |
| Heartbleed (TLS heartbeat) | — | — | ✓ |
| Nuclei CVE scanning | — | — | ✓ |
| Posture score + PDF report | — | — | ✓ |
| Requires external API key | No | No | Optional (Shodan/VirusTotal for enrichment) |
| Avg. scan time | ~30s | 2–5 min | 10–30 min |

---

## 6. Files Modified

| File | Type |
|---|---|
| `backend/cy_asm/config.py` | Config |
| `backend/cy_asm/modules/crypto_checks.py` | Scanner module |
| `backend/cy_asm/modules/web_analysis.py` | Scanner module |
| `backend/cy_asm/cycentra_scan.py` | Orchestrator |
| `portal/src/core/adapter.js` | JS adapter |
| `portal/src/pages/scan/ScanPage.jsx` | React page |
| `portal/src/pages/guest-scan/GuestScanPage.jsx` | React page |
| `portal/src/pages/dashboard/DashboardPage.jsx` | React page |
| `cycentra-setup.sh` | Setup script |
