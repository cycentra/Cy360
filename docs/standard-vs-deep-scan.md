# Standard vs Deep Scan — Why Numbers Differ

## Why does my posture score change between Standard and Deep scan?

This is expected behavior. Here is exactly what each scan type covers:

| Module                  | Passive | Standard | Deep |
|-------------------------|---------|----------|------|
| DNS & WHOIS             | Y       | Y        | Y    |
| Subdomain Enumeration   | —       | Y        | Y    |
| Web Security & Ports    | —       | Y        | Y    |
| SSL / TLS Crypto Audit  | —       | Y        | Y    |
| Email Security          | Y       | Y        | Y    |
| Cloud Exposure          | —       | Y        | Y    |
| OSINT / Threat Intel    | Y       | Y        | Y    |
| Dark Web Monitoring     | Y       | —        | Y    |
| Supply Chain JS Risk    | —       | —        | Y    |
| Social Engineering Intel| —       | —        | Y    |
| Mobile & API Checks     | —       | —        | Y    |
| AI Enrichment           | —       | —        | Y    |

## Posture Score Formula

The posture score starts at 80 and deducts:

| Signal                    | Points    | Cap |
|---------------------------|-----------|-----|
| Critical finding          | -12 each  | -48 |
| High finding              | -6 each   | -30 |
| Medium finding            | -2 each   | -16 |
| Low finding               | -0.5 each | -5  |
| SSL not enabled           | -10       | —   |
| SSL enabled               | +5        | —   |
| Email weak / basic / none | -5        | —   |
| Email elite or robust     | +3        | —   |

Grades: A+ >= 90, A >= 80, B >= 70, C >= 55, D >= 35, F < 35

## Why Deep Scan scores lower

Deep Scan activates 4 additional modules (dark_web, supply_chain, social_eng, mobile_api) plus AI enrichment. These surface findings that Standard did not detect. Each additional finding reduces the score per the formula above.

A lower Deep Scan score does NOT mean the domain became less secure between scans. It means the Deep Scan found more of the attack surface. Think of it as: Standard is a snapshot of your front door, Deep Scan checks every window too.

## What stays the same

The raw SSL/TLS module result, email security module result, and DNS module result are identical between Standard and Deep — they run the exact same code. The counts shown in SSL and Email Security widgets are drawn from the raw module output, not from the total vulnerability count, so those numbers should match between scan types.

## Known differences that are by design (not bugs)

### Standard scan may show different findings than Deep scan for the same domain

The posture score for a Standard scan of a given domain should typically be HIGHER than a Deep scan of the same domain (all else equal), because:
1. Standard runs 6 profile modules (+ vuln_scanner); Deep runs 10 profile modules (+ vuln_scanner + nuclei + AI enrichment)
2. Each additional module can only ADD findings, never remove them
3. More findings → more posture score deductions

If you observe a Standard scan scoring LOWER than a Deep scan, this indicates one of these data-quality issues:
- **False positive paths** in the vuln_scanner (HTTP 200 on probed paths without content verification)
- **Module issue strings** being incorrectly classified at Medium severity instead of Low
- **SSL chain validation** failing in the Python SSL library even though TLS is working

These are fixed in v1.0.390+. Historical scan JSONs on disk will reflect the old (incorrect) scores until a rescan is performed.

### Root causes fixed in v1.0.390–v1.0.393

| Bug | Root cause | Fix | Version |
|-----|-----------|-----|---------|
| `ssl_enabled=False` for working TLS | `chain_valid && san_valid` gated the flag; Python CA bundle rejects intermediate issuers | `ssl_enabled` now reflects TLS handshake success (`protocol` field populated), not cert quality | v1.0.390 |
| False-positive Critical findings for `/.git/` and `/db.dump` | HTTP 200 was accepted at face value; CMS soft-404s return 200 for any path | Content-body verification added; unverified paths demoted to Medium | v1.0.390 |
| All module issue strings defaulted to Medium | `_normalise_issue()` hardcoded `"Medium"` for string issues | Keyword-based classifier `_classify_issue_severity()` maps advisory items to Low | v1.0.390 |
| `ADMIN_EXPOSED` / `DB_DUMP_EXPOSED` duplicate findings | `enrich_exposed_paths` created both verified Critical AND `_UNVERIFIED` Medium for the same path | Rebuilt as `seen: Dict[str, Dict]` keyed by CVE ref — exactly one finding per CVE | v1.0.392 |
| crt.sh intermittent failures causing subdomain count variance | Single call, no retry, 25s timeout | 3-attempt retry with backoff (30s/45s/60s) + 6h on-disk cache | v1.0.392 |
| `Weak key: 256 bits` false positive for ECDSA certs | Key-size check applied RSA 2048-bit minimum to all key types; ECDSA-256 ≈ RSA-3072 | Key-size check is now type-aware: RSA/DSA require ≥ 2048 bits; ECDSA requires ≥ 224 bits | v1.0.393 |
| `SAN mismatch` / `No SANs present` false positives | `ssock.getpeercert()` returns empty dict with `ssl.CERT_NONE`; SANs appeared missing | SANs now read directly from OpenSSL cert object via `subjectAltName` extension | v1.0.393 |
| `Chain validation failed: unable to get local issuer certificate` classified as Medium | Generic chain-validation pattern matched a scanner CA-bundle gap (not a real cert defect) | New Low-priority pattern for the specific error demotes it to informational | v1.0.393 |

## Customer FAQ

**Q: My Standard scan score is 72 (B) but Deep scan shows 48 (D). Is my site less secure?**

A: No. Deep Scan found more vulnerabilities across additional attack surface area. The lower score is more accurate — it reflects a broader view of your exposure.

**Q: Why do SSL and Email Security show the same numbers in both scan types?**

A: Because they run the same underlying module. The raw SSL certificate check and email authentication check are identical. Both scan types will show the same SPF/DKIM/DMARC status and the same certificate details.

**Q: Do I need to run a Deep Scan every time?**

A: Standard Scan is recommended for rapid daily checks on your primary domain. Deep Scan should be run weekly or after infrastructure changes for full coverage.
