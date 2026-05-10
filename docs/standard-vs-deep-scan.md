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

## Customer FAQ

**Q: My Standard scan score is 72 (B) but Deep scan shows 48 (D). Is my site less secure?**

A: No. Deep Scan found more vulnerabilities across additional attack surface area. The lower score is more accurate — it reflects a broader view of your exposure.

**Q: Why do SSL and Email Security show the same numbers in both scan types?**

A: Because they run the same underlying module. The raw SSL certificate check and email authentication check are identical. Both scan types will show the same SPF/DKIM/DMARC status and the same certificate details.

**Q: Do I need to run a Deep Scan every time?**

A: Standard Scan is recommended for rapid daily checks on your primary domain. Deep Scan should be run weekly or after infrastructure changes for full coverage.
