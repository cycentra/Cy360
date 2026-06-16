2. Auto-incident status & case raising — Operational ✓
The SIEM correlation engine is operational and raises native CyCases records automatically. The criteria
are evaluated in ingestor.py (band logic at lines 262–346) on every alert processed.

FP Probability Band → Action
─────────────────────────────────────────────────────────────────────────
≥ fpThreshold (UI slider)               →  Auto-closed directly to "closed"
                                             No ticket. Silent dismiss. Audit: auto_close.
                                             Threshold read live from ai_settings.json —
                                             slider changes take effect on the next alert.

40% – <fpThreshold                      →  Stays "investigating"
                                             Re-evaluated on every new alert merge.
                                             Will never auto-ticket while in this band.

<40% + enrichment complete              →  Advanced to "in_review" + IRIS ticket
                                             (subject to the 4 additional conditions below)
─────────────────────────────────────────────────────────────────────────

All six conditions must be true for a case to be raised automatically:
  1. fp_score < fpThreshold  — not auto-closed (threshold from Settings → Integrations slider)
  2. fp_score < 40%          — not held in the moderate-FP investigation band
  3. Enrichment complete     — any one of:
                                 • MISP ran this cycle (even with 0 IOC hits)
                                 • LLM ran this cycle
                                 • Incident already has llm_summary or misp_enrichment stored
                                 • alert_count ≥ 3 (enrichment window treated as closed)
  4. Severity critical/high  — medium/low incidents reach "in_review" but are never auto-cased
  5. Alert count ≥ 3         — at least 3 correlated alerts in the incident group
  6. No existing case        — case_opened_at is NULL (deduplication guard)

Practical note for O365/cloud alerts: O365 events typically arrive as individual alerts at
"medium" severity. They will reach "in_review" once fp_score < 40%, but will NOT auto-ticket
unless: (a) correlation rules fire and raise severity to high/critical, AND (b) ≥3 alerts
group into the same incident.

Cases include: severity, affected hosts/users, source IPs, MITRE ATT&CK tactics,
MISP IOC matches, and LLM-generated analyst summary + remediation steps (when available).
The artifact created is a native CyCases record (`case_opened_at` set, `case_type` inferred,
a `case_comments` row inserted) — not an external IRIS ticket.

Note on enrichment gate (condition 3): "enriched" is satisfied even when MISP is
disabled or CyMind is not configured, as long as the incident has ≥3 alerts.
This prevents cases from being permanently blocked by missing enrichment pipelines.

Manual escalation: analysts can escalate via the CyMind AI chat action system
(invoked through `blueprints/system/routes.py`). Works for any severity/alert_count.

ASM findings: Cases raised manually via the "Open Case" button → POST /api/asm/open-case
(handled by `blueprints/cases/routes.py`). No auto-case from ASM.
Asset inventory: Status-only tracking; no auto-casing. Both are by design.