2. Auto-incident status & ticket raising — Operational ✓
The SIEM correlation engine is operational and raises CyIRIS tickets automatically. The criteria
are read live from iris_connector.py → advance_incident_status() on every alert processed.

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

All seven conditions must be true for a ticket to be raised automatically:
  1. IRIS configured         — mode = cloud or local, valid API key & URL
                               (FP auto-close still works even when IRIS is disabled)
  2. fp_score < fpThreshold  — not auto-closed (threshold from Settings → Integrations slider)
  3. fp_score < 40%          — not held in the moderate-FP investigation band
  4. Enrichment complete     — any one of:
                                 • MISP ran this cycle (even with 0 IOC hits)
                                 • LLM ran this cycle
                                 • Incident already has llm_summary or misp_enrichment stored
                                 • alert_count ≥ 3 (enrichment window treated as closed)
  5. Severity critical/high  — medium/low incidents reach "in_review" but are never auto-ticketed
  6. Alert count ≥ 3         — at least 3 correlated alerts in the incident group
  7. No existing ticket      — iris_case_id is NULL (deduplication guard)

Practical note for O365/cloud alerts: O365 events typically arrive as individual alerts at
"medium" severity. They will reach "in_review" once fp_score < 40%, but will NOT auto-ticket
unless: (a) correlation rules fire and raise severity to high/critical, AND (b) ≥3 alerts
group into the same incident.

Tickets include: severity, affected hosts/users, source IPs, MITRE ATT&CK tactics,
MISP IOC matches, and LLM-generated analyst summary + remediation steps (when available).

Note on enrichment gate (condition 4): "enriched" is satisfied even when MISP is
disabled or CyMind is not configured, as long as the incident has ≥3 alerts.
This prevents tickets from being permanently blocked by missing enrichment pipelines.

Manual escalation: analysts can bypass all threshold checks via the "Escalate to CyIRIS"
button → POST /engine/incidents/{id}/escalate. Works for any severity/alert_count.

ASM findings: Tickets raised manually via the "Raise Ticket" button → POST /api/asm/escalate.
No auto-ticket from ASM.
Asset inventory: Status-only tracking; no auto-ticketing. Both are by design.