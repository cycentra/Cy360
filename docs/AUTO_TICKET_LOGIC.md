2. Auto-incident status & ticket raising — Operational ✓
The SIEM correlation engine is operational and raises CyIRIS tickets automatically. The criteria (from iris_connector.py and ingestor.py):

FP Probability Band → Action
─────────────────────────────────────────────────────────────────────────
≥ fpThreshold (UI slider, default 90%)  →  Auto-closed directly to "closed"
                                             No ticket. Audit action: auto_close.

40% – <fpThreshold                      →  Stays "investigating"
                                             Re-evaluated on every new alert merge.

<40% — all conditions below met         →  Advanced to "in_review" + IRIS ticket
─────────────────────────────────────────────────────────────────────────

All seven conditions must be true for a ticket to be raised automatically:
  1. IRIS configured         — mode = cloud or local, valid API key
  2. fp_score < fpThreshold  — not auto-closed (threshold from UI slider)
  3. fp_score < 40%          — not in moderate-FP holding band
  4. Enrichment complete     — MISP or LLM ran this cycle, OR stored on incident
                               from a prior cycle, OR alert_count ≥ 3 (window closed)
  5. Severity critical/high  — medium/low incidents are never auto-ticketed
  6. Alert count ≥ 3         — at least 3 correlated alerts
  7. No existing ticket      — iris_case_id is NULL (no duplicates)

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