2. Auto-incident status & ticket raising — Operational ✓
The SIEM correlation engine is operational and raises CyIRIS tickets automatically. The criteria (from iris_connector.py and ingestor.py):

FP Probability	Action
>= watch_zone_upper (default 65%)	Auto-closed as false positive — no ticket
>= iris_fp_threshold (default 40–65%)	Held for 30 min, then re-enriched
< 40% + MISP/LLM enrichment complete	→ in_review + IRIS ticket auto-created
< 40% but enrichment not yet done	Stays investigating
Tickets include: severity, affected hosts/users, MITRE ATT&CK tactics, MISP IOC matches, and LLM-generated summary + remediation steps. IRIS mode must be local or cloud in ai_settings.json with a valid API key.

ASM findings: Tickets raised manually via the "Raise Ticket" button → POST /api/asm/escalate. No auto-ticket from ASM.
Asset inventory: Status-only tracking; no auto-ticketing. Both are by design.