# ============================================================================
# cycentra_scan.py  — REPORT INTEGRATION PATCH
# ============================================================================
#
# Add these 3 lines immediately AFTER the block that saves portal_file
# (i.e. after the "logger.info(f'✅ Portal JSON saved → {portal_file}')" line)
#
# Context: this sits inside the main() function, inside the
#          "try: ... except Exception as e:" block for portal JSON saving.
#
# ── FIND THIS EXISTING LINE (near end of main()): ───────────────────────────
#
#     logger.info(f"✅ Portal JSON saved → {portal_file}")
#
# ── ADD IMMEDIATELY AFTER IT: ───────────────────────────────────────────────

        # ── Generate PDF Reports (Executive + Technical) ─────────────────────
        try:
            from reporting.generate_reports import hook_into_scan
            hook_into_scan(portal_payload, final_tenant_id, domain, timestamp)
        except Exception as _rpt_err:
            logger.warning(f"⚠️ [Reports] PDF generation failed (scan unaffected): {_rpt_err}")

# ============================================================================
# That's it — 5 lines. The hook_into_scan() function is fire-and-forget:
# it catches all its own exceptions so a report failure never blocks
# the portal JSON or NDJSON output.
# ============================================================================


# ============================================================================
# FINAL SUMMARY BLOCK — update the existing log at the very bottom of main()
# to also print the report paths. Replace the existing final logger block with:
# ============================================================================

    logger.info(
        f"\n{'='*60}\n"
        f"🏁 ALL DONE: {domain}\n"
        f"   Scan Type   : {scan_type.upper()}\n"
        f"   AI Provider : {ai_provider_used}\n"
        f"   AI Findings : {len(enriched_issues)} enriched issues\n"
        f"   Reports     : {report_file}\n"
        f"              : {portal_file}\n"
        f"   PDF Reports : /var/log/cycentra/cy-asm/reports/{final_tenant_id}/\n"
        f"{'='*60}"
    )
