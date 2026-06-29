# M11 — Marketplace
**Files:** `backend/blueprints/marketplace/routes.py`
**Run Date:** 2026-06-29

---

## Module Scope

Integration and playbook marketplace. Allows analysts to browse, install, and manage pre-built integrations (AWS, Azure, Okta, O365, Sysmon) and playbooks. Backed by `catalog.json`.

**Endpoints:**
- `GET /api/marketplace/catalog` — Browse available integrations
- `POST /api/marketplace/install/<id>` — Install an integration
- `GET /api/marketplace/installed` — List installed integrations
- `DELETE /api/marketplace/uninstall/<id>` — Remove integration

---

## AI-Executable Tests (Automated)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `marketplace_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | Catalog endpoint accessible to viewers | ✅ PASS | Read-only access |
| A1.03 | Install requires analyst+ role | ✅ PASS | |
| A1.04 | Catalog entries have required fields | ✅ PASS | id, name, description, category |
| A1.05 | No hardcoded secrets in catalog | ✅ PASS | Static scan clean |

---

## Manual Test Suite

### M-MKT-01: Browse Catalog
**Steps:**
1. Navigate to Marketplace
2. Verify categories displayed: Cloud, Identity, SIEM, Endpoint
3. Search for "AWS" — verify AWS integration card appears
4. Click card — verify description, prerequisites, and install button

### M-MKT-02: Install O365 Integration
**Steps:**
1. Click Install on O365 integration
2. Fill in tenant ID, client ID, client secret
3. Submit — verify integration appears in Installed list
4. Navigate to Integrations → O365 → verify connection status

### M-MKT-03: Integration Health Monitoring
**Steps:**
1. Install an integration
2. Navigate to Integrations → Health Monitor
3. Verify integration shows current status (ok/degraded/down)
4. Simulate integration failure (wrong credentials)
5. Verify health status changes to "down" and alert created

### M-MKT-04: Uninstall Integration
**Steps:**
1. Uninstall a previously installed integration
2. Verify removed from Installed list
3. Verify related log ingest stops within 5 minutes
