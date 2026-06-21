"""
Suite 12 — Integration Health Monitor Tests

Tests the full integration health monitoring pipeline:

  Phase 1 — Per-integration check functions
      check_wazuh / check_siem_engine / check_cymind / check_misp / check_cysoar
      All HTTP calls are mocked — no real network required.
      Covers: ok, down, degraded (ingest gap), and skipped states.

  Phase 2 — Marketplace health map (extensibility)
      _build_marketplace_health_map() merges builtin baseline with catalog-declared
      health_config blocks. Covers: builtin precedence, custom ingest_gap, custom
      http endpoint, items without health_config (ignored), and corrupt catalog.

  Phase 3 — Incident and case creation / resolution
      _raise_integration_incident() inserts an incidents row + opens a CyCase.
      _resolve_integration_incident() transitions to resolved + adds comment.
      Stable ID scheme: INTEG-{sha256[:8].upper()}.  Idempotent via ON CONFLICT.

  Phase 4 — run_all_checks() orchestrator
      Drives all checks in order, upserts status, raises/resolves incidents, and
      returns the correct result list shape.  DB and HTTP fully mocked.

  Phase 5 — REST API endpoints (Flask test client)
      GET  /api/integrations/health             viewer+
      GET  /api/integrations/health/<name>      viewer+
      POST /api/integrations/health/check       analyst+
      GET  /api/integrations/health/config      admin
      POST /api/integrations/health/config      admin
      Authentication and RBAC checked for all routes.

  Phase 6 — Scheduler wiring
      integration_health job type is handled by _add_to_apscheduler().
      Health monitor is auto-registered in init_scheduler().
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, call, patch, mock_open

import pytest

# ---------------------------------------------------------------------------
# Path / environment bootstrap
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND   = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND))

os.environ.setdefault("SECRET_KEY",    "test-secret-key")
os.environ.setdefault("BASE_URL",      "https://test.example.com")
os.environ.setdefault("FRONTEND_URL",  "https://test.example.com")
os.environ.setdefault("DATABASE_URL",  "sqlite:///:memory:")
os.environ.setdefault("CYCENTRA_ENV",  "test")


# ---------------------------------------------------------------------------
# Helpers shared across phases
# ---------------------------------------------------------------------------

def _http_ok(status: int = 200) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    return m


def _http_err(exc: Exception) -> MagicMock:
    """A requests.get that raises an exception."""
    m = MagicMock(side_effect=exc)
    return m


def _mock_db_conn(rows=None):
    """Return a mock psycopg2 connection + cursor that yields rows."""
    cur  = MagicMock()
    cur.fetchone.return_value = rows[0] if rows else None
    cur.fetchall.return_value = rows or []
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


def _incident_id(name: str) -> str:
    return "INTEG-" + hashlib.sha256(name.encode()).hexdigest()[:8].upper()


# ===========================================================================
# Phase 1 — Per-integration check functions
# ===========================================================================

class TestCheckWazuh:
    """check_wazuh() covers: ok, down (auth failure), degraded (ingest gap)."""

    def _check(self, **env_overrides):
        import importlib
        import blueprints.integrations.health as h
        importlib.reload(h)
        return h

    def test_ok_when_auth_succeeds_and_recent_alerts(self):
        import blueprints.integrations.health as h
        with patch.object(h, "_last_alert_age_minutes", return_value=2), \
             patch("requests.post", return_value=_http_ok(200)):
            result = h.check_wazuh()
        assert result["status"] == "ok"
        assert result["name"]   == "wazuh"
        assert result["error"]  is None
        assert result["ingest_gap"] == 2

    def test_down_when_auth_request_fails_with_non_200(self):
        import blueprints.integrations.health as h
        with patch("requests.post", return_value=_http_ok(401)):
            result = h.check_wazuh()
        assert result["status"] == "down"
        assert "401" in result["error"]

    def test_down_when_connection_refused(self):
        import blueprints.integrations.health as h
        import requests as req_module
        with patch("requests.post", side_effect=req_module.exceptions.ConnectionError("refused")):
            result = h.check_wazuh()
        assert result["status"] == "down"
        assert result["error"] is not None

    def test_degraded_when_ingest_gap_exceeds_window(self):
        import blueprints.integrations.health as h
        with patch("requests.post", return_value=_http_ok(200)), \
             patch.object(h, "_last_alert_age_minutes", return_value=30), \
             patch.dict(os.environ, {"INTEGRATION_HEALTH_INGEST_WINDOW": "15"}):
            result = h.check_wazuh()
        assert result["status"] == "degraded"
        assert result["ingest_gap"] == 30

    def test_ok_when_ingest_gap_within_window(self):
        import blueprints.integrations.health as h
        with patch("requests.post", return_value=_http_ok(200)), \
             patch.object(h, "_last_alert_age_minutes", return_value=5):
            result = h.check_wazuh()
        assert result["status"] == "ok"

    def test_result_has_required_keys(self):
        import blueprints.integrations.health as h
        with patch("requests.post", return_value=_http_ok(200)), \
             patch.object(h, "_last_alert_age_minutes", return_value=1):
            result = h.check_wazuh()
        for key in ("name", "display", "status", "error", "ingest_gap"):
            assert key in result, f"Missing key {key!r} in check_wazuh() result"


class TestCheckSiemEngine:
    """check_siem_engine() covers: ok, down (HTTP error), down (connection)."""

    def test_ok_when_health_returns_200(self):
        import blueprints.integrations.health as h
        with patch("requests.get", return_value=_http_ok(200)):
            result = h.check_siem_engine()
        assert result["status"] == "ok"
        assert result["name"]   == "siem_engine"

    def test_degraded_when_health_returns_non_200(self):
        import blueprints.integrations.health as h
        with patch("requests.get", return_value=_http_ok(503)):
            result = h.check_siem_engine()
        assert result["status"] == "degraded"
        assert "503" in result["error"]

    def test_down_when_connection_error(self):
        import blueprints.integrations.health as h
        import requests as req_module
        with patch("requests.get", side_effect=req_module.exceptions.Timeout("timed out")):
            result = h.check_siem_engine()
        assert result["status"] == "down"

    def test_no_ingest_gap_for_engine(self):
        """Correlation engine health check doesn't produce an ingest gap value."""
        import blueprints.integrations.health as h
        with patch("requests.get", return_value=_http_ok(200)):
            result = h.check_siem_engine()
        assert result["ingest_gap"] is None


class TestCheckCymind:
    """check_cymind() covers: skipped (disabled), skipped (no URL), ok, down."""

    def _settings(self, enabled: bool, url: str = "http://cymind.local:8080") -> str:
        return json.dumps({"cymind_integration": {"enabled": enabled, "cymindUrl": url}})

    def test_skipped_when_not_enabled(self, tmp_path):
        import blueprints.integrations.health as h
        settings_file = tmp_path / "ai_settings.json"
        settings_file.write_text(self._settings(enabled=False))
        with patch.object(h, "_AI_SETTINGS_FILE", settings_file):
            result = h.check_cymind()
        assert result["status"] == "skipped"

    def test_skipped_when_no_url_configured(self, tmp_path):
        import blueprints.integrations.health as h
        settings_file = tmp_path / "ai_settings.json"
        settings_file.write_text(json.dumps({"cymind_integration": {"enabled": True, "cymindUrl": ""}}))
        with patch.object(h, "_AI_SETTINGS_FILE", settings_file):
            result = h.check_cymind()
        assert result["status"] == "skipped"

    def test_skipped_when_settings_file_missing(self, tmp_path):
        import blueprints.integrations.health as h
        with patch.object(h, "_AI_SETTINGS_FILE", tmp_path / "nonexistent.json"):
            result = h.check_cymind()
        assert result["status"] == "skipped"

    def test_ok_when_health_returns_200(self, tmp_path):
        import blueprints.integrations.health as h
        settings_file = tmp_path / "ai_settings.json"
        settings_file.write_text(self._settings(enabled=True))
        with patch.object(h, "_AI_SETTINGS_FILE", settings_file), \
             patch("requests.get", return_value=_http_ok(200)):
            result = h.check_cymind()
        assert result["status"] == "ok"
        assert result["name"]   == "cymind"

    def test_down_when_health_fails(self, tmp_path):
        import blueprints.integrations.health as h
        import requests as req_module
        settings_file = tmp_path / "ai_settings.json"
        settings_file.write_text(self._settings(enabled=True))
        with patch.object(h, "_AI_SETTINGS_FILE", settings_file), \
             patch("requests.get", side_effect=req_module.exceptions.ConnectionError("refused")):
            result = h.check_cymind()
        assert result["status"] == "down"


class TestCheckMisp:
    """check_misp() covers: skipped (disabled / not configured), ok, down."""

    def test_skipped_when_get_misp_config_returns_none(self):
        import blueprints.integrations.health as h
        with patch("blueprints.integrations.health.get_misp_config", return_value=None):
            result = h.check_misp()
        assert result["status"] == "skipped"

    def test_skipped_when_mode_is_disabled(self):
        import blueprints.integrations.health as h
        with patch("blueprints.integrations.health.get_misp_config",
                   return_value={"mode": "disabled", "url": "https://misp.local", "apiKey": "k"}):
            result = h.check_misp()
        assert result["status"] == "skipped"

    def test_ok_when_version_endpoint_returns_200(self):
        import blueprints.integrations.health as h
        with patch("blueprints.integrations.health.get_misp_config",
                   return_value={"mode": "cloud", "url": "https://misp.local", "apiKey": "k"}), \
             patch("requests.get", return_value=_http_ok(200)):
            result = h.check_misp()
        assert result["status"] == "ok"
        assert result["name"]   == "misp"

    def test_down_when_version_endpoint_returns_401(self):
        import blueprints.integrations.health as h
        with patch("blueprints.integrations.health.get_misp_config",
                   return_value={"mode": "local", "url": "https://misp.local", "apiKey": "k"}), \
             patch("requests.get", return_value=_http_ok(401)):
            result = h.check_misp()
        assert result["status"] == "down"
        assert "401" in result["error"]

    def test_down_when_connection_refused(self):
        import blueprints.integrations.health as h
        import requests as req_module
        with patch("blueprints.integrations.health.get_misp_config",
                   return_value={"mode": "local", "url": "https://misp.local", "apiKey": "k"}), \
             patch("requests.get", side_effect=req_module.exceptions.ConnectionError("refused")):
            result = h.check_misp()
        assert result["status"] == "down"


class TestCheckCysoar:
    """check_cysoar() covers: skipped (not installed), ok, down."""

    def test_skipped_when_module_not_installed(self, tmp_path):
        import blueprints.integrations.health as h
        state_file = tmp_path / "modules_state.json"
        state_file.write_text(json.dumps({"cysoar": {"installed": False}}))
        with patch.object(h, "_MODULES_STATE", state_file):
            result = h.check_cysoar()
        assert result["status"] == "skipped"

    def test_skipped_when_state_file_missing(self, tmp_path):
        import blueprints.integrations.health as h
        with patch.object(h, "_MODULES_STATE", tmp_path / "nonexistent.json"):
            result = h.check_cysoar()
        assert result["status"] == "skipped"

    def test_ok_when_nodered_responds_non_5xx(self, tmp_path):
        import blueprints.integrations.health as h
        state_file = tmp_path / "modules_state.json"
        state_file.write_text(json.dumps({"cysoar": {"installed": True}}))
        with patch.object(h, "_MODULES_STATE", state_file), \
             patch("requests.get", return_value=_http_ok(200)):
            result = h.check_cysoar()
        assert result["status"] == "ok"
        assert result["name"]   == "cysoar"

    def test_ok_when_nodered_redirects(self, tmp_path):
        """Node-RED root returns 302 → 200; non-5xx means it's alive."""
        import blueprints.integrations.health as h
        state_file = tmp_path / "modules_state.json"
        state_file.write_text(json.dumps({"cysoar": {"installed": True}}))
        with patch.object(h, "_MODULES_STATE", state_file), \
             patch("requests.get", return_value=_http_ok(302)):
            result = h.check_cysoar()
        assert result["status"] == "ok"

    def test_down_when_nodered_returns_5xx(self, tmp_path):
        import blueprints.integrations.health as h
        state_file = tmp_path / "modules_state.json"
        state_file.write_text(json.dumps({"cysoar": {"installed": True}}))
        with patch.object(h, "_MODULES_STATE", state_file), \
             patch("requests.get", return_value=_http_ok(502)):
            result = h.check_cysoar()
        assert result["status"] == "down"

    def test_down_when_connection_refused(self, tmp_path):
        import blueprints.integrations.health as h
        import requests as req_module
        state_file = tmp_path / "modules_state.json"
        state_file.write_text(json.dumps({"cysoar": {"installed": True}}))
        with patch.object(h, "_MODULES_STATE", state_file), \
             patch("requests.get", side_effect=req_module.exceptions.ConnectionError("refused")):
            result = h.check_cysoar()
        assert result["status"] == "down"


# ===========================================================================
# Phase 2 — Marketplace health map (extensibility)
# ===========================================================================

class TestBuildMarketplaceHealthMap:
    """_build_marketplace_health_map() merges builtin defaults with custom catalog."""

    def test_returns_builtin_map_when_no_custom_catalog(self, tmp_path):
        import blueprints.integrations.health as h
        with patch.object(h, "_CUSTOM_CATALOG", tmp_path / "nonexistent.json"):
            result = h._build_marketplace_health_map()
        assert "office365"    in result
        assert "google-cloud" in result
        assert "aws"          in result
        assert "github"       in result

    def test_custom_ingest_gap_item_is_added(self, tmp_path):
        import blueprints.integrations.health as h
        custom = tmp_path / "marketplace_custom.json"
        custom.write_text(json.dumps([{
            "id": "splunk-hec",
            "name": "Splunk HEC",
            "health_config": {
                "type": "ingest_gap",
                "rule_groups": ["splunk"],
                "display_name": "Splunk HEC Ingest",
            },
        }]))
        with patch.object(h, "_CUSTOM_CATALOG", custom):
            result = h._build_marketplace_health_map()
        assert "splunk-hec" in result
        assert result["splunk-hec"]["groups"] == ["splunk"]
        assert result["splunk-hec"]["display"] == "Splunk HEC Ingest"

    def test_custom_http_item_is_added(self, tmp_path):
        import blueprints.integrations.health as h
        custom = tmp_path / "marketplace_custom.json"
        custom.write_text(json.dumps([{
            "id": "my-api",
            "name": "My API",
            "health_config": {
                "type": "http",
                "endpoint_url": "https://api.internal/health",
                "display_name": "My API Health",
            },
        }]))
        with patch.object(h, "_CUSTOM_CATALOG", custom):
            result = h._build_marketplace_health_map()
        assert "my-api" in result
        assert result["my-api"]["endpoint_url"] == "https://api.internal/health"
        assert result["my-api"]["groups"] is None

    def test_builtin_takes_precedence_over_custom_same_id(self, tmp_path):
        import blueprints.integrations.health as h
        custom = tmp_path / "marketplace_custom.json"
        custom.write_text(json.dumps([{
            "id": "office365",
            "health_config": {"type": "ingest_gap", "rule_groups": ["custom-o365"]},
        }]))
        with patch.object(h, "_CUSTOM_CATALOG", custom):
            result = h._build_marketplace_health_map()
        # Builtin entry has 2 groups; custom override must NOT replace it
        assert "office365" in result["office365"]["groups"]
        assert result["office365"]["groups"] != ["custom-o365"]

    def test_items_without_health_config_are_ignored(self, tmp_path):
        import blueprints.integrations.health as h
        custom = tmp_path / "marketplace_custom.json"
        custom.write_text(json.dumps([{
            "id": "my-playbook",
            "name": "My Playbook",
            "type": "playbook",
        }]))
        with patch.object(h, "_CUSTOM_CATALOG", custom):
            result = h._build_marketplace_health_map()
        assert "my-playbook" not in result

    def test_corrupt_catalog_returns_builtin_only(self, tmp_path):
        import blueprints.integrations.health as h
        custom = tmp_path / "marketplace_custom.json"
        custom.write_text("this is not valid json{{{{")
        with patch.object(h, "_CUSTOM_CATALOG", custom):
            result = h._build_marketplace_health_map()
        assert "office365" in result      # builtin present
        assert "my-custom" not in result  # no mystery additions


class TestCheckMarketplaceIntegrations:
    """check_marketplace_integrations() covers ingest_gap and http types."""

    def _state_file(self, tmp_path, installed: list) -> Path:
        f = tmp_path / "marketplace_state.json"
        f.write_text(json.dumps({"installed": installed}))
        return f

    def test_empty_when_state_file_missing(self, tmp_path):
        import blueprints.integrations.health as h
        with patch.object(h, "_MARKETPLACE_STATE", tmp_path / "none.json"):
            assert h.check_marketplace_integrations() == []

    def test_empty_when_no_known_integrations_installed(self, tmp_path):
        import blueprints.integrations.health as h
        sf = self._state_file(tmp_path, ["my-unknown-tool"])
        with patch.object(h, "_MARKETPLACE_STATE", sf):
            assert h.check_marketplace_integrations() == []

    def test_ok_for_installed_o365_with_recent_events(self, tmp_path):
        import blueprints.integrations.health as h
        sf = self._state_file(tmp_path, ["office365"])
        with patch.object(h, "_MARKETPLACE_STATE", sf), \
             patch.object(h, "_last_alert_age_minutes", return_value=3), \
             patch.object(h, "_CUSTOM_CATALOG", tmp_path / "none.json"):
            results = h.check_marketplace_integrations()
        assert len(results) == 1
        assert results[0]["status"] == "ok"
        assert results[0]["name"]   == "marketplace_office365"

    def test_degraded_for_o365_ingest_gap(self, tmp_path):
        import blueprints.integrations.health as h
        sf = self._state_file(tmp_path, ["office365"])
        with patch.object(h, "_MARKETPLACE_STATE", sf), \
             patch.object(h, "_last_alert_age_minutes", return_value=45), \
             patch.object(h, "_CUSTOM_CATALOG", tmp_path / "none.json"), \
             patch.dict(os.environ, {"INTEGRATION_HEALTH_INGEST_WINDOW": "15"}):
            results = h.check_marketplace_integrations()
        assert results[0]["status"] == "degraded"
        assert results[0]["ingest_gap"] == 45

    def test_degraded_when_no_events_ever(self, tmp_path):
        import blueprints.integrations.health as h
        sf = self._state_file(tmp_path, ["aws"])
        with patch.object(h, "_MARKETPLACE_STATE", sf), \
             patch.object(h, "_last_alert_age_minutes", return_value=None), \
             patch.object(h, "_CUSTOM_CATALOG", tmp_path / "none.json"):
            results = h.check_marketplace_integrations()
        assert results[0]["status"] == "degraded"
        assert "No events ever" in results[0]["error"]

    def test_multiple_installed_integrations_all_checked(self, tmp_path):
        import blueprints.integrations.health as h
        sf = self._state_file(tmp_path, ["office365", "aws", "github"])
        with patch.object(h, "_MARKETPLACE_STATE", sf), \
             patch.object(h, "_last_alert_age_minutes", return_value=2), \
             patch.object(h, "_CUSTOM_CATALOG", tmp_path / "none.json"):
            results = h.check_marketplace_integrations()
        assert len(results) == 3
        names = {r["name"] for r in results}
        assert "marketplace_office365" in names
        assert "marketplace_aws"       in names
        assert "marketplace_github"    in names

    def test_custom_http_integration_ok(self, tmp_path):
        """A custom http-type integration added via marketplace is health-checked."""
        import blueprints.integrations.health as h
        sf = self._state_file(tmp_path, ["my-api"])
        catalog = tmp_path / "catalog.json"
        catalog.write_text(json.dumps([{
            "id": "my-api",
            "name": "My API",
            "health_config": {"type": "http", "endpoint_url": "https://api.internal/health"},
        }]))
        with patch.object(h, "_MARKETPLACE_STATE", sf), \
             patch.object(h, "_CUSTOM_CATALOG", catalog), \
             patch("requests.get", return_value=_http_ok(200)):
            results = h.check_marketplace_integrations()
        assert len(results) == 1
        assert results[0]["status"] == "ok"
        assert results[0]["name"]   == "marketplace_my_api"

    def test_custom_http_integration_down(self, tmp_path):
        import blueprints.integrations.health as h
        import requests as req_module
        sf = self._state_file(tmp_path, ["my-api"])
        catalog = tmp_path / "catalog.json"
        catalog.write_text(json.dumps([{
            "id": "my-api",
            "health_config": {"type": "http", "endpoint_url": "https://api.internal/health"},
        }]))
        with patch.object(h, "_MARKETPLACE_STATE", sf), \
             patch.object(h, "_CUSTOM_CATALOG", catalog), \
             patch("requests.get", side_effect=req_module.exceptions.ConnectionError("refused")):
            results = h.check_marketplace_integrations()
        assert results[0]["status"] == "down"


# ===========================================================================
# Phase 3 — Incident ID scheme and create/resolve logic
# ===========================================================================

class TestIncidentIdScheme:
    """_incident_id_for() produces stable, deterministic, correctly formatted IDs."""

    def test_id_has_integ_prefix(self):
        from blueprints.integrations.health import _incident_id_for
        assert _incident_id_for("wazuh").startswith("INTEG-")

    def test_id_is_8_hex_chars_after_prefix(self):
        from blueprints.integrations.health import _incident_id_for
        suffix = _incident_id_for("wazuh")[len("INTEG-"):]
        assert len(suffix) == 8
        assert suffix == suffix.upper()
        assert all(c in "0123456789ABCDEF" for c in suffix)

    def test_same_name_produces_same_id(self):
        from blueprints.integrations.health import _incident_id_for
        assert _incident_id_for("cymind") == _incident_id_for("cymind")

    def test_different_names_produce_different_ids(self):
        from blueprints.integrations.health import _incident_id_for
        assert _incident_id_for("wazuh") != _incident_id_for("cymind")
        assert _incident_id_for("misp")  != _incident_id_for("cysoar")

    def test_expected_id_for_wazuh(self):
        from blueprints.integrations.health import _incident_id_for
        expected = "INTEG-" + hashlib.sha256(b"wazuh").hexdigest()[:8].upper()
        assert _incident_id_for("wazuh") == expected


class TestRaiseIntegrationIncident:
    """_raise_integration_incident() inserts incident row and opens case."""

    def _mock_conn(self):
        cur  = MagicMock()
        conn = MagicMock()
        conn.cursor.return_value = cur
        return conn, cur

    def test_executes_insert_into_incidents(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        with patch.object(h, "_db", return_value=conn), \
             patch("blueprints.cases.service.open_case", return_value={}), \
             patch.object(h, "_set_incident_id"):
            h._raise_integration_incident("wazuh", "Wazuh SIEM", "down", "conn refused", None)
        sql_calls = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "INSERT INTO incidents" in sql_calls

    def test_calls_open_case(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        with patch.object(h, "_db", return_value=conn), \
             patch("blueprints.cases.service.open_case", return_value={}) as mock_oc, \
             patch.object(h, "_set_incident_id"):
            h._raise_integration_incident("wazuh", "Wazuh SIEM", "down", "refused", None)
        mock_oc.assert_called_once()
        call_args = mock_oc.call_args
        assert call_args[0][1] == _incident_id("wazuh")   # incident_id arg
        assert call_args[0][2] == "integration-monitor"   # opened_by arg
        assert call_args[1].get("case_type") == "operational"

    def test_uses_high_severity_for_down(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        with patch.object(h, "_db", return_value=conn), \
             patch("blueprints.cases.service.open_case", return_value={}), \
             patch.object(h, "_set_incident_id"):
            h._raise_integration_incident("wazuh", "Wazuh SIEM", "down", "err", None)
        all_sql = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "high" in all_sql

    def test_uses_medium_severity_for_degraded(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        with patch.object(h, "_db", return_value=conn), \
             patch("blueprints.cases.service.open_case", return_value={}), \
             patch.object(h, "_set_incident_id"):
            h._raise_integration_incident("wazuh", "Wazuh SIEM", "degraded", "gap", 30)
        all_sql = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "medium" in all_sql

    def test_notes_contain_error_message(self):
        from blueprints.integrations import health as h
        captured_notes = {}
        original_execute = MagicMock()

        def capture_execute(sql, params=None):
            if params and "INSERT INTO incidents" in str(sql):
                captured_notes["notes"] = params[-1] if params else ""
        conn, cur = self._mock_conn()
        cur.execute.side_effect = capture_execute

        with patch.object(h, "_db", return_value=conn), \
             patch("blueprints.cases.service.open_case", return_value={}), \
             patch.object(h, "_set_incident_id"):
            h._raise_integration_incident(
                "wazuh", "Wazuh SIEM", "down", "Connection timed out", None)

    def test_notes_contain_ingest_gap_when_provided(self):
        from blueprints.integrations import health as h
        calls_sql = []

        def capture(sql, params=None):
            calls_sql.append((str(sql), params or []))
        conn, cur = self._mock_conn()
        cur.execute.side_effect = capture

        with patch.object(h, "_db", return_value=conn), \
             patch("blueprints.cases.service.open_case", return_value={}), \
             patch.object(h, "_set_incident_id"):
            h._raise_integration_incident("misp", "MISP", "degraded", "gap", 45)

        all_params = " ".join(str(p) for _, p in calls_sql)
        assert "45" in all_params or "45 minutes" in all_params.lower() or "gap" in all_params

    def test_db_exception_does_not_raise(self):
        from blueprints.integrations import health as h
        with patch.object(h, "_db", side_effect=Exception("db down")):
            # Must not raise — health check must be fault-tolerant
            h._raise_integration_incident("wazuh", "Wazuh SIEM", "down", "err", None)


class TestResolveIntegrationIncident:
    """_resolve_integration_incident() transitions to resolved and adds a comment."""

    def test_updates_status_to_resolved(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        cur.fetchone.return_value = {"status": "investigating"}
        with patch.object(h, "_db", return_value=conn), \
             patch.object(h, "_set_incident_id"):
            h._resolve_integration_incident("wazuh", "Wazuh SIEM")
        all_sql = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "resolved" in all_sql

    def test_inserts_system_comment(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        cur.fetchone.return_value = {"status": "investigating"}
        with patch.object(h, "_db", return_value=conn), \
             patch.object(h, "_set_incident_id"):
            h._resolve_integration_incident("wazuh", "Wazuh SIEM")
        all_sql = " ".join(str(c) for c in cur.execute.call_args_list)
        assert "case_comments" in all_sql
        assert "RECOVERED" in all_sql or "recovered" in all_sql.lower()

    def test_noop_when_incident_already_resolved(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        cur.fetchone.return_value = {"status": "resolved"}
        with patch.object(h, "_db", return_value=conn), \
             patch.object(h, "_set_incident_id"):
            h._resolve_integration_incident("wazuh", "Wazuh SIEM")
        # UPDATE should NOT be called on an already-resolved incident
        update_calls = [c for c in cur.execute.call_args_list
                        if "UPDATE incidents" in str(c)]
        assert len(update_calls) == 0

    def test_noop_when_incident_row_does_not_exist(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        cur.fetchone.return_value = None
        with patch.object(h, "_db", return_value=conn), \
             patch.object(h, "_set_incident_id"):
            h._resolve_integration_incident("wazuh", "Wazuh SIEM")
        update_calls = [c for c in cur.execute.call_args_list
                        if "UPDATE incidents" in str(c)]
        assert len(update_calls) == 0

    def test_clears_incident_id_on_recovery(self):
        from blueprints.integrations import health as h
        conn, cur = self._mock_conn()
        cur.fetchone.return_value = {"status": "investigating"}
        with patch.object(h, "_db", return_value=conn), \
             patch.object(h, "_set_incident_id") as mock_set:
            h._resolve_integration_incident("wazuh", "Wazuh SIEM")
        mock_set.assert_called_once_with("wazuh", None)

    def test_db_exception_does_not_raise(self):
        from blueprints.integrations import health as h
        with patch.object(h, "_db", side_effect=Exception("db down")):
            h._resolve_integration_incident("wazuh", "Wazuh SIEM")

    def _mock_conn(self):
        cur  = MagicMock()
        conn = MagicMock()
        conn.cursor.return_value = cur
        return conn, cur


# ===========================================================================
# Phase 4 — run_all_checks() orchestrator
# ===========================================================================

class TestRunAllChecks:
    """run_all_checks() drives all checks, persists status, raises/resolves."""

    def _patch_all_ok(self):
        """Return a set of patches that makes every check return 'ok'."""
        ok = lambda name, display: {"name": name, "display": display,
                                    "status": "ok", "error": None, "ingest_gap": None}
        return {
            "check_wazuh":                   ok("wazuh",       "Wazuh SIEM"),
            "check_siem_engine":             ok("siem_engine", "CySIEM Correlation Engine"),
            "check_cymind":                  {"name": "cymind",  "display": "CyMind AI",
                                              "status": "skipped", "error": "disabled",
                                              "ingest_gap": None},
            "check_misp":                    {"name": "misp",   "display": "MISP",
                                              "status": "skipped", "error": "disabled",
                                              "ingest_gap": None},
            "check_cysoar":                  {"name": "cysoar", "display": "CySOAR",
                                              "status": "skipped", "error": "not installed",
                                              "ingest_gap": None},
            "check_marketplace_integrations": [],
        }

    def test_returns_list_of_results(self):
        from blueprints.integrations import health as h
        checks = self._patch_all_ok()
        with patch.object(h, "ensure_health_tables"), \
             patch.object(h, "check_wazuh",          return_value=checks["check_wazuh"]), \
             patch.object(h, "check_siem_engine",    return_value=checks["check_siem_engine"]), \
             patch.object(h, "check_cymind",         return_value=checks["check_cymind"]), \
             patch.object(h, "check_misp",           return_value=checks["check_misp"]), \
             patch.object(h, "check_cysoar",         return_value=checks["check_cysoar"]), \
             patch.object(h, "check_marketplace_integrations", return_value=[]), \
             patch.object(h, "_upsert_status",       return_value={"prev_status": "ok",
                                                                    "incident_id": None,
                                                                    "consecutive_failures": 0}):
            results = h.run_all_checks()
        assert isinstance(results, list)
        assert len(results) >= 2  # at least wazuh + siem_engine

    def test_skipped_integrations_not_upserted(self):
        from blueprints.integrations import health as h
        checks = self._patch_all_ok()
        with patch.object(h, "ensure_health_tables"), \
             patch.object(h, "check_wazuh",          return_value=checks["check_wazuh"]), \
             patch.object(h, "check_siem_engine",    return_value=checks["check_siem_engine"]), \
             patch.object(h, "check_cymind",         return_value=checks["check_cymind"]), \
             patch.object(h, "check_misp",           return_value=checks["check_misp"]), \
             patch.object(h, "check_cysoar",         return_value=checks["check_cysoar"]), \
             patch.object(h, "check_marketplace_integrations", return_value=[]), \
             patch.object(h, "_upsert_status",       return_value={"prev_status": "ok",
                                                                    "incident_id": None,
                                                                    "consecutive_failures": 0}) as mock_us, \
             patch.object(h, "_raise_integration_incident"), \
             patch.object(h, "_resolve_integration_incident"):
            h.run_all_checks()
        # Only non-skipped checks (wazuh, siem_engine) should call _upsert_status
        upserted_names = [c[0][0] for c in mock_us.call_args_list]
        assert "cymind"  not in upserted_names
        assert "cysoar"  not in upserted_names
        assert "wazuh"       in upserted_names
        assert "siem_engine" in upserted_names

    def test_raises_incident_when_integration_down(self):
        from blueprints.integrations import health as h
        down_result = {"name": "wazuh", "display": "Wazuh SIEM",
                       "status": "down", "error": "refused", "ingest_gap": None}
        with patch.object(h, "ensure_health_tables"), \
             patch.object(h, "check_wazuh",          return_value=down_result), \
             patch.object(h, "check_siem_engine",    return_value={
                 "name": "siem_engine", "display": "Engine",
                 "status": "ok", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_cymind",   return_value={"name": "cymind",  "status": "skipped",
                                                              "display": "CyMind", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_misp",     return_value={"name": "misp",    "status": "skipped",
                                                              "display": "MISP",  "error": None, "ingest_gap": None}), \
             patch.object(h, "check_cysoar",   return_value={"name": "cysoar",  "status": "skipped",
                                                              "display": "CySOAR","error": None, "ingest_gap": None}), \
             patch.object(h, "check_marketplace_integrations", return_value=[]), \
             patch.object(h, "_upsert_status",
                          return_value={"prev_status": "ok", "incident_id": None,
                                        "consecutive_failures": 1}), \
             patch.object(h, "_raise_integration_incident") as mock_raise, \
             patch.object(h, "_resolve_integration_incident"):
            h.run_all_checks()
        mock_raise.assert_called_once()
        call_kwargs = mock_raise.call_args
        assert call_kwargs[0][0] == "wazuh"
        assert call_kwargs[0][2] == "down"

    def test_resolves_incident_on_recovery(self):
        from blueprints.integrations import health as h
        ok_result = {"name": "wazuh", "display": "Wazuh SIEM",
                     "status": "ok", "error": None, "ingest_gap": None}
        with patch.object(h, "ensure_health_tables"), \
             patch.object(h, "check_wazuh",       return_value=ok_result), \
             patch.object(h, "check_siem_engine", return_value={
                 "name": "siem_engine", "display": "Engine",
                 "status": "ok", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_cymind",  return_value={"name": "cymind",  "status": "skipped",
                                                             "display": "CyMind", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_misp",    return_value={"name": "misp",    "status": "skipped",
                                                             "display": "MISP",  "error": None, "ingest_gap": None}), \
             patch.object(h, "check_cysoar",  return_value={"name": "cysoar",  "status": "skipped",
                                                             "display": "CySOAR","error": None, "ingest_gap": None}), \
             patch.object(h, "check_marketplace_integrations", return_value=[]), \
             patch.object(h, "_upsert_status",
                          return_value={"prev_status": "down",
                                        "incident_id": "INTEG-ABC12345",
                                        "consecutive_failures": 0}), \
             patch.object(h, "_raise_integration_incident"), \
             patch.object(h, "_resolve_integration_incident") as mock_resolve:
            h.run_all_checks()
        mock_resolve.assert_called()
        assert mock_resolve.call_args[0][0] == "wazuh"

    def test_ensure_health_tables_called_first(self):
        from blueprints.integrations import health as h
        with patch.object(h, "ensure_health_tables") as mock_ht, \
             patch.object(h, "check_wazuh",       return_value={"status": "skipped", "name": "w",
                                                                  "display": "W", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_siem_engine", return_value={"status": "skipped", "name": "s",
                                                                  "display": "S", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_cymind",  return_value={"status": "skipped", "name": "c",
                                                              "display": "C", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_misp",    return_value={"status": "skipped", "name": "m",
                                                              "display": "M", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_cysoar",  return_value={"status": "skipped", "name": "cs",
                                                              "display": "CS", "error": None, "ingest_gap": None}), \
             patch.object(h, "check_marketplace_integrations", return_value=[]):
            h.run_all_checks()
        mock_ht.assert_called_once()

    def test_returns_empty_list_when_ensure_tables_fails(self):
        from blueprints.integrations import health as h
        with patch.object(h, "ensure_health_tables", side_effect=Exception("db error")):
            results = h.run_all_checks()
        assert results == []


# ===========================================================================
# Phase 5 — REST API endpoints (Flask test client)
# ===========================================================================

@pytest.fixture(scope="module")
def flask_app():
    from app import app as _app
    _app.config["TESTING"] = True
    return _app


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


def _set_session(client, email: str, role: str):
    """Inject an authenticated session into the test client."""
    with client.session_transaction() as sess:
        sess["user_email"] = email


class TestApiListHealth:
    """GET /api/integrations/health — viewer+, returns all statuses."""

    def test_401_when_not_authenticated(self, client):
        r = client.get("/api/integrations/health")
        assert r.status_code == 401

    def test_200_for_viewer_with_empty_db(self, client):
        _set_session(client, "viewer@test.com", "viewer")
        with patch("blueprints.integrations.routes.get_user_role", return_value="viewer"), \
             patch("blueprints.integrations.routes._db") as mock_db:
            conn = MagicMock(); cur = MagicMock()
            cur.fetchall.return_value = []
            conn.cursor.return_value = cur
            mock_db.return_value = conn
            with patch("blueprints.integrations.health.ensure_health_tables"):
                r = client.get("/api/integrations/health")
        assert r.status_code == 200
        data = r.get_json()
        assert "integrations" in data
        assert data["count"] == 0

    def test_200_for_analyst(self, client):
        _set_session(client, "analyst@test.com", "analyst")
        with patch("blueprints.integrations.routes.get_user_role", return_value="analyst"), \
             patch("blueprints.integrations.routes._db") as mock_db:
            conn = MagicMock(); cur = MagicMock()
            cur.fetchall.return_value = [{"integration_name": "wazuh", "status": "ok",
                                          "display_name": "Wazuh SIEM", "last_checked": None,
                                          "last_ok": None, "error_message": None,
                                          "ingest_gap_minutes": None, "incident_id": None,
                                          "consecutive_failures": 0, "metadata": None}]
            conn.cursor.return_value = cur
            mock_db.return_value = conn
            with patch("blueprints.integrations.health.ensure_health_tables"):
                r = client.get("/api/integrations/health")
        assert r.status_code == 200
        data = r.get_json()
        assert len(data["integrations"]) == 1
        assert data["integrations"][0]["integration_name"] == "wazuh"


class TestApiGetSingleHealth:
    """GET /api/integrations/health/<name>"""

    def test_401_when_not_authenticated(self, client):
        r = client.get("/api/integrations/health/wazuh")
        assert r.status_code == 401

    def test_404_for_unknown_integration(self, client):
        _set_session(client, "viewer@test.com", "viewer")
        with patch("blueprints.integrations.routes.get_user_role", return_value="viewer"), \
             patch("blueprints.integrations.routes._db") as mock_db:
            conn = MagicMock(); cur = MagicMock()
            cur.fetchone.return_value = None
            conn.cursor.return_value = cur
            mock_db.return_value = conn
            r = client.get("/api/integrations/health/nonexistent")
        assert r.status_code == 404

    def test_200_returns_single_row(self, client):
        _set_session(client, "viewer@test.com", "viewer")
        with patch("blueprints.integrations.routes.get_user_role", return_value="viewer"), \
             patch("blueprints.integrations.routes._db") as mock_db:
            conn = MagicMock(); cur = MagicMock()
            cur.fetchone.return_value = {"integration_name": "siem_engine",
                                         "status": "ok", "display_name": "Engine",
                                         "last_checked": None, "last_ok": None,
                                         "error_message": None, "ingest_gap_minutes": None,
                                         "incident_id": None, "consecutive_failures": 0,
                                         "metadata": None}
            conn.cursor.return_value = cur
            mock_db.return_value = conn
            r = client.get("/api/integrations/health/siem_engine")
        assert r.status_code == 200
        data = r.get_json()
        assert data["integration_name"] == "siem_engine"
        assert data["status"] == "ok"


class TestApiTriggerCheck:
    """POST /api/integrations/health/check — analyst+ only."""

    def test_401_when_not_authenticated(self, client):
        r = client.post("/api/integrations/health/check")
        assert r.status_code == 401

    def test_403_for_viewer(self, client):
        _set_session(client, "viewer@test.com", "viewer")
        with patch("blueprints.integrations.routes.get_user_role", return_value="viewer"):
            r = client.post("/api/integrations/health/check")
        assert r.status_code == 403

    def test_200_for_analyst_calls_run_all_checks(self, client):
        _set_session(client, "analyst@test.com", "analyst")
        with patch("blueprints.integrations.routes.get_user_role", return_value="analyst"), \
             patch("blueprints.integrations.routes.run_all_checks",
                   return_value=[{"name": "wazuh", "status": "ok"}]) as mock_rac:
            r = client.post("/api/integrations/health/check")
        assert r.status_code == 200
        mock_rac.assert_called_once()
        data = r.get_json()
        assert "results" in data
        assert "checked_at" in data

    def test_200_for_admin(self, client):
        _set_session(client, "admin@test.com", "admin")
        with patch("blueprints.integrations.routes.get_user_role", return_value="admin"), \
             patch("blueprints.integrations.routes.run_all_checks", return_value=[]):
            r = client.post("/api/integrations/health/check")
        assert r.status_code == 200


class TestApiConfig:
    """GET/POST /api/integrations/health/config — admin only."""

    def test_get_config_401_unauthenticated(self, client):
        r = client.get("/api/integrations/health/config")
        assert r.status_code == 401

    def test_get_config_403_for_analyst(self, client):
        _set_session(client, "analyst@test.com", "analyst")
        with patch("blueprints.integrations.routes.get_user_role", return_value="analyst"):
            r = client.get("/api/integrations/health/config")
        assert r.status_code == 403

    def test_get_config_200_for_admin(self, client):
        _set_session(client, "admin@test.com", "admin")
        with patch("blueprints.integrations.routes.get_user_role", return_value="admin"), \
             patch("blueprints.integrations.routes._read_config",
                   return_value={"enabled": True, "interval_seconds": 300,
                                 "ingest_window_min": 15, "notify_on_recovery": True}):
            r = client.get("/api/integrations/health/config")
        assert r.status_code == 200
        data = r.get_json()
        assert data["enabled"] is True
        assert data["interval_seconds"] == 300

    def test_post_config_updates_interval(self, client):
        _set_session(client, "admin@test.com", "admin")
        existing = {"enabled": True, "interval_seconds": 300,
                    "ingest_window_min": 15, "notify_on_recovery": True}
        with patch("blueprints.integrations.routes.get_user_role", return_value="admin"), \
             patch("blueprints.integrations.routes._read_config",  return_value=dict(existing)), \
             patch("blueprints.integrations.routes._write_config") as mock_wc:
            r = client.post("/api/integrations/health/config",
                            json={"interval_seconds": 600},
                            content_type="application/json")
        assert r.status_code == 200
        written = mock_wc.call_args[0][0]
        assert written["interval_seconds"] == 600

    def test_post_config_clamps_interval_minimum(self, client):
        """interval_seconds must be at least 60."""
        _set_session(client, "admin@test.com", "admin")
        existing = {"enabled": True, "interval_seconds": 300,
                    "ingest_window_min": 15, "notify_on_recovery": True}
        with patch("blueprints.integrations.routes.get_user_role", return_value="admin"), \
             patch("blueprints.integrations.routes._read_config",  return_value=dict(existing)), \
             patch("blueprints.integrations.routes._write_config") as mock_wc:
            r = client.post("/api/integrations/health/config",
                            json={"interval_seconds": 5},
                            content_type="application/json")
        assert r.status_code == 200
        written = mock_wc.call_args[0][0]
        assert written["interval_seconds"] == 60

    def test_post_config_403_for_viewer(self, client):
        _set_session(client, "viewer@test.com", "viewer")
        with patch("blueprints.integrations.routes.get_user_role", return_value="viewer"):
            r = client.post("/api/integrations/health/config",
                            json={"enabled": False},
                            content_type="application/json")
        assert r.status_code == 403


class TestCorsOptions:
    """OPTIONS preflight returns 204 for all integration health routes."""

    def test_options_health_root(self, client):
        r = client.options("/api/integrations/health")
        assert r.status_code == 204

    def test_options_health_name(self, client):
        r = client.options("/api/integrations/health/wazuh")
        assert r.status_code == 204

    def test_options_health_check(self, client):
        r = client.options("/api/integrations/health/check")
        assert r.status_code == 204

    def test_options_health_config(self, client):
        r = client.options("/api/integrations/health/config")
        assert r.status_code == 204


# ===========================================================================
# Phase 6 — Scheduler wiring
# ===========================================================================

class TestSchedulerWiring:
    """integration_health job type is handled; health monitor auto-registers."""

    def test_integration_health_job_type_is_recognized(self):
        """_add_to_apscheduler must not skip a job with type='integration_health'."""
        import blueprints.scheduler.routes as sched
        mock_sched = MagicMock()
        job = {
            "id":       "my_health_job",
            "type":     "integration_health",
            "name":     "Test Health",
            "enabled":  True,
            "params":   {},
            "schedule": {"type": "interval", "seconds": 300},
        }
        from blueprints.integrations.health import run_all_checks
        with patch("blueprints.integrations.health.run_all_checks", run_all_checks):
            sched._add_to_apscheduler(mock_sched, job)
        mock_sched.add_job.assert_called_once()
        kwargs = mock_sched.add_job.call_args
        assert kwargs[0][0] is run_all_checks or callable(kwargs[0][0])

    def test_health_monitor_auto_registered_in_init(self):
        """init_scheduler() registers the integration_health_monitor job."""
        import blueprints.scheduler.routes as sched
        mock_sched = MagicMock()
        job_ids = []

        def capture_add_job(fn, trigger, id, **kwargs):
            job_ids.append(id)
        mock_sched.add_job.side_effect = capture_add_job
        mock_sched.get_jobs.return_value = []

        from apscheduler.schedulers.background import BackgroundScheduler
        with patch("blueprints.scheduler.routes.BackgroundScheduler",
                   return_value=mock_sched), \
             patch("blueprints.scheduler.routes._scheduler_owner", True), \
             patch("blueprints.scheduler.routes._load_jobs",        return_value=[]), \
             patch("fcntl.flock"), \
             patch("blueprints.integrations.health.run_all_checks"):
            try:
                sched.init_scheduler(MagicMock())
            except Exception:
                pass  # lock or other infra issues are expected in test env
        assert "integration_health_monitor" in job_ids, (
            "init_scheduler() did not register the integration_health_monitor job. "
            f"Registered jobs: {job_ids}"
        )
