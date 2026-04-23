"""
Regression tests — /api/system/iris/test endpoint

Bug 1 (Cloud CyIRIS):
  POST /api/system/iris/test with {apiKey: "", useStored: true} returns
  {"ok": false, "error": "CyIRIS API Key is required — enter your key in the
  field above"} even when CLOUD_IRIS_API_KEY is set in the environment.
  Root cause: iris_test() had no env-var fallback after the ai_settings.json
  read, unlike the equivalent MISP handler.

Bug 2 (Local CyIRIS):
  POST /api/system/iris/test with a URL that returns HTTP 200 + HTML (wrong
  host / proxy default page) raises json.JSONDecodeError inside ver_resp.json()
  which propagates to the outer except → {"ok": false, "error": "Expecting
  value: line 1 column 1 (char 0)"}.
  Root cause: no JSON validation of /api/ping response before proceeding, and
  ver_resp.json() unguarded.

Both tests FAIL on the code before the fix and PASS after.
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

os.environ.setdefault("CYCENTRA_ENV", "test")
os.environ.setdefault("JWT_SECRET", "testsecret")
os.environ.setdefault("BASE_URL", "https://test.example.com")
os.environ.setdefault("FRONTEND_URL", "https://test.example.com")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key")


@pytest.fixture()
def flask_app():
    from app import app
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"
    return app


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


# ── helpers ───────────────────────────────────────────────────────────────────

def _json_resp(data: dict, status: int = 200) -> MagicMock:
    """Build a mock requests.Response that returns the given dict as JSON."""
    mock = MagicMock()
    mock.status_code = status
    mock.ok = (200 <= status < 300)
    mock.json.return_value = data
    return mock


def _html_resp(status: int = 200) -> MagicMock:
    """Build a mock requests.Response whose .json() raises JSONDecodeError."""
    mock = MagicMock()
    mock.status_code = status
    mock.ok = (200 <= status < 300)
    mock.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
    return mock


# ── Bug 1: Cloud CyIRIS — missing CLOUD_IRIS_API_KEY env-var fallback ─────────

class TestCloudIrisApiKeyFallback:
    """
    The backend must use CLOUD_IRIS_API_KEY from the environment when
    useStored=True and ai_settings.json does not contain the key.
    """

    def test_cloud_iris_uses_env_var_when_settings_file_missing(self, client):
        """
        FAILS before fix: returns "CyIRIS API Key is required".
        PASSES after fix: proceeds to the HTTP probe (mocked to succeed).
        """
        ping_ok   = _json_resp({"status": "success", "message": "pong", "data": []})
        ver_ok    = _json_resp({"status": "success", "message": "", "data": {"iris_current": "2.4.0"}})

        with patch.dict(os.environ, {"CLOUD_IRIS_API_KEY": "test-api-key-abc"}, clear=False):
            with patch("blueprints.system.routes.AI_SETTINGS_FILE") as mock_sf:
                mock_sf.exists.return_value = False          # no settings file
                with patch("blueprints.system.routes.http_requests") as mock_http:
                    mock_http.get.side_effect = [ping_ok, ver_ok]
                    with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                        resp = client.post(
                            "/api/system/iris/test",
                            json={"url": "https://cyiris.cycentra.com", "apiKey": "", "useStored": True},
                            content_type="application/json",
                        )

        data = resp.get_json()
        assert resp.status_code == 200
        assert data["ok"] is True, (
            f"Expected ok=True but got: {data.get('error', data)}\n"
            "This confirms Bug 1 — CLOUD_IRIS_API_KEY env-var fallback is missing."
        )

    def test_cloud_iris_uses_env_var_when_key_absent_from_settings(self, client):
        """
        ai_settings.json exists but has no iris.apiKey — still must use env var.
        FAILS before fix, PASSES after.
        """
        stored_settings = {"iris": {"mode": "cloud"}}          # no apiKey key
        ping_ok = _json_resp({"status": "success", "message": "pong", "data": []})
        ver_ok  = _json_resp({"status": "success", "message": "", "data": {"iris_current": "2.4.0"}})

        with patch.dict(os.environ, {"CLOUD_IRIS_API_KEY": "env-key-xyz"}, clear=False):
            with patch("blueprints.system.routes.AI_SETTINGS_FILE") as mock_sf:
                mock_sf.exists.return_value = True
                mock_sf.read_text.return_value = json.dumps(stored_settings)
                with patch("blueprints.system.routes.http_requests") as mock_http:
                    mock_http.get.side_effect = [ping_ok, ver_ok]
                    with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                        resp = client.post(
                            "/api/system/iris/test",
                            json={"url": "https://cyiris.cycentra.com", "apiKey": "", "useStored": True},
                            content_type="application/json",
                        )

        data = resp.get_json()
        assert data["ok"] is True, (
            f"Expected ok=True but got: {data.get('error', data)}\n"
            "Bug 1: env-var fallback not applied when settings file has no key."
        )

    def test_cloud_iris_fails_cleanly_when_no_key_anywhere(self, client):
        """
        No env var and no stored key → must still return the "API Key required" message.
        This test must PASS both before and after the fix (guard must remain).
        """
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLOUD_IRIS_API_KEY", None)
            with patch("blueprints.system.routes.AI_SETTINGS_FILE") as mock_sf:
                mock_sf.exists.return_value = False
                with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                    resp = client.post(
                        "/api/system/iris/test",
                        json={"url": "https://cyiris.cycentra.com", "apiKey": "", "useStored": True},
                        content_type="application/json",
                    )

        data = resp.get_json()
        assert data["ok"] is False
        assert "API Key" in data.get("error", "")


# ── Bug 2: Local CyIRIS — non-JSON ping response / ver_resp.json() unguarded ──

class TestLocalIrisJsonError:
    """
    When the URL points to a server that returns HTTP 200 + HTML (wrong host /
    default nginx page), the backend must return a clear error — NOT the cryptic
    "Expecting value: line 1 column 1 (char 0)".

    Also covers: if /api/ping succeeds but /api/versions returns non-JSON, the
    ping success must still be reported (with version="unknown").
    """

    def test_non_json_ping_gives_clear_error_not_json_decode_message(self, client):
        """
        /api/ping returns HTTP 200 + HTML body (wrong URL/proxy default page).
        Expected: a clear "not a DFIR IRIS instance" message.
        FAILS before fix (returns "Expecting value…"), PASSES after.
        """
        html_ping = _html_resp(200)   # 200 OK but body is HTML, not JSON

        with patch("blueprints.system.routes.http_requests") as mock_http:
            mock_http.get.return_value = html_ping
            with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                resp = client.post(
                    "/api/system/iris/test",
                    json={"url": "http://127.0.0.1", "apiKey": "localkey", "useStored": False},
                    content_type="application/json",
                )

        data = resp.get_json()
        assert data["ok"] is False
        # The error must NOT be the raw Python JSONDecodeError message
        assert "Expecting value" not in data.get("error", ""), (
            "Bug 2 confirmed: raw JSONDecodeError message exposed to UI. "
            "Should return a user-friendly 'non-JSON response' error instead."
        )

    def test_successful_ping_with_non_json_versions_still_reports_connected(self, client):
        """
        /api/ping returns valid IRIS JSON (auth OK), but /api/versions returns
        non-JSON (e.g. version endpoint not available).  Must still return ok=True
        with version="unknown" — NOT propagate the JSONDecodeError.
        FAILS before fix (raises JSONDecodeError via except Exception), PASSES after.
        """
        ping_ok      = _json_resp({"status": "success", "message": "pong", "data": []})
        ver_html     = _html_resp(200)    # 200 but not JSON

        with patch("blueprints.system.routes.http_requests") as mock_http:
            mock_http.get.side_effect = [ping_ok, ver_html]
            with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                resp = client.post(
                    "/api/system/iris/test",
                    json={"url": "http://127.0.0.1:4443", "apiKey": "localkey", "useStored": False},
                    content_type="application/json",
                )

        data = resp.get_json()
        assert data["ok"] is True, (
            f"Expected ok=True (connected) even when /api/versions is non-JSON, "
            f"but got: {data.get('error', data)}\n"
            "Bug 2: ver_resp.json() exception propagates and hides the successful ping."
        )
        assert "connected" in data.get("message", "").lower()

    def test_ping_json_status_not_success_gives_clear_error(self, client):
        """
        /api/ping returns HTTP 200 JSON but status != "success" (e.g. an error
        page that happens to be JSON).  Must return a clear URL-mismatch error.
        """
        bad_ping = _json_resp({"status": "error", "message": "not found"}, 200)

        with patch("blueprints.system.routes.http_requests") as mock_http:
            mock_http.get.return_value = bad_ping
            with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                resp = client.post(
                    "/api/system/iris/test",
                    json={"url": "http://127.0.0.1", "apiKey": "localkey", "useStored": False},
                    content_type="application/json",
                )

        data = resp.get_json()
        assert data["ok"] is False
        assert "Expecting value" not in data.get("error", "")
