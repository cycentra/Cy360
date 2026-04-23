"""
Regression tests — /api/system/iris/test endpoint

Bug 1 (Cloud CyIRIS):
  POST /api/system/iris/test with {apiKey: "", useStored: true} returns
  {"ok": false, "error": "CyIRIS API Key is required — enter your key in the
  field above"} even when CLOUD_IRIS_API_KEY is set in the environment.
  Root cause: iris_test() had no env-var fallback after the ai_settings.json
  read, unlike the equivalent MISP handler.

Bug 1b (Cloud CyIRIS — URL override):
  Even after the API key is resolved, the function used the URL the UI sent
  (https://cyiris.cycentra.com) which routes through the nginx IAP gate
  (oauth2-proxy) — Bearer tokens are not recognised by the proxy → HTML
  redirect → "Server returned a non-JSON response".
  Fix: resolve URL from CLOUD_IRIS_URL env var (same as iris_connector.py)
  so the internal Docker address (e.g. http://127.0.0.1:4433) is used,
  bypassing the IAP gate entirely.

Bug 2 (Local CyIRIS):
  POST /api/system/iris/test with a URL that returns HTTP 200 + HTML (wrong
  host / proxy default page) raises json.JSONDecodeError inside ver_resp.json()
  which propagates to the outer except → {"ok": false, "error": "Expecting
  value: line 1 column 1 (char 0)"}.
  Root cause: no JSON validation of /api/ping response before proceeding, and
  ver_resp.json() unguarded.

Bug 2b (Local CyIRIS — misleading 403 message):
  "http://127.0.0.1" on the CyCentra server hits CyCentra's own nginx/Flask,
  not CyIRIS. Flask returns 403 (auth middleware). The error "Access denied
  (403 Forbidden)" implies the API key is wrong, not the URL. Fix: detect
  whether the 403 is from a real IRIS instance (has {"status":"error"} JSON)
  vs a non-IRIS server, and surface an appropriate message in each case.

All tests FAIL on the code before the fix and PASS after.
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
        ping_ok = _json_resp({"status": "success", "message": "pong", "data": []})
        ver_ok  = _json_resp({"status": "success", "message": "", "data": {"iris_current": "2.4.0"}})

        with patch.dict(os.environ, {"CLOUD_IRIS_API_KEY": "test-api-key-abc",
                                     "CLOUD_IRIS_URL": "http://127.0.0.1:4433"}, clear=False):
            with patch("blueprints.system.routes.AI_SETTINGS_FILE") as mock_sf:
                mock_sf.exists.return_value = False
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
        assert data["ok"] is True, f"Expected ok=True but got: {data.get('error', data)}"

    def test_cloud_iris_uses_env_var_when_key_absent_from_settings(self, client):
        stored_settings = {"iris": {"mode": "cloud"}}
        ping_ok = _json_resp({"status": "success", "message": "pong", "data": []})
        ver_ok  = _json_resp({"status": "success", "message": "", "data": {"iris_current": "2.4.0"}})

        with patch.dict(os.environ, {"CLOUD_IRIS_API_KEY": "env-key-xyz",
                                     "CLOUD_IRIS_URL": "http://127.0.0.1:4433"}, clear=False):
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
        assert data["ok"] is True, f"Expected ok=True but got: {data.get('error', data)}"

    def test_cloud_iris_fails_cleanly_when_no_key_anywhere(self, client):
        env = {k: v for k, v in os.environ.items() if k != "CLOUD_IRIS_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
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


# ── Bug 1b: Cloud CyIRIS — URL must be overridden with CLOUD_IRIS_URL env var ─

class TestCloudIrisUrlOverride:
    """
    When useStored=True the backend must use CLOUD_IRIS_URL from env (the
    internal Docker address that bypasses the nginx IAP gate) instead of the
    public https://cyiris.DOMAIN URL the UI always sends.
    """

    def test_cloud_iris_uses_internal_url_from_env(self, client):
        """
        CLOUD_IRIS_URL=http://127.0.0.1:4433 — the HTTP probe must be made to
        that address, not to https://cyiris.cycentra.com.
        FAILS before fix (probe goes to wrong URL → non-JSON or IAP HTML),
        PASSES after fix.
        """
        ping_ok = _json_resp({"status": "success", "message": "pong", "data": []})
        ver_ok  = _json_resp({"status": "success", "message": "", "data": {"iris_current": "2.4.0"}})

        internal_url = "http://127.0.0.1:4433"
        called_url = {}

        def fake_get(url, **kwargs):
            called_url["url"] = url
            if "/api/ping" in url:
                return ping_ok
            return ver_ok

        with patch.dict(os.environ, {"CLOUD_IRIS_API_KEY": "key123",
                                     "CLOUD_IRIS_URL": internal_url}, clear=False):
            with patch("blueprints.system.routes.AI_SETTINGS_FILE") as mock_sf:
                mock_sf.exists.return_value = False
                with patch("blueprints.system.routes.http_requests") as mock_http:
                    mock_http.get.side_effect = fake_get
                    with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                        resp = client.post(
                            "/api/system/iris/test",
                            json={"url": "https://cyiris.cycentra.com", "apiKey": "", "useStored": True},
                            content_type="application/json",
                        )

        data = resp.get_json()
        assert data["ok"] is True, f"Expected ok=True but got: {data}"
        assert called_url.get("url", "").startswith(internal_url), (
            f"Expected probe to use internal URL {internal_url!r} "
            f"but it used {called_url.get('url')!r}\n"
            "Bug 1b: CLOUD_IRIS_URL env var not applied to the test URL."
        )

    def test_cloud_iris_falls_back_to_ui_url_when_env_not_set(self, client):
        """
        When CLOUD_IRIS_URL is not in env, the URL from the request body is used.
        """
        ping_ok = _json_resp({"status": "success", "message": "pong", "data": []})
        ver_ok  = _json_resp({"status": "success", "message": "", "data": {"iris_current": "2.4.0"}})

        env_without_url = {k: v for k, v in os.environ.items() if k != "CLOUD_IRIS_URL"}
        with patch.dict(os.environ, {**env_without_url, "CLOUD_IRIS_API_KEY": "key123"}, clear=True):
            with patch("blueprints.system.routes.AI_SETTINGS_FILE") as mock_sf:
                mock_sf.exists.return_value = False
                with patch("blueprints.system.routes.http_requests") as mock_http:
                    mock_http.get.side_effect = [ping_ok, ver_ok]
                    with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                        resp = client.post(
                            "/api/system/iris/test",
                            json={"url": "https://cyiris.cycentra.com", "apiKey": "", "useStored": True},
                            content_type="application/json",
                        )

        data = resp.get_json()
        # Even without CLOUD_IRIS_URL override, if the ping succeeds it should report OK
        assert data["ok"] is True


# ── Bug 2: Local CyIRIS — non-JSON ping response / ver_resp.json() unguarded ──

class TestLocalIrisJsonError:

    def test_non_json_ping_gives_clear_error_not_json_decode_message(self, client):
        html_ping = _html_resp(200)

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
        assert "Expecting value" not in data.get("error", ""), (
            "Bug 2 confirmed: raw JSONDecodeError message exposed to UI."
        )

    def test_successful_ping_with_non_json_versions_still_reports_connected(self, client):
        ping_ok  = _json_resp({"status": "success", "message": "pong", "data": []})
        ver_html = _html_resp(200)

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
            f"Expected ok=True even when /api/versions is non-JSON, got: {data}"
        )
        assert "connected" in data.get("message", "").lower()

    def test_ping_json_status_not_success_gives_clear_error(self, client):
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


# ── Bug 2b: Local CyIRIS — misleading 403 message ────────────────────────────

class TestLocalIris403Message:
    """
    A 403 from a real IRIS instance means the API key has no access.
    A 403 from a non-IRIS server (e.g. CyCentra's own nginx/Flask) means the
    URL is wrong.  The two cases must produce distinct, actionable messages.
    """

    def test_real_iris_403_mentions_api_key(self, client):
        """
        IRIS returns {"status": "error", "message": "Permission denied"} on 403.
        The error message should tell the user to check their API key.
        """
        iris_403 = _json_resp({"status": "error", "message": "Permission denied", "data": []}, 403)
        iris_403.ok = False

        with patch("blueprints.system.routes.http_requests") as mock_http:
            mock_http.get.return_value = iris_403
            with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                resp = client.post(
                    "/api/system/iris/test",
                    json={"url": "http://127.0.0.1:4433", "apiKey": "badkey", "useStored": False},
                    content_type="application/json",
                )

        data = resp.get_json()
        assert data["ok"] is False
        error = data.get("error", "")
        assert "key" in error.lower() or "API" in error, (
            f"Expected API key hint in error for real IRIS 403, got: {error!r}"
        )

    def test_non_iris_403_mentions_url_or_port(self, client):
        """
        A non-IRIS server returns 403 with HTML body.  The error must hint that
        the URL/port may be wrong — NOT that the API key is wrong.
        FAILS before fix (was "Access denied (403 Forbidden)" with no URL hint),
        PASSES after fix.
        """
        non_iris_403 = _html_resp(403)
        non_iris_403.ok = False

        with patch("blueprints.system.routes.http_requests") as mock_http:
            mock_http.get.return_value = non_iris_403
            with patch("blueprints.system.routes.add_cors_headers", side_effect=lambda r: r):
                resp = client.post(
                    "/api/system/iris/test",
                    json={"url": "http://127.0.0.1", "apiKey": "anykey", "useStored": False},
                    content_type="application/json",
                )

        data = resp.get_json()
        assert data["ok"] is False
        error = data.get("error", "")
        assert "port" in error.lower() or "url" in error.lower() or "wrong" in error.lower(), (
            f"Expected URL/port hint for non-IRIS 403, got: {error!r}\n"
            "Bug 2b: non-IRIS 403 gives misleading 'Access denied' message."
        )


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
