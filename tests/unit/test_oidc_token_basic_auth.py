"""
Regression test — CyIRIS / pyoidc client_secret_basic auth method

Bug: POST /oidc/token with credentials in Authorization: Basic header
     returned 401 {"error": "invalid_client"} because the endpoint only
     read client_id/client_secret from the POST form body.

This test FAILS on code before the fix and PASSES after.
"""

import base64
import json
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

import pytest

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


def _basic_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}"
    return "Basic " + base64.b64encode(raw.encode()).decode()


def _seed_auth_code(flask_app, code: str, client_id: str, email: str):
    """Inject a valid auth code directly into the provider's in-memory store."""
    from blueprints.oidc import provider as oidc_prov
    oidc_prov._AUTH_CODES[code] = {
        "email": email,
        "client_id": client_id,
        "redirect_uri": "https://test.example.com/callback",
        "nonce": "test-nonce",
        "expires": time.time() + 300,
    }


class TestOidcTokenBasicAuth:
    """These tests FAIL before the fix (client_secret_basic not supported)."""

    def test_basic_auth_returns_200_and_id_token(self, client, flask_app):
        """
        When pyoidc (or any client using client_secret_basic) POSTs to /oidc/token
        with credentials in the Authorization: Basic header, the endpoint must
        return 200 with an id_token — not 401.

        REGRESSION: was returning 401 {"error": "invalid_client"}
        """
        from core.config import OIDC_CLIENTS
        # Pick first registered client's real credentials
        client_id = next(iter(OIDC_CLIENTS))
        client_secret = OIDC_CLIENTS[client_id]["client_secret"]

        code = "testcode_basicauth_regression"
        _seed_auth_code(flask_app, code, client_id, "admin@test.local")

        resp = client.post(
            "/oidc/token",
            data={"grant_type": "authorization_code", "code": code},
            headers={"Authorization": _basic_header(client_id, client_secret)},
        )
        assert resp.status_code == 200, (
            f"Expected 200, got {resp.status_code}: {resp.data}"
        )
        body = json.loads(resp.data)
        assert "id_token" in body, (
            f"id_token missing from token response: {body}"
        )

    def test_form_body_still_works_after_fix(self, client, flask_app):
        """client_secret_post must continue to work after the Basic-auth fix."""
        from core.config import OIDC_CLIENTS
        client_id = next(iter(OIDC_CLIENTS))
        client_secret = OIDC_CLIENTS[client_id]["client_secret"]

        code = "testcode_post_regression"
        _seed_auth_code(flask_app, code, client_id, "admin@test.local")

        resp = client.post(
            "/oidc/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        assert resp.status_code == 200
        body = json.loads(resp.data)
        assert "id_token" in body

    def test_basic_auth_wrong_secret_returns_401(self, client, flask_app):
        """Wrong client_secret in Basic auth must still be rejected."""
        from core.config import OIDC_CLIENTS
        client_id = next(iter(OIDC_CLIENTS))

        resp = client.post(
            "/oidc/token",
            data={"grant_type": "authorization_code", "code": "any"},
            headers={"Authorization": _basic_header(client_id, "wrongsecret")},
        )
        assert resp.status_code == 401
