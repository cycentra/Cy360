"""
blueprints/oidc/provider.py
============================
OIDC Identity Provider — CyCentra acts as the IdP for CyIRIS and CySOAR.

Routes (all under /oidc/):
  GET  /oidc/.well-known/openid-configuration
  GET  /oidc/jwks
  GET  /oidc/authorize
  POST /oidc/token
  GET  /oidc/userinfo
  POST /oidc/introspect
"""

import hashlib
import json
import os
import time
import uuid
import urllib.parse
import base64
from pathlib import Path

from flask import Blueprint, request, redirect, jsonify, session

from core.config import BASE_URL, FRONTEND_URL, OIDC_CLIENTS, JWT_SECRET, TOKEN_TTL
from blueprints.rbac.manager import get_user_role, get_user_apps, user_can_access_client
from core.helpers import auth_event

try:
    import jwt as pyjwt
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

# ── RSA key for RS256 JWT signing (required for OpenSearch/Wazuh OIDC) ────────
_RSA_KEY_FILE = Path(os.environ.get("OIDC_RSA_KEY_FILE", "/opt/cycentra/oidc_private.pem"))
_RSA_AVAILABLE  = False
_JWT_PRIVATE_KEY = None
_JWT_PUBLIC_KEY  = None
_JWK_CACHE: dict = {}

if _JWT_AVAILABLE:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        if _RSA_KEY_FILE.exists():
            with open(_RSA_KEY_FILE, "rb") as _f:
                _JWT_PRIVATE_KEY = serialization.load_pem_private_key(_f.read(), password=None)
        else:
            _JWT_PRIVATE_KEY = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            try:
                _RSA_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(_RSA_KEY_FILE, "wb") as _f:
                    _f.write(_JWT_PRIVATE_KEY.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))
            except OSError:
                pass  # in-memory key only; persisted on next writable startup

        _JWT_PUBLIC_KEY = _JWT_PRIVATE_KEY.public_key()
        pub_numbers = _JWT_PUBLIC_KEY.public_numbers()

        def _int_to_base64url(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        _kid = hashlib.sha256(str(pub_numbers.n).encode()).hexdigest()[:16]
        _JWK_CACHE = {
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": _kid,
            "n": _int_to_base64url(pub_numbers.n),
            "e": _int_to_base64url(pub_numbers.e),
        }
        _RSA_AVAILABLE = True
    except Exception:
        _RSA_AVAILABLE = False

oidc_bp = Blueprint("oidc", __name__)

# Server-side auth code store (avoids client-session limitation on s2s token exchange)
_AUTH_CODES: dict = {}


# ── Discovery & JWKS ─────────────────────────────────────────────────────────

@oidc_bp.route("/oidc/.well-known/openid-configuration")
def oidc_discovery():
    return jsonify({
        "issuer":                                f"{BASE_URL}/oidc",
        "authorization_endpoint":                f"{BASE_URL}/oidc/authorize",
        "token_endpoint":                        f"{BASE_URL}/oidc/token",
        "userinfo_endpoint":                     f"{BASE_URL}/oidc/userinfo",
        "introspection_endpoint":                f"{BASE_URL}/oidc/introspect",
        "jwks_uri":                              f"{BASE_URL}/oidc/jwks",
        "response_types_supported":              ["code"],
        "grant_types_supported":                 ["authorization_code"],
        "subject_types_supported":               ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        "scopes_supported":                      ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported":                      ["sub", "iss", "email", "name", "roles", "apps"],
    })


@oidc_bp.route("/oidc/jwks")
def oidc_jwks():
    if _RSA_AVAILABLE and _JWK_CACHE:
        return jsonify({"keys": [_JWK_CACHE]})
    return jsonify({"keys": []})


# ── Authorize ─────────────────────────────────────────────────────────────────

@oidc_bp.route("/oidc/authorize")
def oidc_authorize():
    client_id    = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    state        = request.args.get("state", "")
    nonce        = request.args.get("nonce", "")

    client = OIDC_CLIENTS.get(client_id)
    if not client:
        return jsonify({"error": "unknown_client"}), 400
    if redirect_uri not in client["redirect_uris"]:
        return jsonify({"error": "invalid_redirect_uri"}), 400

    user_email = session.get("user_email")
    if not user_email:
        return_to = BASE_URL + "/oidc/authorize?" + urllib.parse.urlencode(request.args)
        return redirect(f"{FRONTEND_URL}?oidc_return={urllib.parse.quote(return_to)}")

    if not user_can_access_client(user_email, client_id):
        params = urllib.parse.urlencode({
            "error":             "access_denied",
            "error_description": f"Your account is not permitted to access {client_id}",
            "state":             state,
        })
        return redirect(f"{redirect_uri}?{params}")

    code = hashlib.sha256(
        f"{user_email}:{client_id}:{state}:{time.time()}".encode()
    ).hexdigest()[:32]

    _AUTH_CODES[code] = {
        "email":        user_email,
        "client_id":    client_id,
        "redirect_uri": redirect_uri,
        "nonce":        nonce,
        "expires":      time.time() + 300,
    }

    params = urllib.parse.urlencode({"code": code, "state": state})
    return redirect(f"{redirect_uri}?{params}")


# ── Token ─────────────────────────────────────────────────────────────────────

@oidc_bp.route("/oidc/token", methods=["POST"])
def oidc_token():
    grant_type    = request.form.get("grant_type")
    code          = request.form.get("code")
    client_id     = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    # Support client_secret_basic (RFC 6749 §2.3.1) — pyoidc sends credentials
    # in Authorization: Basic header by default; client_secret_post reads from form.
    if not client_id or not client_secret:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                client_id, client_secret = decoded.split(":", 1)
            except Exception:
                pass

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    client = OIDC_CLIENTS.get(client_id)
    if not client or client["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    code_data = _AUTH_CODES.pop(code, None)
    if not code_data or code_data.get("client_id") != client_id:
        return jsonify({"error": "invalid_grant"}), 400
    if time.time() > code_data.get("expires", 0):
        return jsonify({"error": "invalid_grant", "error_description": "Code expired"}), 400

    email = code_data["email"]
    now   = int(time.time())

    payload = {
        "iss":   f"{BASE_URL}/oidc",
        "sub":   email,
        "aud":   client_id,
        "iat":   now,
        "exp":   now + TOKEN_TTL,
        "email": email,
        "name":  session.get("user_name", ""),
        "roles": [get_user_role(email)],
        "apps":  get_user_apps(email),
        **( {"nonce": code_data["nonce"]} if code_data.get("nonce") else {} ),
    }
    # pyoidc-based clients (e.g. cyiris) verify id_token using client_secret (HS256).
    # They do not fetch JWKS, so RS256 fails silently — id_token dropped from response.
    # OpenSearch (cysiem) requires RS256 verifiable via JWKS.
    # All other clients (cysoar) don't verify id_token at all — either works.
    _RS256_CLIENTS = {"cysiem"}
    if _JWT_AVAILABLE and _RSA_AVAILABLE and client_id in _RS256_CLIENTS:
        id_token = pyjwt.encode(payload, _JWT_PRIVATE_KEY, algorithm="RS256",
                                headers={"kid": _kid})
    elif _JWT_AVAILABLE:
        id_token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
    else:
        payload  = json.dumps({"sub": email, "email": email, "iss": f"{BASE_URL}/oidc"}).encode()
        id_token = base64.b64encode(payload).decode()

    access_token = hashlib.sha256(
        f"{email}:{now}:{uuid.uuid4()}".encode()
    ).hexdigest()
    session[f"at_{access_token}"] = {
        "email":     email,
        "client_id": client_id,
        "exp":       now + TOKEN_TTL,
    }

    auth_event("oidc_token", email, client_id, "success")
    return jsonify({
        "access_token": access_token,
        "token_type":   "Bearer",
        "expires_in":   TOKEN_TTL,
        "id_token":     id_token,
        "scope":        "openid email profile",
    })


# ── UserInfo ──────────────────────────────────────────────────────────────────

@oidc_bp.route("/oidc/userinfo")
def oidc_userinfo():
    auth  = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    data  = session.get(f"at_{token}")

    if not data or time.time() > data.get("exp", 0):
        return jsonify({"error": "invalid_token"}), 401

    email = data["email"]
    return jsonify({
        "sub":   email,
        "email": email,
        "name":  session.get("user_name", ""),
        "roles": [get_user_role(email)],
        "apps":  get_user_apps(email),
    })


# ── Introspect ────────────────────────────────────────────────────────────────

@oidc_bp.route("/oidc/introspect", methods=["POST"])
def oidc_introspect():
    token     = request.form.get("token", "")
    client_id = request.form.get("client_id", "")
    data      = session.get(f"at_{token}")

    if not data or time.time() > data.get("exp", 0):
        return jsonify({"active": False})

    email = data["email"]
    return jsonify({
        "active":    True,
        "sub":       email,
        "email":     email,
        "client_id": client_id,
        "roles":     [get_user_role(email)],
        "apps":      get_user_apps(email),
        "exp":       data.get("exp"),
    })
