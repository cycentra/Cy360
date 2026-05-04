"""
smtp_service.py — Email notifications for CyCentra 360
======================================================
Used for SSO approval workflow:
  - Notify admin of new SSO login pending approval
  - Notify user when their access is approved or rejected
  - Send test email to verify SMTP config

Configuration is stored in the cy_sso_config table under keys:
  smtp_host           SMTP server hostname
  smtp_port           Port (default 587 for STARTTLS, 465 for SSL)
  smtp_user           Auth username
  smtp_password       Auth password
  smtp_from           "From" address (falls back to smtp_user)
  smtp_admin_email    Destination for admin approval-request emails
  smtp_use_tls        "true"|"false"

Env-var fallbacks (see core/config.py) are used when DB config is absent.
"""

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from core.config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD,
    SMTP_FROM, SMTP_ADMIN_EMAIL, SMTP_USE_TLS,
    FRONTEND_URL,
)

logger = logging.getLogger("cycentra.smtp")

SMTP_CONFIG_KEYS = [
    "smtp_host", "smtp_port", "smtp_user", "smtp_password",
    "smtp_from", "smtp_admin_email", "smtp_use_tls",
]


# ── DB config helpers ─────────────────────────────────────────────────────────

def get_smtp_config() -> dict:
    """
    Load SMTP config from cy_sso_config table.
    Falls back to env vars if the DB row is absent.
    """
    try:
        from blueprints.sso.routes import _sso_db_get_all
        db_cfg = _sso_db_get_all()
    except Exception:
        db_cfg = {}

    return {
        "smtp_host":        db_cfg.get("smtp_host",        SMTP_HOST),
        "smtp_port":        int(db_cfg.get("smtp_port",    SMTP_PORT) or SMTP_PORT),
        "smtp_user":        db_cfg.get("smtp_user",        SMTP_USER),
        "smtp_password":    db_cfg.get("smtp_password",    SMTP_PASSWORD),
        "smtp_from":        db_cfg.get("smtp_from",        SMTP_FROM),
        "smtp_admin_email": db_cfg.get("smtp_admin_email", SMTP_ADMIN_EMAIL),
        "smtp_use_tls":     (db_cfg.get("smtp_use_tls",
                              "true" if SMTP_USE_TLS else "false")).lower() == "true",
    }


def save_smtp_config(data: dict) -> None:
    """Upsert SMTP config keys in cy_sso_config."""
    from blueprints.sso.routes import _sso_db_set
    allowed = set(SMTP_CONFIG_KEYS)
    for k, v in data.items():
        if k not in allowed:
            continue
        if k == "smtp_password" and v == "":
            continue  # never wipe an existing password with empty string
        _sso_db_set(k, str(v))


# ── Core send ─────────────────────────────────────────────────────────────────

def _send_sync(cfg: dict, to: str, subject: str, html: str) -> tuple:
    """
    Synchronous SMTP send.
    Returns (True, None) on success or (False, "error message") on failure.

    Port routing:
      465          → SMTP_SSL (implicit TLS)
      587 / other  → SMTP + STARTTLS when smtp_use_tls=True
      25 / other   → plain SMTP when smtp_use_tls=False
    """
    host = cfg.get("smtp_host", "").strip()
    if not host or not to:
        logger.debug("SMTP not configured — skipping email to %s", to)
        return False, "SMTP host or recipient not set"

    from_addr = (cfg.get("smtp_from") or cfg.get("smtp_user") or "cycentra@noreply.local").strip()
    port      = int(cfg.get("smtp_port", 587) or 587)
    use_tls   = cfg.get("smtp_use_tls", True)
    user      = cfg.get("smtp_user", "")
    password  = cfg.get("smtp_password", "")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = to
    msg.attach(MIMEText(html, "html"))

    try:
        if port == 465:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
                s.ehlo()
                if user and password:
                    s.login(user, password)
                s.sendmail(from_addr, to, msg.as_string())
        elif use_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo()
                s.starttls(context=ctx)
                s.ehlo()
                if user and password:
                    s.login(user, password)
                s.sendmail(from_addr, to, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo()
                if user and password:
                    s.login(user, password)
                s.sendmail(from_addr, to, msg.as_string())

        logger.info("SMTP sent '%s' to %s", subject, to)
        return True, None

    except smtplib.SMTPAuthenticationError as exc:
        err = f"Authentication failed — check smtp_user / smtp_password"
        logger.warning("SMTP auth error to %s: %s", to, exc)
        return False, err
    except smtplib.SMTPException as exc:
        logger.warning("SMTP error sending to %s: %s", to, exc)
        return False, str(exc)
    except Exception as exc:
        logger.warning("SMTP send failed to %s: %s", to, exc)
        return False, str(exc)


# ── Non-blocking send helper ──────────────────────────────────────────────────

def _send_background(to: str, subject: str, html: str) -> None:
    """Fire-and-forget: send in a daemon thread. Errors are logged, never raised."""
    import threading

    def _worker():
        try:
            cfg = get_smtp_config()
            ok, err = _send_sync(cfg, to, subject, html)
            if not ok:
                logger.warning("Background SMTP failed to %s: %s", to, err)
        except Exception as exc:
            logger.warning("Background SMTP exception to %s: %s", to, exc)

    threading.Thread(target=_worker, daemon=True).start()


# ── Email templates ───────────────────────────────────────────────────────────

_BASE_STYLE = """
<div style="font-family:Inter,Helvetica,Arial,sans-serif;max-width:560px;margin:0 auto;
            background:#0d1117;color:#e6edf3;border-radius:10px;
            padding:28px 32px;border:1px solid #21262d">
  <div style="margin-bottom:20px;display:flex;align-items:center;gap:10px">
    <svg width="28" height="28" viewBox="0 0 24 24">
      <polygon points="12,2 22,8 22,16 12,22 2,16 2,8" fill="none" stroke="#00e5a0" stroke-width="1.5"/>
      <circle cx="12" cy="12" r="2" fill="#00e5a0"/>
    </svg>
    <span style="font-size:13px;font-weight:700;color:#00e5a0;
                 letter-spacing:1.5px;font-family:monospace">CYCENTRA 360</span>
  </div>
  {body}
  <hr style="border:none;border-top:1px solid #21262d;margin:24px 0"/>
  <p style="font-size:11px;color:#484f58;margin:0">
    This is an automated notification from CyCentra 360. Do not reply to this email.
  </p>
</div>
"""


def send_approval_request(admin_email: str, user_email: str, user_name: str,
                          provider: str, approve_url: str, reject_url: str) -> None:
    """Email to admin: new SSO user is waiting for approval."""
    body = f"""
      <h2 style="color:#e6edf3;margin-top:0;font-size:20px">New Access Request</h2>
      <p style="color:#8b949e;margin-bottom:16px">
        A user signed in via SSO and requires your approval before accessing CyCentra 360.
      </p>
      <table style="background:#161b22;border-radius:6px;padding:16px 20px;
                    width:100%;border-collapse:collapse;margin-bottom:20px">
        <tr>
          <td style="color:#8b949e;padding:5px 0;width:110px;font-size:13px">Email</td>
          <td style="color:#e6edf3;font-size:13px">{user_email}</td>
        </tr>
        <tr>
          <td style="color:#8b949e;padding:5px 0;font-size:13px">Name</td>
          <td style="color:#e6edf3;font-size:13px">{user_name or "—"}</td>
        </tr>
        <tr>
          <td style="color:#8b949e;padding:5px 0;font-size:13px">Provider</td>
          <td style="color:#e6edf3;font-size:13px">{provider}</td>
        </tr>
      </table>
      <div>
        <a href="{approve_url}"
           style="display:inline-block;background:#00e5a0;color:#0d1117;
                  padding:11px 22px;border-radius:5px;text-decoration:none;
                  font-weight:700;font-size:13px;margin-right:10px">✓ Approve</a>
        <a href="{reject_url}"
           style="display:inline-block;background:rgba(255,59,59,0.12);color:#ff3b3b;
                  border:1px solid rgba(255,59,59,0.35);
                  padding:10px 22px;border-radius:5px;text-decoration:none;
                  font-weight:700;font-size:13px">✗ Reject</a>
      </div>
      <p style="color:#484f58;font-size:11px;margin-top:16px">
        You can also manage pending users at
        <a href="{FRONTEND_URL}" style="color:#00e5a0">{FRONTEND_URL}</a>
        → System Settings → SSO.
      </p>
    """
    html = _BASE_STYLE.format(body=body)
    _send_background(admin_email, "CyCentra 360 — New Access Request", html)


def send_access_approved(user_email: str, user_name: str) -> None:
    """Email to user: their access request was approved."""
    body = f"""
      <h2 style="color:#00e5a0;margin-top:0;font-size:20px">✓ Access Approved</h2>
      <p style="color:#8b949e;margin-bottom:20px">
        Hi {user_name or user_email},<br/><br/>
        Your access request for <strong style="color:#e6edf3">CyCentra 360</strong>
        has been approved. You can now sign in.
      </p>
      <a href="{FRONTEND_URL}"
         style="display:inline-block;background:#00e5a0;color:#0d1117;
                padding:11px 26px;border-radius:5px;text-decoration:none;
                font-weight:700;font-size:13px">Sign in to CyCentra 360</a>
    """
    html = _BASE_STYLE.format(body=body)
    _send_background(user_email, "CyCentra 360 — Access Approved", html)


def send_access_rejected(user_email: str, user_name: str, reason: str = "") -> None:
    """Email to user: their access request was rejected."""
    reason_block = (
        f'<p style="color:#8b949e;font-size:13px"><strong style="color:#e6edf3">Reason:</strong> {reason}</p>'
        if reason else ""
    )
    body = f"""
      <h2 style="color:#ff3b3b;margin-top:0;font-size:20px">✗ Access Denied</h2>
      <p style="color:#8b949e;margin-bottom:12px">
        Hi {user_name or user_email},<br/><br/>
        Your access request for <strong style="color:#e6edf3">CyCentra 360</strong>
        was not approved.
      </p>
      {reason_block}
      <p style="color:#484f58;font-size:12px;margin-top:16px">
        If you believe this is an error, please contact your system administrator.
      </p>
    """
    html = _BASE_STYLE.format(body=body)
    _send_background(user_email, "CyCentra 360 — Access Request Declined", html)


def send_test_email(to: str) -> tuple:
    """Send a test email. Returns (bool, error_msg)."""
    body = """
      <h2 style="color:#00e5a0;margin-top:0">SMTP Test</h2>
      <p style="color:#8b949e">
        This is a test email from CyCentra 360.<br/>
        Your SMTP configuration is working correctly.
      </p>
    """
    html = _BASE_STYLE.format(body=body)
    cfg = get_smtp_config()
    return _send_sync(cfg, to, "CyCentra 360 — SMTP Test", html)
