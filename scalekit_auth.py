"""Minimal Scalekit M2M token cache and post-user-info helper.

The ONLY external call we make is the standard OAuth2 client-credentials
token endpoint plus the post-user-info call it authorises.
No Scalekit SDK — just httpx, to stay lean and to avoid hiding what Scalekit
actually sends back.
"""

import os
import time

import httpx
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Module-level credentials + token cache
# Defaults come from env vars (set once in Render).
# /configure can override them when switching Scalekit environments.
# ---------------------------------------------------------------------------
_creds: dict = {
    "env_url":       os.getenv("SCALEKIT_ENVIRONMENT_URL", "").rstrip("/"),
    "client_id":     os.getenv("SCALEKIT_CLIENT_ID", ""),
    "client_secret": os.getenv("SCALEKIT_CLIENT_SECRET", ""),
}
_cache: dict = {"token": None, "expires_at": 0.0}


def update_credentials(env_url: str, client_id: str, client_secret: str) -> None:
    """Override M2M credentials at runtime (called by /configure for cross-env tests)."""
    _creds["env_url"]       = env_url.rstrip("/")
    _creds["client_id"]     = client_id
    _creds["client_secret"] = client_secret
    # Invalidate cached token so next call fetches a fresh one for the new env
    _cache["token"]      = None
    _cache["expires_at"] = 0.0


def _get_m2m_token() -> str:
    """Return a valid Scalekit M2M access token, refreshing when near-expiry.

    Raises RuntimeError (with the full Scalekit response body) if the token
    endpoint returns non-2xx — never swallow.
    """
    now = time.monotonic()
    if _cache["token"] and now < _cache["expires_at"] - 30:
        return _cache["token"]

    env_url       = _creds["env_url"] or os.environ["SCALEKIT_ENVIRONMENT_URL"].rstrip("/")
    client_id     = _creds["client_id"] or os.environ["SCALEKIT_CLIENT_ID"]
    client_secret = _creds["client_secret"] or os.environ["SCALEKIT_CLIENT_SECRET"]

    resp = httpx.post(
        f"{env_url}/oauth/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
        },
        timeout=10,
    )
    if not resp.is_success:
        raise RuntimeError(
            f"Failed to fetch Scalekit M2M token.\n"
            f"Status: {resp.status_code}\nBody: {resp.text}"
        )

    data       = resp.json()
    token      = data["access_token"]
    expires_in = int(data.get("expires_in", 3600))

    _cache["token"]      = token
    _cache["expires_at"] = now + expires_in
    return token


def create_auth_request(env_url: str, conn_id: str, pkce_params: dict) -> tuple:
    """Create a Scalekit auth-request for a PKCE/MCP-OAuth2 flow.

    Passes the full PKCE context so Scalekit can tie the new auth-request to
    the Claude session that triggered this /authorize redirect.

    Returns (login_request_id, error_message).
    On success: (non-empty string, "")
    On failure: ("", descriptive error message with Scalekit's response body)
    """
    try:
        token = _get_m2m_token()
        resp = httpx.post(
            f"{env_url.rstrip('/')}/api/v1/connections/{conn_id}/auth-requests",
            headers={"Authorization": f"Bearer {token}"},
            json=pkce_params,
            timeout=10,
        )
        if resp.is_success:
            lr_id = resp.json().get("login_request_id", "")
            if lr_id:
                return lr_id, ""
            return "", f"auth-requests API returned 2xx but no login_request_id in body: {resp.text}"
        return "", f"auth-requests API returned HTTP {resp.status_code}: {resp.text}"
    except Exception as exc:
        return "", f"Exception calling auth-requests API (env={env_url!r}, conn={conn_id!r}): {exc}"


def post_user_info(post_url: str, user_info: dict) -> httpx.Response:
    """POST user_info to the Scalekit own-auth post-user-info endpoint.

    Returns the raw httpx.Response so the caller can inspect status AND body.
    Does NOT raise on non-2xx — server.py is responsible for surfacing errors
    to the browser verbatim.
    """
    token = _get_m2m_token()
    return httpx.post(
        post_url,
        json=user_info,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        },
        timeout=10,
    )
