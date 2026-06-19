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
# Module-level token cache
# ---------------------------------------------------------------------------
_cache: dict = {"token": None, "expires_at": 0.0}


def _get_m2m_token() -> str:
    """Return a valid Scalekit M2M access token, refreshing when near-expiry.

    Raises RuntimeError (with the full Scalekit response body) if the token
    endpoint returns non-2xx — never swallow.
    """
    now = time.monotonic()
    if _cache["token"] and now < _cache["expires_at"] - 30:
        return _cache["token"]

    env_url       = os.environ["SCALEKIT_ENVIRONMENT_URL"].rstrip("/")
    client_id     = os.environ["SCALEKIT_CLIENT_ID"]
    client_secret = os.environ["SCALEKIT_CLIENT_SECRET"]

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
