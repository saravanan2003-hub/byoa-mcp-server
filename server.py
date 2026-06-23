"""BYOA MCP server — own-authentication-service + FastMCP todo tools.

This server does two things:

  1. Serves FastMCP todo tools protected by Scalekit BYOA (ScalekitProvider
     validates every tool-call access token against the registered MCP resource).

  2. Acts as the "own authentication service" that Scalekit redirects the MCP
     client browser to during the OAuth flow (/authorize + /login).

Primary motive: detect and surface anything Scalekit sends incorrectly.
  - /authorize: validates that Scalekit forwarded BOTH login_request_id and state
    (missing → 400 + clear message, never silently render the form).
  - /login: posts user_info to Scalekit and exposes the full status + body on any
    non-2xx (never swallow Scalekit errors).

Derived from github.com/scalekit-inc/mcp-auth-demos/tree/main/todo-fastmcp.
"""

import os
import uuid
from dataclasses import asdict, dataclass
from typing import Optional

from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.auth.providers.scalekit import ScalekitProvider
from fastmcp.server.dependencies import AccessToken, get_access_token
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from scalekit_auth import post_user_info, update_credentials

load_dotenv()


# ---------------------------------------------------------------------------
# DynamicScalekitProvider — protected-resource metadata served live
#
# ScalekitProvider's parent (RemoteAuthProvider) calls create_protected_resource_routes()
# at app-build time with a snapshot of authorization_servers.  Because this server
# starts with placeholder values and /configure rewrites resource_id at runtime,
# the frozen route would permanently advertise ".../resources/placeholder" — which
# causes Scalekit to return HTTP 400 on RFC-8414 discovery and MCP clients that
# follow RFC-9728 (e.g. Claude) to fall back to the base URL, bypassing Scalekit.
#
# This subclass overrides get_routes() to drop the frozen route and replace it
# with a handler that builds ProtectedResourceMetadata fresh on every request
# from the live self.resource_id — mirroring the existing dynamic AS-forwarder
# (oauth_authorization_server_metadata, which is already a closure over self).
# ---------------------------------------------------------------------------

class DynamicScalekitProvider(ScalekitProvider):
    """ScalekitProvider variant that serves protected-resource metadata dynamically.

    Fixes the /configure-after-startup pattern: the default implementation
    snapshots authorization_servers at app-build time and never reflects
    later mutations.  This subclass re-reads self.resource_id on every
    /.well-known/oauth-protected-resource/mcp request so the advertised
    authorization_server is always the one set by /configure.
    """

    def get_routes(self, mcp_path=None):
        # Let the parent install all routes — this handles the dynamic
        # AS-forwarder, token-verification routes, etc.
        routes = super().get_routes(mcp_path)

        # Drop the frozen protected-resource route(s) built at startup.
        routes = [
            r for r in routes
            if not (hasattr(r, "path") and r.path.startswith("/.well-known/oauth-protected-resource"))
        ]

        # Build the resource URL (parent already called set_mcp_path() above).
        resource_url = self._get_resource_url(mcp_path)
        if resource_url:
            from urllib.parse import urlparse
            from mcp.shared.auth import ProtectedResourceMetadata
            from mcp.server.auth.json_response import PydanticJSONResponse
            from mcp.server.auth.routes import cors_middleware, build_resource_metadata_url

            provider = self  # close over the live provider instance

            async def _dynamic_protected_resource_metadata(request):
                """Serve RFC-9728 metadata using the live resource_id."""
                metadata = ProtectedResourceMetadata(
                    resource=resource_url,
                    authorization_servers=[
                        AnyHttpUrl(
                            f"{provider.environment_url}/resources/{provider.resource_id}"
                        )
                    ],
                    scopes_supported=(
                        provider._scopes_supported
                        if provider._scopes_supported is not None
                        else provider.token_verifier.scopes_supported
                    ),
                    resource_name=provider.resource_name,
                    resource_documentation=provider.resource_documentation,
                )
                return PydanticJSONResponse(
                    content=metadata,
                    # No-store: different resource_ids are issued each test run;
                    # a cached document from a prior run would send the client to
                    # the wrong authorization_server.
                    headers={"Cache-Control": "no-store"},
                )

            metadata_url = build_resource_metadata_url(resource_url)
            parsed = urlparse(str(metadata_url))
            well_known_path = parsed.path

            # Prepend so it wins over any stale route still in the list.
            routes.insert(
                0,
                Route(
                    well_known_path,
                    endpoint=cors_middleware(_dynamic_protected_resource_metadata, ["GET", "OPTIONS"]),
                    methods=["GET", "OPTIONS"],
                ),
            )

        return routes


# ---------------------------------------------------------------------------
# FastMCP server — resource/relying side
#
# DynamicScalekitProvider is initialised with placeholder values so the server
# starts without any pre-configured resource ID. /configure replaces
# environment_url, resource_id, and the JWTVerifier in-place before each test
# run — no restart needed, one deployment handles all 3 Scalekit environments.
# ---------------------------------------------------------------------------

_DEFAULT_ENV_URL = os.getenv("SCALEKIT_ENVIRONMENT_URL", "https://placeholder.scalekit.com")
_DEFAULT_RESOURCE_ID = "placeholder"

mcp = FastMCP(
    "BYOA Todo Server",
    auth=DynamicScalekitProvider(
        environment_url=_DEFAULT_ENV_URL,
        resource_id=_DEFAULT_RESOURCE_ID,
        # FastMCP appends /mcp automatically; keep base URL with trailing slash.
        base_url=os.getenv("MCP_BASE_URL", "http://localhost:3002/"),
    ),
)


# ---------------------------------------------------------------------------
# Todo tools (in-memory CRUD, scope-gated)
# ---------------------------------------------------------------------------

@dataclass
class TodoItem:
    id: str
    title: str
    description: Optional[str]
    completed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


_TODO_STORE: dict[str, TodoItem] = {}


def _require_scope(scope: str) -> Optional[str]:
    """Return an error string if the active token lacks the given scope."""
    token: AccessToken = get_access_token()
    if scope not in token.scopes:
        return f"Insufficient permissions: `{scope}` scope required."
    return None


@mcp.tool
def create_todo(title: str, description: Optional[str] = None) -> dict:
    """Create a new todo item."""
    error = _require_scope("todo:write")
    if error:
        return {"error": error}
    todo = TodoItem(id=str(uuid.uuid4()), title=title, description=description)
    _TODO_STORE[todo.id] = todo
    return {"todo": todo.to_dict()}


@mcp.tool
def list_todos(completed: Optional[bool] = None) -> dict:
    """List all todos, optionally filtering by completion state."""
    error = _require_scope("todo:read")
    if error:
        return {"error": error}
    todos = [
        t.to_dict() for t in _TODO_STORE.values()
        if completed is None or t.completed == completed
    ]
    return {"todos": todos}


@mcp.tool
def get_todo(todo_id: str) -> dict:
    """Fetch a single todo by its identifier."""
    error = _require_scope("todo:read")
    if error:
        return {"error": error}
    todo = _TODO_STORE.get(todo_id)
    if todo is None:
        return {"error": f"Todo `{todo_id}` not found."}
    return {"todo": todo.to_dict()}


@mcp.tool
def update_todo(
    todo_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    completed: Optional[bool] = None,
) -> dict:
    """Update fields on an existing todo."""
    error = _require_scope("todo:write")
    if error:
        return {"error": error}
    todo = _TODO_STORE.get(todo_id)
    if todo is None:
        return {"error": f"Todo `{todo_id}` not found."}
    if title is not None:
        todo.title = title
    if description is not None:
        todo.description = description
    if completed is not None:
        todo.completed = completed
    return {"todo": todo.to_dict()}


@mcp.tool
def delete_todo(todo_id: str) -> dict:
    """Remove a todo from the store."""
    error = _require_scope("todo:write")
    if error:
        return {"error": error}
    todo = _TODO_STORE.pop(todo_id, None)
    if todo is None:
        return {"error": f"Todo `{todo_id}` not found."}
    return {"deleted": todo_id}


# ---------------------------------------------------------------------------
# Own-authentication-service — runtime config (set per test run via /configure)
#
# The test creates a fresh MCP server in Scalekit, copies the two URL templates,
# then POSTs them here — no pre-configured env vars needed.  This mirrors the
# test_mcp.py pattern where server_resource[0]/[1] are obtained fresh each run.
# ---------------------------------------------------------------------------

_CONFIGURE_SECRET = os.getenv("CONFIGURE_SECRET", "")  # required; protects /configure

# Mutable state updated by /configure on each test run.
_runtime: dict = {
    "user_info_post_url_template": "",
    "redirect_url_template":       "",
    "test_user_sub":               "byoa-test-user-001",
    "test_user_email":             "byoa-test@automation.example",
}

# Per-LRI template snapshot — fixes parallel-test race condition.
# When /configure is called by multiple tests simultaneously, _runtime is overwritten.
# We snapshot the templates at /authorize time (keyed by login_request_id) so that
# /login always uses the templates that were current when *this* LRI was issued.
_lri_templates: dict = {}  # {login_request_id: {post_tmpl, redirect_tmpl}}

_LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BYOA Login</title>
  <style>
    body {{ font-family: system-ui, sans-serif; display:flex; justify-content:center;
            align-items:center; min-height:100vh; margin:0; background:#f0f2f5; }}
    .card {{ background:#fff; border-radius:8px; padding:2rem; width:360px;
             box-shadow:0 2px 8px rgba(0,0,0,.12); }}
    h1 {{ font-size:1.2rem; margin:0 0 1.5rem; }}
    label {{ display:block; font-size:.875rem; margin-bottom:.25rem; color:#555; }}
    input[type=text], input[type=email] {{
      width:100%; padding:.5rem .75rem; border:1px solid #ccc; border-radius:4px;
      box-sizing:border-box; margin-bottom:1rem; font-size:1rem; }}
    button {{ width:100%; padding:.625rem; background:#3b5bdb; color:#fff; border:none;
              border-radius:4px; font-size:1rem; cursor:pointer; }}
    button:hover {{ background:#2f4ac9; }}
    .hint {{ font-size:.75rem; color:#999; margin-top:1rem; text-align:center; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Sign in to continue</h1>
    <form method="post" action="/login">
      <input type="hidden" name="login_request_id" value="{login_request_id}">
      <input type="hidden" name="state"            value="{state}">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" value="{test_email}" required>
      <label for="sub">User ID (sub)</label>
      <input type="text"  id="sub"   name="sub"   value="{test_sub}"   required>
      <button type="submit">Sign in</button>
    </form>
    <p class="hint">Test stub — any submission is accepted by Scalekit.</p>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Own-authentication-service HTTP routes
# ---------------------------------------------------------------------------

@mcp.custom_route("/configure", methods=["POST"])
async def configure(request: Request) -> Response:
    """Called by the test right after creating a fresh MCP server in Scalekit.

    Body (JSON):
      {
        "resource_id":                 "mcp_...",   # REQUIRED — changes every test run
        "user_info_post_url_template": "...",        # REQUIRED — contains {{login_request_id}}
        "redirect_url_template":       "...",        # REQUIRED — contains {{state_value}}
        "environment_url":             "...",        # optional — override for diff SK env
        "client_id":                   "...",        # optional — override M2M credentials
        "client_secret":               "...",        # optional — override M2M credentials
        "test_user_sub":               "...",        # optional
        "test_user_email":             "..."         # optional
      }

    Swaps the ScalekitProvider's resource_id + JWTVerifier in-place so one
    deployment handles all 3 Scalekit environments without a restart.

    Protected by X-Configure-Secret header. Returns 200 on success.
    """
    if not _CONFIGURE_SECRET:
        return PlainTextResponse(
            "CONFIGURE_SECRET env var is not set on this server.", status_code=500
        )
    if request.headers.get("X-Configure-Secret", "") != _CONFIGURE_SECRET:
        return PlainTextResponse("Unauthorized — wrong X-Configure-Secret.", status_code=401)

    try:
        body = await request.json()
    except Exception:
        return PlainTextResponse("Request body must be valid JSON.", status_code=400)

    resource_id   = (body.get("resource_id")                    or "").strip()
    post_tmpl     = (body.get("user_info_post_url_template")     or "").strip()
    redirect_tmpl = (body.get("redirect_url_template")           or "").strip()

    missing = [f for f, v in [
        ("resource_id", resource_id),
        ("user_info_post_url_template", post_tmpl),
        ("redirect_url_template", redirect_tmpl),
    ] if not v]
    if missing:
        return PlainTextResponse(
            f"Missing required fields: {', '.join(missing)}", status_code=400
        )

    # --- Update URL templates + test user ---
    _runtime["user_info_post_url_template"] = post_tmpl
    _runtime["redirect_url_template"]       = redirect_tmpl
    if body.get("test_user_sub"):
        _runtime["test_user_sub"]   = body["test_user_sub"].strip()
    if body.get("test_user_email"):
        _runtime["test_user_email"] = body["test_user_email"].strip()

    # --- Swap ScalekitProvider internals in-place ---
    # environment_url: use override if provided, else keep current value
    env_url = (body.get("environment_url") or "").strip().rstrip("/") \
              or mcp.auth.environment_url

    mcp.auth.environment_url = env_url
    mcp.auth.resource_id     = resource_id

    # Replace the JWTVerifier so token validation uses the new audience + JWKS
    mcp.auth.token_verifier = JWTVerifier(
        jwks_uri=f"{env_url}/keys",
        issuer=env_url,
        algorithm="RS256",
        audience=resource_id,
    )

    # Update authorization_servers so protected-resource metadata points correctly
    mcp.auth.authorization_servers = [
        AnyHttpUrl(f"{env_url}/resources/{resource_id}")
    ]

    # --- Update M2M credentials if overridden (for cross-env tests) ---
    if body.get("client_id") and body.get("client_secret"):
        update_credentials(
            env_url=env_url,
            client_id=body["client_id"].strip(),
            client_secret=body["client_secret"].strip(),
        )

    return PlainTextResponse("configured", status_code=200)


@mcp.custom_route("/authorize", methods=["GET"])
async def authorize(request: Request) -> Response:
    """Scalekit redirects the MCP client's browser here during OAuth initiation.

    Traditional BYOA (ChatGPT / non-PKCE): Scalekit forwards BOTH login_request_id
    and state.  Missing either → 400 (Scalekit defect catch).
    """
    if not _runtime["user_info_post_url_template"]:
        return PlainTextResponse(
            "BYOA server not configured — POST /configure with the MCP server "
            "templates before connecting a client.",
            status_code=503,
        )

    login_request_id = request.query_params.get("login_request_id", "").strip()
    state            = request.query_params.get("state", "").strip()

    missing = [p for p, v in [("login_request_id", login_request_id), ("state", state)] if not v]
    if missing:
        return PlainTextResponse(
            f"BYOA /authorize: Scalekit redirect is missing required param(s): "
            f"{', '.join(missing)}.\n"
            f"Full query: {dict(request.query_params)}\n"
            "Expected both login_request_id and state in the query string.",
            status_code=400,
        )

    # Snapshot the URL templates at /authorize time so /login uses the correct
    # connection even when parallel tests overwrite _runtime["user_info_post_url_template"]
    # between now and when the form is submitted.
    _lri_templates[login_request_id] = {
        "post_tmpl":     _runtime["user_info_post_url_template"],
        "redirect_tmpl": _runtime["redirect_url_template"],
    }

    return HTMLResponse(
        _LOGIN_HTML.format(
            login_request_id=login_request_id,
            state=state,
            test_email=_runtime["test_user_email"],
            test_sub=_runtime["test_user_sub"],
        )
    )


@mcp.custom_route("/login", methods=["POST"])
async def login(request: Request) -> Response:
    """Handle stub-login form submission.

    1. POST user_info to Scalekit's post-user-info endpoint.
    2. On 2xx → 302 to Scalekit's consent redirect URL.
    3. On non-2xx → 502 showing Scalekit's status + full body verbatim
       (primary Scalekit-defect catch point — never swallow).
    """
    form             = await request.form()
    login_request_id = (form.get("login_request_id") or "").strip()
    state            = (form.get("state")            or "").strip()
    email            = (form.get("email")            or _runtime["test_user_email"]).strip()
    sub              = (form.get("sub")              or _runtime["test_user_sub"]).strip()

    if not login_request_id or not state:
        return PlainTextResponse(
            "BYOA /login: login_request_id and state are required form fields.",
            status_code=400,
        )

    # Use the per-LRI snapshot if present (parallel-test safety); fall back to global.
    lri_state     = _lri_templates.pop(login_request_id, None)
    post_tmpl     = lri_state["post_tmpl"]     if lri_state else _runtime["user_info_post_url_template"]
    redirect_tmpl = lri_state["redirect_tmpl"] if lri_state else _runtime["redirect_url_template"]
    if not post_tmpl or not redirect_tmpl:
        return PlainTextResponse(
            "BYOA server not configured — POST /configure first.",
            status_code=503,
        )

    post_url     = post_tmpl.replace("{{login_request_id}}", login_request_id)
    redirect_url = redirect_tmpl.replace("{{state_value}}", state)

    user_info = {
        "sub":            sub,
        "email":          email,
        "email_verified": True,
        "given_name":     "BYOA",
        "family_name":    "Test",
        "name":           "BYOA Test",
    }

    resp = post_user_info(post_url, user_info)

    if not resp.is_success:
        # Show Scalekit's error verbatim — key Scalekit-defect catch surface.
        return HTMLResponse(
            "<pre style='font-family:monospace; padding:1rem'>"
            "Scalekit post-user-info returned an error.\n\n"
            f"URL:    {post_url}\n"
            f"Status: {resp.status_code}\n\n"
            f"Body:\n{resp.text}"
            "</pre>",
            status_code=502,
        )

    return RedirectResponse(redirect_url, status_code=302)


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> Response:
    """Health-check endpoint used by Render and load balancers."""
    return PlainTextResponse("ok")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "3002")),
        stateless_http=True,
    )
