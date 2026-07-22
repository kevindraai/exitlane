from __future__ import annotations

import asyncio
import sqlite3
import hashlib
import base64
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from exitlane import __version__
from exitlane.core import (
    DB,
    DATA,
    SettingsStorageError,
    WG_DIR,
    command,
    hash_password,
    init,
    set_setting,
    setting,
    verify_password,
)
from exitlane.settings import (
    SettingsUpdate,
    current_general_settings,
    settings_response,
    update_settings,
)
from exitlane.providers.nordvpn import provider
from exitlane.services.diagnostics import run as diagnostics
from exitlane.services.dashboard import DashboardResponse, build_dashboard, system_status
from exitlane.services.wireguard import create as create_wireguard
from exitlane.services.vpn_selection import (
    QUICK_COUNTRIES,
    country_summary,
    measure_servers,
    remember_country,
    select_server,
    server_latency,
)
from exitlane.config import (
    DEFAULT_WIREGUARD_CLIENT,
    DEFAULT_WIREGUARD_INTERFACE,
    DEFAULT_WIREGUARD_DNS,
    DEFAULT_WIREGUARD_PORT,
    DEFAULT_WIREGUARD_SUBNET,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    MAX_REQUEST_BODY_BYTES,
    HTTPS_ONLY,
    SESSION_COOKIE_SECURE,
    SESSION_MAX_AGE_SECONDS,
    validate_config,
)
from exitlane.events import (
    EVENT_DEFINITIONS,
    FILTER_CATEGORIES,
    FILTER_LEVELS,
    EventPage,
    list_events,
    record_event,
)
from exitlane.html import render_index

SYSTEM_WIREGUARD_DIR = Path("/etc/wireguard")
_system_started_databases: set[Path] = set()
_wireguard_observed_state: tuple[bool, bool] | None = None
_pending_provider_connection: dict | None = None


class Admin(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    password: str = Field(
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
    )


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class Token(BaseModel):
    token: str = Field(
        min_length=20,
        max_length=512,
    )


class Callback(BaseModel):
    callback_url: str = Field(
        min_length=20,
        max_length=2048,
    )


class Connect(BaseModel):
    target: str | None = Field(
        default=None,
        max_length=80,
    )


class CountryConnect(BaseModel):
    country_code: str = Field(pattern=r"^[A-Za-z]{2}$")


class WireGuard(BaseModel):
    endpoint: str = Field(
        min_length=1,
        max_length=255,
    )
    subnet: str = DEFAULT_WIREGUARD_SUBNET
    dns: str = Field(
        default=DEFAULT_WIREGUARD_DNS,
        min_length=1,
        max_length=45,
    )
    port: int = Field(
        default=DEFAULT_WIREGUARD_PORT,
        ge=1,
        le=65535,
    )
    interface: str = Field(
        default=DEFAULT_WIREGUARD_INTERFACE,
        pattern=r"^[A-Za-z0-9-]{1,15}$",
    )
    client: str = Field(
        default=DEFAULT_WIREGUARD_CLIENT,
        pattern=r"^[A-Za-z0-9_-]{1,64}$",
    )


class Webhook(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=80,
    )
    url: str = Field(
        min_length=8,
        max_length=2048,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    validate_config()
    init()
    database = DB.resolve()
    if database not in _system_started_databases:
        record_event("system.started")
        _system_started_databases.add(database)
    yield


app = FastAPI(
    title="Exitlane",
    description="Smart egress for every network",
    version=__version__,
    lifespan=lifespan,
)

SESSION_COOKIE = "exitlane_session"
PUBLIC_API_ROUTES = {
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
    ("GET", "/api/auth/session"),
}
SETUP_API_ROUTES = {
    ("GET", "/api/config/public"),
    ("GET", "/api/setup/state"),
    ("POST", "/api/setup/admin"),
    ("POST", "/api/setup/complete"),
    ("GET", "/api/system/network"),
    ("GET", "/api/diagnostics"),
    ("POST", "/api/providers/nordvpn/install"),
    ("GET", "/api/providers/nordvpn/install/status"),
    ("POST", "/api/providers/nordvpn/login/token"),
    ("POST", "/api/providers/nordvpn/login/callback"),
    ("POST", "/api/providers/nordvpn/login/browser/start"),
    ("POST", "/api/providers/nordvpn/configure-defaults"),
    ("GET", "/api/providers/nordvpn/status"),
    ("POST", "/api/ingress/wireguard"),
    ("GET", "/api/ingress/wireguard/status"),
}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PROTECTED_APPLICATION_ROUTES = {"/docs", "/redoc", "/openapi.json"}
SENSITIVE_CACHE_CONTROL = "no-store"


def _theme_script_hash() -> str:
    """Return the CSP hash for the single trusted inline bootstrap script."""
    index_source = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    start = index_source.index("<script>") + len("<script>")
    end = index_source.index("</script>", start)
    digest = hashlib.sha256(index_source[start:end].encode()).digest()
    return base64.b64encode(digest).decode()


CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        f"script-src 'self' 'sha256-{_theme_script_hash()}'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "manifest-src 'self'",
    )
)


def session_user(token: str | None) -> dict | None:
    if not token:
        return None
    now = int(time.time())
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with sqlite3.connect(DB) as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        row = connection.execute(
            """SELECT users.id, users.username FROM sessions
               JOIN users ON users.id = sessions.user_id
               WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
            (token_hash, now),
        ).fetchone()
    return None if row is None else {"id": row[0], "username": row[1]}


def request_has_trusted_origin(request: Request) -> bool:
    """Reject browser cross-site writes; non-browser clients may omit these headers."""
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    source = origin or referer
    if not source:
        return True
    parsed = urlsplit(source)
    host = request.headers.get("host", "")
    if not host or any(character in host for character in "\r\n/\\"):
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and parsed.netloc.casefold() == host.casefold()
    )


def is_setup_client_download(method: str, path: str) -> bool:
    prefix = "/api/ingress/wireguard/client/"
    client_name = path.removeprefix(prefix)
    return method == "GET" and path.startswith(prefix) and bool(client_name) and "/" not in client_name


def request_actor(request: Request) -> dict | None:
    return getattr(request.state, "user", None)


def observe_wireguard_state(*, configured: bool, active: bool, handshake: bool, interface: str, client: str) -> None:
    """Record only confirmed poll transitions; the first observation establishes a baseline."""
    global _wireguard_observed_state
    current = (active, handshake)
    previous = _wireguard_observed_state
    _wireguard_observed_state = current
    if not configured or previous is None:
        return
    if previous[0] != active:
        record_event(
            "wireguard.interface_active" if active else "wireguard.interface_inactive",
            metadata={"interface": interface},
        )
    if not previous[1] and handshake:
        record_event("wireguard.handshake_received", metadata={"client_name": client})


async def require_authentication(request: Request, call_next):
    path = request.url.path
    route = (request.method, path)
    if path.startswith("/api/") and request.method not in SAFE_METHODS:
        # SameSite=Lax is the first CSRF boundary. Origin/Referer validation also
        # protects deployments where an attacker controls another same-site origin.
        if not request_has_trusted_origin(request):
            return JSONResponse(status_code=403, content={"detail": "Request origin not allowed"})
    if path in PROTECTED_APPLICATION_ROUTES:
        user = session_user(request.cookies.get(SESSION_COOKIE))
        if user:
            request.state.user = user
            return await call_next(request)
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    if not path.startswith("/api/") or route in PUBLIC_API_ROUTES:
        return await call_next(request)

    user = session_user(request.cookies.get(SESSION_COOKIE))
    request.state.user = user
    setup_complete = bool(setting("setup_complete", False))
    setup_client_download = is_setup_client_download(request.method, path)
    if user or (not setup_complete and (route in SETUP_API_ROUTES or setup_client_download)):
        return await call_next(request)
    return JSONResponse(status_code=401, content={"detail": "Authentication required"})


@app.middleware("http")
async def security_baseline(request: Request, call_next):
    """Apply request limits and headers at the outermost application boundary."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                response = JSONResponse(status_code=413, content={"detail": "Request body too large"})
            else:
                response = await require_authentication(request, call_next)
        except ValueError:
            response = JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
    else:
        response = await require_authentication(request, call_next)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cache-Control"] = SENSITIVE_CACHE_CONTROL
    if "server" in response.headers:
        del response.headers["server"]
    if HTTPS_ONLY:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response

static_dir = Path(__file__).parent / "static"
app.mount(
    "/assets",
    StaticFiles(directory=static_dir),
    name="assets",
)


@app.get("/", include_in_schema=False, response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(render_index())


@app.get("/api/health")
async def health() -> dict:
    return {
        "ok": True,
        "service": "exitlane",
        "version": __version__,
    }


@app.get("/api/dashboard", response_model=DashboardResponse)
async def dashboard() -> DashboardResponse:
    return await build_dashboard(
        provider.status,
        wireguard_status,
        __version__,
        system_status_call=lambda: system_status(DATA),
    )


@app.get("/api/settings")
async def get_settings() -> dict:
    return settings_response()


@app.put("/api/settings")
async def put_settings(req: SettingsUpdate, request: Request) -> dict:
    before = current_general_settings().model_dump()
    try:
        result = update_settings(req)
    except SettingsStorageError as error:
        raise HTTPException(status_code=503, detail="Settings storage is temporarily unavailable") from error
    after = result["general"]
    changed = [field for field in req.general.model_fields_set if before[field] != after[field]]
    if changed:
        record_event("settings.updated", actor=request.state.user, metadata={"fields": changed})
    return result


@app.post("/api/auth/login")
async def login(req: Login, response: Response) -> dict:
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            "SELECT id, username, password_hash, salt FROM users WHERE username = ?",
            (req.username,),
        ).fetchone()

    # Always run scrypt, including for unknown users, to avoid a username timing oracle.
    valid = verify_password(
        req.password,
        row[2] if row else "0" * 128,
        row[3] if row else "0" * 32,
    )
    if row is None or not valid:
        record_event("auth.login_failed", metadata={"reason": "invalid_credentials"})
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_MAX_AGE_SECONDS
    with sqlite3.connect(DB) as connection:
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (hashlib.sha256(token.encode()).hexdigest(), row[0], expires_at),
        )

    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    record_event("auth.login_succeeded", actor={"id": row[0], "username": row[1]})
    return {"authenticated": True, "user": {"username": row[1]}}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response) -> dict:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with sqlite3.connect(DB) as connection:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            )
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    record_event("auth.logout", actor=request.state.user)
    return {"ok": True}


@app.get("/api/events", response_model=EventPage)
async def get_events(
    limit: int = Query(50, ge=1, le=200),
    cursor: int | None = Query(None, ge=1),
    category: str | None = Query(None),
    level: str | None = Query(None),
    code: str | None = Query(None),
) -> EventPage:
    if category is not None and category not in FILTER_CATEGORIES:
        raise HTTPException(status_code=422, detail="Invalid event category")
    if level is not None and level not in FILTER_LEVELS:
        raise HTTPException(status_code=422, detail="Invalid event level")
    if code is not None and code not in EVENT_DEFINITIONS:
        raise HTTPException(status_code=422, detail="Invalid event code")
    try:
        return list_events(limit=limit, cursor=cursor, category=category, level=level, code=code)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail="Events are temporarily unavailable") from error


@app.get("/api/auth/session")
async def auth_session(request: Request) -> dict:
    user = session_user(request.cookies.get(SESSION_COOKIE))
    return {
        "authenticated": user is not None,
        "user": None if user is None else {"username": user["username"]},
        "setup_complete": bool(setting("setup_complete", False)),
    }


@app.get("/api/setup/state")
async def setup_state() -> dict:
    with sqlite3.connect(DB) as connection:
        admin_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    provider_status = await provider.status()

    steps = {
        "system": bool(setting("setup_system_complete", False)),
        "admin": admin_count > 0,
        "provider": bool(provider_status.get("authenticated", False)),
        "wireguard": bool(setting("wireguard_configured", False)),
    }

    if not steps["system"]:
        current_step = 1
    elif not steps["admin"]:
        current_step = 2
    elif not steps["provider"]:
        current_step = 3
    elif not steps["wireguard"]:
        current_step = 4
    else:
        current_step = 5

    stored_step = int(setting("setup_current_step", current_step))

    if stored_step != current_step:
        set_setting("setup_current_step", current_step)

    return {
        "complete": bool(setting("setup_complete", False)),
        "current_step": current_step,
        "steps": steps,
        "provider": provider_status,
    }


@app.post("/api/setup/admin")
async def create_admin(req: Admin) -> dict:
    digest, salt = hash_password(req.password)

    with sqlite3.connect(DB) as connection:
        admin_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]

        if admin_count:
            raise HTTPException(
                status_code=409,
                detail="An administrator already exists",
            )

        connection.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                salt
            )
            VALUES (?, ?, ?)
            """,
            (
                req.username,
                digest,
                salt,
            ),
        )

    set_setting("setup_current_step", 3)

    return {
        "ok": True,
        "message": "Administrator created",
    }


@app.get("/api/system/network")
async def system_network() -> dict:
    route_rc, route_out, route_err = await command(
        "ip",
        "-4",
        "route",
        "show",
        "table",
        "main",
        "default",
    )

    if route_rc != 0:
        raise HTTPException(
            status_code=500,
            detail=(route_err or "Could not determine the management interface"),
        )

    route_tokens = route_out.split()

    try:
        interface = route_tokens[route_tokens.index("dev") + 1]
    except (ValueError, IndexError) as error:
        raise HTTPException(
            status_code=500,
            detail="Could not parse the management interface",
        ) from error

    address_rc, address_out, address_err = await command(
        "ip",
        "-4",
        "-o",
        "address",
        "show",
        "dev",
        interface,
        "scope",
        "global",
    )

    if address_rc != 0:
        raise HTTPException(
            status_code=500,
            detail=(address_err or "Could not determine the management address"),
        )

    address_tokens = address_out.split()

    try:
        endpoint = address_tokens[address_tokens.index("inet") + 1].split("/", 1)[0]
    except (ValueError, IndexError) as error:
        raise HTTPException(
            status_code=500,
            detail="Could not parse the management address",
        ) from error

    return {
        "interface": interface,
        "endpoint": endpoint,
        "source": "main-default-route",
    }


@app.get("/api/diagnostics")
async def diagnostic_checks() -> dict:
    checks = await diagnostics()
    all_passed = all(check["ok"] for check in checks)

    if all_passed:
        set_setting("setup_system_complete", True)

        current_step = int(setting("setup_current_step", 1))
        if current_step < 2:
            set_setting("setup_current_step", 2)

    return {
        "ok": all_passed,
        "checks": checks,
    }


@app.post("/api/providers/nordvpn/install")
async def install_nordvpn() -> dict:
    return await provider.start_install()


@app.get("/api/providers/nordvpn/install/status")
async def nordvpn_install_status() -> dict:
    return provider.install_status()


@app.post("/api/providers/nordvpn/login/token")
async def login_token(req: Token) -> dict:
    result = await provider.login_token(req.token)

    if result.get("ok"):
        set_setting("setup_provider_complete", True)
        set_setting("setup_current_step", 4)

    return result


@app.post("/api/providers/nordvpn/login/callback")
async def login_callback(req: Callback) -> dict:
    result = await provider.login_callback(req.callback_url)

    if result.get("ok"):
        set_setting("setup_provider_complete", True)
        set_setting("setup_current_step", 4)

    return result


@app.post("/api/providers/nordvpn/configure-defaults")
async def configure_nordvpn_defaults() -> dict:
    results = await provider.defaults()

    return {
        "ok": all(result.get("ok", False) for result in results),
        "operations": results,
    }


@app.get("/api/providers/nordvpn/status")
async def nordvpn_status() -> dict:
    global _pending_provider_connection
    status = await provider.status()
    if _pending_provider_connection and status.get("connected"):
        pending = _pending_provider_connection
        _pending_provider_connection = None
        record_event(
            "provider.connected",
            actor=pending["actor"],
            metadata={
                key: status[key]
                for key in ("country", "city", "server")
                if status.get(key)
            },
            correlation_id=pending["correlation_id"],
        )
    return {"status": {**status, **server_latency(status.get("server"))}}


@app.get("/api/providers/nordvpn/countries")
async def nordvpn_countries() -> dict:
    return {
        "countries": await provider.countries(),
    }


async def _vpn_catalog() -> list[dict]:
    return await provider.countries()


def _country_id(catalog: list[dict], country_code: str) -> int | None:
    return next(
        (item["id"] for item in catalog if item["country_code"] == country_code.upper()), None
    )


@app.get("/api/vpn/status")
async def vpn_status() -> dict:
    status = await provider.status()
    catalog = await _vpn_catalog()
    connected = next(
        (
            item["country_code"]
            for item in catalog
            if item["provider_name"].casefold() == status.get("country", "").casefold()
        ),
        None,
    )
    summary = country_summary(connected) if connected else {}
    return {
        **status,
        "country_code": connected,
        "latency_ms": summary.get("latency_ms"),
        "latency_measured_at": summary.get("latency_measured_at"),
    }


@app.get("/api/vpn/countries")
async def vpn_countries() -> dict:
    catalog, status = await asyncio.gather(_vpn_catalog(), provider.status())
    connected = next(
        (
            item["country_code"]
            for item in catalog
            if item["provider_name"].casefold() == status.get("country", "").casefold()
        ),
        None,
    )
    codes = [item["country_code"] for item in catalog]
    last = setting("vpn.last_country")
    quick = list(dict.fromkeys(code for code in (connected, last, *QUICK_COUNTRIES) if code in codes))
    return {
        "quick_country_codes": quick,
        "countries": [
            country_summary(
                item["country_code"],
                connected_code=connected,
                provider_name=item["provider_name"],
            )
            for item in catalog
        ],
    }


@app.get("/api/vpn/countries/{country_code}/servers")
async def vpn_country_servers(country_code: str) -> dict:
    code = country_code.upper()
    country_id = _country_id(await _vpn_catalog(), code)
    if country_id is None:
        raise HTTPException(404, "Unsupported country")
    return {"country_code": code, "servers": await provider.servers(country_id)}


@app.post("/api/vpn/countries/{country_code}/measure")
async def measure_vpn_country(country_code: str) -> dict:
    code = country_code.upper()
    country_id = _country_id(await _vpn_catalog(), code)
    if country_id is None:
        raise HTTPException(404, "Unsupported country")
    servers = await provider.servers(country_id)
    measurements = await measure_servers(code, servers, force=True)
    return {**country_summary(code), "servers": measurements}


@app.post("/api/vpn/connect")
async def connect_vpn_country(req: CountryConnect, request: Request) -> dict:
    code = req.country_code.upper()
    country_id = _country_id(await _vpn_catalog(), code)
    if country_id is None:
        raise HTTPException(404, "Unsupported country")
    selected = await select_server(code, await provider.servers(country_id))
    target = selected["server"] if selected else code
    result = await connect_nordvpn(Connect(target=target), request)
    if result.get("ok"):
        remember_country(code)
    return {
        **result,
        "success": bool(result.get("ok")),
        "country_code": code,
        "server": selected["server"] if selected else None,
        "latency_ms": selected["latency_ms"] if selected else None,
        "status": result.get("state"),
    }


@app.post("/api/vpn/disconnect")
async def disconnect_vpn(request: Request) -> dict:
    return await disconnect_nordvpn(request)


@app.post("/api/providers/nordvpn/connect")
async def connect_nordvpn(req: Connect, request: Request) -> dict:
    global _pending_provider_connection
    correlation_id = str(uuid.uuid4())
    metadata = {"target": req.target or "recommended"}
    record_event("provider.connect_started", actor=request_actor(request), metadata=metadata, correlation_id=correlation_id)
    result = await provider.connect(req.target)
    if result.get("ok"):
        try:
            status = await provider.status()
        except Exception:  # Provider detail is intentionally not exposed to the event log.
            status = None
        if status and status.get("connected"):
            record_event(
                "provider.connected",
                actor=request_actor(request),
                metadata={
                    key: status[key]
                    for key in ("country", "city", "server")
                    if status.get(key)
                },
                correlation_id=correlation_id,
            )
            _pending_provider_connection = None
        elif status is None:
            record_event(
                "provider.connect_failed",
                actor=request_actor(request),
                metadata={**metadata, "reason": "provider_unavailable"},
                correlation_id=correlation_id,
            )
            _pending_provider_connection = None
        else:
            _pending_provider_connection = {
                "actor": request_actor(request),
                "correlation_id": correlation_id,
            }
    else:
        reason = "invalid_target" if result.get("error_code") == "invalid_target" else "connection_failed"
        record_event("provider.connect_failed", actor=request_actor(request), metadata={**metadata, "reason": reason}, correlation_id=correlation_id)
        _pending_provider_connection = None
    return result


@app.post("/api/providers/nordvpn/disconnect")
async def disconnect_nordvpn(request: Request) -> dict:
    global _pending_provider_connection
    correlation_id = str(uuid.uuid4())
    record_event("provider.disconnect_started", actor=request_actor(request), correlation_id=correlation_id)
    result = await provider.disconnect()
    _pending_provider_connection = None
    record_event(
        "provider.disconnected" if result.get("ok") else "provider.disconnect_failed",
        actor=request_actor(request),
        metadata=None if result.get("ok") else {"reason": "connection_failed"},
        correlation_id=correlation_id,
    )
    return result


@app.post("/api/providers/nordvpn/login/browser/start")
async def start_browser_login() -> dict:
    return await provider.start_browser_login()


async def activate_wireguard_interface(interface: str) -> None:
    source_config = WG_DIR / f"{interface}.conf"
    system_config = SYSTEM_WIREGUARD_DIR / f"{interface}.conf"
    service_name = f"wg-quick@{interface}.service"

    if not source_config.exists():
        raise RuntimeError(f"WireGuard-configuratie ontbreekt: {source_config}")

    SYSTEM_WIREGUARD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    source_config.chmod(0o600)

    if system_config.is_symlink():
        if system_config.resolve() != source_config.resolve():
            system_config.unlink()
            system_config.symlink_to(source_config)
    elif system_config.exists():
        raise RuntimeError(f"{system_config} bestaat al en is geen symlink.")
    else:
        system_config.symlink_to(source_config)

    enable_rc, _, enable_error = await command(
        "systemctl",
        "enable",
        service_name,
    )

    if enable_rc != 0:
        raise RuntimeError(enable_error or "De WireGuard-service kon niet worden ingeschakeld.")

    service_rc, _, _ = await command(
        "systemctl",
        "is-active",
        "--quiet",
        service_name,
    )

    if service_rc != 0:
        link_rc, _, _ = await command(
            "ip",
            "link",
            "show",
            "dev",
            interface,
        )

        if link_rc == 0:
            await command(
                "wg-quick",
                "down",
                str(source_config),
            )

    restart_rc, _, restart_error = await command(
        "systemctl",
        "restart",
        service_name,
    )

    if restart_rc != 0:
        raise RuntimeError(restart_error or "De WireGuard-service kon niet worden gestart.")

    active_rc, _, active_error = await command(
        "systemctl",
        "is-active",
        "--quiet",
        service_name,
    )

    if active_rc != 0:
        raise RuntimeError(active_error or "De WireGuard-service is niet actief geworden.")


@app.post("/api/ingress/wireguard")
async def create_wireguard_ingress(req: WireGuard, request: Request) -> dict:
    global _wireguard_observed_state
    try:
        result = await create_wireguard(
            endpoint=req.endpoint,
            subnet=req.subnet,
            dns=req.dns,
            port=req.port,
            interface=req.interface,
            client=req.client,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error
    except RuntimeError as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        ) from error

    try:
        await activate_wireguard_interface(
            req.interface,
        )
    except RuntimeError as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        ) from error

    set_setting("wireguard_configured", True)
    set_setting("wireguard_client_name", req.client)
    set_setting("wireguard_interface", req.interface)
    set_setting("setup_current_step", 5)

    record_event("wireguard.configuration_generated", actor=request_actor(request), metadata={"client_name": req.client})
    record_event("wireguard.interface_active", actor=request_actor(request), metadata={"interface": req.interface})
    _wireguard_observed_state = (True, False)

    return result


@app.get("/api/ingress/wireguard/client/{name}")
async def wireguard_client_config(name: str) -> FileResponse:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="Invalid client name",
        )

    path = WG_DIR / f"{name}.conf"

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail="WireGuard client configuration not found",
        )

    return FileResponse(
        path=path,
        media_type="application/x-wireguard-profile",
        filename=f"exitlane-{name}.conf",
    )


@app.get("/api/ingress/wireguard/status")
async def wireguard_status() -> dict:
    interface = setting(
        "wireguard_interface",
        DEFAULT_WIREGUARD_INTERFACE,
    )
    client_name = setting(
        "wireguard_client_name",
        DEFAULT_WIREGUARD_CLIENT,
    )

    service_name = f"wg-quick@{interface}.service"

    service_rc, _, _ = await command(
        "systemctl",
        "is-active",
        "--quiet",
        service_name,
    )

    service_active = service_rc == 0

    rc, out, err = await command(
        "wg",
        "show",
        interface,
        "dump",
    )

    if rc != 0:
        configured = bool(setting("wireguard_configured", False))
        observe_wireguard_state(
            configured=configured,
            active=False,
            handshake=False,
            interface=interface,
            client=client_name,
        )
        return {
            "configured": configured,
            "active": False,
            "service_active": service_active,
            "connected": False,
            "interface": interface,
            "client": client_name,
            "message": (err or "De WireGuard-interface is niet actief."),
        }

    lines = [line for line in out.splitlines() if line.strip()]

    peers = []

    for line in lines[1:]:
        columns = line.split("\t")

        if len(columns) < 8:
            continue

        public_key = columns[0]
        endpoint = columns[2]
        latest_handshake = int(columns[4] or 0)
        received_bytes = int(columns[5] or 0)
        sent_bytes = int(columns[6] or 0)

        peers.append(
            {
                "public_key": public_key,
                "endpoint": endpoint,
                "latest_handshake": latest_handshake,
                "received_bytes": received_bytes,
                "sent_bytes": sent_bytes,
            }
        )

    latest_handshake = max(
        (peer["latest_handshake"] for peer in peers),
        default=0,
    )
    configured = bool(setting("wireguard_configured", False))
    observe_wireguard_state(
        configured=configured,
        active=True,
        handshake=latest_handshake > 0,
        interface=interface,
        client=client_name,
    )

    return {
        "configured": configured,
        "active": True,
        "service_active": service_active,
        "connected": latest_handshake > 0,
        "interface": interface,
        "client": client_name,
        "latest_handshake": latest_handshake,
        "peers": peers,
    }


@app.post("/api/notifications/webhook")
async def create_webhook(req: Webhook, request: Request) -> dict:
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="Webhook URL must use HTTP or HTTPS",
        )

    with sqlite3.connect(DB) as connection:
        cursor = connection.execute(
            """
            INSERT INTO webhooks (
                name,
                url
            )
            VALUES (?, ?)
            """,
            (
                req.name,
                req.url,
            ),
        )

    record_event("notifications.webhook_added", actor=request_actor(request), metadata={"name": req.name})

    return {
        "ok": True,
        "id": cursor.lastrowid,
    }


@app.post("/api/setup/complete")
async def complete_setup(request: Request) -> dict:
    state = await setup_state()

    incomplete_steps = [name for name, completed in state["steps"].items() if not completed]

    if incomplete_steps:
        raise HTTPException(
            status_code=409,
            detail=("Setup steps are incomplete: " + ", ".join(incomplete_steps)),
        )

    set_setting("setup_complete", True)
    set_setting("setup_current_step", 5)

    record_event("setup.completed", actor=request_actor(request))

    return {
        "ok": True,
        "message": "Exitlane setup completed",
    }


@app.get("/api/config/public")
async def public_config() -> dict:
    return {
        "password": {
            "minimum_length": MIN_PASSWORD_LENGTH,
            "maximum_length": MAX_PASSWORD_LENGTH,
        },
        "wireguard": {
            "default_interface": DEFAULT_WIREGUARD_INTERFACE,
            "default_subnet": DEFAULT_WIREGUARD_SUBNET,
            "default_port": DEFAULT_WIREGUARD_PORT,
            "default_client": DEFAULT_WIREGUARD_CLIENT,
        },
        "frontend": {
            "provider_refresh_interval_seconds": (
                current_general_settings().provider_refresh_interval_seconds
            ),
        },
    }
