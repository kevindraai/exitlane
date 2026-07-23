from __future__ import annotations

import asyncio
import logging
import sqlite3
import hashlib
import base64
import ipaddress
import re
import time
import uuid
from io import BytesIO
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import AsyncIterator
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import segno
import pyotp

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
    set_settings,
    setting,
    verify_password,
)
from exitlane.settings import (
    SettingsUpdate,
    current_general_settings,
    settings_response,
    update_settings,
)
from exitlane.providers.nordvpn import SIGN_OUT_ERROR_CODES, TOKEN_ERROR_CODES, provider
from exitlane.providers.registry import ProviderNotFound, ProviderRegistry
from exitlane.services.diagnostics import run as diagnostics
from exitlane.services.dashboard import DashboardResponse, build_dashboard, system_status
from exitlane.services import wireguard as wireguard_service
from exitlane.services.vpn_selection import (
    QUICK_COUNTRIES,
    country_summary,
    measure_servers,
    remember_country,
    select_server,
    server_latency,
)
from exitlane.services import vpn_operations
from exitlane.services.credentials import CredentialError, change_password
from exitlane.services import auth_security
from exitlane.services import network_security
from exitlane.services import killswitch
from exitlane.proxy import deployment_status, normalized_origin, request_security, trusted_origin
from exitlane.config import (
    DEFAULT_WIREGUARD_CLIENT,
    DEFAULT_WIREGUARD_INTERFACE,
    DEFAULT_WIREGUARD_DNS,
    DEFAULT_WIREGUARD_PORT,
    DEFAULT_WIREGUARD_SUBNET,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    MAX_REQUEST_BODY_BYTES,
    SESSION_COOKIE_POLICY,
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
_wireguard_generation_lock: asyncio.Lock | None = None
_password_change_failures: dict[tuple[Path, int], deque[float]] = defaultdict(deque)
_provider_sign_out_failures: dict[tuple[Path, int], deque[float]] = defaultdict(deque)
_login_failures: dict[tuple[Path, str, str], deque[float]] = defaultdict(deque)
_security_rejection_logs: dict[str, deque[float]] = defaultdict(deque)
_network_reauth_failures: dict[tuple[Path, int], deque[float]] = defaultdict(deque)
_killswitch_reauth_failures: dict[tuple[Path, int], deque[float]] = defaultdict(deque)
logger = logging.getLogger("exitlane.security")
PASSWORD_CHANGE_ATTEMPTS = 5
PASSWORD_CHANGE_WINDOW_SECONDS = 300
PROVIDER_SIGN_OUT_ATTEMPTS = 5
PROVIDER_SIGN_OUT_WINDOW_SECONDS = 60
LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
SECURITY_REJECTION_LOG_ATTEMPTS = 5
SECURITY_REJECTION_LOG_WINDOW_SECONDS = 60
NETWORK_REAUTH_ATTEMPTS = 5
NETWORK_REAUTH_WINDOW_SECONDS = 300
NORDVPN_HOST_COUNTRY_CODES = {"UK": "GB"}
provider_registry = ProviderRegistry([provider], default_id=provider.id)


def observe_auth_phase(_request: Request, _phase: str) -> None:
    """Stable no-op seam for tests that prove where an authentication request stops."""


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


class MfaVerify(BaseModel):
    code: str = Field(min_length=6, max_length=64)
    mode: str = Field(default="totp", pattern=r"^(totp|recovery)$")


class KillswitchChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    code: str | None = Field(default=None, min_length=6, max_length=64)
    confirm_access_loss: bool = False


def _reauthenticate_killswitch(req: KillswitchChange, request: Request) -> None:
    user = request.state.user
    failure_key = (DB.resolve(), user["id"])
    now = time.monotonic()
    failures = _killswitch_reauth_failures[failure_key]
    while failures and failures[0] <= now - NETWORK_REAUTH_WINDOW_SECONDS:
        failures.popleft()
    if len(failures) >= NETWORK_REAUTH_ATTEMPTS:
        raise HTTPException(status_code=429, detail="too_many_attempts")
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            "SELECT password_hash,salt,mfa_enabled FROM users WHERE id=?", (user["id"],)
        ).fetchone()
    if not row or not verify_password(req.current_password, row[0], row[1]):
        failures.append(now)
        raise HTTPException(status_code=401, detail="invalid_credentials")
    if row[2] and (not req.code or not auth_security.verify_totp(user["id"], req.code)):
        failures.append(now)
        raise HTTPException(status_code=401, detail="invalid_mfa_code")
    if not req.confirm_access_loss:
        raise HTTPException(status_code=409, detail="access_loss_confirmation_required")
    _killswitch_reauth_failures.pop(failure_key, None)


class MfaEnrollmentStart(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class MfaEnrollmentConfirm(BaseModel):
    enrollment: str = Field(min_length=20, max_length=128)
    code: str = Field(min_length=6, max_length=8)


class MfaDisable(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    code: str = Field(min_length=6, max_length=8)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    confirmation: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class NetworkSecurityUpdate(BaseModel):
    public_url: str = Field(default="", max_length=network_security.MAX_PUBLIC_URL_LENGTH)
    trusted_proxies: list[str] = Field(default_factory=list, max_length=64)
    secure_cookie_policy: str = Field(pattern=r"^(auto|always|never)$")
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    code: str | None = Field(default=None, min_length=6, max_length=8)
    confirm_broad_trust: bool = False
    confirm_access_loss: bool = False


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


class ProviderReconnect(BaseModel):
    country_code: str | None = Field(default=None, pattern=r"^[A-Za-z]{2}$")


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
    auth_security.ensure_master_key()
    database = DB.resolve()
    if database not in _system_started_databases:
        record_event("system.started")
        _system_started_databases.add(database)
    monitor = asyncio.create_task(_monitor_killswitch())
    try:
        yield
    finally:
        monitor.cancel()
        with suppress(asyncio.CancelledError):
            await monitor


async def _monitor_killswitch() -> None:
    previous: str | None = None
    previous_facts: killswitch.TunnelFacts | None = None
    while True:
        await asyncio.sleep(5)
        if not setting(killswitch.SETTING_CONFIGURED, False):
            previous = None
            previous_facts = None
            continue
        try:
            selected = provider_registry.get(
                setting("vpn.provider_id", provider_registry.default_id)
            )
            facts = await selected.network_facts()
            current = (
                await killswitch.reconcile(facts)
                if facts != previous_facts
                else await killswitch.status(facts)
            )
            previous_facts = facts
        except (killswitch.KillswitchError, ProviderNotFound):
            if previous != "error":
                record_event(
                    "network.killswitch_error", metadata={"reason": "firewall_apply_failed"}
                )
            previous = "error"
            continue
        if current.state != previous:
            if current.state == "enabled_protected" and previous is not None:
                record_event("network.killswitch_released")
            elif current.state in {"enabled_waiting_for_tunnel", "enabled_degraded"}:
                record_event("network.killswitch_engaged", metadata={"reason": current.reason})
            previous = current.state


app = FastAPI(
    title="Exitlane",
    description="Smart egress for every network",
    version=__version__,
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def safe_request_validation_error(
    _request: Request, _error: RequestValidationError
) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": "invalid_request"})


SESSION_COOKIE = "exitlane_session"
MFA_CHALLENGE_COOKIE = "exitlane_mfa_challenge"
# Kept for compatibility with integrations importing the former boolean.
SESSION_COOKIE_SECURE = SESSION_COOKIE_POLICY == "always"
PUBLIC_API_ROUTES = {
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/mfa"),
    ("DELETE", "/api/auth/mfa"),
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
    return auth_security.session_user(token)


def request_origin_rejection(request: Request) -> str | None:
    """Reject browser cross-site writes; non-browser clients may omit these headers."""
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    source = origin or referer
    if not source:
        return None
    security = request_security(request)
    if security.forwarded_rejected:
        return "deployment_origin_mismatch"
    actual = normalized_origin(source)
    expected = normalized_origin(trusted_origin(request, security))
    if actual is None:
        return "invalid_origin"
    if expected is None or actual != expected:
        return "invalid_origin"
    return None


def request_has_trusted_origin(request: Request) -> bool:
    return request_origin_rejection(request) is None


def log_security_rejection(reason: str) -> None:
    now = time.monotonic()
    attempts = _security_rejection_logs[reason]
    while attempts and attempts[0] <= now - SECURITY_REJECTION_LOG_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) < SECURITY_REJECTION_LOG_ATTEMPTS:
        logger.warning("Request rejected by deployment security: reason=%s", reason)
        attempts.append(now)


def is_setup_client_download(method: str, path: str) -> bool:
    prefix = "/api/ingress/wireguard/client/"
    client_name = path.removeprefix(prefix)
    return (
        method == "GET" and path.startswith(prefix) and bool(client_name) and "/" not in client_name
    )


def is_setup_provider_route(method: str, path: str) -> bool:
    if method != "POST":
        return False
    match = re.fullmatch(r"/api/vpn/providers/([a-z0-9_-]+)/authenticate", path)
    if not match:
        return False
    try:
        provider_registry.get(match.group(1))
    except ProviderNotFound:
        return False
    return True


def request_actor(request: Request) -> dict | None:
    return getattr(request.state, "user", None)


def observe_wireguard_state(
    *, configured: bool, active: bool, handshake: bool, interface: str, client: str
) -> None:
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
        if reason := request_origin_rejection(request):
            log_security_rejection(reason)
            return JSONResponse(status_code=403, content={"detail": reason})
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
    setup_provider_route = is_setup_provider_route(request.method, path)
    if user or (
        not setup_complete
        and (route in SETUP_API_ROUTES or setup_client_download or setup_provider_route)
    ):
        return await call_next(request)
    return JSONResponse(status_code=401, content={"detail": "Authentication required"})


@app.middleware("http")
async def security_baseline(request: Request, call_next):
    """Apply request limits and headers at the outermost application boundary."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                response = JSONResponse(
                    status_code=413, content={"detail": "Request body too large"}
                )
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
    if request_security(request).scheme == "https":
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
        raise HTTPException(
            status_code=503, detail="Settings storage is temporarily unavailable"
        ) from error
    after = result["general"]
    changed = [field for field in req.general.model_fields_set if before[field] != after[field]]
    if changed:
        record_event("settings.updated", actor=request.state.user, metadata={"fields": changed})
    return result


def _cookie_secure(request: Request) -> bool:
    return SESSION_COOKIE_SECURE or request_security(request).secure_cookie


@app.post("/api/auth/login")
async def login(req: Login, request: Request, response: Response) -> dict:
    observe_auth_phase(request, "login_handler")
    client_ip = request_security(request).client_ip
    failure_key = (DB.resolve(), req.username.casefold(), client_ip)
    now_monotonic = time.monotonic()
    failures = _login_failures[failure_key]
    while failures and failures[0] <= now_monotonic - LOGIN_WINDOW_SECONDS:
        failures.popleft()
    if len(failures) >= LOGIN_ATTEMPTS:
        raise HTTPException(status_code=429, detail="too_many_attempts")
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            "SELECT id, username, password_hash, salt, mfa_enabled FROM users WHERE username = ?",
            (req.username,),
        ).fetchone()

    # Always run scrypt, including for unknown users, to avoid a username timing oracle.
    observe_auth_phase(request, "credential_validation")
    valid = verify_password(
        req.password,
        row[2] if row else "0" * 128,
        row[3] if row else "0" * 32,
    )
    if row is None or not valid:
        failures.append(now_monotonic)
        record_event("auth.login_failed", metadata={"reason": "invalid_credentials"})
        raise HTTPException(status_code=401, detail="invalid_credentials")
    _login_failures.pop(failure_key, None)
    if row[4]:
        challenge = auth_security.start_challenge(row[0], client_ip)
        response.set_cookie(
            MFA_CHALLENGE_COOKIE,
            challenge,
            max_age=auth_security.MFA_CHALLENGE_SECONDS,
            httponly=True,
            secure=_cookie_secure(request),
            samesite="strict",
            path="/api/auth",
        )
        return {"authenticated": False, "mfa_required": True}

    observe_auth_phase(request, "session_creation")
    token = auth_security.create_session(row[0], client_ip, request.headers.get("user-agent", ""))
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    record_event("auth.login_succeeded", actor={"id": row[0], "username": row[1]})
    return {"authenticated": True, "user": {"username": row[1]}}


@app.post("/api/auth/mfa")
async def login_mfa(req: MfaVerify, request: Request, response: Response) -> dict:
    challenge = request.cookies.get(MFA_CHALLENGE_COOKIE)
    if not challenge:
        raise HTTPException(status_code=401, detail="mfa_challenge_expired")
    try:
        user_id, recovery_used = auth_security.consume_challenge(
            challenge, req.code, req.mode, request_security(request).client_ip
        )
    except auth_security.AuthSecurityError as error:
        if error.code != "invalid_mfa_code":
            response.delete_cookie(
                MFA_CHALLENGE_COOKIE,
                httponly=True,
                secure=_cookie_secure(request),
                samesite="strict",
                path="/api/auth",
            )
        raise HTTPException(status_code=401, detail=error.code) from None
    with sqlite3.connect(DB) as connection:
        username = connection.execute(
            "SELECT username FROM users WHERE id=?", (user_id,)
        ).fetchone()[0]
    token = auth_security.create_session(
        user_id, request_security(request).client_ip, request.headers.get("user-agent", "")
    )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    response.delete_cookie(
        MFA_CHALLENGE_COOKIE,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="strict",
        path="/api/auth",
    )
    record_event(
        "auth.recovery_code_used" if recovery_used else "auth.login_succeeded",
        actor={"id": user_id, "username": username},
    )
    return {
        "authenticated": True,
        "user": {"username": username},
        "recovery_code_used": recovery_used,
    }


@app.delete("/api/auth/mfa")
async def cancel_login_mfa(request: Request, response: Response) -> dict:
    challenge = request.cookies.get(MFA_CHALLENGE_COOKIE)
    if challenge:
        with sqlite3.connect(DB) as connection:
            connection.execute(
                "DELETE FROM mfa_challenges WHERE token_hash=?",
                (auth_security.token_hash(challenge),),
            )
    response.delete_cookie(
        MFA_CHALLENGE_COOKIE,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="strict",
        path="/api/auth",
    )
    return {"ok": True}


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
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    record_event("auth.logout", actor=request.state.user)
    return {"ok": True}


@app.post("/api/auth/password")
async def update_password(req: PasswordChange, request: Request, response: Response) -> dict:
    failure_key = (DB.resolve(), request.state.user["id"])
    now = time.monotonic()
    failures = _password_change_failures[failure_key]
    while failures and failures[0] <= now - PASSWORD_CHANGE_WINDOW_SECONDS:
        failures.popleft()
    if len(failures) >= PASSWORD_CHANGE_ATTEMPTS:
        raise HTTPException(status_code=429, detail="too_many_attempts")
    if req.new_password != req.confirmation:
        raise HTTPException(status_code=422, detail="password_mismatch")
    try:
        change_password(
            request.state.user["id"],
            current_password=req.current_password,
            new_password=req.new_password,
        )
    except CredentialError as error:
        if error.code == "invalid_credentials":
            failures.append(now)
        status_code = 401 if error.code == "invalid_credentials" else 422
        raise HTTPException(status_code=status_code, detail=error.code) from None
    _password_change_failures.pop(failure_key, None)
    record_event("auth.password_changed", actor=request.state.user)
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    return {"ok": True, "reauthentication_required": True}


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


@app.get("/api/auth/security")
async def auth_security_status(request: Request) -> dict:
    user = request.state.user
    return {
        "mfa": auth_security.mfa_status(user["id"]),
        "sessions": auth_security.list_sessions(user["id"], user["session_id"]),
    }


@app.post("/api/auth/mfa/enrollment")
async def begin_mfa_enrollment(req: MfaEnrollmentStart, request: Request) -> Response:
    user, session_token = request.state.user, request.cookies.get(SESSION_COOKIE, "")
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            "SELECT password_hash,salt FROM users WHERE id=?", (user["id"],)
        ).fetchone()
    if not row or not verify_password(req.current_password, row[0], row[1]):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    enrollment, secret = auth_security.start_enrollment(user["id"], session_token)
    label = f"{user['username']}@ExitLane"
    uri = pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name="ExitLane")
    buffer = BytesIO()
    segno.make(uri, micro=False).save(
        buffer,
        kind="svg",
        scale=6,
        border=4,
        dark="#000000",
        light="#ffffff",
        xmldecl=False,
        svgclass="mfa-qr-svg",
        lineclass="mfa-qr-modules",
    )
    record_event("auth.mfa_enrollment_started", actor=user)
    return JSONResponse(
        {
            "enrollment": enrollment,
            "setup_key": secret,
            "issuer": "ExitLane",
            "account_label": label,
            "qr_svg": buffer.getvalue().decode(),
        },
        headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"},
    )


@app.delete("/api/auth/mfa/enrollment")
async def cancel_mfa_enrollment(request: Request) -> dict:
    with sqlite3.connect(DB) as connection:
        connection.execute(
            "DELETE FROM mfa_enrollments WHERE user_id=?", (request.state.user["id"],)
        )
    return {"ok": True}


@app.post("/api/auth/mfa/enrollment/confirm")
async def finish_mfa_enrollment(req: MfaEnrollmentConfirm, request: Request) -> Response:
    try:
        codes = auth_security.confirm_enrollment(
            request.state.user["id"],
            request.cookies.get(SESSION_COOKIE, ""),
            req.enrollment,
            req.code,
        )
    except auth_security.AuthSecurityError as error:
        raise HTTPException(status_code=401, detail=error.code) from None
    record_event("auth.mfa_enabled", actor=request.state.user)
    record_event("auth.recovery_codes_generated", actor=request.state.user)
    return JSONResponse({"recovery_codes": codes}, headers={"Cache-Control": "no-store, private"})


@app.post("/api/auth/mfa/recovery-codes")
async def regenerate_mfa_recovery_codes(req: MfaDisable, request: Request) -> Response:
    user = request.state.user
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            "SELECT password_hash,salt FROM users WHERE id=?", (user["id"],)
        ).fetchone()
    if (
        not row
        or not verify_password(req.current_password, row[0], row[1])
        or not auth_security.verify_totp(user["id"], req.code)
    ):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    codes = auth_security.regenerate_recovery_codes(user["id"], user["session_id"])
    record_event("auth.recovery_codes_regenerated", actor=user)
    return JSONResponse({"recovery_codes": codes}, headers={"Cache-Control": "no-store, private"})


@app.post("/api/auth/mfa/disable")
async def disable_mfa(req: MfaDisable, request: Request, response: Response) -> dict:
    user = request.state.user
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            "SELECT password_hash,salt FROM users WHERE id=?", (user["id"],)
        ).fetchone()
    if (
        not row
        or not verify_password(req.current_password, row[0], row[1])
        or not auth_security.verify_totp(user["id"], req.code)
    ):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    auth_security.disable_mfa(user["id"])
    response.delete_cookie(
        SESSION_COOKIE, httponly=True, secure=_cookie_secure(request), samesite="lax", path="/"
    )
    record_event("auth.mfa_disabled", actor=user)
    return {"ok": True, "reauthentication_required": True}


@app.delete("/api/auth/sessions/{session_id}")
async def revoke_auth_session(session_id: str, request: Request) -> dict:
    try:
        revoked = auth_security.revoke_session(
            request.state.user["id"], session_id, request.state.user["session_id"]
        )
    except auth_security.AuthSecurityError as error:
        raise HTTPException(status_code=409, detail=error.code) from None
    if not revoked:
        raise HTTPException(status_code=404, detail="session_not_found")
    record_event("auth.session_revoked", actor=request.state.user)
    return {"ok": True}


@app.post("/api/auth/sessions/revoke-others")
async def revoke_other_auth_sessions(request: Request) -> dict:
    count = auth_security.revoke_other_sessions(
        request.state.user["id"], request.state.user["session_id"]
    )
    record_event("auth.other_sessions_revoked", actor=request.state.user)
    return {"ok": True, "revoked": count}


@app.get("/api/deployment/security")
async def get_deployment_security(request: Request) -> dict:
    status = deployment_status(request)
    status["mfa_required"] = auth_security.mfa_status(request.state.user["id"])["enabled"]
    return status


@app.get("/api/vpn/killswitch")
async def get_killswitch_status(request: Request) -> dict:
    selected = provider_registry.get(setting("vpn.provider_id", provider_registry.default_id))
    facts = await selected.network_facts()
    result = (await killswitch.status(facts)).as_dict()
    result["mfa_required"] = auth_security.mfa_status(request.state.user["id"])["enabled"]
    return result


@app.post("/api/vpn/killswitch/enable")
async def enable_killswitch(req: KillswitchChange, request: Request) -> dict:
    _reauthenticate_killswitch(req, request)
    selected = provider_registry.get(setting("vpn.provider_id", provider_registry.default_id))
    facts = await selected.network_facts()
    try:
        result = await killswitch.enable(facts)
    except killswitch.KillswitchError as error:
        record_event(
            "network.killswitch_error", actor=request.state.user, metadata={"reason": error.code}
        )
        raise HTTPException(status_code=503, detail=error.code) from None
    record_event("network.killswitch_enabled", actor=request.state.user)
    if not result.tunnel_available:
        record_event("network.killswitch_engaged", metadata={"reason": result.reason})
    return result.as_dict()


@app.post("/api/vpn/killswitch/disable")
async def disable_killswitch(req: KillswitchChange, request: Request) -> dict:
    _reauthenticate_killswitch(req, request)
    try:
        result = await killswitch.disable()
    except killswitch.KillswitchError as error:
        record_event(
            "network.killswitch_error", actor=request.state.user, metadata={"reason": error.code}
        )
        raise HTTPException(status_code=503, detail=error.code) from None
    record_event("network.killswitch_disabled", actor=request.state.user)
    return result.as_dict()


@app.put("/api/deployment/security")
async def update_deployment_security(req: NetworkSecurityUpdate, request: Request) -> dict:
    user = request.state.user
    failure_key = (DB.resolve(), user["id"])
    now = time.monotonic()
    failures = _network_reauth_failures[failure_key]
    while failures and failures[0] <= now - NETWORK_REAUTH_WINDOW_SECONDS:
        failures.popleft()
    if len(failures) >= NETWORK_REAUTH_ATTEMPTS:
        raise HTTPException(status_code=429, detail="too_many_attempts")
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            "SELECT password_hash,salt,mfa_enabled FROM users WHERE id=?", (user["id"],)
        ).fetchone()
    password_valid = bool(row) and verify_password(req.current_password, row[0], row[1])
    if not password_valid:
        failures.append(now)
        raise HTTPException(status_code=401, detail="invalid_credentials")
    if row[2] and (not req.code or not auth_security.verify_totp(user["id"], req.code)):
        failures.append(now)
        raise HTTPException(status_code=401, detail="invalid_mfa_code")
    try:
        public_url, proxies, _policy = network_security.validate_configuration(
            req.public_url,
            req.trusted_proxies,
            req.secure_cookie_policy,
            confirm_broad_trust=req.confirm_broad_trust,
        )
    except network_security.NetworkSecurityError as error:
        raise HTTPException(
            status_code=409 if "confirmation_required" in error.code else 422,
            detail={"code": error.code, "field": error.field},
        ) from None
    current_origin = request.headers.get("origin") or request.headers.get("referer") or ""
    origin_risk = bool(
        public_url and normalized_origin(current_origin) != normalized_origin(public_url)
    )
    peer = request.client.host if request.client else str(ipaddress.IPv4Address(0))
    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:
        peer_address = ipaddress.IPv4Address(0)
    proxy_risk = request_security(request).direct_peer_trusted and not any(
        peer_address in network for network in proxies
    )
    if (origin_risk or proxy_risk) and not req.confirm_access_loss:
        raise HTTPException(status_code=409, detail="access_loss_confirmation_required")
    try:
        configuration, changed = network_security.update_config(
            public_url=req.public_url,
            trusted_proxies=req.trusted_proxies,
            secure_cookie_policy=req.secure_cookie_policy,
            confirm_broad_trust=req.confirm_broad_trust,
        )
    except network_security.NetworkSecurityError as error:
        raise HTTPException(
            status_code=409 if error.code == "environment_override" else 422,
            detail={"code": error.code, "field": error.field},
        ) from None
    _network_reauth_failures.pop(failure_key, None)
    if changed:
        record_event(
            "network.security_settings_updated",
            actor=user,
            metadata={
                "fields": changed,
                "public_scheme": urlsplit(configuration.public_url).scheme
                if configuration.public_url
                else "none",
                "trusted_proxy_count": len(configuration.trusted_proxies),
            },
        )
    return {
        **deployment_status(request),
        "configuration": configuration.as_public_dict(),
        "mfa_required": bool(row[2]),
    }


@app.get("/api/setup/state")
async def setup_state() -> dict:
    with sqlite3.connect(DB) as connection:
        admin_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    selected_provider_id = setting("vpn.provider_id", provider_registry.default_id)
    selected_provider = _provider_or_404(selected_provider_id)
    provider_status = await selected_provider.status()

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
        "providers": [_provider_metadata(item) for item in provider_registry.all()],
        "selected_provider_id": selected_provider_id,
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
    result = await provider.authenticate(req.token)

    if result.get("ok"):
        set_setting("vpn.provider_id", provider.id)
        set_setting("setup_provider_complete", True)
        set_setting("setup_current_step", 4)

    return result


@app.post("/api/providers/nordvpn/token")
async def update_nordvpn_token(req: Token, request: Request) -> dict:
    return await _authenticate_provider(provider, req, request)


async def _authenticate_provider(provider_instance, req: Token, request: Request) -> dict:
    status = await provider_instance.status(timeout=8)
    if status.get("authenticated"):
        raise HTTPException(status_code=409, detail="token_replacement_unsupported")
    result = await provider_instance.authenticate(req.token)
    if not result.get("ok"):
        error = result.get("error")
        if error not in TOKEN_ERROR_CODES:
            error = "provider_error"
        status_code = (
            504
            if error == "timeout"
            else 503
            if error in {"daemon_unavailable", "command_unavailable", "provider_error"}
            else 409
            if error in {"already_logged_in", "token_replacement_unsupported"}
            else 422
        )
        raise HTTPException(status_code=status_code, detail=error)
    record_event(
        "provider.session_started",
        actor=request_actor(request),
        metadata={"provider": provider_instance.id},
    )
    set_setting("vpn.provider_id", provider_instance.id)
    if not setting("setup_complete", False):
        set_setting("setup_provider_complete", True)
        set_setting("setup_current_step", 4)
    return {"ok": True, "reconnect_required": bool(result.get("reconnect_required", False))}


def _provider_authentication_state(status: dict) -> str:
    state = status.get("management", {}).get("authentication", {}).get("state")
    if state:
        return state
    if status.get("authenticated") is True:
        return "signed_in"
    if status.get("installed") is True and status.get("authenticated") is False:
        return "signed_out"
    return "unknown"


def _provider_or_404(provider_id: str):
    try:
        return provider_registry.get(provider_id)
    except ProviderNotFound:
        raise HTTPException(status_code=404, detail="provider_not_found") from None


def _provider_metadata(provider_instance) -> dict:
    return {
        **provider_instance.metadata.as_dict(),
        "enabled": True,
        "active": provider_instance.id == setting("vpn.provider_id", provider_registry.default_id),
    }


@app.post("/api/providers/nordvpn/session/end")
async def end_nordvpn_session(request: Request) -> dict:
    return await _end_provider_session(provider, request)


async def _end_provider_session(provider_instance, request: Request) -> dict:
    failure_key = (DB.resolve(), request.state.user["id"])
    now = time.monotonic()
    failures = _provider_sign_out_failures[failure_key]
    while failures and failures[0] <= now - PROVIDER_SIGN_OUT_WINDOW_SECONDS:
        failures.popleft()
    if len(failures) >= PROVIDER_SIGN_OUT_ATTEMPTS:
        raise HTTPException(status_code=429, detail="too_many_attempts")

    before = await _fresh_status_for(provider_instance)
    if _provider_authentication_state(before) == "signed_out":
        _provider_sign_out_failures.pop(failure_key, None)
        return {"ok": True, "already_signed_out": True, "status": before}
    if _provider_authentication_state(before) != "signed_in":
        raise HTTPException(status_code=409, detail="provider_state_unknown")

    try:
        result = await provider_instance.sign_out()
    except asyncio.CancelledError:
        raise
    except Exception:
        result = {"ok": False, "error": "provider_error"}
    after = await _fresh_status_for(provider_instance)
    signed_out = _provider_authentication_state(after) == "signed_out"
    if result.get("ok") and signed_out:
        _provider_sign_out_failures.pop(failure_key, None)
        record_event(
            "provider.session_ended",
            actor=request_actor(request),
            metadata={"provider": provider_instance.id},
        )
        return {
            "ok": True,
            "already_signed_out": bool(result.get("already_signed_out")),
            "status": after,
        }

    error = result.get("error")
    if error not in SIGN_OUT_ERROR_CODES:
        error = "provider_error"
    if signed_out:
        _provider_sign_out_failures.pop(failure_key, None)
        record_event(
            "provider.session_ended",
            actor=request_actor(request),
            metadata={"provider": provider_instance.id},
        )
        return {"ok": True, "already_signed_out": False, "status": after}

    failures.append(now)
    record_event(
        "provider.session_end_failed",
        actor=request_actor(request),
        metadata={"provider": provider_instance.id, "reason": error},
    )
    status_code = (
        504
        if error == "timeout"
        else 503
        if error in {"daemon_unavailable", "command_unavailable", "provider_error"}
        else 409
    )
    raise HTTPException(status_code=status_code, detail=error)


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
    status = await _fresh_vpn_status()
    if _pending_provider_connection and status.get("connected"):
        pending = _pending_provider_connection
        _pending_provider_connection = None
        record_event(
            "provider.connected",
            actor=pending["actor"],
            metadata={key: status[key] for key in ("country", "city", "server") if status.get(key)},
            correlation_id=pending["correlation_id"],
        )
    return {"status": {**status, **server_latency(status.get("server"))}}


@app.get("/api/providers/nordvpn/countries")
async def nordvpn_countries() -> dict:
    return {
        "countries": await provider.countries(),
    }


async def _provider_overview(provider_instance) -> dict:
    status = await _fresh_status_for(provider_instance)
    metadata = _provider_metadata(provider_instance)
    if not metadata["active"]:
        status.pop("operation", None)
    summary = (
        country_summary(status["country_code"], provider_id=provider_instance.id)
        if status.get("country_code")
        else {}
    )
    return {
        **metadata,
        "status": {
            **status,
            "latency_ms": summary.get("latency_ms"),
            "latency_measured_at": summary.get("latency_measured_at"),
            "observed_at": datetime.now(UTC).isoformat(),
        },
    }


@app.get("/api/vpn/providers")
async def vpn_providers() -> dict:
    providers = await asyncio.gather(
        *(_provider_overview(item) for item in provider_registry.all())
    )
    return {
        "active_provider_id": setting("vpn.provider_id", provider_registry.default_id),
        "providers": providers,
    }


@app.get("/api/vpn/providers/{provider_id}")
async def vpn_provider_detail(provider_id: str) -> dict:
    return {"provider": _provider_metadata(_provider_or_404(provider_id))}


@app.get("/api/vpn/providers/{provider_id}/status")
async def vpn_provider_status(provider_id: str) -> dict:
    provider_instance = _provider_or_404(provider_id)
    return {
        "provider": _provider_metadata(provider_instance),
        "status": await _fresh_status_for(provider_instance),
    }


@app.post("/api/vpn/providers/{provider_id}/authenticate")
async def authenticate_vpn_provider(provider_id: str, req: Token, request: Request) -> dict:
    return await _authenticate_provider(_provider_or_404(provider_id), req, request)


@app.post("/api/vpn/providers/{provider_id}/sign-out")
async def sign_out_vpn_provider(provider_id: str, request: Request) -> dict:
    return await _end_provider_session(_provider_or_404(provider_id), request)


@app.get("/api/vpn/providers/{provider_id}/locations")
async def vpn_provider_locations(provider_id: str) -> dict:
    provider_instance = _provider_or_404(provider_id)
    vpn = await _require_provider_authentication(provider_instance)
    catalog = await _vpn_catalog(provider_instance)
    connected = vpn["country_code"]
    codes = [item["country_code"] for item in catalog]
    last = setting("vpn.last_country")
    quick = list(
        dict.fromkeys(code for code in (connected, last, *QUICK_COUNTRIES) if code in codes)
    )
    return {
        "provider_id": provider_id,
        "quick_country_codes": quick,
        "vpn": vpn,
        "countries": [
            country_summary(
                item["country_code"],
                connected_code=connected,
                provider_name=item["provider_name"],
                provider_id=provider_id,
            )
            for item in catalog
        ],
    }


async def _vpn_catalog(provider_instance=provider) -> list[dict]:
    return await provider_instance.countries()


def _country_id(catalog: list[dict], country_code: str) -> int | None:
    return next(
        (item["id"] for item in catalog if item["country_code"] == country_code.upper()), None
    )


def _vpn_snapshot(status: dict) -> dict:
    hostname = status.get("server", "")
    match = re.fullmatch(r"([a-z]{2})[0-9]+\.nordvpn\.com", hostname.lower())
    connected = bool(status.get("connected"))
    hostname_code = match.group(1).upper() if connected and match else None
    country_code = NORDVPN_HOST_COUNTRY_CODES.get(hostname_code, hostname_code)
    operation = vpn_operations.snapshot()
    if operation["state"] not in vpn_operations.ACTIVE_STATES:
        operation["state"] = (
            "connected" if connected else "failed" if operation.get("last_error_code") else "idle"
        )
    return {
        **status,
        "connected": connected,
        "country_code": country_code,
        "country": status.get("country") or None if connected else None,
        "city": status.get("city") or None if connected else None,
        "server": hostname or None if connected else None,
        "hostname": hostname or None if connected else None,
        "operation": operation,
    }


async def _fresh_vpn_status(provider_instance=provider) -> dict:
    try:
        return _vpn_snapshot(
            await provider_instance.status(timeout=vpn_operations.STATUS_TIMEOUT_SECONDS)
        )
    except Exception:
        return _vpn_snapshot(
            {
                "available": False,
                "connected": False,
                "state": "error",
                "error_code": "provider_status_unavailable",
            }
        )


async def _fresh_status_for(provider_instance) -> dict:
    # Keep legacy tests and aliases patchable while provider-scoped routes can
    # explicitly select another registered implementation.
    if provider_instance is provider:
        return await _fresh_vpn_status()
    return await _fresh_vpn_status(provider_instance)


async def _require_provider_authentication(provider_instance=provider) -> dict:
    status = await _fresh_status_for(provider_instance)
    authentication_state = _provider_authentication_state(status)
    if authentication_state == "signed_out":
        raise HTTPException(status_code=409, detail="provider_authentication_required")
    if authentication_state != "signed_in":
        raise HTTPException(status_code=409, detail="provider_state_unknown")
    return status


def _action_conflict() -> JSONResponse:
    operation = vpn_operations.snapshot()
    return JSONResponse(
        status_code=409,
        content={"error": "vpn_action_in_progress", **operation},
    )


def _release_vpn_claim_after_failure(error: BaseException) -> None:
    error_code = (
        error.detail
        if isinstance(error, HTTPException) and isinstance(error.detail, str)
        else "provider_action_failed"
    )
    vpn_operations.finish(connected=False, error_code=error_code)


@app.get("/api/vpn/status")
async def vpn_status() -> dict:
    status = await _fresh_vpn_status()
    summary = country_summary(status["country_code"]) if status["country_code"] else {}
    return {
        **status,
        "latency_ms": summary.get("latency_ms"),
        "latency_measured_at": summary.get("latency_measured_at"),
    }


@app.get("/api/vpn/countries")
async def vpn_countries() -> dict:
    vpn = await _require_provider_authentication()
    catalog = await _vpn_catalog()
    connected = vpn["country_code"]
    codes = [item["country_code"] for item in catalog]
    last = setting("vpn.last_country")
    quick = list(
        dict.fromkeys(code for code in (connected, last, *QUICK_COUNTRIES) if code in codes)
    )
    return {
        "quick_country_codes": quick,
        "vpn": vpn,
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
    await _require_provider_authentication()
    code = country_code.upper()
    country_id = _country_id(await _vpn_catalog(), code)
    if country_id is None:
        raise HTTPException(404, "Unsupported country")
    return {"country_code": code, "servers": await provider.servers(country_id)}


@app.post("/api/vpn/countries/{country_code}/measure")
async def measure_vpn_country(country_code: str) -> dict:
    try:
        vpn_operations.begin("measuring", country_code=country_code.upper(), timeout=30)
    except vpn_operations.VPNActionInProgress:
        return _action_conflict()
    try:
        vpn = await _require_provider_authentication()
        code = country_code.upper()
        country_id = _country_id(await _vpn_catalog(), code)
        if country_id is None:
            raise HTTPException(404, "Unsupported country")
        servers = await provider.servers(country_id)
        measurements = await measure_servers(code, servers, force=True)
        vpn_operations.finish(connected=vpn.get("connected", False))
        return {**country_summary(code), "servers": measurements}
    except (asyncio.CancelledError, Exception) as error:
        _release_vpn_claim_after_failure(error)
        raise


@app.post("/api/vpn/connect")
async def connect_vpn_country(req: CountryConnect, request: Request) -> dict:
    global _pending_provider_connection
    code = req.country_code.upper()
    try:
        vpn_operations.begin("connecting", country_code=code, timeout=125)
    except vpn_operations.VPNActionInProgress:
        return _action_conflict()
    try:
        await _require_provider_authentication()
        catalog = await _vpn_catalog()
        country = next((item for item in catalog if item["country_code"] == code), None)
        country_id = country["id"] if country else None
        if country_id is None:
            raise HTTPException(404, "Unsupported country")
    except (asyncio.CancelledError, Exception) as error:
        _release_vpn_claim_after_failure(error)
        raise

    actor = request_actor(request)
    correlation_id = str(uuid.uuid4())
    country_name = country_summary(code, provider_name=country["provider_name"])["name"]
    technical = {"country_code": code, "cli_action": "connect_country"}
    record_event(
        "provider.connect_started",
        actor=actor,
        metadata={"target": country_name, **technical},
        correlation_id=correlation_id,
    )
    indication = None
    result = {"ok": False, "exit_code": None, "error_code": "provider_connect_failed"}
    status = None
    recovered = False
    try:
        indication = await select_server(code, await provider.servers(country_id))
        result = await provider.connect_country(
            code, timeout=vpn_operations.CONNECT_TIMEOUT_SECONDS
        )
        status = await _fresh_vpn_status()

        if result.get("error_code") == "vpn_connect_timeout" and not status.get("connected"):
            if vpn_operations.recovery_allowed():
                vpn_operations.record_recovery()
                vpn_operations.transition("recovering")
                record_event(
                    "provider.recovery_started",
                    actor=actor,
                    metadata={"country_code": code, "reason": "timeout"},
                    correlation_id=correlation_id,
                )
                recovery = await provider.recover_daemon()
                if recovery.get("ok"):
                    recovered = True
                    record_event(
                        "provider.recovered",
                        actor=actor,
                        metadata={"country_code": code},
                        correlation_id=correlation_id,
                    )
                    vpn_operations.transition("connecting")
                    record_event(
                        "provider.retry_started",
                        actor=actor,
                        metadata={"country_code": code},
                        correlation_id=correlation_id,
                    )
                    result = await provider.connect_country(
                        code, timeout=vpn_operations.CONNECT_TIMEOUT_SECONDS
                    )
                    status = await _fresh_vpn_status()
                else:
                    result = {**result, "error_code": recovery.get("error_code")}
                    status = await _fresh_vpn_status()
                    record_event(
                        "provider.recovery_failed",
                        actor=actor,
                        metadata={"country_code": code, "reason": "healthcheck_failed"},
                        correlation_id=correlation_id,
                    )
            else:
                result = {**result, "error_code": "provider_recovery_rate_limited"}
                record_event(
                    "provider.recovery_rate_limited",
                    actor=actor,
                    metadata={"country_code": code, "reason": "timeout"},
                    correlation_id=correlation_id,
                )
    except asyncio.CancelledError:
        status = await _fresh_vpn_status()
        vpn_operations.finish(
            connected=status.get("connected", False),
            error_code=None if status.get("connected") else "provider_connect_cancelled",
        )
        raise
    except Exception:
        result = {"ok": False, "exit_code": None, "error_code": "provider_connect_failed"}
        status = await _fresh_vpn_status()

    status = status or await _fresh_vpn_status()

    expected_country = country["provider_name"].casefold()
    proven = bool(
        result.get("ok")
        and status.get("connected")
        and status.get("country", "").casefold() == expected_country
    )
    event_technical = {**technical, "exit_code": str(result.get("exit_code"))}
    if proven:
        remember_country(code)
        record_event(
            "provider.connected",
            actor=actor,
            metadata={
                **event_technical,
                **{key: status[key] for key in ("country", "city", "server") if status.get(key)},
            },
            correlation_id=correlation_id,
        )
        _pending_provider_connection = None
    else:
        reason = (
            "timeout"
            if result.get("error_code") == "vpn_connect_timeout"
            else "connection_failed"
            if not result.get("ok")
            else "provider_status_unavailable"
            if status.get("available") is False
            else "not_connected"
            if not status.get("connected")
            else "wrong_country"
        )
        record_event(
            "provider.connect_failed",
            actor=actor,
            metadata={"target": country_name, "reason": reason, **event_technical},
            correlation_id=correlation_id,
        )
    error_code = None if proven else result.get("error_code") or reason
    operation = vpn_operations.finish(connected=proven, error_code=error_code)
    status["operation"] = operation
    return {
        **result,
        "success": proven,
        "country_code": code,
        "server": status.get("server"),
        "latency_ms": indication["latency_ms"] if indication else None,
        "status": "connected" if proven else "error",
        "error": error_code,
        "error_code": error_code,
        "operation_state": operation["state"],
        "recovered": recovered,
        "vpn": status,
    }


@app.post("/api/vpn/disconnect")
async def disconnect_vpn(request: Request) -> dict:
    try:
        vpn_operations.begin("disconnecting", timeout=25)
    except vpn_operations.VPNActionInProgress:
        return _action_conflict()
    try:
        await _require_provider_authentication()
    except (asyncio.CancelledError, Exception) as error:
        _release_vpn_claim_after_failure(error)
        raise
    correlation_id = str(uuid.uuid4())
    actor = request_actor(request)
    record_event("provider.disconnect_started", actor=actor, correlation_id=correlation_id)
    try:
        result = await provider.disconnect(timeout=15)
    except asyncio.CancelledError:
        status = await _fresh_vpn_status()
        vpn_operations.finish(
            connected=status.get("connected", False),
            error_code="provider_disconnect_cancelled" if status.get("connected") else None,
        )
        raise
    except Exception:
        result = {"ok": False, "error_code": "provider_disconnect_failed"}
    status = await _fresh_vpn_status()
    success = not status.get("connected")
    error_code = None if success else result.get("error_code") or "provider_disconnect_failed"
    operation = vpn_operations.finish(
        connected=status.get("connected", False), error_code=error_code
    )
    status["operation"] = operation
    record_event(
        "provider.disconnected" if success else "provider.disconnect_failed",
        actor=actor,
        metadata=None if success else {"reason": "connection_failed"},
        correlation_id=correlation_id,
    )
    return {
        **result,
        "success": success,
        "error": error_code,
        "operation_state": operation["state"],
        "vpn": status,
    }


@app.post("/api/providers/nordvpn/connect")
async def connect_nordvpn(req: Connect, request: Request) -> dict:
    global _pending_provider_connection
    if req.target and re.fullmatch(r"[A-Za-z]{2}", req.target):
        return await connect_vpn_country(CountryConnect(country_code=req.target), request)
    try:
        vpn_operations.begin("connecting", timeout=50)
    except vpn_operations.VPNActionInProgress:
        return _action_conflict()
    try:
        await _require_provider_authentication()
    except (asyncio.CancelledError, Exception) as error:
        _release_vpn_claim_after_failure(error)
        raise
    correlation_id = str(uuid.uuid4())
    metadata = {"target": req.target or "recommended"}
    record_event(
        "provider.connect_started",
        actor=request_actor(request),
        metadata=metadata,
        correlation_id=correlation_id,
    )
    try:
        result = await provider.connect(req.target, timeout=vpn_operations.CONNECT_TIMEOUT_SECONDS)
    except Exception:
        result = {"ok": False, "error_code": "provider_connect_failed"}
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
                    key: status[key] for key in ("country", "city", "server") if status.get(key)
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
        reason = (
            "invalid_target"
            if result.get("error_code") == "invalid_target"
            else "timeout"
            if result.get("error_code") == "vpn_connect_timeout"
            else "connection_failed"
        )
        record_event(
            "provider.connect_failed",
            actor=request_actor(request),
            metadata={**metadata, "reason": reason},
            correlation_id=correlation_id,
        )
        _pending_provider_connection = None
    status = await _fresh_vpn_status()
    proven = bool(result.get("ok") and status.get("connected"))
    error_code = None if proven else result.get("error_code") or "connection_failed"
    operation = vpn_operations.finish(connected=proven, error_code=error_code)
    status["operation"] = operation
    return {
        **result,
        "success": proven,
        "error": error_code,
        "operation_state": operation["state"],
        "vpn": status,
    }


@app.post("/api/providers/nordvpn/disconnect")
async def disconnect_nordvpn(request: Request) -> dict:
    return await disconnect_vpn(request)


def _require_active_provider(provider_id: str) -> None:
    _provider_or_404(provider_id)
    active_id = setting("vpn.provider_id", provider_registry.default_id)
    if provider_id != active_id:
        raise HTTPException(status_code=409, detail="provider_action_unsupported")


@app.post("/api/vpn/providers/{provider_id}/connect")
async def connect_vpn_provider(provider_id: str, req: Connect, request: Request) -> dict:
    _require_active_provider(provider_id)
    return await connect_nordvpn(req, request)


@app.post("/api/vpn/providers/{provider_id}/disconnect")
async def disconnect_vpn_provider(provider_id: str, request: Request) -> dict:
    _require_active_provider(provider_id)
    return await disconnect_vpn(request)


@app.post("/api/vpn/providers/{provider_id}/reconnect")
async def reconnect_vpn_provider(
    provider_id: str, req: ProviderReconnect, request: Request
) -> dict:
    _require_active_provider(provider_id)
    if req.country_code:
        return await connect_vpn_country(CountryConnect(country_code=req.country_code), request)
    return await connect_nordvpn(Connect(target=None), request)


@app.post("/api/vpn/providers/{provider_id}/location")
async def select_vpn_provider_location(
    provider_id: str, req: CountryConnect, request: Request
) -> dict:
    _require_active_provider(provider_id)
    return await connect_vpn_country(req, request)


@app.get("/api/vpn/providers/{provider_id}/locations/{country_code}/servers")
async def vpn_provider_location_servers(provider_id: str, country_code: str) -> dict:
    _require_active_provider(provider_id)
    return await vpn_country_servers(country_code)


@app.post("/api/vpn/providers/{provider_id}/locations/{country_code}/measure")
async def measure_vpn_provider_location(provider_id: str, country_code: str) -> dict:
    _require_active_provider(provider_id)
    return await measure_vpn_country(country_code)


@app.get("/api/vpn/providers/{provider_id}/latency")
async def vpn_provider_latency(provider_id: str) -> dict:
    locations = await vpn_provider_locations(provider_id)
    return {
        "provider_id": provider_id,
        "locations": [
            {
                "country_code": item["country_code"],
                "latency_ms": item.get("latency_ms"),
                "latency_measured_at": item.get("latency_measured_at"),
            }
            for item in locations["countries"]
        ],
    }


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
    generation_lock = wireguard_generation_lock()
    try:
        if generation_lock.locked():
            return JSONResponse(
                status_code=409, content={"error": "wireguard_generation_in_progress"}
            )
        async with generation_lock:
            result = await wireguard_service.provision(
                activate=activate_wireguard_interface,
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
    except wireguard_service.WireGuardConfigurationError as error:
        raise HTTPException(
            status_code=500,
            detail=error.code,
        ) from error

    set_settings(
        {
            "wireguard_configured": True,
            "wireguard_client_name": req.client,
            "wireguard_interface": req.interface,
            "wireguard_endpoint": req.endpoint,
            "wireguard_subnet": req.subnet,
            "wireguard_dns": req.dns,
            "wireguard_port": req.port,
            "setup_current_step": 5,
        }
    )

    record_event(
        "wireguard.configuration_generated",
        actor=request_actor(request),
        metadata={"client_name": req.client},
    )
    record_event(
        "wireguard.interface_active",
        actor=request_actor(request),
        metadata={"interface": req.interface},
    )
    _wireguard_observed_state = (True, False)

    return result


def _private_response(content: dict, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"},
    )


def wireguard_generation_lock() -> asyncio.Lock:
    global _wireguard_generation_lock
    if _wireguard_generation_lock is None:
        _wireguard_generation_lock = asyncio.Lock()
    return _wireguard_generation_lock


async def _current_wireguard_configuration() -> dict | None:
    interface = setting("wireguard_interface", DEFAULT_WIREGUARD_INTERFACE)
    client = setting("wireguard_client_name", DEFAULT_WIREGUARD_CLIENT)
    return await wireguard_service.read_current(interface, client)


@app.get("/api/ingress/wireguard/config")
async def current_wireguard_configuration() -> JSONResponse:
    try:
        configuration = await _current_wireguard_configuration()
    except wireguard_service.WireGuardConfigurationError as error:
        return _private_response({"error": error.code}, status_code=409)
    if configuration is None:
        return _private_response({"available": False, "configuration": None})
    return _private_response(
        {
            "available": True,
            "client_name": configuration["client_name"],
            "filename": configuration["filename"],
            "configuration": configuration["client_config"],
        }
    )


@app.get("/api/ingress/wireguard/config/download")
async def download_wireguard_configuration() -> Response:
    try:
        configuration = await _current_wireguard_configuration()
    except wireguard_service.WireGuardConfigurationError as error:
        return _private_response({"error": error.code}, status_code=409)
    if configuration is None:
        return _private_response({"error": "wireguard_configuration_missing"}, status_code=404)
    client = setting("wireguard_client_name", DEFAULT_WIREGUARD_CLIENT)
    response = FileResponse(
        path=WG_DIR / f"{client}.conf",
        media_type="application/x-wireguard-profile",
        filename="exitlane-wireguard.conf",
    )
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/api/ingress/wireguard/config/qr")
async def wireguard_configuration_qr() -> Response:
    try:
        configuration = await _current_wireguard_configuration()
    except wireguard_service.WireGuardConfigurationError as error:
        return _private_response({"error": error.code}, status_code=409)
    if configuration is None:
        return _private_response({"error": "wireguard_configuration_missing"}, status_code=404)
    output = BytesIO()
    segno.make_qr(configuration["client_config"], error="m").save(
        output,
        kind="svg",
        scale=5,
        xmldecl=False,
        svgclass="wireguard-qr-svg",
        lineclass="wireguard-qr-modules",
    )
    return Response(
        content=output.getvalue(),
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"},
    )


@app.post("/api/ingress/wireguard/config/regenerate")
async def regenerate_wireguard_configuration(request: Request) -> JSONResponse:
    global _wireguard_observed_state
    generation_lock = wireguard_generation_lock()
    if generation_lock.locked():
        return _private_response({"error": "wireguard_generation_in_progress"}, status_code=409)
    interface = setting("wireguard_interface", DEFAULT_WIREGUARD_INTERFACE)
    client = setting("wireguard_client_name", DEFAULT_WIREGUARD_CLIENT)
    try:
        if await wireguard_service.read_current(interface, client) is None:
            raise wireguard_service.WireGuardConfigurationError("wireguard_configuration_missing")
        parameters = {
            "endpoint": setting("wireguard_endpoint"),
            "subnet": setting("wireguard_subnet"),
            "dns": setting("wireguard_dns"),
            "port": setting("wireguard_port"),
            "interface": interface,
            "client": client,
        }
        if not all(parameters.values()):
            parameters = await wireguard_service.parameters_from_current(interface, client)
        async with generation_lock:
            result = await wireguard_service.provision(
                activate=activate_wireguard_interface,
                **parameters,
            )
    except wireguard_service.WireGuardConfigurationError as error:
        return _private_response(
            {"error": error.code},
            status_code=409 if "invalid" in error.code or "missing" in error.code else 500,
        )
    except (ValueError, RuntimeError):
        return _private_response({"error": "wireguard_regeneration_failed"}, status_code=500)

    set_setting("wireguard_configured", True)
    record_event(
        "wireguard.configuration_regenerated",
        actor=request_actor(request),
        metadata={"client_name": client},
    )
    _wireguard_observed_state = (True, False)
    return _private_response(
        {
            "ok": True,
            "available": True,
            "client_name": client,
            "filename": "exitlane-wireguard.conf",
            "configuration": result["client_config"],
        }
    )


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
        headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"},
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

    record_event(
        "notifications.webhook_added", actor=request_actor(request), metadata={"name": req.name}
    )

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
