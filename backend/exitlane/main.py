from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from exitlane import __version__
from exitlane.core import (
    DB,
    WG_DIR,
    hash_password,
    init,
    set_setting,
    setting,
)
from exitlane.providers.nordvpn import provider
from exitlane.services.diagnostics import run as diagnostics
from exitlane.services.wireguard import create as create_wireguard
from exitlane.config import (
    DEFAULT_WIREGUARD_CLIENT,
    DEFAULT_WIREGUARD_INTERFACE,
    DEFAULT_WIREGUARD_PORT,
    DEFAULT_WIREGUARD_SUBNET,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PROVIDER_REFRESH_INTERVAL_SECONDS,
    validate_config,
)


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


class WireGuard(BaseModel):
    endpoint: str = Field(
        min_length=1,
        max_length=255,
    )
    subnet: str = DEFAULT_WIREGUARD_SUBNET
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
    yield


app = FastAPI(
    title="Exitlane",
    description="Smart egress for every network",
    version=__version__,
    lifespan=lifespan,
)

static_dir = Path(__file__).parent / "static"
app.mount(
    "/assets",
    StaticFiles(directory=static_dir),
    name="assets",
)


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/api/health")
async def health() -> dict:
    return {
        "ok": True,
        "service": "exitlane",
        "version": __version__,
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
    return await provider.install()


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
    return {
        "status": await provider.status(),
    }


@app.get("/api/providers/nordvpn/countries")
async def nordvpn_countries() -> dict:
    return {
        "countries": await provider.countries(),
    }


@app.post("/api/providers/nordvpn/connect")
async def connect_nordvpn(req: Connect) -> dict:
    return await provider.connect(req.target)


@app.post("/api/providers/nordvpn/disconnect")
async def disconnect_nordvpn() -> dict:
    return await provider.disconnect()


@app.post("/api/ingress/wireguard")
async def create_wireguard_ingress(req: WireGuard) -> dict:
    try:
        result = await create_wireguard(
            endpoint=req.endpoint,
            subnet=req.subnet,
            port=req.port,
            interface=req.interface,
            client=req.client,
        )
    except (ValueError, RuntimeError) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    set_setting("wireguard_configured", True)
    set_setting("wireguard_client_name", req.client)
    set_setting("setup_current_step", 5)

    return result


@app.get(
    "/api/ingress/wireguard/client/{name}",
    response_class=PlainTextResponse,
)
async def wireguard_client_config(name: str) -> str:
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

    return path.read_text(encoding="utf-8")


@app.post("/api/notifications/webhook")
async def create_webhook(req: Webhook) -> dict:
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

    return {
        "ok": True,
        "id": cursor.lastrowid,
    }


@app.post("/api/setup/complete")
async def complete_setup() -> dict:
    state = await setup_state()

    incomplete_steps = [name for name, completed in state["steps"].items() if not completed]

    if incomplete_steps:
        raise HTTPException(
            status_code=409,
            detail=("Setup steps are incomplete: " + ", ".join(incomplete_steps)),
        )

    set_setting("setup_complete", True)
    set_setting("setup_current_step", 5)

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
            "provider_refresh_interval_seconds": (PROVIDER_REFRESH_INTERVAL_SECONDS),
        },
    }
