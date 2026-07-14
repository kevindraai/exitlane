from __future__ import annotations
import asyncio
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from exitlane.config import MIN_PASSWORD_LENGTH

DATA = Path(os.getenv("EXITLANE_DATA_DIR", "/etc/exitlane"))
DB = DATA / "exitlane.db"
WG_DIR = DATA / "wireguard"


def init():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    WG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    with sqlite3.connect(DB) as c:
        c.executescript(
            """CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,salt TEXT); CREATE TABLE IF NOT EXISTS webhooks(id INTEGER PRIMARY KEY,name TEXT,url TEXT,enabled INTEGER DEFAULT 1);"""
        )


def setting(key, default=None):
    with sqlite3.connect(DB) as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return default if row is None else json.loads(row[0])


def set_setting(key, value):
    with sqlite3.connect(DB) as c:
        c.execute(
            "INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )


def hash_password(password, salt=None):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must have at least {MIN_PASSWORD_LENGTH} characters")
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return digest.hex(), salt.hex()


async def command(*args, timeout=60, input_text=None):
    p = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if input_text else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(
            p.communicate(input_text.encode() if input_text else None), timeout
        )
    except TimeoutError:
        p.kill()
        await p.wait()
        return 124, "", "timeout"
    return p.returncode, out.decode(errors="replace").strip(), err.decode(errors="replace").strip()
