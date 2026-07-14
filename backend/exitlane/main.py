from __future__ import annotations
import sqlite3,urllib.request,json
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI,HTTPException
from fastapi.responses import FileResponse,PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from exitlane import __version__
from exitlane.core import DB,WG_DIR,hash_password,init,set_setting,setting
from exitlane.providers.nordvpn import provider
from exitlane.services.diagnostics import run as diagnostics
from exitlane.services.wireguard import create as create_wireguard

class Admin(BaseModel): username:str=Field(min_length=3,pattern=r"^[A-Za-z0-9_.-]+$"); password:str=Field(min_length=12)
class Token(BaseModel): token:str=Field(min_length=20,max_length=512)
class Callback(BaseModel): callback_url:str=Field(min_length=20,max_length=2048)
class Connect(BaseModel): target:str|None=None
class WireGuard(BaseModel): endpoint:str; subnet:str="10.99.99.0/24"; port:int=51820; interface:str="wg0"; client:str="router"
class Webhook(BaseModel): name:str; url:str

@asynccontextmanager
async def lifespan(app): init(); yield
app=FastAPI(title="Exitlane",version=__version__,lifespan=lifespan)
static=Path(__file__).parent/"static"; app.mount("/assets",StaticFiles(directory=static),name="assets")
@app.get("/",include_in_schema=False)
async def index(): return FileResponse(static/"index.html")
@app.get("/api/health")
async def health(): return {"ok":True,"version":__version__}
@app.get("/api/setup/state")
async def setup_state():
    with sqlite3.connect(DB) as c: count=c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return {"complete":setting("setup_complete",False),"admin_created":count>0,"provider":await provider.status(),"wireguard_configured":setting("wireguard_configured",False)}
@app.post("/api/setup/admin")
async def admin(req:Admin):
    digest,salt=hash_password(req.password)
    with sqlite3.connect(DB) as c:
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]: raise HTTPException(409,"administrator already exists")
        c.execute("INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",(req.username,digest,salt))
    return {"ok":True}
@app.get("/api/diagnostics")
async def diag():
    checks=await diagnostics(); return {"ok":all(x["ok"] for x in checks),"checks":checks}
@app.post("/api/providers/nordvpn/install")
async def install(): return await provider.install()
@app.post("/api/providers/nordvpn/login/token")
async def login_token(req:Token): return await provider.login_token(req.token)
@app.post("/api/providers/nordvpn/login/callback")
async def login_callback(req:Callback): return await provider.login_callback(req.callback_url)
@app.post("/api/providers/nordvpn/configure-defaults")
async def defaults(): return {"operations":await provider.defaults()}
@app.get("/api/providers/nordvpn/status")
async def status(): return {"status":await provider.status()}
@app.get("/api/providers/nordvpn/countries")
async def countries(): return {"countries":await provider.countries()}
@app.post("/api/providers/nordvpn/connect")
async def connect(req:Connect): return await provider.connect(req.target)
@app.post("/api/providers/nordvpn/disconnect")
async def disconnect(): return await provider.disconnect()
@app.post("/api/ingress/wireguard")
async def wireguard(req:WireGuard):
    try: result=await create_wireguard(**req.model_dump()); set_setting("wireguard_configured",True); return result
    except (ValueError,RuntimeError) as e: raise HTTPException(400,str(e))
@app.get("/api/ingress/wireguard/client/{name}",response_class=PlainTextResponse)
async def client(name:str):
    path=WG_DIR/f"{name}.conf"
    if not path.exists(): raise HTTPException(404,"not found")
    return path.read_text()
@app.post("/api/notifications/webhook")
async def webhook(req:Webhook):
    if not req.url.startswith(("http://","https://")): raise HTTPException(400,"invalid URL")
    with sqlite3.connect(DB) as c: cur=c.execute("INSERT INTO webhooks(name,url) VALUES(?,?)",(req.name,req.url)); return {"ok":True,"id":cur.lastrowid}
@app.post("/api/setup/complete")
async def complete(): set_setting("setup_complete",True); return {"ok":True}
