from __future__ import annotations
import re,shutil
from exitlane.core import command
from .base import Provider

def parse(output):
    result={}
    for line in output.splitlines():
        if ":" in line:
            k,v=line.split(":",1); result[k.strip()]=v.strip()
    return result

class NordVPN(Provider):
    id="nordvpn"; display_name="NordVPN"
    async def status(self):
        if not shutil.which("nordvpn"): return {"installed":False,"authenticated":False,"connected":False}
        rc,out,err=await command("nordvpn","status"); values=parse(out or err)
        arc,aout,aerr=await command("nordvpn","account")
        return {"installed":True,"authenticated":arc==0 and "not logged in" not in aout.lower(),"connected":values.get("Status","").lower()=="connected","country":values.get("Country",""),"city":values.get("City",""),"server":values.get("Hostname",values.get("Server","")),"external_ip":values.get("IP",""),"technology":values.get("Current technology","")}
    async def install(self):
        if shutil.which("nordvpn"): return {"ok":True,"message":"already installed"}
        rc,out,err=await command("bash","-c","curl -fsSL https://downloads.nordcdn.com/apps/linux/install.sh | sh",timeout=180); return {"ok":rc==0,"stdout":out,"stderr":err}
    async def login_token(self,token):
        if not re.fullmatch(r"[A-Za-z0-9._~-]{20,512}",token): return {"ok":False,"message":"invalid token format"}
        rc,out,err=await command("nordvpn","login","--token",token); return {"ok":rc==0,"stdout":out,"stderr":err}
    async def login_callback(self,url):
        if not url.startswith(("nordvpn://","https://")): return {"ok":False,"message":"invalid callback URL"}
        rc,out,err=await command("nordvpn","login","--callback",url); return {"ok":rc==0,"stdout":out,"stderr":err}
    async def defaults(self):
        results=[]
        for k,v in [("technology","NordLynx"),("routing","on"),("lan-discovery","on"),("firewall","on"),("killswitch","on"),("ipv6","off"),("analytics","off")]:
            rc,out,err=await command("nordvpn","set",k,v); results.append({"setting":k,"ok":rc==0,"output":out or err})
        return results
    async def countries(self):
        rc,out,err=await command("nordvpn","countries"); return sorted(out.split()) if rc==0 else []
    async def connect(self,target=None):
        args=["nordvpn","connect"]
        if target:
            if not re.fullmatch(r"[A-Za-z0-9 _.-]{1,80}",target): return {"ok":False,"message":"invalid target"}
            args.append(target)
        rc,out,err=await command(*args,timeout=90); return {"ok":rc==0,"stdout":out,"stderr":err}
    async def disconnect(self):
        rc,out,err=await command("nordvpn","disconnect"); return {"ok":rc==0,"stdout":out,"stderr":err}
provider=NordVPN()
