import os
import platform
import shutil
from exitlane.core import command


async def run():
    checks = [
        {"name": "Linux", "ok": platform.system() == "Linux", "detail": platform.platform()},
        {"name": "Root", "ok": os.geteuid() == 0, "detail": f"uid={os.geteuid()}"},
        {"name": "TUN", "ok": os.path.exists("/dev/net/tun"), "detail": "/dev/net/tun"},
    ]
    for item in ("ip", "wg", "nft", "curl", "systemctl"):
        path = shutil.which(item)
        checks.append({"name": item, "ok": bool(path), "detail": path or "not installed"})
    rc, out, err = await command("ping", "-c", "1", "-W", "2", "1.1.1.1", timeout=5)
    checks.append({"name": "Internet", "ok": rc == 0, "detail": out or err})
    rc, out, err = await command("getent", "hosts", "api.nordvpn.com", timeout=5)
    checks.append({"name": "DNS", "ok": rc == 0, "detail": out or err})
    return checks
