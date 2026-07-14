# Exitlane

**Smart egress for every network.**

Exitlane is a self-hosted egress gateway for routers, VLANs and applications. The first provider is NordVPN, while the core stays provider- and router-neutral.

## v0.1.0-alpha.1

- FastAPI backend and OpenAPI docs
- SQLite state
- first-run WebUI
- NordVPN CLI adapter
- WireGuard ingress generator
- diagnostics and generic webhooks
- Debian/Proxmox LXC installer
- Docker development scaffold
- tests and GitHub Actions

> Early alpha. Keep the management interface on a trusted network.

## Install on Debian 12 LXC

The LXC needs `/dev/net/tun`; a privileged LXC is the currently tested path.

```bash
git clone https://github.com/kevindraai/exitlane.git
cd exitlane
sudo ./installer/install-debian.sh
```

Open `http://<LXC-IP>:8787` and complete the wizard.

## Development

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn exitlane.main:app --reload --host 0.0.0.0 --port 8787
```

See `ROADMAP.md` and `docs/`.
