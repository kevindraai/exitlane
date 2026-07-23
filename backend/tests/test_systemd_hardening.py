from pathlib import Path


UNIT = Path(__file__).parents[2] / "systemd" / "exitlane.service"


def test_service_has_compatible_sandbox_and_filesystem_boundaries():
    content = UNIT.read_text(encoding="utf-8")
    required = {
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectHome=true",
        "ProtectSystem=strict",
        "ProtectKernelModules=true",
        "ProtectControlGroups=true",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
        "MemoryDenyWriteExecute=true",
        "RestrictRealtime=true",
        "SystemCallArchitectures=native",
        "UMask=0077",
        "Environment=HOME=/var/lib/exitlane",
        "ReadWritePaths=/etc/exitlane /etc/wireguard /var/lib/exitlane /var/log/exitlane",
        "ExecStart=/opt/exitlane/venv/bin/uvicorn exitlane.main:app --host ${EXITLANE_HOST} --port ${EXITLANE_PORT} --no-server-header --no-proxy-headers",
    }
    assert required <= set(content.splitlines())
