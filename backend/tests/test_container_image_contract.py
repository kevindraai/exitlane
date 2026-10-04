"""Image/Compose trust contract without Docker or runtime state mutation."""

import importlib.util
import re
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "image_contract", ROOT / "scripts/check_container_image.py"
)
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


def test_runtime_export_matches_locked_graph_and_hashes():
    exported = image.validate_requirements((ROOT / "docker/requirements-runtime.txt").read_text())
    lock = tomllib.loads((ROOT / "backend/uv.lock").read_text())
    packages = {p["name"]: p for p in lock["package"]}
    pending = list(packages["exitlane"]["dependencies"])
    expected = set()
    visited = set()
    while pending:
        dependency = pending.pop()
        name = dependency["name"]
        extras = tuple(dependency.get("extra", []))
        if (name, extras) in visited:
            continue
        visited.add((name, extras))
        expected.add(name)
        package = packages[name]
        pending.extend(package.get("dependencies", []))
        for extra in extras:
            pending.extend(package.get("optional-dependencies", {})[extra])
    assert set(exported) == expected
    for name, (version, hashes) in exported.items():
        package = packages[name]
        assert version == package["version"]
        artifacts = package.get("wheels", []) + ([package["sdist"]] if "sdist" in package else [])
        assert hashes == {artifact["hash"].removeprefix("sha256:") for artifact in artifacts}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "fastapi>=1",
        "fastapi==1",
        "--index-url https://example.invalid",
        "urllib3==2.8.0 --hash=sha256:" + "a" * 64,
    ],
)
def test_unpinned_or_development_requirements_refused(text):
    with pytest.raises(image.ImageContractError):
        image.validate_requirements(text)


def test_compose_bounds_namespace_privileges_and_exposure():
    compose = yaml.safe_load((ROOT / "docker/compose.appliance.yml").read_text())
    service = compose["services"]["exitlane"]
    assert service["image"].startswith("${EXITLANE_IMAGE:?") and "latest" not in service["image"]
    assert service["platform"] == "linux/amd64"
    assert service["init"] is True and service["read_only"] is True
    assert service["cap_drop"] == ["ALL"] and service["cap_add"] == ["NET_ADMIN"]
    assert service["devices"] == ["/dev/net/tun:/dev/net/tun"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert not set(service).intersection({"privileged", "pid", "network_mode", "userns_mode"})
    assert service["volumes"] == ["exitlane-state:/data"]
    assert service["networks"] == ["exitlane"]
    assert compose["networks"]["exitlane"] == {"driver": "bridge", "enable_ipv6": False}
    assert service["ports"] == [
        "${EXITLANE_MANAGEMENT_BIND:-127.0.0.1}:8787:8787/tcp",
        "${EXITLANE_INGRESS_BIND:-127.0.0.1}:51820:51820/udp",
    ]
    assert service["sysctls"] == {
        "net.ipv4.ip_forward": "1",
        "net.ipv6.conf.all.forwarding": "0",
        "net.ipv4.ping_group_range": "0 0",
    }
    assert len(service["tmpfs"]) == 2
    for mount in service["tmpfs"]:
        assert mount.startswith(("/run:", "/tmp:"))
        assert all(
            option in mount for option in ("nosuid", "nodev", "noexec", "size=", "mode=0700")
        )
    assert (
        service["pids_limit"] == 128 and service["mem_limit"] == "2g" and service["cpus"] == "2.0"
    )
    assert service["logging"]["options"] == {"max-size": "10m", "max-file": "3"}


def test_dockerfile_selective_build_and_real_supervised_entrypoint():
    text = (ROOT / "docker/Dockerfile.appliance").read_text()
    bases = re.findall(r"^FROM (\S+)", text, re.MULTILINE)
    assert len(bases) == 2 and bases[0] == bases[1]
    assert re.fullmatch(r"python:3\.13-slim-trixie@sha256:[0-9a-f]{64}", bases[0])
    assert 'CMD ["python", "-m", "exitlane.container_entrypoint", "serve"]' in text
    assert 'CMD ["python", "-m", "exitlane.container_entrypoint", "health"]' in text
    assert "--require-hashes" in text and "--no-deps /tmp/wheel/*.whl" in text
    assert "COPY backend /" not in text and "COPY . " not in text
    assert "COPY LICENSE /usr/share/doc/exitlane/LICENSE" in text
    assert 'org.exitlane.support="v1"' in text
    assert (
        "org.opencontainers.image.revision" in text and "org.opencontainers.image.version" in text
    )
    assert "EXITLANE_DATA_DIR=/data/state" in text and "EXITLANE_CONFIG_DIR=/data/config" in text


@pytest.fixture
def image_root(tmp_path):
    site = tmp_path / "usr/local/lib/python3.13/site-packages"
    package = site / "exitlane"
    metadata = site / "exitlane-0.3.0rc3.dist-info/METADATA"
    paths = [tmp_path / p for p in image.REQUIRED_TOOLS]
    paths.extend(package / p for p in image.REQUIRED_ASSETS)
    paths.extend(
        tmp_path / p
        for p in (
            "usr/share/doc/exitlane/LICENSE",
            "etc/ssl/certs/ca-certificates.crt",
            "usr/share/zoneinfo/UTC",
        )
    )
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic-public-file")
    metadata.parent.mkdir()
    metadata.write_text("Name: exitlane\nVersion: 0.3.0rc3\n")
    return tmp_path


def test_clean_content_has_public_hash_receipt_without_reading_volume(image_root):
    private = image_root / "data/config/secret.key"
    private.parent.mkdir(parents=True)
    private.write_bytes(b"synthetic-private-volume")
    result = image.inspect_root(image_root)
    assert result["packages"] == {"exitlane": "0.3.0rc3"}
    assert result["package_files"] == len(image.REQUIRED_ASSETS)
    assert len(result["package_sha256"]) == 64
    assert all(len(value) == 64 for value in result["public_sha256"].values())
    assert "secret.key" not in str(result)


@pytest.mark.parametrize("name", ["pip", "setuptools", "wheel"])
def test_build_time_python_packaging_tools_are_not_part_of_runtime_image(image_root, name):
    metadata = image_root / f"usr/local/lib/python3.13/site-packages/{name}-1.0.dist-info/METADATA"
    metadata.parent.mkdir(parents=True)
    metadata.write_text(f"Name: {name}\nVersion: 1.0\n")
    with pytest.raises(image.ImageContractError, match="image_development_dependency"):
        image.inspect_root(image_root)


@pytest.mark.parametrize(
    "relative",
    [
        "src/source.py",
        "root/.cache/file",
        "usr/local/lib/python3.13/site-packages/exitlane/tests/test_x.py",
        "usr/local/lib/python3.13/site-packages/exitlane/key.key",
        "usr/local/lib/python3.13/site-packages/exitlane/state.db",
        "usr/local/lib/python3.13/site-packages/exitlane/__pycache__/cached.pyc",
        "usr/local/lib/python3.13/site-packages/exitlane/private.pem",
        "usr/local/lib/python3.13/site-packages/exitlane/wg-office.conf",
        "usr/local/lib/python3.13/site-packages/exitlane/state.db-journal",
        "usr/local/lib/python3.13/site-packages/exitlane/.env.production",
    ],
)
def test_build_development_or_state_artifacts_refused(image_root, relative):
    path = image_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"synthetic-forbidden")
    with pytest.raises(image.ImageContractError):
        image.inspect_root(image_root)


def test_missing_public_asset_refused(image_root):
    (image_root / "usr/share/doc/exitlane/LICENSE").unlink()
    with pytest.raises(image.ImageContractError, match="image_public_asset_missing"):
        image.inspect_root(image_root)


def test_package_symlink_cannot_read_appliance_key(image_root):
    secret = image_root / "data/config/secret.key"
    secret.parent.mkdir(parents=True)
    secret.write_bytes(b"synthetic-private-volume")
    asset = image_root / "usr/local/lib/python3.13/site-packages/exitlane/providers/pia_ca.pem"
    asset.unlink()
    asset.symlink_to(secret)
    with pytest.raises(image.ImageContractError, match="image_public_asset_missing"):
        image.inspect_root(image_root)
