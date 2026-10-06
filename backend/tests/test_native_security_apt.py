"""Synthetic offline APT snapshots; no package, service or network mutation."""

import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/qualification"))
from native_security_apt import collect_apt

INVENTORY = {
    "packages": [
        {
            "name": "sample",
            "architecture": "amd64",
            "version": "1.0-1",
            "source_name": "sample-src",
            "source_version": "1.0-1",
            "status": "install ok installed",
            "state": "installed",
        }
    ],
}
POLICY = """sample:
  Installed: 1.0-1
  Candidate: 1.0-2+b1
  Version table:
     1.0-2+b1 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
        release o=Debian,l=Debian,n=trixie
 *** 1.0-1 100
        100 /var/lib/dpkg/status
"""
SHOW = """Package: sample
Architecture: amd64
Version: 1.0-2+b1
Source: sample-src (1.0-2)
"""
STATUS = """Package: sample
Status: install ok installed
Architecture: amd64
Version: 1.0-1
Source: sample-src (1.0-1)
Depends: libc6 (>= 2.0)
Description: omitted private-looking arbitrary prose

"""


class Host:
    def __init__(self, tmp_path):
        self.root = tmp_path / "root"
        self.work = tmp_path / "work"
        self.work.mkdir()
        status = self.root / "var/lib/dpkg/status"
        status.parent.mkdir(parents=True)
        status.write_text(STATUS)
        lists = self.root / "var/lib/apt/lists"
        lists.mkdir(parents=True)
        (lists / "deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages").write_text(
            SHOW
            + "Filename: pool/main/s/sample/sample_1.0-2+b1_amd64.deb\nSize: 123\nSHA256: "
            + "0" * 64
            + "\n\n"
        )
        self.calls = []
        self.policy = POLICY
        self.simulation = "Inst sample [1.0-1] (1.0-2+b1 Debian:13/trixie [amd64])\n"
        self.fail = False
        self.mutate = False

    def run(self, argv, *, env=None, timeout=60, input=None):
        config = Path(env["APT_CONFIG"])
        self.calls.append(argv)
        text = config.read_text()
        assert 'Dir::Etc::main "-";' in text
        assert "#clear DPkg::Pre-Invoke;" in text
        assert 'Dir::Bin::dpkg "/bin/false";' in text
        assert "Dir::Bin::Methods" in text
        assert (config.parent / "methods/http").read_text().startswith("#!/usr/bin/python3 -S\n")
        status = (config.parent / "status").read_text()
        assert "Depends: libc6 (>= 2.0)" in status
        assert "Description:" not in status
        if self.mutate:
            (self.root / "var/lib/dpkg/status").write_text(STATUS + "\n")
        output = (
            self.policy if argv[1] == "policy" else SHOW if argv[1] == "show" else self.simulation
        )
        return SimpleNamespace(
            returncode=1 if self.fail else 0, stdout=output.encode(), stderr_sha256="e" * 64
        )


def test_candidates_preserve_source_version_without_false_archive_trust(tmp_path):
    host = Host(tmp_path)
    result = collect_apt(host, INVENTORY)
    candidate = result["data"]["candidates"]["sample:amd64"]
    assert candidate["candidate_version"] == "1.0-2+b1"
    assert candidate["source_version"] == "1.0-2"
    assert candidate["eligible"] is True
    assert candidate["sources_authenticated"] is False
    assert result["status"] == "incomplete"
    assert result["data"]["simulation"]["status"] == "skipped"
    assert all(call[0] == "apt-cache" for call in host.calls)
    assert result["data"]["snapshot"]["consistent"] is True
    assert not list(host.work.iterdir())


def test_optional_simulation_exact_versions_and_indirect_provider_exclusion(tmp_path):
    host = Host(tmp_path)
    host.simulation += "Inst nordvpn (99.0 Vendor:stable [amd64])\n"
    result = collect_apt(host, INVENTORY, simulate=True)
    simulation = result["data"]["simulation"]
    assert next(call for call in host.calls if call[0] == "apt-get") == [
        "apt-get",
        "--simulate",
        "--no-download",
        "install",
        "sample:amd64=1.0-2+b1",
    ]
    assert simulation["requests"] == ["sample:amd64=1.0-2+b1"]
    assert simulation["additions"][0]["name"] == "nordvpn"
    assert simulation["excluded_touched"] == ["nordvpn"]
    assert simulation["eligible"] is False


def test_provider_is_never_requested(tmp_path):
    host = Host(tmp_path)
    inventory = {
        "packages": [dict(INVENTORY["packages"][0], name="nordvpn", source_name="sample-src")]
    }
    (host.root / "var/lib/dpkg/status").write_text(
        STATUS.replace("Package: sample", "Package: nordvpn")
    )
    original = host.run

    def run(argv, **kwargs):
        if argv[1] == "show":
            result = original(argv, **kwargs)
            result.stdout = SHOW.replace("Package: sample", "Package: nordvpn").encode()
            return result
        return original(argv, **kwargs)

    host.run = run
    result = collect_apt(host, inventory, simulate=True)
    assert result["data"]["candidates"]["nordvpn:amd64"]["eligible"] is False
    assert result["data"]["simulation"]["excluded_requests"] == ["nordvpn:amd64"]
    assert not any(call[0] == "apt-get" for call in host.calls)


@pytest.mark.parametrize("bad_suite", ["sid", "bookworm", "testing"])
def test_unsupported_suite_candidate_is_ineligible(tmp_path, bad_suite):
    host = Host(tmp_path)
    host.policy = POLICY.replace("trixie/main", bad_suite + "/main")
    result = collect_apt(host, INVENTORY, simulate=True)
    assert result["data"]["candidates"]["sample:amd64"]["eligible"] is False
    assert not any(call[0] == "apt-get" for call in host.calls)


def test_changed_snapshot_and_command_failure_are_incomplete(tmp_path):
    host = Host(tmp_path)
    host.mutate = True
    assert collect_apt(host, INVENTORY)["reason"] == "apt_snapshot_changed"
    host.mutate = False
    host.fail = True
    result = collect_apt(host, INVENTORY, simulate=True)
    assert result["reason"] == "apt_command_failed"
    assert result["data"]["simulation"]["status"] == "incomplete"


def test_secret_uri_is_rejected_without_exporting_raw_output(tmp_path):
    host = Host(tmp_path)
    host.policy = POLICY.replace("http://deb.debian.org", "http://secret:password@deb.debian.org")
    result = collect_apt(host, INVENTORY)
    assert result["status"] == "incomplete"
    assert "password" not in str(result)
    assert "secret:" not in str(result)


def test_symlink_public_input_and_inventory_drift_are_rejected(tmp_path):
    host = Host(tmp_path)
    status = host.root / "var/lib/dpkg/status"
    status.unlink()
    target = tmp_path / "private"
    target.write_text("synthetic-private-marker")
    status.symlink_to(target)
    result = collect_apt(host, INVENTORY)
    assert result["reason"] == "apt_snapshot_input_invalid"
    assert "synthetic-private-marker" not in str(result)
    assert not host.calls
    status.unlink()
    status.write_text(STATUS.replace("Version: 1.0-1", "Version: 0.9-1"))
    assert collect_apt(host, INVENTORY)["reason"] == "apt_inventory_changed"


def test_held_inventory_is_not_requested(tmp_path):
    host = Host(tmp_path)
    inventory = {"packages": [dict(INVENTORY["packages"][0], status="hold ok installed")]}
    (host.root / "var/lib/dpkg/status").write_text(
        STATUS.replace("install ok installed", "hold ok installed")
    )
    result = collect_apt(host, inventory, simulate=True)
    assert result["data"]["simulation"]["held_inventory"] == ["sample:amd64"]
    assert not any(call[0] == "apt-get" for call in host.calls)


@pytest.mark.skipif(
    not shutil.which("apt-cache") or not shutil.which("apt-get"), reason="APT tools absent"
)
def test_real_apt_offline_resolver_against_synthetic_current_cache(tmp_path):
    host = Host(tmp_path)
    (host.root / "var/lib/dpkg/status").write_text(STATUS.replace("Depends: libc6 (>= 2.0)\n", ""))

    def run(argv, *, env=None, timeout=60, input=None):
        host.calls.append(argv)
        completed = subprocess.run(
            argv, env=env, input=input, timeout=timeout, capture_output=True, check=False
        )
        return SimpleNamespace(
            returncode=completed.returncode, stdout=completed.stdout, stderr_sha256="e" * 64
        )

    host.run = run
    result = collect_apt(host, INVENTORY, simulate=True)
    assert result["reason"] == "apt_simulation_source_unverified", result
    candidate = result["data"]["candidates"]["sample:amd64"]
    assert candidate["candidate_version"] == "1.0-2+b1"
    assert candidate["source_version"] == "1.0-2"
    assert result["data"]["simulation"]["upgrades"][0]["version"] == "1.0-2+b1"


@pytest.mark.parametrize("failure", [None, "signature", "hash", "source", "codename", "expiry"])
def test_cached_signature_index_chain_exact_binding(tmp_path, failure):
    import hashlib

    host = Host(tmp_path)
    keyring = host.root / "usr/share/keyrings/debian-archive-keyring.gpg"
    keyring.parent.mkdir(parents=True)
    keyring.write_bytes(b"synthetic-public-keyring")
    payload = SHOW.encode() + b"\n"
    digest = hashlib.sha256(payload).hexdigest()
    release = (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
        "Origin: Debian\nLabel: Debian\nCodename: trixie\nSuite: trixie\n"
        "Date: Wed, 01 Jan 2020 00:00:00 UTC\n"
        "SHA256:\n " + digest + " " + str(len(payload)) + " main/binary-amd64/Packages\n"
        "-----BEGIN PGP SIGNATURE-----\nsynthetic\n-----END PGP SIGNATURE-----\n"
    )
    if failure == "codename":
        release = release.replace("Codename: trixie", "Codename: sid")
    if failure == "expiry":
        release = release.replace(
            "SHA256:\n", "Valid-Until: Wed, 02 Jan 2020 00:00:00 UTC\nSHA256:\n"
        )
    (host.root / "var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease").write_text(
        release
    )
    original = host.run

    def run(argv, *, env=None, timeout=60, input=None, limit=None):
        if argv[0] == "gpgv":
            # Signature primitive mocked here; hash and exact metadata bindings are real.
            return SimpleNamespace(
                returncode=1 if failure == "signature" else 0, stdout=b"", stderr_sha256="e" * 64
            )
        if argv[0] == "/usr/lib/apt/apt-helper":
            output = payload
            if failure == "hash":
                output += b"modified"
            elif failure == "source":
                output = payload.replace(b"(1.0-2)", b"(1.0-1)")
            return SimpleNamespace(returncode=0, stdout=output, stderr_sha256="e" * 64)
        return original(argv, env=env, timeout=timeout, input=input)

    host.run = run
    result = collect_apt(host, INVENTORY)
    assert result["data"]["candidates"]["sample:amd64"]["sources_authenticated"] is (
        failure is None
    )
    assert result["status"] == ("complete" if failure is None else "incomplete")
    assert "configured_host_sources_and_pinning_not_observed" in result["data"]["limitations"]


@pytest.mark.skipif(not shutil.which("gpgv"), reason="gpgv absent")
def test_real_gpgv_rejects_unsigned_cached_origin_labels(tmp_path):
    host = Host(tmp_path)
    keyring = host.root / "usr/share/keyrings/debian-archive-keyring.gpg"
    keyring.parent.mkdir(parents=True)
    keyring.write_bytes(b"invalid-synthetic-keyring")
    (host.root / "var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease").write_text(
        "Origin: Debian\nCodename: trixie\n"
    )
    original = host.run

    def run(argv, *, env=None, timeout=60, input=None):
        if argv[0] == "gpgv":
            completed = subprocess.run(
                argv, env=env, timeout=timeout, capture_output=True, check=False
            )
            return SimpleNamespace(
                returncode=completed.returncode, stdout=completed.stdout, stderr_sha256="e" * 64
            )
        return original(argv, env=env, timeout=timeout, input=input)

    host.run = run
    result = collect_apt(host, INVENTORY)
    assert not result["data"]["candidates"]["sample:amd64"]["sources_authenticated"]
    assert result["data"]["archive_authentication"]["status"] == "incomplete"


# Synthetic RSA OpenPGP fixture; no production key material.
_TEST_ARCHIVE_KEY_B64 = "xsBNBF4L4QABCADDbxbCEdvg3+nU5OBbB10XhcgVS+jv0KRAYyYQRpoRJQ39Z7Tr7UJlVVh2/l7n/wp670REY5AHHCENDFMAOnSPDvtvvk2CjDW4po78tUsDj0tfXnb2NYPqYAGNZEpTycWwOOYgtCGsPyNn8FbB6nybELz0nxknS+z23lkSztKk+BtvQw3lXd92a8fw9BNe/jJUMwpVQYJ7/1gw77rDXO3HdqpiCTI+fdkk9qTCDti9WfnkL+4pvUzOSv4m811ikB8CQZshG6IHHsSm25cpDp4fHMC6oWyknRBAc3xC5ZyAaAoR3l/AlVZkBec8ZUFcymPnEPVFEr2/AZBc3jzI4aQ5ABEBAAHNLlN5bnRoZXRpYyBPZmZsaW5lIEFyY2hpdmUgPGFyY2hpdmVAcWEuaW52YWxpZD7CwFwEEwEIAAYFAl4L4QAACgkQwv0yF3ziLcfHHwgAt68G6H5lj2+cTcKxXWphl/hWL85StJF2bHMvDzf+k3YT+tvMmNFs+zjiB1ykTfC4vSO7w6LvzzixNQ3eF3N2PBcPNT9SQaWbOL4uHLP+VrA09PycT1r/Db4VjfVccWrPJfklzJ6qcHNTx8K1XfXSX8qmb8TbrbSfkki6ufoz4od7PlRzB5/7db7+eNGK/8HxZHjWtE5taF+OseKXhYE8PM+d0VkeoT3Y831GKcjxXkli+Qwg8iuhJ7nXN5PNe0WrLrXzuYOAeyrkIkUJMex0ni2dpDsuPHT+bY7CGROKbV501/8fY5Ofv0r53KNO3qvaThct1YMjFzJvpuQQTg69jg=="
_TEST_INRELEASE = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\nLabel: Debian\nSuite: trixie\nCodename: trixie\nDate: Wed, 01 Jan 2020 00:00:00 UTC\nSHA256:\n ddc1a7ea56ed93abdcf4571f428cd66411c34f442ed24f01a47123248d14245a 82 main/binary-amd64/Packages\n-----BEGIN PGP SIGNATURE-----\n\nwsBcBAEBCAAGBQJeC+EAAAoJEML9Mhd84i3HYyYIALuIf3w+h0O2WYlP2YHL3ona\nb4ot+SWw0Bg8xUYOw7+biTdxNkZLz6CzHEs2n2EUsgUl9LkIg7lRI9xZK7cqxm0a\nppQ9RANY9idf3zkCuSK9xCLFw7AKb79ZM6o7NFlYMJoUKYOTIQtQAW5uJdkOZ43m\nLQg7/mpyQ9ycej9FcOiPJq0fMixb4V8BaBLm9YVOFY15gALZEoMlyqS0xASwEh2P\n6vBz6KL5KL+z3IfloYuPvNu4XMrkkS4a+0DD0FIA+9d891lSQXuWH9adk6jN/+ze\nHLafIDBUOE/emdQDy1mXaW2OwExCBT3O68TcUPnED7rcYX7ZxFULc4jl3tZ0dII=\n-----END PGP SIGNATURE-----\n"


@pytest.mark.skipif(
    not shutil.which("gpgv") or not Path("/usr/lib/apt/apt-helper").exists(),
    reason="offline verification tools absent",
)
@pytest.mark.parametrize("tamper", [False, True])
def test_real_signature_and_decompressed_packages_chain(tmp_path, tamper):
    import base64

    host = Host(tmp_path)
    keyring = host.root / "usr/share/keyrings/debian-archive-keyring.gpg"
    keyring.parent.mkdir(parents=True)
    keyring.write_bytes(base64.b64decode(_TEST_ARCHIVE_KEY_B64))
    lists = host.root / "var/lib/apt/lists"
    (lists / "deb.debian.org_debian_dists_trixie_InRelease").write_text(_TEST_INRELEASE)
    payload = SHOW + "\n"
    if tamper:
        payload = payload.replace("(1.0-2)", "(1.0-1)")
    (lists / "deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages").write_text(payload)
    original = host.run

    def run(argv, *, env=None, timeout=60, input=None, limit=None):
        if argv[0] in {"gpgv", "/usr/lib/apt/apt-helper"}:
            completed = subprocess.run(
                argv, env=env, timeout=timeout, capture_output=True, check=False
            )
            return SimpleNamespace(
                returncode=completed.returncode, stdout=completed.stdout, stderr_sha256="e" * 64
            )
        return original(argv, env=env, timeout=timeout, input=input)

    host.run = run
    result = collect_apt(host, INVENTORY)
    assert result["data"]["candidates"]["sample:amd64"]["sources_authenticated"] is not tamper
    assert result["status"] == ("incomplete" if tamper else "complete")
    assert result["data"]["mode"] == "controlled_cache_projection"


def test_indirect_transaction_touching_held_package_is_ineligible(tmp_path):
    host = Host(tmp_path)
    inventory = {
        "packages": [
            INVENTORY["packages"][0],
            dict(INVENTORY["packages"][0], name="other", status="hold ok installed"),
        ]
    }
    (host.root / "var/lib/dpkg/status").write_text(
        STATUS
        + STATUS.replace("Package: sample", "Package: other").replace(
            "install ok installed", "hold ok installed"
        )
    )
    host.simulation += "Inst other [1.0-1] (1.0-2+b1 Debian:13/trixie [amd64])\n"
    original = host.run

    def run(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv[1] == "show" and argv[-1].startswith("other:"):
            result.stdout = SHOW.replace("Package: sample", "Package: other").encode()
        return result

    host.run = run
    result = collect_apt(host, inventory, simulate=True)
    simulation = result["data"]["simulation"]
    assert simulation["requests"] == ["sample:amd64=1.0-2+b1"]
    assert simulation["held_touched"] == ["other"]
    assert simulation["eligible"] is False


def test_snapshot_change_invalidates_completed_simulation(tmp_path):
    host = Host(tmp_path)
    host.mutate = True
    result = collect_apt(host, INVENTORY, simulate=True)
    assert result["reason"] == "apt_snapshot_changed"
    assert result["data"]["simulation"]["status"] == "incomplete"
    assert result["data"]["snapshot"]["consistent"] is False


@pytest.mark.parametrize("dependency_bound", [True, False])
def test_every_simulated_dependency_requires_own_authenticated_source_identity(
    tmp_path, dependency_bound
):
    import hashlib

    host = Host(tmp_path)
    keyring = host.root / "usr/share/keyrings/debian-archive-keyring.gpg"
    keyring.parent.mkdir(parents=True)
    keyring.write_bytes(b"synthetic-public-keyring")
    dependency = "Package: new-dependency\nArchitecture: amd64\nVersion: 2.0+b1\nSource: dependency-src (2.0)\n"
    payload = (SHOW + "\n" + (dependency + "\n" if dependency_bound else "")).encode()
    release = (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\nCodename: trixie\n"
        "Date: Wed, 01 Jan 2020 00:00:00 UTC\nSHA256:\n "
        + hashlib.sha256(payload).hexdigest()
        + " "
        + str(len(payload))
        + " main/binary-amd64/Packages\n"
        "-----BEGIN PGP SIGNATURE-----\nsynthetic\n-----END PGP SIGNATURE-----\n"
    )
    (host.root / "var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease").write_text(
        release
    )
    host.simulation += "Inst new-dependency (2.0+b1 Debian:13/trixie [amd64])\n"
    original = host.run

    def run(argv, *, env=None, timeout=60, input=None, limit=None):
        if argv[0] == "gpgv":
            return SimpleNamespace(returncode=0, stdout=b"", stderr_sha256="e" * 64)
        if argv[0] == "/usr/lib/apt/apt-helper":
            return SimpleNamespace(returncode=0, stdout=payload, stderr_sha256="e" * 64)
        result = original(argv, env=env, timeout=timeout, input=input)
        if argv[1] == "show" and argv[-1].startswith("new-dependency:"):
            result.stdout = dependency.encode()
        if argv[1] == "policy" and argv[-1].startswith("new-dependency:"):
            result.stdout = POLICY.replace("1.0-2+b1", "2.0+b1").encode()
        return result

    host.run = run
    result = collect_apt(host, INVENTORY, simulate=True)
    simulation = result["data"]["simulation"]
    assert result["data"]["candidates"]["sample:amd64"]["sources_authenticated"] is True
    assert simulation["additions"][0]["source_name"] == "dependency-src"
    assert simulation["additions"][0]["source_version"] == "2.0"
    assert simulation["additions"][0]["sources_authenticated"] is dependency_bound
    assert simulation["eligible"] is dependency_bound
    assert simulation["status"] == ("complete" if dependency_bound else "incomplete")
    assert result["status"] == ("complete" if dependency_bound else "incomplete")


def test_standard_debian_keyring_alias_only(tmp_path):
    from native_security_apt import _snapshot

    host = Host(tmp_path)
    folder = host.root / "usr/share/keyrings"
    folder.mkdir(parents=True)
    canonical = folder / "debian-archive-keyring.pgp"
    canonical.write_bytes(b"synthetic public archive key")
    alias = folder / "debian-archive-keyring.gpg"
    alias.symlink_to(canonical.name)
    captured, _ = _snapshot(host.root)
    assert captured[alias] == canonical.read_bytes()
    alias.unlink()
    private = host.root / "private-canary"
    private.write_text("PRIVATE_KEY_CANARY")
    alias.symlink_to(private)
    from native_security_evidence import EvidenceError

    with pytest.raises(EvidenceError, match="apt_snapshot_input_invalid"):
        _snapshot(host.root)
