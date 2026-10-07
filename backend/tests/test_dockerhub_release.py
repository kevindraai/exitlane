from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import dockerhub_release as hub
import validate_docker_release as release

SHA = "a" * 40
MAIN = "b" * 40
DIGEST = "sha256:" + "c" * 64
TAG = "v1.0.1"


@pytest.fixture(autouse=True)
def workflow_context(monkeypatch):
    for key, value in {
        "GITHUB_REPOSITORY": "kevindraai/exitlane",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SHA": MAIN,
        "DOCKERHUB_NAMESPACE": "tunedpixel",
    }.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def facts():
    return hub.identity(
        TAG, SHA, DIGEST, f"MIRROR EXITLANE {TAG} {SHA} {DIGEST} TO tunedpixel/exitlane"
    )


def attestation(predicate, kind, *, name=hub.SOURCE, digest=DIGEST):
    return [
        {
            "verificationResult": {
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": kind,
                    "subject": [{"name": name, "digest": {"sha256": digest[7:]}}],
                    "predicate": predicate,
                }
            }
        }
    ]


@pytest.fixture
def evidence(facts):
    repo = "https://github.com/kevindraai/exitlane"
    source = {
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {
                "workflow": {
                    "ref": "refs/heads/main",
                    "repository": repo,
                    "path": ".github/workflows/docker-release.yml",
                },
                "inputs": {
                    "release_tag": TAG,
                    "source_sha": SHA,
                    "confirmation": f"PUBLISH EXITLANE {TAG} {SHA}",
                },
            },
            "resolvedDependencies": [
                {"uri": f"git+{repo}@refs/tags/{TAG}", "digest": {"gitCommit": SHA}}
            ],
        }
    }
    sbom = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "exitlane"}]}
    return attestation(source, hub.SLSA), attestation(sbom, hub.SPDX)


@pytest.mark.parametrize("tag", ["latest", "main", "v1.0.1\nINJECT=yes", "--help", "v01.0.1"])
def test_nonrelease_or_injected_refs_never_reach_git_or_registry(tag):
    with pytest.raises(release.ReleaseValidationError):
        hub.identity(tag, SHA, DIGEST, "confirmation")


@pytest.mark.parametrize(
    "namespace", ["https://evil.example", "tunedpixel/other", "Tunedpixel", "a\nB=value"]
)
def test_namespace_cannot_change_host_repository_or_workflow_output(monkeypatch, namespace):
    monkeypatch.setenv("DOCKERHUB_NAMESPACE", namespace)
    with pytest.raises(release.ReleaseValidationError, match="namespace_invalid"):
        hub.destination()


def test_confirmation_includes_destination_and_canonical_digest(facts):
    assert facts["destination"] == "docker.io/tunedpixel/exitlane"
    for sha, digest, confirmation in [
        ("main", DIGEST, "confirmation"),
        (SHA, "latest", "confirmation"),
        (SHA, DIGEST, f"MIRROR EXITLANE {TAG} {SHA} {DIGEST} TO draaiodijk/exitlane"),
    ]:
        with pytest.raises(release.ReleaseValidationError):
            hub.identity(TAG, sha, digest, confirmation)


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_REPOSITORY", "other/exitlane"),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_SHA", "main"),
    ],
)
def test_forks_pull_requests_and_untrusted_branches_cannot_publish(monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(release.ReleaseValidationError, match="workflow_context_invalid"):
        hub.context()


def test_upstream_source_and_sbom_are_bound_to_selected_digest_and_tag(facts, evidence):
    source, sbom = evidence
    assert hub.verify_source(facts, source, sbom)["packages"] == [{"name": "exitlane"}]
    for changes in ("source_sha", "release_tag", "confirmation"):
        tampered = copy.deepcopy(source)
        tampered[0]["verificationResult"]["statement"]["predicate"]["buildDefinition"][
            "externalParameters"
        ]["inputs"][changes] = "wrong"
        with pytest.raises(release.ReleaseValidationError, match="upstream_source_mismatch"):
            hub.verify_source(facts, tampered, sbom)
    for field in ("predicateType", "subject", "_type"):
        tampered = copy.deepcopy(source)
        tampered[0]["verificationResult"]["statement"][field] = "wrong"
        with pytest.raises(release.ReleaseValidationError, match="verified_attestation_mismatch"):
            hub.verify_source(facts, tampered, sbom)


def test_upstream_dependency_and_sbom_cannot_be_borrowed_from_other_source(facts, evidence):
    source, sbom = evidence
    source[0]["verificationResult"]["statement"]["predicate"]["buildDefinition"][
        "resolvedDependencies"
    ] = []
    with pytest.raises(release.ReleaseValidationError, match="upstream_source_mismatch"):
        hub.verify_source(facts, source, sbom)
    with pytest.raises(release.ReleaseValidationError, match="verified_attestation_mismatch"):
        hub.statement(
            attestation({}, hub.SPDX, digest="sha256:" + "d" * 64),
            name=hub.SOURCE,
            digest=DIGEST,
            predicate_type=hub.SPDX,
        )


def repository():
    return {
        "is_private": False,
        "immutable_tags_settings": {"enabled": True, "rules": [hub.IMMUTABLE_RULE]},
    }


def mirror_stubs(monkeypatch):
    calls = []
    monkeypatch.setattr(hub, "get_json", lambda _: repository())
    monkeypatch.setattr(hub, "command", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(hub, "validate_image", lambda *args: None)
    return calls


def test_existing_conflicting_tag_is_never_replaced(monkeypatch, facts):
    calls = mirror_stubs(monkeypatch)
    monkeypatch.setattr(hub, "manifest", lambda *_: "sha256:" + "d" * 64)
    with pytest.raises(release.ReleaseValidationError, match="existing_tag_digest_mismatch"):
        hub.mirror(facts)
    assert not calls


def test_identical_existing_tag_resumes_signing_without_republishing(monkeypatch, facts):
    calls = mirror_stubs(monkeypatch)
    monkeypatch.setattr(hub, "manifest", lambda *_: DIGEST)
    assert hub.mirror(facts)["already_present"] is True
    assert not calls


def test_registry_errors_never_count_as_tag_absence(monkeypatch, facts):
    calls = mirror_stubs(monkeypatch)

    def forbidden(*_):
        raise urllib.error.HTTPError("registry", 403, "denied", {}, None)

    monkeypatch.setattr(hub, "manifest", forbidden)
    with pytest.raises(urllib.error.HTTPError):
        hub.mirror(facts)
    assert not calls


def test_missing_tag_is_copied_by_digest_without_rebuilding(monkeypatch, facts):
    calls = mirror_stubs(monkeypatch)
    manifests = iter([None, DIGEST, DIGEST])

    def inspect(*_):
        value = next(manifests)
        if value is None:
            raise urllib.error.HTTPError("registry", 404, "missing", {}, None)
        return value

    monkeypatch.setattr(hub, "manifest", inspect)
    assert hub.mirror(facts)["already_present"] is False
    assert calls == [
        [
            "docker",
            "buildx",
            "imagetools",
            "create",
            "--prefer-index=false",
            "--tag",
            "docker.io/tunedpixel/exitlane:v1.0.1",
            hub.SOURCE + "@" + DIGEST,
        ]
    ]


def test_private_or_mutable_repository_cannot_receive_release(monkeypatch, facts):
    for repo in (
        {"is_private": True},
        {"is_private": False},
        {"is_private": False, "immutable_tags_settings": {"enabled": True, "rules": ["other"]}},
    ):
        calls = mirror_stubs(monkeypatch)
        monkeypatch.setattr(hub, "get_json", lambda _, value=repo: value)
        with pytest.raises(
            release.ReleaseValidationError, match="public_immutable_repository_required"
        ):
            hub.mirror(facts)
        assert not calls


def test_platform_and_source_labels_are_checked_before_distribution(monkeypatch, facts):
    info = {
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "Labels": {
                "org.opencontainers.image.revision": SHA,
                "org.opencontainers.image.version": "v1.0.1",
                "org.opencontainers.image.source": "https://github.com/kevindraai/exitlane",
            }
        },
    }
    monkeypatch.setattr(hub, "command", lambda args, **kw: json.dumps(info))
    hub.validate_image(hub.SOURCE + "@" + DIGEST, facts)
    info["Architecture"] = "arm64"
    with pytest.raises(release.ReleaseValidationError, match="image_identity_mismatch"):
        hub.validate_image(hub.SOURCE + "@" + DIGEST, facts)


def test_copy_errors_do_not_leak_subprocess_output(monkeypatch):
    monkeypatch.setattr(
        hub.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 1, "secret", "PAT")
    )
    with pytest.raises(release.ReleaseValidationError, match="^dockerhub_command_failed$"):
        hub.command(["docker", "push"])


def test_hub_environment_allows_owner_approval_and_retains_protection():
    environment = {
        "name": hub.ENVIRONMENT,
        "can_admins_bypass": False,
        "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": [{"type": "User", "reviewer": {"login": "kevindraai"}}],
            }
        ],
    }
    release.validate_publication_environment(
        environment, name=hub.ENVIRONMENT, prevent_self_review=False
    )
    environment["protection_rules"][0]["prevent_self_review"] = True
    with pytest.raises(release.ReleaseValidationError, match="self_review_policy_mismatch"):
        release.validate_publication_environment(
            environment, name=hub.ENVIRONMENT, prevent_self_review=False
        )


def test_hub_prepare_requests_owner_approval_policy(monkeypatch, facts):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    calls = []

    def check(repository, token, **policy):
        calls.append((repository, policy))
        raise release.ReleaseValidationError("stop_before_git_or_network")

    monkeypatch.setattr(release, "_fetch_publication_environment", check)
    with pytest.raises(release.ReleaseValidationError, match="stop_before_git_or_network"):
        hub.prepare(facts)
    assert calls == [
        ("kevindraai/exitlane", {"name": hub.ENVIRONMENT, "prevent_self_review": False})
    ]


def test_workflow_exposes_credentials_only_in_protected_publication_job():
    path = Path(__file__).resolve().parents[2] / ".github/workflows/dockerhub-release.yml"
    text = path.read_text()
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    validate = workflow["jobs"]["validate"]
    publish = workflow["jobs"]["publish"]
    assert "secrets." not in json.dumps(validate)
    assert publish["needs"] == "validate"
    assert publish["environment"] == hub.ENVIRONMENT
    assert "refs/heads/main" in publish["if"]
    assert "--deny-self-hosted-runners" in text
    assert "--source-digest" in text
    assert "docker logout" in text and "DOCKER_CONFIG=$(mktemp -d)" in text
    assert "docker build " not in text


def test_destination_retry_finds_exact_predicate_among_older_attestations(facts):
    expected = hub.mirror_predicate(facts, b"current verification", b"qualification receipt")
    old = hub.mirror_predicate(facts, b"old verification", b"qualification receipt")
    results = attestation(old, hub.MIRROR_TYPE, name=hub.destination())
    results += attestation(expected, hub.MIRROR_TYPE, name=hub.destination())
    assert (
        hub.statement(
            results,
            name=hub.destination(),
            digest=DIGEST,
            predicate_type=hub.MIRROR_TYPE,
            expected=expected,
        )
        == expected
    )
    with pytest.raises(release.ReleaseValidationError, match="verified_attestation_mismatch"):
        hub.statement(
            results[:1],
            name=hub.destination(),
            digest=DIGEST,
            predicate_type=hub.MIRROR_TYPE,
            expected=expected,
        )


def qualification_asset(raw):
    return {
        "name": "docker-v1.0.1-published-image-qualification.md",
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "browser_download_url": "https://github.com/kevindraai/exitlane/releases/download/v1.0.1/docker-v1.0.1-published-image-qualification.md",
    }


def qualification_bytes(digest=DIGEST, source=SHA):
    return (
        "Published-image Docker qualification passed within the scope below.\n"
        f"The versioned image `{hub.SOURCE}:{TAG}` resolved to registry\n"
        f"digest `{digest}`.\n"
        f"The image declares source commit\n`{source}` and version `v1.0.1`.\n"
    ).encode()


def test_qualification_receipt_hash_and_actual_declaration_bind_image(monkeypatch, tmp_path, facts):
    monkeypatch.chdir(tmp_path)
    raw = qualification_bytes()
    asset = qualification_asset(raw)
    monkeypatch.setattr(hub.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(raw))
    hub.validate_qualification(facts, {"assets": [asset]}, asset["name"])
    assert (tmp_path / "source-qualification.md").read_bytes() == raw
    raw = (
        qualification_bytes("sha256:" + "d" * 64)
        + (f"Historical source {SHA} digest {DIGEST}").encode()
    )
    asset = qualification_asset(raw)
    with pytest.raises(
        release.ReleaseValidationError, match="qualification_receipt_identity_mismatch"
    ):
        hub.validate_qualification(facts, {"assets": [asset]}, asset["name"])
    raw = qualification_bytes(source="d" * 40)
    asset = qualification_asset(raw)
    with pytest.raises(
        release.ReleaseValidationError, match="qualification_receipt_identity_mismatch"
    ):
        hub.validate_qualification(facts, {"assets": [asset]}, asset["name"])


def test_qualification_download_refuses_tampered_hash_or_external_url(monkeypatch, tmp_path, facts):
    monkeypatch.chdir(tmp_path)
    raw = qualification_bytes()
    asset = qualification_asset(raw)
    monkeypatch.setattr(hub.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"tampered"))
    with pytest.raises(release.ReleaseValidationError, match="qualification_receipt_hash_mismatch"):
        hub.validate_qualification(facts, {"assets": [asset]}, asset["name"])
    asset["browser_download_url"] = "https://external.example/receipt"
    with pytest.raises(
        release.ReleaseValidationError, match="published_image_qualification_missing"
    ):
        hub.validate_qualification(facts, {"assets": [asset]}, asset["name"])


def test_prepare_checks_qualification_before_accepting_manifest(monkeypatch, facts):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(release, "_fetch_publication_environment", lambda *a, **kw: None)
    monkeypatch.setattr(release, "_fetch_release", lambda *a: {"assets": []})
    monkeypatch.setattr(release, "_project_version", lambda *_: "1.0.1")
    monkeypatch.setattr(release, "_tag_commit", lambda *_: SHA)
    monkeypatch.setattr(release, "validate", lambda **kw: None)
    monkeypatch.setattr(hub, "command", lambda *a, **kw: MAIN)
    monkeypatch.setattr(
        hub,
        "manifest",
        lambda *a: pytest.fail("Missing qualification must fail before manifest acceptance"),
    )
    with pytest.raises(
        release.ReleaseValidationError, match="published_image_qualification_missing"
    ):
        hub.prepare(facts)


@pytest.mark.parametrize(
    "url",
    [
        "file:///root/credentials_docker.env",
        "http://hub.docker.com",
        "https://evil.example",
        "https://hub.docker.com@evil.example",
    ],
)
def test_api_hosts_and_schemes_are_fixed_before_network_access(url):
    with pytest.raises(release.ReleaseValidationError, match="api_url_invalid"):
        hub.get_json(url)
