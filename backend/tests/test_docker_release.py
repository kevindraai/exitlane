from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import docker_release_provenance as provenance
import push_ghcr_image as push
import validate_docker_release as release

SHA = "a" * 40
MINIMUM = "b" * 40
MAIN = "c" * 40
RELEASE = {"tag_name": "v1.2.3-rc.4", "draft": False, "published_at": "2026-10-01T00:00:00Z"}


@pytest.mark.parametrize(
    ("tag", "expected"),
    [("v1.2.3", "1.2.3"), ("v1.2.3-rc.4", "1.2.3rc4")],
)
def test_release_tag_maps_to_package_version(tag, expected):
    assert release.package_version_for_tag(tag) == expected


def test_project_metadata_is_read_as_data_from_only_the_validated_git_sha(monkeypatch):
    calls = []

    def show(args, **kwargs):
        calls.append((args, kwargs))
        if args[:2] == ["git", "cat-file"]:
            return "32"
        return '[project]\nversion = "1.2.3rc4"\n'

    monkeypatch.setattr(release.subprocess, "check_output", show)
    assert release._project_version(SHA) == "1.2.3rc4"
    assert calls[0][0] == ["git", "cat-file", "-s", f"{SHA}:backend/pyproject.toml"]
    assert calls[1][0] == ["git", "show", f"{SHA}:backend/pyproject.toml"]
    assert all(call[1]["stderr"] == release.subprocess.DEVNULL for call in calls)
    with pytest.raises(release.ReleaseValidationError, match="docker_release_source_sha_invalid"):
        release._project_version("main")


def test_project_metadata_size_is_bounded_before_contents_are_read(monkeypatch):
    def size_only(args, **kwargs):
        assert args[:3] == ["git", "cat-file", "-s"]
        return str(release.MAX_PROJECT_METADATA + 1)

    monkeypatch.setattr(release.subprocess, "check_output", size_only)
    with pytest.raises(
        release.ReleaseValidationError, match="docker_release_project_metadata_invalid"
    ):
        release._project_version(SHA)


@pytest.mark.parametrize(
    "tag",
    ["main", "v1.2", "v01.2.3", "v1.2.3-rc.0", "v1.2.3-rc.04", "v1.2.3+local", "v1.2.3/evil"],
)
def test_release_tag_rejects_noncanonical_or_nonrelease_refs(tag):
    with pytest.raises(release.ReleaseValidationError, match="docker_release_tag_invalid"):
        release.package_version_for_tag(tag)


def test_release_validation_binds_confirmation_release_tag_sha_and_qualified_main():
    ancestors = []

    def is_ancestor(ancestor, descendant):
        ancestors.append((ancestor, descendant))
        return True

    result = release.validate(
        tag="v1.2.3-rc.4",
        source_sha=SHA,
        confirmation=f"PUBLISH EXITLANE v1.2.3-rc.4 {SHA}",
        current_sha=MAIN,
        main_sha=MAIN,
        project_version="1.2.3rc4",
        release=RELEASE,
        tag_commit=SHA,
        is_ancestor=is_ancestor,
        minimum_sha=MINIMUM,
    )
    assert result == {
        "tag": "v1.2.3-rc.4",
        "source_sha": SHA,
        "app_version": "v1.2.3rc4",
        "image": "ghcr.io/kevindraai/exitlane:v1.2.3-rc.4",
    }
    assert ancestors == [(MINIMUM, SHA), (SHA, MAIN)]


@pytest.mark.parametrize(
    "changes",
    [
        {"confirmation": "PUBLISH EXITLANE v1.2.3-rc.4"},
        {"source_sha": "d" * 40},
        {"current_sha": "d" * 40},
        {"main_sha": "d" * 40},
        {"tag_commit": "d" * 40},
        {"project_version": "9.9.9"},
    ],
)
def test_release_validation_rejects_source_or_confirmation_mismatch(changes):
    values = {
        "tag": "v1.2.3-rc.4",
        "source_sha": SHA,
        "confirmation": f"PUBLISH EXITLANE v1.2.3-rc.4 {SHA}",
        "current_sha": MAIN,
        "main_sha": MAIN,
        "project_version": "1.2.3rc4",
        "release": RELEASE,
        "tag_commit": SHA,
        "is_ancestor": lambda *_: True,
        "minimum_sha": MINIMUM,
    }
    values.update(changes)
    with pytest.raises(release.ReleaseValidationError):
        release.validate(**values)


@pytest.mark.parametrize(
    "ancestor_results",
    [(False, True), (True, False)],
)
def test_release_validation_requires_qualified_source_ancestry(ancestor_results):
    results = iter(ancestor_results)
    with pytest.raises(
        release.ReleaseValidationError,
        match="docker_release_source_not_qualified_main",
    ):
        release.validate(
            tag="v1.2.3-rc.4",
            source_sha=SHA,
            confirmation=f"PUBLISH EXITLANE v1.2.3-rc.4 {SHA}",
            current_sha=MAIN,
            main_sha=MAIN,
            project_version="1.2.3rc4",
            release=RELEASE,
            tag_commit=SHA,
            is_ancestor=lambda *_: next(results),
            minimum_sha=MINIMUM,
        )


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {},
        {"tag_name": "v9.9.9", "draft": False, "published_at": "2026-10-01"},
        {"tag_name": "v1.2.3-rc.4", "draft": True, "published_at": "2026-10-01"},
        {"tag_name": "v1.2.3-rc.4", "draft": False, "published_at": ""},
    ],
)
def test_published_release_metadata_fails_closed(metadata):
    with pytest.raises(release.ReleaseValidationError, match="docker_release_not_published"):
        release.validate_published_release("v1.2.3-rc.4", metadata)


def test_published_release_api_is_https_bounded_and_rejects_network_failure(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            assert size == release.MAX_RELEASE_RESPONSE + 1
            return b'{"tag_name":"v1.2.3-rc.4","draft":false,"published_at":"today"}'

    def open_url(request, timeout):
        assert (
            request.full_url
            == "https://api.github.com/repos/kevindraai/exitlane/releases/tags/v1.2.3-rc.4"
        )
        assert request.get_header("Authorization") == "Bearer synthetic-token"
        assert timeout <= 15
        return Response()

    monkeypatch.setattr(release.urllib.request, "urlopen", open_url)
    release._fetch_release("v1.2.3-rc.4", "kevindraai/exitlane", "synthetic-token")

    monkeypatch.setattr(
        release.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()),
    )
    with pytest.raises(release.ReleaseValidationError, match="docker_release_api_unavailable"):
        release._fetch_release("v1.2.3-rc.4", "kevindraai/exitlane", "synthetic-token")


def test_release_workflow_is_manual_exact_tag_and_limits_package_write():
    workflow = Path(__file__).resolve().parents[2] / ".github/workflows/docker-release.yml"
    source = workflow.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in source
    assert "exitlane:latest" not in source
    assert "packages: write" in source
    assert source.count("packages: write") == 1
    publish = source.split("  publish:\n", maxsplit=1)[1]
    assert "packages: write" in publish
    assert "packages: write" not in source.split("  publish:\n", maxsplit=1)[0]
    assert "release_tag" in source and "source_sha" in source and "confirmation" in source
    assert "Checkout trusted workflow source and full ancestry" in source
    assert "Checkout the exact validated application source as build input" in source
    assert "path: release-source" in source
    assert '-t "$IMAGE" release-source' in source
    assert "scripts/push_ghcr_image.py" in source
    assert "environment: ghcr-production" in publish
    assert "predicate-path: release-provenance.json" in publish
    assert "--source-digest" in publish
    assert "scripts/docker_release_provenance.py verify" in publish


def protected_environment():
    return {
        "name": "ghcr-production",
        "can_admins_bypass": False,
        "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
        "protection_rules": [
            {
                "type": "required_reviewers",
                "reviewers": [
                    {"type": "User", "reviewer": {"login": "kevindraai"}},
                ],
            }
        ],
    }


def test_publication_requires_a_separate_product_owner_approval_boundary():
    release.validate_publication_environment(protected_environment())


@pytest.mark.parametrize("environment", [None, {}, {"name": "copilot"}])
def test_missing_or_wrong_publication_environment_fails_closed(environment):
    with pytest.raises(release.ReleaseValidationError):
        release.validate_publication_environment(environment)


@pytest.mark.parametrize(
    "change",
    [
        {"can_admins_bypass": True},
        {"can_admins_bypass": None},
        {"protection_rules": []},
        {"protection_rules": [{"type": "required_reviewers", "reviewers": []}]},
        {
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "reviewers": [
                        {"type": "User", "reviewer": {"login": "someone-else"}},
                    ],
                }
            ]
        },
        {"deployment_branch_policy": None},
        {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
    ],
)
def test_unprotected_publication_environment_cannot_schedule_publish(change):
    environment = protected_environment()
    environment.update(change)
    with pytest.raises(release.ReleaseValidationError):
        release.validate_publication_environment(environment)


def test_publication_environment_api_failure_is_not_an_approval(monkeypatch):
    monkeypatch.setattr(
        release.urllib.request, "urlopen", lambda *a, **kw: (_ for _ in ()).throw(TimeoutError())
    )
    with pytest.raises(release.ReleaseValidationError, match="approval_environment_unavailable"):
        release._fetch_publication_environment("kevindraai/exitlane", "synthetic-token")


def verified_provenance():
    expected = provenance.predicate(
        tag="v1.2.3-rc.4", source_sha=SHA, workflow_sha=MAIN, invocation="123/1"
    )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": provenance.PREDICATE_TYPE,
        "subject": [{"name": provenance.IMAGE, "digest": {"sha256": "d" * 64}}],
        "predicate": expected,
    }
    return [{"verificationResult": {"statement": statement}}]


def test_provenance_distinguishes_older_application_source_from_workflow_source():
    results = verified_provenance()
    expected = provenance.predicate(
        tag="v1.2.3-rc.4", source_sha=SHA, workflow_sha=MAIN, invocation="123/1"
    )
    provenance.verify(results, digest="sha256:" + "d" * 64, expected=expected)
    dependencies = expected["buildDefinition"]["resolvedDependencies"]
    assert dependencies[0]["digest"]["gitCommit"] == SHA
    assert dependencies[1]["digest"]["gitCommit"] == MAIN


@pytest.mark.parametrize("field", ["source", "workflow", "tag", "digest", "builder"])
def test_verified_signature_alone_cannot_accept_wrong_application_provenance(field):
    results = verified_provenance()
    expected = provenance.predicate(
        tag="v1.2.3-rc.4", source_sha=SHA, workflow_sha=MAIN, invocation="123/1"
    )
    statement = results[0]["verificationResult"]["statement"]
    if field in ("source", "workflow"):
        index = 0 if field == "source" else 1
        statement["predicate"]["buildDefinition"]["resolvedDependencies"][index]["digest"][
            "gitCommit"
        ] = "e" * 40
    elif field == "tag":
        statement["predicate"]["buildDefinition"]["externalParameters"]["releaseTag"] = "v9.9.9"
    elif field == "digest":
        statement["subject"][0]["digest"]["sha256"] = "e" * 64
    else:
        statement["predicate"]["runDetails"]["builder"]["id"] = "https://example.invalid/builder"
    with pytest.raises(release.ReleaseValidationError, match="provenance_source_mismatch"):
        provenance.verify(results, digest="sha256:" + "d" * 64, expected=expected)


def test_push_parses_one_registry_digest_without_echoing_other_output():
    digest = "sha256:" + "d" * 64

    def run(argv, **kwargs):
        assert argv == ["docker", "push", "ghcr.io/kevindraai/exitlane:v1.2.3-rc.4"]
        assert kwargs["timeout"] == 600 and kwargs["capture_output"] is True
        return subprocess.CompletedProcess(
            argv, 0, f"v1.2.3-rc.4: digest: {digest} size: 123\n", ""
        )

    assert push.push_digest("ghcr.io/kevindraai/exitlane:v1.2.3-rc.4", run=run) == digest


def test_publication_fails_closed_on_existing_exact_registry_tag():
    digest = "sha256:" + "e" * 64

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            assert size == push.MAX_PACKAGE_RESPONSE + 1
            return json.dumps(
                [{"name": digest, "metadata": {"container": {"tags": ["v1.2.3-rc.4"]}}}]
            ).encode()

    def open_url(request, timeout):
        assert request.full_url.endswith("?per_page=100&page=1")
        assert request.get_header("Authorization") == "Bearer synthetic-token"
        assert timeout <= 15
        return Response()

    with pytest.raises(push.PushError, match="docker_release_tag_already_published"):
        push._existing_release_digest(
            "v1.2.3-rc.4", "kevindraai/exitlane", "synthetic-token", open_url=open_url
        )


def test_publication_refuses_unknown_registry_state_and_malformed_metadata():
    def unavailable(*args, **kwargs):
        raise TimeoutError

    with pytest.raises(push.PushError, match="docker_release_tag_registry_state_unknown"):
        push._existing_release_digest(
            "v1.2.3-rc.4", "kevindraai/exitlane", "synthetic-token", open_url=unavailable
        )

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return b'[{"name":"invalid","metadata":{}}]'

    with pytest.raises(push.PushError, match="docker_release_tag_registry_response_invalid"):
        push._existing_release_digest(
            "v1.2.3-rc.4",
            "kevindraai/exitlane",
            "synthetic-token",
            open_url=lambda *args, **kwargs: Response(),
        )


@pytest.mark.parametrize(
    "output,code",
    [
        ("", "docker_push_digest_invalid"),
        (
            "tag: digest: sha256:"
            + "a" * 64
            + " size: 1\ntag: digest: sha256:"
            + "b" * 64
            + " size: 2",
            "docker_push_digest_invalid",
        ),
        ("", "docker_push_failed"),
    ],
)
def test_push_rejects_failed_missing_or_ambiguous_digest(output, code):
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 1 if code == "docker_push_failed" else 0, output, ""
        )

    with pytest.raises(push.PushError, match=code):
        push.push_digest("ghcr.io/kevindraai/exitlane:v1.2.3-rc.4", run=run)


@pytest.mark.parametrize(
    "image",
    [
        "ghcr.io/other/exitlane:v1.2.3",
        "ghcr.io/kevindraai/exitlane:latest",
        "ghcr.io/kevindraai/exitlane:v1.2.3@sha256:" + "a" * 64,
    ],
)
def test_push_accepts_only_exact_release_tags_for_project_image(image):
    with pytest.raises(push.PushError, match="docker_push_image_invalid"):
        push.push_digest(image, run=lambda *a, **k: pytest.fail("must validate before push"))
