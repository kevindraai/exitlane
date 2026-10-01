from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
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
        current_sha=SHA,
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
        {"tag_commit": "d" * 40},
        {"project_version": "9.9.9"},
    ],
)
def test_release_validation_rejects_source_or_confirmation_mismatch(changes):
    values = {
        "tag": "v1.2.3-rc.4",
        "source_sha": SHA,
        "confirmation": f"PUBLISH EXITLANE v1.2.3-rc.4 {SHA}",
        "current_sha": SHA,
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
            current_sha=SHA,
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
        assert request.full_url == "https://api.github.com/repos/kevindraai/exitlane/releases/tags/v1.2.3-rc.4"
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


def test_push_parses_one_registry_digest_without_echoing_other_output():
    digest = "sha256:" + "d" * 64

    def run(argv, **kwargs):
        assert argv == ["docker", "push", "ghcr.io/kevindraai/exitlane:v1.2.3-rc.4"]
        assert kwargs["timeout"] == 600 and kwargs["capture_output"] is True
        return subprocess.CompletedProcess(argv, 0, f"v1.2.3-rc.4: digest: {digest} size: 123\n", "")

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
            return json.dumps([
                {"name": digest, "metadata": {"container": {"tags": ["v1.2.3-rc.4"]}}}
            ]).encode()

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
            "v1.2.3-rc.4", "kevindraai/exitlane", "synthetic-token",
            open_url=lambda *args, **kwargs: Response(),
        )


@pytest.mark.parametrize(
    "output,code",
    [
        ("", "docker_push_digest_invalid"),
        ("tag: digest: sha256:" + "a" * 64 + " size: 1\ntag: digest: sha256:" + "b" * 64 + " size: 2", "docker_push_digest_invalid"),
        ("", "docker_push_failed"),
    ],
)
def test_push_rejects_failed_missing_or_ambiguous_digest(output, code):
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1 if code == "docker_push_failed" else 0, output, "")

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
