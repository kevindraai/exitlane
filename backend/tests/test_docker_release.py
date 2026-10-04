from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import docker_release_provenance as provenance
import push_ghcr_image as push
import resume_docker_release as resume
import validate_docker_release as release

SHA = "a" * 40
MINIMUM = "b" * 40
MAIN = "c" * 40
RELEASE = {"tag_name": "v1.2.3-rc.4", "draft": False, "published_at": "2026-10-01T00:00:00Z"}


@pytest.fixture(autouse=True)
def github_actions_context(monkeypatch):
    context = {
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "kevindraai/exitlane",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": MAIN,
        "GITHUB_WORKFLOW_SHA": MAIN,
        "GITHUB_WORKFLOW_REF": "kevindraai/exitlane/.github/workflows/docker-release.yml@refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY_ID": "1300425127",
        "GITHUB_REPOSITORY_OWNER_ID": "1483233",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    for key, value in context.items():
        monkeypatch.setenv(key, value)
    return context


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
        statement["predicate"]["buildDefinition"]["externalParameters"]["inputs"]["release_tag"] = (
            "v9.9.9"
        )
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


def resume_origin():
    run = {
        "id": 123,
        "head_sha": SHA,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": ".github/workflows/docker-release.yml",
        "status": "completed",
        "conclusion": "failure",
        "repository": {"full_name": "kevindraai/exitlane"},
        "run_attempt": 1,
    }
    steps = [{"name": name, "conclusion": "success"} for name in resume.QUALIFIED_STEPS]
    steps.append({"name": "Attest image build provenance", "conclusion": "failure"})
    return (
        run,
        [{"name": "publish", "steps": steps}],
        ("Pushed ghcr.io/kevindraai/exitlane:v1.2.3 with digest sha256:" + "d" * 64),
    )


def recover(run=None, jobs=None, log=None):
    original_run, original_jobs, original_log = resume_origin()
    return resume.validate_origin(
        run=original_run if run is None else run,
        jobs=original_jobs if jobs is None else jobs,
        log=original_log if log is None else log,
        run_id="123",
        tag="v1.2.3",
        source_sha=SHA,
        digest="sha256:" + "d" * 64,
    )


def test_resume_binds_qualified_failed_run_without_any_push():
    result = recover()
    assert result["original_invocation"] == "123/1"
    assert result["original_workflow_sha"] == SHA
    assert result["digest"] == "sha256:" + "d" * 64


@pytest.mark.parametrize(
    "field", ["head_sha", "head_branch", "event", "path", "status", "conclusion"]
)
def test_resume_refuses_untrusted_or_unfinished_origin(field):
    run, _, _ = resume_origin()
    run[field] = "different"
    with pytest.raises(release.ReleaseValidationError):
        recover(run=run)


@pytest.mark.parametrize("step", resume.QUALIFIED_STEPS)
def test_resume_requires_every_original_qualification_and_publication_step(step):
    _, jobs, _ = resume_origin()
    next(s for s in jobs[0]["steps"] if s["name"] == step)["conclusion"] = "failure"
    with pytest.raises(release.ReleaseValidationError):
        recover(jobs=jobs)


@pytest.mark.parametrize(
    "log",
    [
        "",
        "different digest",
        "Pushed ghcr.io/kevindraai/exitlane:v9.9.9 with digest sha256:" + "d" * 64,
    ],
)
def test_resume_refuses_missing_or_other_tag_push_evidence(log):
    with pytest.raises(release.ReleaseValidationError):
        recover(log=log)


def test_resume_refuses_mismatched_digest_even_after_qualified_push():
    _, _, log = resume_origin()
    with pytest.raises(release.ReleaseValidationError):
        recover(log=log.replace("d" * 64, "e" * 64))


def test_recovery_provenance_names_original_build_and_current_attestor_separately(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "456")
    recovered = recover()
    result = provenance.predicate(
        tag="v1.2.3", source_sha=SHA, workflow_sha=MAIN, invocation="456/1", recovery=recovered
    )
    definition = result["buildDefinition"]
    assert definition["buildType"] == "https://actions.github.io/buildtypes/workflow/v1"
    assert definition["externalParameters"]["workflow"] == {
        "ref": "refs/heads/main",
        "repository": provenance.REPOSITORY,
        "path": ".github/workflows/docker-release.yml",
    }
    assert definition["resolvedDependencies"][1]["digest"]["gitCommit"] == MAIN
    assert result["runDetails"]["metadata"]["invocationId"].endswith("/456/attempts/1")
    assert definition["externalParameters"]["inputs"]["resume_digest"] == recovered["digest"]
    assert definition["externalParameters"]["inputs"]["original_run_id"] == "123"
    recovery = definition["internalParameters"]["exitlaneRecovery"]
    assert recovery["operation"] == "qualify-and-attest-existing-image"
    assert recovery["attestingWorkflowSha"] == MAIN
    assert definition["resolvedDependencies"][2] == {
        "uri": "oci://" + provenance.IMAGE + "@" + recovered["digest"],
        "digest": {"sha256": "d" * 64},
        "annotations": {"exitlane:role": "existing-qualified-image"},
    }
    assert recovery["attestationInvocation"].endswith("/456/attempts/1")


def test_verified_recovery_provenance_cannot_be_reused_for_another_digest(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "456")
    expected = provenance.predicate(
        tag="v1.2.3", source_sha=SHA, workflow_sha=MAIN, invocation="456/1", recovery=recover()
    )
    with pytest.raises(release.ReleaseValidationError, match="recovery_digest_mismatch"):
        provenance.verify([], digest="sha256:" + "e" * 64, expected=expected)


def test_workflow_recovery_skips_build_and_push_and_retains_original_evidence():
    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/docker-release.yml"
    ).read_text()
    assert "if: ${{ inputs.resume_digest == '' }}" in workflow
    assert "scripts/resume_docker_release.py" in workflow
    assert "recovery-original-build.log" in workflow
    assert "steps.provenance.outputs.bundle-path" in workflow
    assert "sbom-verification.json" in workflow


def test_recovery_evidence_is_permanently_attached_without_replacing_release_assets():
    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/docker-release.yml"
    ).read_text()
    assert (
        'archive="docker-release-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-evidence.tar.gz"'
        in workflow
    )
    assert 'sha256sum "$archive" > "$archive.sha256"' in workflow
    assert 'gh release upload "$RELEASE_TAG"' in workflow
    assert "--clobber" not in workflow


def test_resume_rejects_other_failure_or_duplicate_publish_jobs():
    _, jobs, _ = resume_origin()
    jobs[0]["steps"][-1]["name"] = "Create SPDX SBOM for exact release image"
    with pytest.raises(release.ReleaseValidationError):
        recover(jobs=jobs)
    _, jobs, _ = resume_origin()
    with pytest.raises(release.ReleaseValidationError):
        recover(jobs=jobs + jobs)


def test_resume_rejects_ambiguous_push_receipt():
    _, _, log = resume_origin()
    with pytest.raises(release.ReleaseValidationError):
        recover(log=log + "\n" + log)


@pytest.mark.parametrize("recovery", [False, True])
def test_full_canonical_core_matches_executed_pinned_official_generator(recovery):
    canonical = json.loads(
        (Path(__file__).parent / "fixtures/github_actions_provenance_v1.json").read_text()
    )
    actual = provenance.predicate(
        tag="v1.2.3",
        source_sha=SHA,
        workflow_sha=MAIN,
        invocation="123/1",
        recovery=recover() if recovery else None,
    )
    definition = actual["buildDefinition"]
    assert definition["buildType"] == canonical["buildDefinition"]["buildType"]
    assert (
        definition["externalParameters"]["workflow"]
        == canonical["buildDefinition"]["externalParameters"]["workflow"]
    )
    assert (
        definition["internalParameters"]["github"]
        == canonical["buildDefinition"]["internalParameters"]["github"]
    )
    assert (
        definition["resolvedDependencies"][1]
        == canonical["buildDefinition"]["resolvedDependencies"][0]
    )
    assert actual["runDetails"] == canonical["runDetails"]
    if recovery:
        assert definition["internalParameters"]["exitlaneRecovery"]["originalBuild"] == recover()


@pytest.mark.parametrize(
    "key",
    [
        "GITHUB_SERVER_URL",
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_WORKFLOW_SHA",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_EVENT_NAME",
        "RUNNER_ENVIRONMENT",
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REPOSITORY_OWNER_ID",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ],
)
@pytest.mark.parametrize("bad", [None, "", "incorrect"])
def test_missing_or_mismatched_github_metadata_refuses_attestation(monkeypatch, key, bad):
    if bad is None:
        monkeypatch.delenv(key)
    else:
        monkeypatch.setenv(key, bad)
    with pytest.raises(release.ReleaseValidationError, match="provenance_github"):
        provenance.predicate(tag="v1.2.3", source_sha=SHA, workflow_sha=MAIN, invocation="123/1")
