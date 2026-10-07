#!/usr/bin/env python3
"""Mirror a verified public ExitLane release; never build or replace a version tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import validate_docker_release as release

SOURCE = "ghcr.io/kevindraai/exitlane"
ENVIRONMENT = "dockerhub-production"
REPOSITORY = "kevindraai/exitlane"
MIRROR_TYPE = "https://github.com/kevindraai/exitlane/attestations/registry-mirror/v1"
SLSA = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document/v2.3"
MAX_BYTES = 8 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMMUTABLE_RULE = r"^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$"


def fail(code):
    raise release.ReleaseValidationError("dockerhub_" + code)


def destination():
    namespace = os.environ.get("DOCKERHUB_NAMESPACE", "tunedpixel")
    if re.fullmatch(r"[a-z0-9]{4,30}", namespace) is None:
        fail("namespace_invalid")
    return "docker.io/" + namespace + "/exitlane"


def identity(tag, source_sha, digest, confirmation):
    version = release.package_version_for_tag(tag)
    if release.SHA.fullmatch(source_sha or "") is None or DIGEST.fullmatch(digest or "") is None:
        fail("identity_invalid")
    if confirmation != f"MIRROR EXITLANE {tag} {source_sha} {digest} TO {destination()[10:]}":
        fail("confirmation_invalid")
    return {
        "tag": tag,
        "source_sha": source_sha,
        "digest": digest,
        "version": "v" + version,
        "destination": destination(),
    }


def context():
    if (
        os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or release.SHA.fullmatch(os.environ.get("GITHUB_SHA", "")) is None
    ):
        fail("workflow_context_invalid")
    return os.environ["GITHUB_SHA"]


def read_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        fail("evidence_too_large")
    return json.loads(raw)


def get_json(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc not in {
        "ghcr.io",
        "auth.docker.io",
        "hub.docker.com",
    }:
        fail("api_url_invalid")
    with urllib.request.urlopen(url, timeout=20) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        fail("response_too_large")
    return json.loads(raw)


def manifest(repository, reference):
    if repository == SOURCE:
        host, image, token_url = "ghcr.io", "kevindraai/exitlane", "https://ghcr.io/token"
        service = "ghcr.io"
    elif repository == destination():
        host, image, token_url = (
            "registry-1.docker.io",
            destination()[10:],
            "https://auth.docker.io/token",
        )
        service = "registry.docker.io"
    else:
        fail("registry_invalid")
    if release.TAG.fullmatch(reference) is None and DIGEST.fullmatch(reference) is None:
        fail("manifest_reference_invalid")
    token = get_json(
        token_url
        + "?"
        + urllib.parse.urlencode({"service": service, "scope": f"repository:{image}:pull"})
    )
    bearer = token.get("token") or token.get("access_token")
    if not isinstance(bearer, str) or not bearer:
        fail("anonymous_token_invalid")
    request = urllib.request.Request(
        f"https://{host}/v2/{image}/manifests/{reference}",
        headers={
            "Authorization": "Bearer " + bearer,
            "Accept": (
                "application/vnd.oci.image.manifest.v1+json,"
                "application/vnd.oci.image.index.v1+json,"
                "application/vnd.docker.distribution.manifest.v2+json,"
                "application/vnd.docker.distribution.manifest.list.v2+json"
            ),
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(MAX_BYTES + 1)
        digest = response.headers.get("Docker-Content-Digest")
    if len(raw) > MAX_BYTES or digest != "sha256:" + hashlib.sha256(raw).hexdigest():
        fail("manifest_digest_invalid")
    return digest


def statement(results, *, name, digest, predicate_type, expected=None):
    if not isinstance(results, list):
        fail("verified_attestation_invalid")
    for result in results:
        verified = result.get("verificationResult") if isinstance(result, dict) else None
        value = verified.get("statement") if isinstance(verified, dict) else None
        if (
            isinstance(value, dict)
            and value.get("_type") == "https://in-toto.io/Statement/v1"
            and value.get("predicateType") == predicate_type
            and value.get("subject") == [{"name": name, "digest": {"sha256": digest[7:]}}]
        ):
            predicate = value.get("predicate")
            if isinstance(predicate, dict) and (expected is None or predicate == expected):
                return predicate
    fail("verified_attestation_mismatch")


def verify_source(facts, provenance, sbom):
    """Consume only output of successful, signer-constrained gh attestation verify."""
    predicate = statement(provenance, name=SOURCE, digest=facts["digest"], predicate_type=SLSA)
    definition = predicate.get("buildDefinition", {})
    external = definition.get("externalParameters", {})
    inputs = external.get("inputs", {})
    dependencies = definition.get("resolvedDependencies", [])
    repo = "https://github.com/" + REPOSITORY
    if (
        definition.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1"
        or external.get("workflow")
        != {
            "ref": "refs/heads/main",
            "repository": repo,
            "path": ".github/workflows/docker-release.yml",
        }
        or inputs.get("release_tag") != facts["tag"]
        or inputs.get("source_sha") != facts["source_sha"]
        or inputs.get("confirmation") != f"PUBLISH EXITLANE {facts['tag']} {facts['source_sha']}"
        or not isinstance(dependencies, list)
        or {
            "uri": f"git+{repo}@refs/tags/{facts['tag']}",
            "digest": {"gitCommit": facts["source_sha"]},
        }
        not in dependencies
    ):
        fail("upstream_source_mismatch")
    value = statement(sbom, name=SOURCE, digest=facts["digest"], predicate_type=SPDX)
    if value.get("spdxVersion") != "SPDX-2.3" or not value.get("packages"):
        fail("upstream_sbom_invalid")
    return value


def command(arguments, *, output=False, timeout=600):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        fail("command_failed")
    return result.stdout if output else None


def validate_image(image, facts):
    command(["docker", "pull", image])
    info = json.loads(
        command(["docker", "image", "inspect", image, "--format", "{{json .}}"], output=True)
    )
    labels = info.get("Config", {}).get("Labels", {})
    if (
        info.get("Os") != "linux"
        or info.get("Architecture") != "amd64"
        or labels.get("org.opencontainers.image.revision") != facts["source_sha"]
        or labels.get("org.opencontainers.image.version") != facts["version"]
        or labels.get("org.opencontainers.image.source") != "https://github.com/" + REPOSITORY
    ):
        fail("image_identity_mismatch")


def prepare(facts):
    sha = context()
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        fail("github_token_missing")
    release._fetch_publication_environment(
        REPOSITORY, token, name=ENVIRONMENT, prevent_self_review=False
    )
    command(
        [
            "git",
            "fetch",
            "--no-tags",
            "origin",
            "main",
            f"refs/tags/{facts['tag']}:refs/tags/{facts['tag']}",
        ],
        timeout=60,
    )
    published = release._fetch_release(facts["tag"], REPOSITORY, token)
    release.validate(
        tag=facts["tag"],
        source_sha=facts["source_sha"],
        confirmation=f"PUBLISH EXITLANE {facts['tag']} {facts['source_sha']}",
        current_sha=command(["git", "rev-parse", "HEAD"], output=True).strip(),
        main_sha=command(["git", "rev-parse", "origin/main"], output=True).strip(),
        project_version=release._project_version(facts["source_sha"]),
        release=published,
        tag_commit=release._tag_commit(facts["tag"]),
    )
    if command(["git", "rev-parse", "HEAD"], output=True).strip() != sha:
        fail("workflow_sha_mismatch")
    receipt = f"docker-{facts['tag']}-published-image-qualification.md"
    validate_qualification(facts, published, receipt)
    if facts["source_sha"] not in published.get("body", "") or facts["digest"] not in published.get(
        "body", ""
    ):
        fail("published_image_identity_missing")
    if (
        manifest(SOURCE, facts["tag"]) != facts["digest"]
        or manifest(SOURCE, facts["digest"]) != facts["digest"]
    ):
        fail("published_image_digest_mismatch")


def validate_qualification(facts, published, receipt):
    assets = [
        a for a in published.get("assets", []) if isinstance(a, dict) and a.get("name") == receipt
    ]
    url = f"https://github.com/{REPOSITORY}/releases/download/{facts['tag']}/{receipt}"
    if (
        len(assets) != 1
        or assets[0].get("browser_download_url") != url
        or DIGEST.fullmatch(assets[0].get("digest", "")) is None
    ):
        fail("published_image_qualification_missing")
    with urllib.request.urlopen(url, timeout=20) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES or "sha256:" + hashlib.sha256(raw).hexdigest() != assets[0]["digest"]:
        fail("qualification_receipt_hash_mismatch")
    text = " ".join(raw.decode("utf-8").split())
    expected = (
        f"The versioned image `{SOURCE}:{facts['tag']}` resolved to registry "
        f"digest `{facts['digest']}`."
    )
    expected_source = (
        f"The image declares source commit `{facts['source_sha']}` "
        f"and version `{facts['version']}`."
    )
    if (
        expected not in text
        or expected_source not in text
        or "Published-image Docker qualification passed within the scope below." not in text
    ):
        fail("qualification_receipt_identity_mismatch")
    Path("source-qualification.md").write_bytes(raw)


def mirror(facts):
    context()
    repo = get_json(
        "https://hub.docker.com/v2/namespaces/"
        + destination().split("/")[1]
        + "/repositories/exitlane"
    )
    immutable = repo.get("immutable_tags_settings", {})
    if (
        repo.get("is_private") is not False
        or immutable.get("enabled") is not True
        or IMMUTABLE_RULE not in immutable.get("rules", [])
    ):
        fail("public_immutable_repository_required")
    target = destination() + ":" + facts["tag"]
    exists = False
    try:
        existing = manifest(destination(), facts["tag"])
        if existing != facts["digest"]:
            fail("existing_tag_digest_mismatch")
        exists = True
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    source = SOURCE + "@" + facts["digest"]
    if manifest(SOURCE, facts["digest"]) != facts["digest"]:
        fail("source_digest_mismatch")
    validate_image(source, facts)
    if not exists:
        command(
            [
                "docker",
                "buildx",
                "imagetools",
                "create",
                "--prefer-index=false",
                "--tag",
                target,
                source,
            ]
        )
    if manifest(destination(), facts["tag"]) != facts["digest"]:
        fail("destination_digest_mismatch")
    return {"already_present": exists, **facts}


def mirror_predicate(facts, source_evidence, qualification_evidence):
    return {
        "operation": "copy-without-rebuild",
        "source": {
            "name": SOURCE,
            "digest": facts["digest"],
            "gitCommit": facts["source_sha"],
            "releaseTag": facts["tag"],
        },
        "destination": {"name": destination(), "digest": facts["digest"]},
        "upstreamVerificationSha256": hashlib.sha256(source_evidence).hexdigest(),
        "qualificationReceiptSha256": hashlib.sha256(qualification_evidence).hexdigest(),
        "workflowSha": context(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "evidence", "mirror", "verify"))
    args = parser.parse_args(argv)
    try:
        facts = identity(
            os.environ.get("RELEASE_TAG", ""),
            os.environ.get("RELEASE_SOURCE_SHA", ""),
            os.environ.get("RELEASE_DIGEST", ""),
            os.environ.get("RELEASE_CONFIRMATION", ""),
        )
        context()
        if args.operation == "prepare":
            prepare(facts)
        else:
            source = read_json("source-provenance-verification.json")
            sbom = verify_source(facts, source, read_json("source-sbom-verification.json"))
            predicate = mirror_predicate(
                facts,
                Path("source-provenance-verification.json").read_bytes(),
                Path("source-qualification.md").read_bytes(),
            )
            if args.operation == "evidence":
                Path("mirror-predicate.json").write_text(json.dumps(predicate) + "\n")
                Path("mirror.spdx.json").write_text(json.dumps(sbom) + "\n")
            elif args.operation == "mirror":
                Path("mirror-result.json").write_text(json.dumps(mirror(facts)) + "\n")
            else:
                verified = statement(
                    read_json("destination-provenance-verification.json"),
                    name=destination(),
                    digest=facts["digest"],
                    predicate_type=MIRROR_TYPE,
                    expected=predicate,
                )
                signed_sbom = statement(
                    read_json("destination-sbom-verification.json"),
                    name=destination(),
                    digest=facts["digest"],
                    predicate_type=SPDX,
                    expected=sbom,
                )
                if verified != predicate or signed_sbom != sbom:
                    fail("destination_attestation_mismatch")
                if manifest(destination(), facts["tag"]) != facts["digest"]:
                    fail("destination_tag_changed")
                validate_image(destination() + "@" + facts["digest"], facts)
        return 0
    except (
        release.ReleaseValidationError,
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        subprocess.SubprocessError,
    ):
        # No raw subprocess output, HTTP responses, tokens or tracebacks in public logs.
        print("dockerhub_validation_or_publication_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
