# Docker Hub release publication

The `Docker Hub release mirror` workflow prepares a second distribution path for the official
ExitLane appliance. It copies a qualified, published GHCR image without rebuilding it. The default
destination is `docker.io/tunedpixel/exitlane`; GHCR remains the existing operator path until a
Docker Hub publication run and its final verification succeed. A repository or green PR alone
does not establish image availability.

## Account and repository

Use the personal Docker account `tunedpixel`. Docker IDs cannot be renamed, so this is separate
from the earlier `draaiodijk` account. The login account and destination namespace are independent;
`DOCKERHUB_NAMESPACE` is an optional GitHub repository variable, defaulting to `tunedpixel`.
Changing it requires a matching confirmation and a configured repository under that namespace.

Create the public repository `tunedpixel/exitlane` and enable immutable tags with this exact rule:

```text
^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$
```

Only version tags are protected by this rule, leaving OCI attestation storage tags usable. No
`latest` alias is published. The workflow verifies public visibility and this immutable-tag setting
before copying. An existing version with another digest is an error; an identical existing digest
is retained and can resume a failed signing or verification stage without republishing the image.

Set these existing GitHub repository secrets to credentials for the new account:

| Secret | Value |
| --- | --- |
| `DOCKER_USERNAME` | `tunedpixel` |
| `DOCKER_PAT` | A Docker personal access token with Read and Write permission |

Do not commit credential files. A host-side `/root/credentials_docker.env` is for authorized
operator setup only; the workflow never reads it. Login secrets are referenced only in the
publication job after the environment gate. Registry manifests and final pulls use anonymous access.

## Protected environment

The `dockerhub-production` GitHub environment requires:

- reviewer `kevindraai`;
- prevention of self-review;
- no administrator bypass;
- deployments from protected branches.

The workflow independently restricts execution to `main` in `kevindraai/exitlane`. Before scheduling
publication, and again after approval, it checks the environment through the GitHub API. A missing
or weakened environment fails validation; the workflow cannot silently create an unprotected one.
An approvable run must be initiated by an authorized identity other than the required reviewer.
The workflow does not change approval rules to accommodate its trigger identity.

## Source and evidence

Supply the tag, application source SHA and GHCR digest recorded in the published GitHub release.
The workflow requires:

- a canonical release tag, exact tagged source, matching package version and qualified ancestry;
- a current `main` workflow commit, source SHA and digest present in the published release record;
- the release asset `docker-<tag>-published-image-qualification.md`;
- the asset's SHA-256 and published-image declaration matching the selected source, version and
  registry digest; candidate or OCI-config digests elsewhere in the receipt do not qualify it;
- an anonymous GHCR tag and digest lookup matching the requested image digest;
- cryptographically verified original Docker release provenance and SPDX SBOM, signed by the
  expected GitHub-hosted release workflow on `main`;
- a provenance dependency and release inputs binding that exact application source and tag.

The published v1.0.1 record uses this receipt convention. Earlier releases lacking the named
published-image receipt are deliberately rejected rather than inheriting an unverified claim.
Source signing-workflow revisions may differ from application commits; the application dependency
must match the release SHA. Revalidation fails if `main` advances while approval is pending; start
a new run from current `main` in that case.

After copying, the anonymous Docker Hub manifest digest must equal the GHCR digest. The workflow
signs a distinct mirror predicate describing the copy, source identities and verification hash,
then signs the original verified SPDX SBOM under the Hub image name. This does not describe the
mirror as a new build. Final verification checks the Hub signatures, exact mirror predicate and
unchanged SBOM, workflow source SHA, anonymous digest pull, Linux amd64 platform and OCI source /
version labels. A mismatch leaves a failed run and retained evidence, without overwriting a tag.

## Dispatch and operator acceptance

Merge the reviewed workflow PR and wait for the applicable `main` checks before dispatching.
Choose `Docker Hub release mirror` in GitHub Actions on `main`, using:

```text
release_tag: v1.0.1
source_sha: <exact application SHA from the published release>
digest: sha256:<qualified GHCR digest from the published release>
confirmation: MIRROR EXITLANE v1.0.1 <source_sha> <digest> TO tunedpixel/exitlane
```

Review and approve the protected publication job. Retain the `dockerhub-mirror-evidence` artifact,
including source verification, mirror receipt, signed bundles, SPDX and final destination
verification. A partial run may already have copied an immutable version before a later stage
fails; rerun with the same identities to complete verification, never move the tag.

Before advertising Docker Hub as an operator source, record the successful run and exact
Hub digest in release evidence. On a supported host, anonymously pull both the Hub tag and digest
and run the existing version-matched Compose/host preflight and first-run checks using
`EXITLANE_IMAGE=docker.io/tunedpixel/exitlane@sha256:<verified digest>`. Copying does not extend the
existing Linux amd64, Engine >=28, rootful / TUN / NET_ADMIN support contract or establish new
live-provider interoperability. No image publication or supported-host operator acceptance is
claimed by this implementation PR.

References: [Docker registry copying](https://docs.docker.com/build/ci/github-actions/copy-image-registries/),
[immutable tags](https://docs.docker.com/docker-hub/repos/manage/hub-images/immutable-tags/),
[personal access tokens](https://docs.docker.com/security/access-tokens/personal-access-tokens/),
[Docker ID rules](https://docs.docker.com/faqs/accounts/).
