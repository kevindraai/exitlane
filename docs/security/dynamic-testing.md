# Dynamic security testing

The PR workflow runs ZAP baseline mode only, against a temporary local installation with dummy state. It spiders GET-accessible pages passively, has a short timeout and holds no provider/WireGuard credentials.

An authenticated passive or OpenAPI scan requires a temporary account and
cookies held only in process memory. Reports must be checked for cookies before
upload and retained briefly. The beta appliance validation used a root-local
temporary password, existing TOTP MFA, and in-memory Secure cookies. It restored
the original password verifier, revoked the temporary session and deleted the
credential and sanitized summary immediately after the run.

Active scanning is manual and may mutate state or trigger privileged
provider/network operations. Use only an explicitly authorized, labelled LXC
with dummy credentials, an allowlisted private target and no access to
production networks. Record the target and stop time; stop on unexpected
outbound access, privilege expansion, real credentials, host instability or
sensitive output.

The beta run was explicitly authorized only for `172.16.130.81`. A bounded
root-local scanner allowed GET, HEAD and OPTIONS against public and authenticated
read-only routes, and hard-excluded settings, password, logout, setup, provider,
killswitch, WireGuard regeneration/download and notification mutations. It ran
5 public GETs, 14 authenticated GETs, 13 HEADs, 13 OPTIONS and 42 injection,
header and path probes with no HTTP 5xx or finding. No ZAP context, cookie file,
request archive or response report was created.
