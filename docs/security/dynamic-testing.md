# Dynamic security testing

The PR workflow runs ZAP baseline mode only, against a temporary local installation with dummy state. It spiders GET-accessible pages passively, has a short timeout and holds no provider/WireGuard credentials.

An authenticated passive or OpenAPI scan requires a temporary account and cookie held only in process memory. Reports must be checked for cookies before upload and retained briefly. Because the current setup API can invoke host networking operations before completion, authenticated automation is deferred until a mock provider/runtime boundary exists.

Active scanning is manual and may mutate state or trigger privileged provider/network operations. Use only a disposable, explicitly labelled LXC restored from a clean snapshot, with dummy credentials, an allowlisted private target and no access to production networks. Record target ownership, snapshot ID and stop time; stop on unexpected outbound access, privilege expansion, real credentials, host instability or sensitive report content. The fixed test LXC is not an active-scan target without prior explicit approval. No active script is supplied until these properties can be technically enforced.
