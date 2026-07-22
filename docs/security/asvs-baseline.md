# ASVS-based baseline

This is a selected control mapping based on OWASP ASVS 5 structure for a local administrative application. It is neither certification nor a claim of complete compliance.

| Reference / requirement | Applicable | Current implementation | Automatic test | Manual test / open risk |
| --- | --- | --- | --- | --- |
| V1 architecture/threat model | yes | documented boundaries and assets | documentation/link review | update for every new privileged feature |
| V2 authentication | yes | scrypt verifier, generic failures | auth regressions | no MFA; alpha assumption |
| V3 sessions | yes | random token, SHA-256 digest, expiry and revocation | cookie/session tests | Secure requires HTTPS configuration |
| V4 access control | yes | central default-deny after setup | route/method/setup tests | static shell is intentionally public |
| V5 validation/encoding | yes | strict Pydantic fields, URL/path/command allowlists | negative API and frontend tests | expand property tests with new models |
| V6 stored cryptography | partially | passwords use scrypt; keys are mode 0600 | hash and permissions tests | SQLite is not encrypted at rest; host boundary applies |
| V7 errors/logging | yes | generic HTTP errors and allowlisted Activity metadata | error/event tests | provider journal output requires operational review |
| V8 data protection | partially | no-store, key/database filesystem isolation | header/installer tests | backups are operator-managed and must be encrypted |
| V9 communications | partially | same-origin app; HTTPS deployment supported | HSTS opt-in test | TLS is external to Exitlane and mandatory for untrusted links |
| V10 malicious input | yes | argv subprocesses, fixed executables, bounded models | Bandit/negative tests | provider output remains untrusted |
| V13 API security | yes | auth middleware, content types/models, OpenAPI protected | API boundary tests | headerless clients follow documented CSRF policy |
| V14 configuration | yes | environment-only security controls, debug off | config/unit tests | trusted proxies are deliberately unsupported |
| V12 files/resources | yes | fixed static tree, constrained client name, 0600 configs | traversal/permission tests | authenticated client download contains a private key |

Requirements for registration, multi-user roles, OAuth/OIDC, payment, GraphQL, user-uploaded active content and public account recovery are not applicable because those features do not exist. Availability controls against Internet-scale traffic are not applicable to the supported firewalled deployment, though request limits remain applicable.
