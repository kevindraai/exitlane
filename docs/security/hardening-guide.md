# Deployment hardening guide

Before upgrades, create and verify an encrypted appliance backup and copy it off
the appliance. Keep `/var/lib/exitlane/recovery` mode `0700`; it contains local
plaintext rollback material. Never expose `.elb` passphrases in arguments,
environment variables, shell history, logs, or CI artifacts. See
[Backup and restore](../backup-and-restore.md) and
[Upgrade and recovery](../upgrade-and-recovery.md).

- Place Exitlane on a trusted management VLAN; firewall TCP 8787 to operator addresses and never expose it directly to the Internet.
- Prefer an HTTPS reverse proxy. Configure only its exact peer IP/CIDR with `EXITLANE_TRUSTED_PROXIES`, set `EXITLANE_PUBLIC_URL`, and retain the default `EXITLANE_SECURE_COOKIES=auto`. Never use wildcard proxy trust.
- Keep the default bind only on an isolated appliance; otherwise set `EXITLANE_HOST` to the management address. Keep debug disabled and protect docs/OpenAPI as shipped.
- Preserve `/etc/exitlane`, `/var/lib/exitlane`, `/var/log/exitlane` as root-only and WireGuard files as 0600. Encrypt and access-control database/config backups; test restore offline.
- Apply OS, Python dependency and appliance updates regularly. Review Dependabot/security alerts and retain Activity/journal data only as operationally required.
- Keep the one-hour idle and 24-hour absolute session limits and the 1 MiB request limit conservative. Password and MFA attempts are separately bounded.
