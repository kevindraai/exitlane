# Deployment hardening guide

- Place Exitlane on a trusted management VLAN; firewall TCP 8787 to operator addresses and never expose it directly to the Internet.
- Prefer an HTTPS reverse proxy. Set `EXITLANE_SESSION_COOKIE_SECURE=true` and `EXITLANE_HTTPS_ONLY=true` only when every browser request is HTTPS. Exitlane does not trust forwarded client-IP/Host headers; preserve the external Host and do not rewrite untrusted forwarding headers into authority.
- Keep the default bind only on an isolated appliance; otherwise set `EXITLANE_HOST` to the management address. Keep debug disabled and protect docs/OpenAPI as shipped.
- Preserve `/etc/exitlane`, `/var/lib/exitlane`, `/var/log/exitlane` as root-only and WireGuard files as 0600. Encrypt and access-control database/config backups; test restore offline.
- Apply OS, Python dependency and appliance updates regularly. Review Dependabot/security alerts and retain Activity/journal data only as operationally required.
- Keep session lifetime and the 1 MiB request limit conservative. Login throttling is not implemented in this alpha: rely on network restriction and monitor failed-login Activity events.
