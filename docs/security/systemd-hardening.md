# systemd hardening

Compatibility takes priority over a cosmetic score. Exitlane currently remains `User=root`: it creates network interfaces/configuration, calls systemctl/wg-quick and coordinates NordVPN. Splitting privileged operations into a narrow helper is the preferred future design.

| Directive | State | Reason / residual risk |
| --- | --- | --- |
| `UMask=0077`, `PrivateTmp`, `ProtectHome`, `ProtectSystem=strict` | enabled | isolates temporary/home/system files; explicit writable paths cover Exitlane and WireGuard |
| `NoNewPrivileges`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictRealtime`, `SystemCallArchitectures=native` | enabled | removes common escalation/runtime surfaces |
| `ProtectKernelModules`, `ProtectControlGroups` | enabled | installer verifies WireGuard support before service start |
| `ProtectKernelTunables` | not enabled | `wg-quick` configuration currently sets IPv4 forwarding; refactor before enabling |
| dedicated user/group | not enabled | direct network/systemd operations currently require root; largest accepted sandbox risk |
| capability bounding/ambient set | not enabled | NordVPN/systemctl/wg-quick compatibility is not yet proven with a minimal set |
| `DeviceAllow=/dev/net/tun` / closed device policy | not enabled | NordVPN daemon/device ownership crosses the service boundary |
| private network namespace | not enabled | would break the gateway's core routing role |

Validate the installed unit with `systemd-analyze verify`, `systemd-analyze security exitlane.service`, service/login/provider/WireGuard flows and journal review. The score is diagnostic, not a universal pass threshold.

The 2026-07-22 test-LXC baseline scored 7.7 ("exposed"), dominated by the accepted root,
capability, device and host-network access needed by the current architecture. Enabled sandbox
directives passed unit verification and service startup; this score is not presented as a pass.
