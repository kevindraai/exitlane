"""Temporary, exact-owned protection across replacement of ingress identities.

This table only drops protected packets. The permanent D3 policy retains provider
source guards; publishing/restoring state never grants forwarding permission.
"""

from __future__ import annotations

import json

from exitlane import core
from exitlane.container_recovery import IngressIdentity
from exitlane.container_runtime import ContainerLifecycleError

TABLE = "exitlane_recovery_guard"


class MaintenanceGuard:
    def __init__(self, *, runner=core.command):
        self.runner = runner
        self.identities: tuple[IngressIdentity, ...] = ()
        self.active = False

    def objects(self, identities):
        objects = [{"table": {"family": "inet", "name": TABLE}}]
        for name, hook in (("forward", "forward"), ("input", "input"), ("output", "output")):
            objects.append(
                {
                    "chain": {
                        "family": "inet",
                        "table": TABLE,
                        "name": name,
                        "type": "filter",
                        "hook": hook,
                        "prio": -300,
                        "policy": "drop" if name == "forward" and not identities else "accept",
                    }
                }
            )
            for identity in identities:
                if name != "output":
                    objects.append(
                        {
                            "rule": {
                                "family": "inet",
                                "table": TABLE,
                                "chain": name,
                                "expr": [
                                    {
                                        "match": {
                                            "op": "==",
                                            "left": {"meta": {"key": "iifname"}},
                                            "right": identity.interface,
                                        }
                                    },
                                    {"drop": None},
                                ],
                            }
                        }
                    )
                network, prefix = identity.subnet.split("/")
                objects.append(
                    {
                        "rule": {
                            "family": "inet",
                            "table": TABLE,
                            "chain": name,
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                        "right": {"prefix": {"addr": network, "len": int(prefix)}},
                                    }
                                },
                                {"drop": None},
                            ],
                        }
                    }
                )
        # nft JSON readback groups declarations ahead of rules. Preserve every
        # rule's order within its chain while matching that canonical layout.
        return [item for kind in ("table", "chain", "rule") for item in objects if kind in item]

    async def checked(self, *args, input_text=None):
        rc, output, _error = await self.runner(*args, input_text=input_text, timeout=10)
        if rc:
            raise ContainerLifecycleError("container_recovery_guard_failed")
        return output

    async def observed(self, identities):
        try:
            raw = json.loads(await self.checked("nft", "-j", "list", "table", "inet", TABLE))
            objects = []
            for item in raw["nftables"]:
                if set(item) == {"metainfo"}:
                    continue
                if len(item) != 1 or next(iter(item)) not in {"table", "chain", "rule"}:
                    raise ValueError
                kind, value = next(iter(item.items()))
                objects.append(
                    {
                        kind: {
                            key: value
                            for key, value in value.items()
                            if key not in {"handle", "index"}
                        }
                    }
                )
            if objects != self.objects(identities):
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ContainerLifecycleError("container_recovery_guard_unproven") from None

    async def arm(self, identities):
        # IngressIdentity construction owns grammar validation, not shell quoting.
        identities = tuple(identities)
        if len(identities) > 8 or any(not isinstance(item, IngressIdentity) for item in identities):
            raise ContainerLifecycleError("container_recovery_guard_invalid")
        identities = tuple(sorted(set(identities), key=lambda item: (item.interface, item.subnet)))
        tables = json.loads(await self.checked("nft", "-j", "list", "tables"))["nftables"]
        exists = any(
            item.get("table", {}).get("name") == TABLE
            and item.get("table", {}).get("family") == "inet"
            for item in tables
        )
        if exists:
            # A restart accepts only the complete journal-derived drop policy;
            # a live transition may extend its previously observed owned policy.
            await self.observed(self.identities if self.active else identities)
        identities = tuple(
            sorted(
                set(self.identities + identities), key=lambda item: (item.interface, item.subnet)
            )
        )
        if len(identities) > 8:
            raise ContainerLifecycleError("container_recovery_guard_invalid")
        commands = [{"delete": {"table": {"family": "inet", "name": TABLE}}}] if exists else []
        commands.extend({"add": item} for item in self.objects(identities))
        payload = json.dumps({"nftables": commands})
        await self.checked("nft", "-j", "-c", "-f", "/dev/stdin", input_text=payload)
        await self.checked("nft", "-j", "-f", "/dev/stdin", input_text=payload)
        self.identities = identities
        self.active = True
        await self.observed(identities)

    async def release(self):
        if not self.active:
            raise ContainerLifecycleError("container_recovery_guard_unproven")
        await self.observed(self.identities)
        await self.checked("nft", "delete", "table", "inet", TABLE)
        self.active = False
        self.identities = ()
