from __future__ import annotations

import asyncio
import json

import pytest

from exitlane.container_maintenance import TABLE, MaintenanceGuard
from exitlane.container_recovery import IngressIdentity
from exitlane.container_runtime import ContainerLifecycleError


class Nft:
    def __init__(self):
        self.objects = None
        self.calls = []

    async def __call__(self, *args, input_text=None, **kwargs):
        self.calls.append(args)
        if args == ("nft", "-j", "list", "tables"):
            return (
                0,
                json.dumps(
                    {
                        "nftables": (
                            [{"table": {"family": "inet", "name": TABLE}}]
                            if self.objects is not None
                            else []
                        )
                    }
                ),
                "",
            )
        if args == ("nft", "-j", "list", "table", "inet", TABLE):
            return 0, json.dumps({"nftables": self.objects}), ""
        if args == ("nft", "-j", "-f", "/dev/stdin"):
            self.objects = [
                item["add"] for item in json.loads(input_text)["nftables"] if "add" in item
            ]
        if args == ("nft", "delete", "table", "inet", TABLE):
            self.objects = None
        return 0, "", ""


def test_guard_covers_old_new_ingress_before_replacement_and_release():
    async def scenario():
        nft = Nft()
        guard = MaintenanceGuard(runner=nft)
        old = IngressIdentity("wg-office", "10.77.0.0/24")
        new = IngressIdentity("wg-new", "10.78.0.0/24")
        await guard.arm((old,))
        assert ("nft", "-j", "-c", "-f", "/dev/stdin") in nft.calls
        assert ("nft", "-j", "-f", "/dev/stdin") in nft.calls
        await guard.arm((new,))
        assert guard.identities == tuple(sorted((old, new), key=lambda item: item.interface))
        assert all("drop" in rule["expr"][-1] for item in nft.objects if (rule := item.get("rule")))
        await guard.release()
        assert nft.objects is None

    asyncio.run(scenario())


def test_restart_only_recognizes_complete_journal_drop_policy():
    async def scenario():
        nft = Nft()
        identity = IngressIdentity("wg-office", "10.77.0.0/24")
        first = MaintenanceGuard(runner=nft)
        await first.arm((identity,))
        restarted = MaintenanceGuard(runner=nft)
        await restarted.arm((identity,))
        nft.objects[-1]["rule"]["expr"][-1] = {"accept": None}
        with pytest.raises(ContainerLifecycleError, match="unproven"):
            await restarted.release()
        assert nft.objects is not None

    asyncio.run(scenario())


def test_foreign_table_is_not_replaced_or_deleted():
    async def scenario():
        nft = Nft()
        nft.objects = [{"table": {"family": "inet", "name": TABLE}}]
        with pytest.raises(ContainerLifecycleError, match="unproven"):
            await MaintenanceGuard(runner=nft).arm(())
        assert not any("-f" in args or "delete" in args for args in nft.calls)

    asyncio.run(scenario())


def test_release_requires_observed_ownership():
    with pytest.raises(ContainerLifecycleError, match="unproven"):
        asyncio.run(MaintenanceGuard(runner=Nft()).release())


def test_unknown_startup_identities_block_all_forwarding_until_reconciled():
    async def scenario():
        nft = Nft()
        guard = MaintenanceGuard(runner=nft)
        await guard.arm(())
        forward = next(
            item["chain"] for item in nft.objects if item.get("chain", {}).get("name") == "forward"
        )
        assert forward["policy"] == "drop"
        await guard.arm((IngressIdentity("wg-office", "10.77.0.0/24"),))
        await guard.observed(guard.identities)

    asyncio.run(scenario())
