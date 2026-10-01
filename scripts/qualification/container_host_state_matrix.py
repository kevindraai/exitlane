"""D6 owned state/namespace faults; never an automatic whole-program PASS.

The caller supplies the existing HostHarness and independently continuous peer
captures. Synthetic upstreams, actual application lifecycle and leases stay intact.
Run API operations before restore, which deliberately revokes the browser session.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import uuid

from container_host import IMAGE, QualificationError

DIRECT = {"mullvad": "wg-mullvad", "pia": "wg-pia", "proton": "wg-proton"}


class StateQualification:
    def __init__(self, harness, captures, *, image, provider, epoch_hook=None):
        if IMAGE.fullmatch(image) is None or provider not in DIRECT:
            raise QualificationError("qualification_state_config_invalid")
        self.h = harness
        self.captures = captures
        self.image = image
        self.provider = provider
        self.epoch_hook = epoch_hook or (lambda _phase, _before: None)
        self.root = "/var/lib/exitlane-qualification/state-matrix-" + str(uuid.uuid4())
        self.used = set()
        self.h.candidate.run(
            "from pathlib import Path\np=Path(payload);p.mkdir(mode=0o700,exist_ok=False)\n",
            data=self.root,
        )

    def record(self, phase, state, *, facts=None):
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", phase) is None or state not in {
            "RUNNING",
            "PASS",
            "FAIL",
        }:
            raise QualificationError("qualification_state_receipt_invalid")
        self.h.candidate.run(
            """from pathlib import Path
import stat
p=Path(payload['root']);f=p.lstat()
if not stat.S_ISDIR(f.st_mode) or f.st_uid!=0 or f.st_mode&0o077:raise SystemExit('qualification_state_receipt_unsafe')
temporary=p/('.'+payload['phase']+'.new')
descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(descriptor,'w') as stream:
 json.dump(payload['receipt'],stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
os.replace(temporary,p/(payload['phase']+'.json'))
descriptor=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(descriptor)
finally:os.close(descriptor)
""",
            data={
                "root": self.root,
                "phase": phase,
                "receipt": {
                    "phase": phase,
                    "state": state,
                    "facts": facts or {},
                    "run_id": self.h.config["run_id"],
                    "revision": self.h.config["revision"],
                    "image": self.image,
                    "claim": "partial-D6-owned-state-mechanisms",
                },
            },
        )

    def phase(self, name, operation, *, blocked=False, recovery=True):
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) is None
        ):
            raise QualificationError("qualification_phase_invalid")
        if name in self.used:
            raise QualificationError("qualification_phase_reused")
        self.used.add(name)
        phase = name + "-" + secrets.token_hex(4)
        self.record(phase, "RUNNING")
        try:
            evidence = self.h.packet_phase(
                phase,
                self.captures,
                operation=operation,
                blocked=blocked,
                require_recovery=recovery,
            )
            expected = (
                "blocked"
                if blocked
                else "provider_or_block_with_fresh_recovery"
                if recovery
                else "provider_or_block_transition"
            )
            receipt = evidence.get("receipt") if isinstance(evidence, dict) else None
            if (
                not isinstance(receipt, dict)
                or receipt.get("accepted") is not True
                or receipt.get("phase") != phase
                or receipt.get("expected_state") != expected
            ):
                raise QualificationError("qualification_state_packet_receipt_invalid")
        except Exception:
            self.record(
                phase, "FAIL", facts={"error": "qualification_state_phase_failed"}
            )
            raise
        self.record(phase, "PASS", facts={"packet": evidence["receipt"]})
        return evidence

    def ownership(self):
        self.h.assert_disposable()
        container = self.h.assert_owned("container", self.h.container)
        network = self.h.assert_owned("network", self.h.network)
        volume = self.h.assert_owned("volume", self.h.volume)
        if container["Image"] != self.image:
            raise QualificationError("qualification_state_image_changed")
        mounts = [m for m in container["Mounts"] if m.get("Destination") == "/data"]
        if (
            len(mounts) != 1
            or mounts[0].get("Type") != "volume"
            or mounts[0].get("Name") != self.h.volume
        ):
            raise QualificationError("qualification_state_volume_changed")
        for identifier in network.get("Containers", {}):
            if identifier != container["Id"]:
                raise QualificationError("qualification_foreign_network_endpoint")
        return container, network, volume

    def intents(self):
        """Validated generations and public fingerprints, never ciphertexts/keys."""
        source = """from pathlib import Path
import hashlib,json
from exitlane.container_state import ContainerState,ContainerLayout
from exitlane.providers.wireguard_keys import _public_key_for_private
v=ContainerState(ContainerLayout(Path('/data'))).validate()
items=[]
for i in v.intents:
 c=i.config
 items.append({'provider':i.provider_id,'status':i.status,'generation':i.generation,
 'local_public_fingerprint':hashlib.sha256(_public_key_for_private(c.private_key).encode()).hexdigest() if c else None,
 'peer_public_fingerprint':hashlib.sha256(c.peer_public_key.encode()).hexdigest() if c else None,
 'interface':c.interface if c else None,'address':c.address if c else None})
print(json.dumps({'schema':v.schema,'selected_provider':v.selected_provider,'intents':items},sort_keys=True))
"""
        value = json.loads(
            self.h.docker("exec", self.h.container, "python", "-c", source)["stdout"]
        )
        if (
            not isinstance(value, dict)
            or value.get("schema") != 1
            or value.get("selected_provider") != self.provider
            or not isinstance(value.get("intents"), list)
            or not any(
                item.get("provider") == self.provider and item.get("status") == "active"
                for item in value["intents"]
            )
        ):
            raise QualificationError("qualification_state_intent_invalid")
        return value

    def polling_interval(self):
        # Public projection in selected runtime; no initialization or direct SQL.
        result = self.h.docker(
            "exec",
            self.h.container,
            "python",
            "-c",
            "from exitlane.settings import current_general_settings;"
            "print(current_general_settings().provider_refresh_interval_seconds)",
        )
        try:
            value = int(result["stdout"].strip())
        except (TypeError, ValueError):
            raise QualificationError("qualification_state_setting_invalid") from None
        if not 2 <= value <= 300:
            raise QualificationError("qualification_state_setting_invalid")
        return value

    def recreate(self, image, *, phase):
        if IMAGE.fullmatch(image) is None:
            raise QualificationError("qualification_state_image_invalid")
        target = json.loads(self.h.docker("image", "inspect", image)["stdout"])[0]
        labels = target.get("Config", {}).get("Labels", {})
        if (
            target.get("Id") != image
            or target.get("Architecture") != "amd64"
            or target.get("Os") != "linux"
            or labels.get("org.opencontainers.image.revision")
            != self.h.config["revision"]
            or labels.get("org.opencontainers.image.source")
            != "https://github.com/kevindraai/exitlane"
            or labels.get("org.exitlane.runtime") != "container"
            or labels.get("org.exitlane.schema") != "1:1"
            or labels.get("org.exitlane.support") != "experimental"
        ):
            raise QualificationError("qualification_state_image_invalid")
        old, _, _ = self.ownership()
        before = self.h.pair()
        intents = self.intents()
        self.epoch_hook(phase, True)
        self.h.docker("stop", "--time", "15", self.h.container)
        self.h.docker("rm", self.h.container)
        # The exact volume is retained. HostHarness.create never runs an installer.
        self.h.create(image=image)
        actual = self.h.assert_owned("container", self.h.container)
        if (
            actual["Id"] == old["Id"]
            or actual["Image"] != image
            or self.h.pair() != before
            or self.intents() != intents
        ):
            raise QualificationError("qualification_state_recreation_invalid")
        self.image = image
        self.epoch_hook(phase, False)

    def container_recreation(self):
        return self.phase(
            "state-container-recreation",
            lambda: self.recreate(self.image, phase="container"),
        )

    def replacement_image(self):
        """Only a qualification label changes: prove mechanism, not a future upgrade."""
        self.ownership()
        base = self.h.prefix + "-state-base:fixture"
        self.h.docker("image", "tag", self.image, base)
        bound = json.loads(self.h.docker("image", "inspect", base)["stdout"])[0]
        if bound.get("Id") != self.image:
            raise QualificationError("qualification_state_replacement_invalid")
        # Resolve the UUID-owned label-only derivative through inspect, never
        # parse a build-output line as an image identity.
        tag = self.h.prefix + "-state-replacement:fixture"
        self.h.docker(
            "build",
            "--network=none",
            "--pull=false",
            "--build-arg",
            "BASE=" + base,
            "-t",
            tag,
            "-",
            data='ARG BASE\nFROM ${BASE}\nLABEL org.exitlane.qualification.replacement="schema1-mechanism-only"\n',
            timeout=120,
        )
        facts = json.loads(self.h.docker("image", "inspect", tag)["stdout"])[0]
        replacement = facts["Id"]
        if IMAGE.fullmatch(replacement) is None or replacement == self.image:
            raise QualificationError("qualification_state_replacement_invalid")
        labels = facts["Config"]["Labels"]
        if (
            labels.get("org.exitlane.qualification.replacement")
            != "schema1-mechanism-only"
        ):
            raise QualificationError("qualification_state_replacement_invalid")
        return replacement

    def image_replacement(self):
        previous = self.image
        replacement = self.replacement_image()
        self.phase(
            "state-image-replacement",
            lambda: self.recreate(replacement, phase="replacement"),
        )
        return self.phase(
            "state-image-rollback", lambda: self.recreate(previous, phase="rollback")
        )

    def bridge_recreation(self):
        old, network, _ = self.ownership()
        before = self.h.pair()
        intents = self.intents()
        old_gateways = {entry.get("Gateway") for entry in network["IPAM"]["Config"]}
        routes = json.loads(
            self.h.command(
                self.h.candidate, ["ip", "-j", "route", "show", "table", "all"]
            )["stdout"]
        )
        occupied = [
            ipaddress.ip_network(item["dst"], strict=False)
            for item in routes
            if item.get("dst", "default") != "default"
        ]
        subnet = None
        start = int(uuid.UUID(self.h.config["run_id"]).hex[-2:], 16)
        for index in range(256):
            candidate = ipaddress.ip_network(f"172.28.{(start + index) % 256}.0/24")
            if not any(
                value.version == 4 and value.overlaps(candidate) for value in occupied
            ):
                subnet = candidate
                break
        if subnet is None:
            raise QualificationError("qualification_state_bridge_range_unavailable")
        gateway = str(subnet.network_address + 1)
        if gateway in old_gateways:
            raise QualificationError("qualification_state_bridge_gateway_unchanged")

        def operation():
            self.ownership()
            self.epoch_hook("bridge", True)
            self.h.docker("stop", "--time", "15", self.h.container)
            self.h.docker("rm", self.h.container)
            self.h.assert_owned("network", self.h.network)
            if json.loads(
                self.h.docker("network", "inspect", self.h.network)["stdout"]
            )[0].get("Containers"):
                raise QualificationError("qualification_foreign_network_endpoint")
            self.h.docker("network", "rm", self.h.network)
            self.h.docker(
                "network",
                "create",
                "--label",
                "org.exitlane.qualification.run=" + self.h.config["run_id"],
                "--subnet",
                str(subnet),
                "--gateway",
                gateway,
                self.h.network,
            )
            self.h.create(image=self.image)
            current = self.h.assert_owned("network", self.h.network)
            if (
                current["Id"] == network["Id"]
                or current["IPAM"]["Config"][0].get("Gateway") != gateway
            ):
                raise QualificationError(
                    "qualification_state_bridge_recreation_invalid"
                )
            if (
                self.h.assert_owned("container", self.h.container)["Id"] == old["Id"]
                or self.h.pair() != before
                or self.intents() != intents
            ):
                raise QualificationError("qualification_state_recreation_invalid")
            self.epoch_hook("bridge", False)

        return self.phase("state-bridge-recreation", operation)

    def delete_interface(self, interface):
        if interface not in {"wg-office", DIRECT[self.provider]}:
            raise QualificationError("qualification_state_interface_invalid")
        self.ownership()
        source = """from pathlib import Path
from exitlane.container_state import ContainerState,ContainerLayout
from exitlane.providers.wireguard_keys import _public_key_for_private
from exitlane.container_runtime import IngressConfig
s=ContainerState(ContainerLayout(Path('/data')));v=s.validate()
interface=payload['interface']
if interface=='wg-office':expected=_public_key_for_private(IngressConfig.from_file(s.layout.wireguard/'wg-office.conf').private_key)
else:
 configs=[i.config for i in v.intents if i.provider_id==payload['provider'] and i.status=='active' and i.config is not None]
 if len(configs)!=1:raise SystemExit('qualification_state_interface_unowned')
 expected=_public_key_for_private(configs[0].private_key)
def inspect():
 r=subprocess.run(['ip','-j','-d','link','show','dev',interface],capture_output=True,text=True,check=True)
 a=json.loads(r.stdout)
 if len(a)!=1 or a[0].get('linkinfo',{}).get('info_kind')!='wireguard':raise SystemExit('qualification_state_interface_unowned')
 return a[0]['ifindex']
index=inspect()
public=subprocess.run(['wg','show',interface,'public-key'],capture_output=True,text=True,check=True).stdout.strip()
if public!=expected or inspect()!=index:raise SystemExit('qualification_state_interface_unowned')
subprocess.run(['ip','link','delete','dev',interface],check=True)
print(json.dumps({'deleted':interface,'ifindex':index}))
"""
        self.h.docker(
            "exec",
            "-i",
            self.h.container,
            "python",
            "-c",
            "import json,subprocess,sys\npayload=json.load(sys.stdin)\n" + source,
            data=json.dumps({"interface": interface, "provider": self.provider}),
        )

    def recover_provider(self):
        result = self.h.api(
            "/api/vpn/providers/" + self.provider + "/reconnect",
            method="POST",
            body={},
            timeout=90,
        )
        if result["status"] != 200 or result["body"].get("success") is not True:
            raise QualificationError("qualification_state_provider_recovery_failed")

    def interface_deletion(self, *, ingress=False):
        interface = "wg-office" if ingress else DIRECT[self.provider]
        kind = "ingress" if ingress else "provider"
        # Transition allows already delivered provider packets. A fresh separate
        # steady epoch proves strict block after the interface is absent.
        self.phase(
            "state-" + kind + "-delete",
            lambda: self.delete_interface(interface),
            recovery=False,
        )
        self.phase(
            "state-" + kind + "-absent", lambda: None, blocked=True, recovery=False
        )

        def recover():
            if ingress:
                result = self.h.api(
                    "/api/ingress/wireguard",
                    method="POST",
                    timeout=90,
                    body={
                        "endpoint": self.h.config["candidate"]["address"],
                        "interface": "wg-office",
                        "subnet": "10.77.0.0/24",
                        "client": "synthetic_router",
                        "dns": "10.64.0.1",
                        "port": 51820,
                    },
                )
                if result["status"] != 200:
                    raise QualificationError(
                        "qualification_state_ingress_recovery_failed"
                    )
                profile = self.h.api("/api/ingress/wireguard/config")
                if (
                    profile["status"] != 200
                    or profile["body"].get("available") is not True
                ):
                    raise QualificationError(
                        "qualification_state_ingress_recovery_failed"
                    )
                self.h.command(
                    self.h.peer,
                    [
                        "python3",
                        "/var/lib/exitlane-qualification/container_host_peer.py",
                        "client",
                    ],
                    data=json.dumps(
                        {
                            "run_id": self.h.config["run_id"],
                            "endpoint": self.h.config["candidate"]["address"]
                            + ":51820",
                            "configuration": profile["body"]["configuration"],
                        }
                    ),
                )
            self.recover_provider()

        return self.phase("state-" + kind + "-recovery", recover)

    def oom_injector(self):
        """Prove a real owned cgroup OOM; never call injector death worker OOM."""
        container, _, _ = self.ownership()
        memory = container["HostConfig"].get("Memory")
        swap = container["HostConfig"].get("MemorySwap")
        if (
            type(memory) is not int
            or memory != 2 * 1024**3
            or type(swap) is not int
            or swap != -1
            and swap < memory
        ):
            raise QualificationError("qualification_oom_limit_unproven")
        allocation_program = (
            "import time;chunks=[]\n"
            "for _ in range(3072):chunks.append(bytearray(1024*1024));time.sleep(.0005)\n"
            "raise SystemExit('qualification_oom_not_observed')"
        )
        source = """from pathlib import Path
if Path('/sys/fs/cgroup/memory.max').read_text().strip()!=str(2*1024**3):raise SystemExit('qualification_oom_limit_unproven')
if Path('/sys/fs/cgroup/memory.swap.max').read_text().strip()!='0':raise SystemExit('qualification_oom_limit_unproven')
def events():
 p=Path('/sys/fs/cgroup/memory.events')
 return {key:int(value) for key,value in (line.split() for line in p.read_text().splitlines())}
before=events()
code=ALLOCATION_PROGRAM
r=subprocess.run([sys.executable,'-c',code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
after=events()
if after.get('oom_kill',0)<=before.get('oom_kill',0):raise SystemExit('qualification_oom_not_observed')
print(json.dumps({'oom_kill_before':before['oom_kill'],'oom_kill_after':after['oom_kill'],'injector_exit':r.returncode,'claim':'owned_cgroup_oom_only'}))
""".replace("ALLOCATION_PROGRAM", repr(allocation_program))
        facts = {}

        def operation():
            self.ownership()
            self.h.docker("update", "--memory-swap", str(memory), self.h.container)
            try:
                result = self.h.docker(
                    "exec",
                    self.h.container,
                    "python",
                    "-c",
                    "import json,subprocess,sys\n" + source,
                    timeout=75,
                )
                facts.update(json.loads(result["stdout"]))
                if (
                    type(facts.get("oom_kill_before")) is not int
                    or type(facts.get("oom_kill_after")) is not int
                    or not 0 <= facts["oom_kill_before"] < facts["oom_kill_after"]
                    or facts.get("claim") != "owned_cgroup_oom_only"
                ):
                    raise QualificationError("qualification_oom_not_observed")
                self.h.wait(
                    self.h.healthy, "state_oom_management_recovered", timeout=120
                )
            finally:
                self.h.assert_owned("container", self.h.container)
                self.h.docker("update", "--memory-swap", str(swap), self.h.container)

        evidence = self.phase("state-cgroup-oom", operation)
        self.record(
            evidence["receipt"]["phase"],
            "PASS",
            facts={"packet": evidence["receipt"], "oom": facts},
        )
        return evidence

    def cli(self, command, passphrase, *, name=None, check=True):
        if (
            command not in {"backup", "restore"}
            or not isinstance(passphrase, str)
            or not 12 <= len(passphrase) <= 1024
            or "\n" in passphrase
        ):
            raise QualificationError("qualification_state_cli_invalid")
        args = [
            "exec",
            "-i",
            self.h.container,
            "python",
            "-m",
            "exitlane.container_cli",
            command,
            "--passphrase-stdin",
        ]
        if command == "restore":
            if (
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.elbackup", name)
                is None
            ):
                raise QualificationError("qualification_state_cli_invalid")
            args += ["--name", name, "--confirm", "RESTORE EXITLANE"]
        result = self.h.docker(*args, data=passphrase + "\n", timeout=180, check=check)
        if result["code"]:
            return {"ok": False}
        return json.loads(result["stdout"])

    def backup_restore(self, passphrase):
        before = self.h.pair()
        intents = self.intents()
        interval = self.polling_interval()
        backup = {}

        def create():
            backup.update(self.cli("backup", passphrase))
            if not isinstance(backup.get("name"), str):
                raise QualificationError("qualification_state_backup_failed")

        self.phase("state-cli-backup", create)

        def change_setting():
            canary = interval + 1 if interval < 300 else 299
            value = self.h.api(
                "/api/settings",
                method="PUT",
                body={"general": {"provider_refresh_interval_seconds": canary}},
            )
            if value.get("status") != 200 or self.polling_interval() != canary:
                raise QualificationError("qualification_state_canary_failed")
            if self.h.api("/api/settings").get("status") != 200:
                raise QualificationError("qualification_state_canary_session_invalid")

        self.phase("state-restore-canary", change_setting)

        def wrong():
            facts = self.h.network_snapshot()
            if (
                self.cli(
                    "restore",
                    "synthetic-wrong-passphrase-only",
                    name=backup["name"],
                    check=False,
                ).get("ok")
                is not False
            ):
                raise QualificationError(
                    "qualification_state_wrong_passphrase_accepted"
                )
            after = self.h.network_snapshot()
            if (
                facts != after
                or self.h.pair() != before
                or self.polling_interval() == interval
                or self.intents() != intents
            ):
                raise QualificationError("qualification_state_wrong_passphrase_mutated")

        self.phase("state-cli-wrong-passphrase", wrong)

        def restore():
            if (
                self.cli("restore", passphrase, name=backup["name"]).get("restored")
                is not True
                or self.h.pair() != before
                or self.intents() != intents
                or self.polling_interval() != interval
            ):
                raise QualificationError("qualification_state_restore_failed")
            self.h.wait(self.h.healthy, "state_cli_restore_ready")
            status = self.h.docker(
                "exec",
                self.h.container,
                "python",
                "-m",
                "exitlane.container_cli",
                "status",
            )
            value = json.loads(status["stdout"])
            if value.get("state") != "ready" or value.get("worker_running") is not True:
                raise QualificationError("qualification_state_restore_failed")
            # Authentication failure is the expected proof after session revocation.
            if self.h.api("/api/vpn/providers")["status"] not in {401, 403}:
                raise QualificationError("qualification_state_session_not_revoked")
            self.h.cookie = ""

        return self.phase("state-cli-restore", restore)
