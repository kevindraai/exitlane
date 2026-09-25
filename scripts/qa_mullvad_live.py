"""Bounded live Mullvad QA. Run only on the disposable appliance with root-only auth."""

import argparse
import asyncio
import errno
import http.cookiejar
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

parser = argparse.ArgumentParser()
parser.add_argument("--confirm-disposable", action="store_true", required=True)
parser.add_argument("--admin-file", default="/root/exitlane-qa-admin.json")
parser.add_argument("--client-config", default="/etc/exitlane/wireguard/qa-router.conf")
parser.add_argument("--ingress", default="wg0")
parser.add_argument(
    "--readiness-script",
    default=str(pathlib.Path(__file__).with_name("wireguard_dataplane_readiness.py")),
)
args = parser.parse_args()
assert os.geteuid() == 0
missing_tools = [
    name
    for name in ("ip", "wg", "nft", "tcpdump", "ping", "dig", "python3")
    if shutil.which(name) is None
]
if missing_tools:
    parser.error("Missing test prerequisites: " + ", ".join(missing_tools))
if not pathlib.Path(args.readiness_script).is_file():
    parser.error("The dataplane readiness script does not exist")
suffix = uuid.uuid4().hex[:6]
ns = "exlqa-" + suffix
host = "exlh-" + suffix
peer = "exlp-" + suffix
table = "exitlane_qa_" + suffix
processes = []
capture_processes = []
valid_capture = False
results = []
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)


def api(path, data=None):
    req = urllib.request.Request(
        "http://127.0.0.1:8787" + path,
        data=None if data is None else json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener.open(req, timeout=75) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def run(*cmd, check=True):
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def log(name, **kw):
    row = {"test": name, "time": time.time(), **kw}
    results.append(row)
    print(json.dumps(row), flush=True)


def action(name, path, data, *, allow_failure=False):
    start = time.monotonic()
    code, value = api(path, data)
    safe = {
        k: v
        for k, v in value.items()
        if k in ("ok", "error_code", "state", "target", "detail")
    }
    log(name, http=code, seconds=round(time.monotonic() - start, 2), **safe)
    if not allow_failure:
        assert code == 200 and value.get("ok") is not False, name
    return code, value


def assert_source_guard(name, address, *, connected):
    source = address.split("/")[0]
    rules = json.loads(run("ip", "-j", "-4", "rule", "show").stdout)
    zero = [r for r in rules if r.get("priority") == 0]
    assert zero and str(zero[0].get("table")) in {"local", "255"}
    assert any(
        r.get("src") in {source, source + "/32"}
        and str(r.get("table")) == "51820"
        and str(r.get("protocol")) == "196"
        and set(r) <= {"src", "priority", "table", "protocol"}
        for r in zero[1:]
    ), "Exact retained provider-source rule missing"
    routes = json.loads(run("ip", "-j", "-4", "route", "show", "table", "51820").stdout)
    assert any(
        r.get("type") == "unreachable"
        and r.get("dst") == "default"
        and r.get("metric") == 42760
        and str(r.get("protocol")) == "196"
        for r in routes
    ), "Unreachable provider fallback missing"
    for destination in ("1.1.1.1", "10.64.0.1"):
        route = run(
            "ip", "-4", "route", "get", destination, "from", source, check=False
        )
        if connected:
            assert route.returncode == 0
            assert "dev wg-mullvad" in route.stdout and "table 51820" in route.stdout
        else:
            assert route.returncode != 0, "Late provider-source route escaped"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.setsockopt(socket.SOL_IP, 15, 1)  # IP_FREEBIND after tunnel removal.
            client.bind((source, 0))  # Deliberately no SO_BINDTODEVICE.
            try:
                client.sendto(b"exitlane-source-guard-qa", (destination, 53))
            except OSError as error:
                assert not connected and error.errno in {
                    errno.ENETUNREACH,
                    errno.EHOSTUNREACH,
                }
            else:
                assert connected, "Late provider-source packet escaped"
    host_route = run("ip", "-4", "route", "get", "1.1.1.1")
    assert "dev eth0" in host_route.stdout and "table 51820" not in host_route.stdout
    log(name, source_guard=True, connected=connected, host_main_route=True)


assert api("/api/auth/login", json.loads(pathlib.Path(args.admin_file).read_text()))[
    1
].get("authenticated")
action("prepare_killswitch", "/api/vpn/killswitch/enable", {})
with tempfile.TemporaryDirectory(prefix="exitlane-transition-", dir="/root") as td:
    td = pathlib.Path(td)
    try:
        # This namespace is the actual WireGuard client, not a simulated ingress link.
        fields = {}
        for line in pathlib.Path(args.client_config).read_text().splitlines():
            if " = " in line:
                k, v = line.split(" = ", 1)
                fields[k] = v
        key = td / "client.key"
        key.write_text(fields["PrivateKey"])
        key.chmod(0o600)
        run("ip", "netns", "add", ns)
        run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
        run("ip", "link", "set", peer, "netns", ns)
        run("ip", "address", "add", "10.254.254.1/30", "dev", host)
        run("ip", "link", "set", host, "up")
        run("ip", "-n", ns, "address", "add", "10.254.254.2/30", "dev", peer)
        run("ip", "-n", ns, "link", "set", "lo", "up")
        run("ip", "-n", ns, "link", "set", peer, "up")
        run("ip", "-n", ns, "link", "add", "wgqa", "type", "wireguard")
        run(
            "ip",
            "netns",
            "exec",
            ns,
            "wg",
            "set",
            "wgqa",
            "private-key",
            str(key),
            "peer",
            fields["PublicKey"],
            "endpoint",
            "10.254.254.1:51820",
            "allowed-ips",
            "0.0.0.0/0,::/0",
            "persistent-keepalive",
            "25",
        )
        run("ip", "-n", ns, "address", "add", "10.99.99.2/32", "dev", "wgqa")
        run("ip", "-n", ns, "-6", "address", "add", "fd99::2/128", "dev", "wgqa")
        run("ip", "-n", ns, "link", "set", "wgqa", "up")
        run("ip", "-n", ns, "route", "add", "default", "dev", "wgqa")
        run("ip", "-n", ns, "-6", "route", "add", "default", "dev", "wgqa")
        client_public = run(
            "ip", "netns", "exec", ns, "wg", "show", "wgqa", "public-key"
        ).stdout.strip()
        run(
            "wg",
            "set",
            args.ingress,
            "peer",
            client_public,
            "allowed-ips",
            "10.99.99.2/32,fd99::2/128",
        )
        run("nft", "add", "table", "inet", table)
        run(
            "nft",
            f"add chain inet {table} forward {{ type filter hook forward priority 300; policy accept; }}",
        )
        run(
            "nft",
            "add",
            "rule",
            "inet",
            table,
            "forward",
            "iifname",
            args.ingress,
            "oifname",
            "eth0",
            "counter",
        )
        from exitlane.services import provider_secrets

        provider_address = provider_secrets.load("mullvad")["ipv4_address"]
        run(
            "nft",
            f"add chain inet {table} host_output {{ type filter hook output priority 300; policy accept; }}",
        )
        run(
            "nft",
            "add",
            "rule",
            "inet",
            table,
            "host_output",
            "ip",
            "saddr",
            provider_address,
            "oifname",
            "eth0",
            "counter",
        )
        capture = td / "physical.pcap"
        ingress_capture = td / "ingress.pcap"
        filt = "dst host 1.1.1.1 or dst host 10.64.0.1 or dst host 2606:4700:4700::1111"
        # Capture decrypted client traffic on "any" so ingress recreation during
        # restore cannot terminate its capture. Filter strictly to this QA client.
        client_filter = "(src host 10.99.99.2 or src host fd99::2) and (" + filt + ")"
        for dev, path, expression in [
            ("eth0", capture, filt),
            ("any", ingress_capture, client_filter),
        ]:
            p = subprocess.Popen(
                ["tcpdump", "-U", "-n", "-i", dev, "-w", str(path), expression],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            processes.append(p)
            capture_processes.append(p)
        deadline = time.monotonic() + 5
        while not all(
            path.exists() and path.stat().st_size >= 24
            for path in (capture, ingress_capture)
        ):
            assert all(p.poll() is None for p in capture_processes)
            assert time.monotonic() < deadline, "Capture initialization timed out"
            time.sleep(0.05)
        for target in ["1.1.1.1", "2606:4700:4700::1111"]:
            p = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    ns,
                    "ping",
                    "-n",
                    "-i",
                    "0.2",
                    "-W",
                    "1",
                    target,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            processes.append(p)
        dns_code = "import socket,struct,time\nq=b'\\x12\\x34'+struct.pack('!HHHHH',256,1,0,0,0)+b'\\x07mullvad\\x03net\\x00\\x00\\x01\\x00\\x01'\nwhile True:\n for typ in (socket.SOCK_DGRAM,socket.SOCK_STREAM):\n  try:\n   with socket.socket(socket.AF_INET,typ) as s:\n    s.settimeout(.7);s.connect(('10.64.0.1',53));s.sendall(q if typ==socket.SOCK_DGRAM else struct.pack('!H',len(q))+q);s.recv(4096)\n  except OSError:pass\n time.sleep(.2)\n"
        processes.append(
            subprocess.Popen(
                ["ip", "netns", "exec", ns, "python3", "-c", dns_code],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        action("enable_killswitch", "/api/vpn/killswitch/enable", {})
        action("activate_mullvad", "/api/vpn/providers/mullvad/activate", {})
        action("initial_disconnect", "/api/vpn/providers/mullvad/disconnect", {})
        from exitlane.providers.mullvad import MullvadApi

        relays = asyncio.run(MullvadApi().relays())
        targets = []
        for country in ("nl", "de", "au"):
            eligible = sorted([r.hostname for r in relays if r.country_code == country])
            targets.extend(eligible[:2] if country == "nl" else eligible[:1])
        for target in targets:
            code, value = action(
                "relay_" + target,
                "/api/vpn/providers/mullvad/connect",
                {"target": target},
                allow_failure=True,
            )
            if not value.get("ok"):
                action(
                    "retry_" + target,
                    "/api/vpn/providers/mullvad/connect",
                    {"target": target},
                )
        code, value = action(
            "baseline_nl", "/api/vpn/providers/mullvad/connect", {"target": targets[0]}
        )
        assert code == 200 and value.get("ok"), "No proven baseline relay"
        ready = run(
            "ip",
            "netns",
            "exec",
            ns,
            "python3",
            args.readiness_script,
            "--interface",
            "wgqa",
            "--target",
            "1.1.1.1",
            "--deadline-seconds",
            "35",
            "--steady-count",
            "5",
            check=False,
        )
        log("dataplane_readiness", passed=ready.returncode == 0)
        assert ready.returncode == 0
        for tcp in (False, True):
            probe = run(
                "ip",
                "netns",
                "exec",
                ns,
                "dig",
                "+short",
                "+time=5",
                "+tries=1",
                *(["+tcp"] if tcp else []),
                "@10.64.0.1",
                "mullvad.net",
                check=False,
            )
            log(
                "dns_tcp" if tcp else "dns_udp",
                passed=probe.returncode == 0 and bool(probe.stdout.strip()),
            )
            assert probe.returncode == 0 and probe.stdout.strip()
        # Reproduce an unavailable relay deterministically, leaving management untouched.
        previous = provider_secrets.load("mullvad")["active"]["generation"]
        assert_source_guard("connected_source_guard", provider_address, connected=True)
        unavailable = next(r for r in relays if r.hostname == targets[2])
        run(
            "nft",
            f"add chain inet {table} output {{ type filter hook output priority -100; policy accept; }}",
        )
        run(
            "nft",
            "add",
            "rule",
            "inet",
            table,
            "output",
            "ip",
            "daddr",
            unavailable.endpoint,
            "udp",
            "dport",
            "51820",
            "drop",
        )
        try:
            _, failed = action(
                "injected_relay_timeout",
                "/api/vpn/providers/mullvad/connect",
                {"target": unavailable.hostname},
                allow_failure=True,
            )
            restored = provider_secrets.load("mullvad").get("active", {})
            log(
                "timeout_rollback",
                failed_as_expected=failed.get("ok") is False,
                prior_generation_restored=restored.get("generation") == previous,
            )
            assert failed.get("ok") is False and restored.get("generation") == previous
            assert failed.get("error_code") == "vpn_connect_timeout"
        finally:
            run("nft", "flush", "chain", "inet", table, "output")
        # Backups preserve the same provider identity; restoring must arm routing
        # even when the backup records the optional firewall as disabled.
        from exitlane import cli, core, lifecycle
        from exitlane.services import killswitch

        action("restore_backup_policy", "/api/vpn/killswitch/disable", {})
        assert core.setting(killswitch.SETTING_CONFIGURED, False) is False
        recovery = td / "restore"
        recovery.mkdir(mode=0o700)
        import secrets

        passphrase = secrets.token_urlsafe(32)
        backup = recovery / "source.elb"
        lifecycle.create_backup(backup, passphrase)
        identity = provider_secrets.load("mullvad")
        original_key = pathlib.Path("/etc/exitlane/secret.key").read_bytes()
        devices_before = asyncio.run(
            MullvadApi(str(identity["account_number"])).devices()
        )
        original_ids = {d.id for d in devices_before}
        for active_target in (False, True):
            if not active_target:
                action("guard_before_disconnect", "/api/vpn/killswitch/enable", {})
                action(
                    "disconnect_before_restore",
                    "/api/vpn/providers/mullvad/disconnect",
                    {},
                )
            log("restore_window_start")
            lifecycle.restore_backup(
                backup,
                passphrase,
                confirmation="RESTORE EXITLANE",
                service_action=cli._systemd_service_action,
                health_check=cli._local_health_check,
                forwarding_guard=cli._restore_forwarding_guard,
            )
            stale_session = api("/api/settings")[0]
            restored = provider_secrets.load("mullvad")
            blocked = run(
                "ip",
                "route",
                "get",
                "1.1.1.1",
                "from",
                "10.99.99.2",
                "iif",
                args.ingress,
                check=False,
            )
            exact_identity = all(
                restored[k] == identity[k]
                for k in ("account_number", "private_key", "public_key", "device_id")
            )
            log(
                "restore_active_target"
                if active_target
                else "restore_disconnected_target",
                blocked=blocked.returncode != 0,
                old_session_rejected=stale_session == 401,
                identity_preserved=exact_identity,
                master_key_preserved=pathlib.Path(
                    "/etc/exitlane/secret.key"
                ).read_bytes()
                == original_key,
            )
            assert blocked.returncode != 0 and stale_session == 401 and exact_identity
            assert_source_guard(
                "restored_source_guard", provider_address, connected=False
            )
            assert api(
                "/api/auth/login", json.loads(pathlib.Path(args.admin_file).read_text())
            )[1].get("authenticated")
            _, reconnected = action(
                "restore_reconnect",
                "/api/vpn/providers/mullvad/connect",
                {"target": targets[0]},
            )
            assert reconnected.get("ok")
            steady = run(
                "ip",
                "netns",
                "exec",
                ns,
                "python3",
                args.readiness_script,
                "--interface",
                "wgqa",
                "--target",
                "1.1.1.1",
                "--deadline-seconds",
                "35",
                "--steady-count",
                "5",
                check=False,
            )
            log("restored_client_dataplane", passed=steady.returncode == 0)
            assert steady.returncode == 0
        # Inject a failed restored-service health check, then require healthy rollback.
        core.set_setting("language", "nl")
        before_wg = {p.name: p.read_bytes() for p in core.WG_DIR.iterdir()}
        health_calls = [False]

        def injected_health():
            return health_calls.pop() if health_calls else cli._local_health_check()

        try:
            lifecycle.restore_backup(
                backup,
                passphrase,
                confirmation="RESTORE EXITLANE",
                service_action=cli._systemd_service_action,
                health_check=injected_health,
                forwarding_guard=cli._restore_forwarding_guard,
            )
            raise AssertionError("Injected failure unexpectedly succeeded")
        except lifecycle.LifecycleError as error:
            assert error.code == "restored_service_unhealthy", error.code
        assert core.setting("language") == "nl"
        assert before_wg == {p.name: p.read_bytes() for p in core.WG_DIR.iterdir()}
        assert pathlib.Path("/etc/exitlane/secret.key").read_bytes() == original_key
        assert (
            run(
                "nft", "list", "table", "inet", "exitlane_restore", check=False
            ).returncode
            != 0
        )
        devices_after = asyncio.run(
            MullvadApi(str(identity["account_number"])).devices()
        )
        assert {d.id for d in devices_after} == original_ids
        log("failed_restore_rollback", passed=True, remote_devices_unchanged=True)
        assert api(
            "/api/auth/login", json.loads(pathlib.Path(args.admin_file).read_text())
        )[1].get("authenticated")
        _, reconnected = action(
            "rollback_reconnect",
            "/api/vpn/providers/mullvad/connect",
            {"target": targets[0]},
        )
        assert reconnected.get("ok")
        # Optional firewall off: mandatory routing guard must stand on its own.
        action("disable_optional_killswitch", "/api/vpn/killswitch/disable", {})
        assert core.setting(killswitch.SETTING_CONFIGURED, False) is False
        run("ip", "link", "delete", "wg-mullvad")
        time.sleep(4)
        blocked = run(
            "ip",
            "route",
            "get",
            "1.1.1.1",
            "from",
            "10.99.99.2",
            "iif",
            args.ingress,
            check=False,
        )
        log("tunnel_loss_route", blocked=blocked.returncode != 0)
        assert blocked.returncode != 0
        assert_source_guard(
            "lost_tunnel_source_guard", provider_address, connected=False
        )
        assert api("/api/health")[0] == 200
        action(
            "recover_after_loss",
            "/api/vpn/providers/mullvad/connect",
            {"target": targets[0]},
        )
        action("enable_before_teardown", "/api/vpn/killswitch/enable", {})
        action("final_disconnect", "/api/vpn/providers/mullvad/disconnect", {})
        assert_source_guard(
            "disconnected_source_guard", provider_address, connected=False
        )
        time.sleep(3)
    finally:
        for p in processes:
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
        for p in processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        if "capture" in locals():
            physical_read = run("tcpdump", "-n", "-r", str(capture), check=False)
            ingress_read = run("tcpdump", "-n", "-r", str(ingress_capture), check=False)
            ipv6_read = run(
                "tcpdump", "-n", "-r", str(ingress_capture), "ip6", check=False
            )
            physical = physical_read.stdout.splitlines()
            inbound = ingress_read.stdout.splitlines()
            ipv6_packets = len(ipv6_read.stdout.splitlines())
            counts = run(
                "nft", "-j", "list", "chain", "inet", table, "forward", check=False
            )
            host_counts = run(
                "nft", "-j", "list", "chain", "inet", table, "host_output", check=False
            )
            counters = []
            output_counters = []
            try:
                for result, target in (
                    (counts, counters),
                    (host_counts, output_counters),
                ):
                    for e in json.loads(result.stdout)["nftables"]:
                        for expr in e.get("rule", {}).get("expr", []):
                            if "counter" in expr:
                                target.append(expr["counter"])
            except (ValueError, KeyError, TypeError):
                pass
            valid_capture = (
                len(capture_processes) == 2
                and all(p.returncode == 0 for p in capture_processes)
                and all(
                    r.returncode == 0
                    for r in (
                        physical_read,
                        ingress_read,
                        ipv6_read,
                        counts,
                        host_counts,
                    )
                )
                and len(counters) == 1
                and len(output_counters) == 1
                and all(
                    path.is_file() and path.stat().st_size >= 24
                    for path in (capture, ingress_capture)
                )
            )
            if (
                physical
                or not valid_capture
                or ipv6_packets == 0
                or len(inbound) <= 50
                or any(c["packets"] for c in counters + output_counters)
            ):
                forensic = pathlib.Path("/root/exitlane-qa-capture-failure-" + suffix)
                forensic.mkdir(mode=0o700, exist_ok=True)
                for path in (capture, ingress_capture):
                    if path.exists():
                        saved = forensic / path.name
                        shutil.copyfile(path, saved)
                        saved.chmod(0o600)
                # The physical filter includes only test destinations, never the
                # management API or credentials. Retain details locally for RCA.
                detail = run(
                    "tcpdump", "-tt", "-nn", "-vv", "-r", str(capture), check=False
                )
                diagnostic = forensic / "physical.txt"
                diagnostic.write_text(detail.stdout)
                diagnostic.chmod(0o600)
            log(
                "captures",
                capture_valid=valid_capture,
                capture_exit_codes=[p.returncode for p in capture_processes],
                read_exit_codes=[
                    r.returncode
                    for r in (
                        physical_read,
                        ingress_read,
                        ipv6_read,
                        counts,
                        host_counts,
                    )
                ],
                physical_plaintext_packets=len(physical),
                ingress_packets=len(inbound),
                ipv6_ingress_packets=ipv6_packets,
                forward_counters=counters,
                host_output_counters=output_counters,
            )
        if "client_public" in locals():
            run(
                "wg",
                "set",
                args.ingress,
                "peer",
                client_public,
                "allowed-ips",
                "10.99.99.2/32",
                check=False,
            )
        run("ip", "netns", "delete", ns, check=False)
        run("ip", "link", "delete", host, check=False)
        run("nft", "delete", "table", "inet", table, check=False)
    assert (
        valid_capture
        and len(physical) == 0
        and ipv6_packets > 0
        and len(inbound) > 50
        and all(c["packets"] == 0 for c in counters + output_counters)
    ), "Leak or missing positive traffic evidence"
log("completed", passed=True)
