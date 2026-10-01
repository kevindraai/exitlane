"""D6 peer fixture validation without namespaces, packages or infrastructure."""
import base64
import http.client
import importlib.util
import json
import os
import struct
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[2] / 'scripts/qualification/container_host_peer.py'
spec = importlib.util.spec_from_file_location('container_host_peer', SOURCE)
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
IDENTIFIER = '0b0dcc00-ff11-4333-aaaa-012345678901'
PUBLIC_A = base64.b64encode(bytes(range(32))).decode()
PUBLIC_B = base64.b64encode(bytes(range(32, 64))).decode()
PRIVATE_A = base64.b64encode(b'synthetic-private-peer-a'.ljust(32, b'!')).decode()
PRIVATE_B = base64.b64encode(b'synthetic-private-peer-b'.ljust(32, b'!')).decode()


def config(**changes):
    result = {'run_id': IDENTIFIER, 'candidate_vm_address': '172.16.135.80',
              'peer_vm_address': '172.16.135.81', 'token': 'a' * 64, 'port': 8991}
    result.update(changes)
    return result


def fixture(tmp_path):
    store = peer.Store(IDENTIFIER, root=tmp_path)
    store.directory(create=True)
    state = {'keys': {'a': {'private_key': PRIVATE_A, 'public_key': PUBLIC_A},
                      'b': {'private_key': PRIVATE_B, 'public_key': PUBLIC_B}},
             'registrations': {provider: [] for provider in peer.ADDRESSES}}
    store.write('state.json', state)
    network = SimpleNamespace(names={'a': 'owned-a'}, links={'a': 'owned-veth'}, applied=[])
    network.apply_keys = lambda state: network.applied.append(json.loads(json.dumps(state)))
    return peer.UpstreamFixture(config(), store, network)


@pytest.mark.parametrize('changes', [
    {'run_id': '../bad'}, {'run_id': IDENTIFIER.upper()}, {'token': 'z' * 64}, {'token': 'a' * 63},
    {'candidate_vm_address': '8.8.8.8'}, {'candidate_vm_address': '127.0.0.1'},
    {'candidate_vm_address': '169.254.1.1'}, {'candidate_vm_address': '0.0.0.0'},
    {'candidate_vm_address': '172.16.135.81'}, {'peer_vm_address': '::1'},
    {'port': True}, {'port': 80}, {'extra': 'arbitrary'},
])
def test_configuration_fails_closed(changes):
    with pytest.raises(peer.FixtureError, match='fixture_configuration_invalid'):
        peer.configuration(config(**changes))


def test_default_port_and_strict_duplicate_json():
    value = config()
    value.pop('port')
    assert peer.configuration(value)['port'] == 8991
    for raw in (b'{"action":"one","action":"two"}', b'[]', b'', b'x' * 4097):
        with pytest.raises(peer.FixtureError):
            peer.decode(raw)


def test_store_private_permissions_and_symlink_refusal(tmp_path):
    store = peer.Store(IDENTIFIER, root=tmp_path)
    store.directory(create=True)
    store.write('state.json', {'public': PUBLIC_A})
    assert store.path.stat().st_mode & 0o777 == 0o700
    assert (store.path / 'state.json').stat().st_mode & 0o777 == 0o600
    (store.path / 'symlink.json').symlink_to(store.path / 'state.json')
    with pytest.raises(peer.FixtureError, match='fixture_state_unsafe'):
        store.read('symlink.json')
    with pytest.raises(peer.FixtureError, match='fixture_state_unsafe'):
        store.write('symlink.json', {'public': PUBLIC_B})
    assert not (store.path / '.symlink.json.new').exists()
    (store.path / 'state.json').chmod(0o644)
    with pytest.raises(peer.FixtureError, match='fixture_state_unsafe'):
        store.read('state.json')


def test_fifo_state_is_rejected_without_waiting_for_writer(tmp_path):
    store = peer.Store(IDENTIFIER, root=tmp_path)
    store.directory(create=True)
    os.mkfifo(store.path / 'state.json', 0o600)
    finished = threading.Event()
    errors = []
    def inspect():
        try:
            store.read('state.json')
        except peer.FixtureError as error:
            errors.append(str(error))
        finally:
            finished.set()
    thread = threading.Thread(target=inspect, daemon=True)
    thread.start()
    assert finished.wait(1), 'FIFO open blocked before the regular-file gate'
    thread.join(timeout=1)
    assert errors == ['fixture_state_unsafe']
    with pytest.raises(peer.FixtureError, match='fixture_state_unsafe'):
        store.write('state.json', {'replacement': True})
    assert (store.path / 'state.json').is_fifo()
    assert not (store.path / '.state.json.new').exists()


def test_daemon_lock_prevents_reuse(tmp_path):
    store = peer.Store(IDENTIFIER, root=tmp_path)
    store.directory(create=True)
    with (store.lock(daemon=True), pytest.raises(peer.FixtureError, match='fixture_resource_conflict'),
          store.lock(daemon=True)):
        pytest.fail('second fixture daemon accepted')


def test_registration_uses_production_parsers_and_survives_process_restart(tmp_path):
    from exitlane.providers.mullvad import Device, Relay
    from exitlane.providers.pia_api import PiaKeyResponse, PiaServer
    value = fixture(tmp_path)
    device = value.request({'action': 'mullvad_register', 'public_key': PUBLIC_A})
    assert Device.parse(device).pubkey == PUBLIC_A
    assert all(Relay.parse(item) is not None for item in value.request({'action': 'mullvad_relays'}))
    assert value.request({'action': 'mullvad_devices'}) == [device]
    restarted = peer.UpstreamFixture(config(), value.store, value.network)
    assert restarted.request({'action': 'mullvad_devices'}) == [device]
    assert restarted.request({'action': 'mullvad_register', 'public_key': PUBLIC_A}) == device
    servers = [PiaServer.parse(item['region'], item['server'], item['address'])
               for item in restarted.request({'action': 'pia_catalog'})]
    for server in servers:
        response = restarted.request({'action': 'pia_register', 'peer': server.region_id, 'public_key': PUBLIC_B})
        assert PiaKeyResponse.parse(response, expected_public_key=PUBLIC_B,
                                    expected_server_address=server.address).peer_ip == '10.65.0.2/32'
    last = value.network.applied[-1]['registrations']
    assert last['mullvad'][0]['public_key'] == PUBLIC_A
    assert last['pia'][0]['public_key'] == PUBLIC_B and last['pia'][0]['peers'] == ['a', 'b']
    # Another process's public registration is read afresh, never overwritten.
    assert value.request({'action': 'mullvad_devices'}) == [device]
    assert value.state['registrations']['pia'][0]['public_key'] == PUBLIC_B
    value.request({'action': 'mullvad_delete', 'device_id': device['id']})
    assert value.request({'action': 'mullvad_devices'}) == []
    assert value.network.applied[-1]['registrations']['pia'][0]['public_key'] == PUBLIC_B


@pytest.mark.parametrize('provider', ['pia', 'proton'])
def test_direct_public_registration_retains_other_peer_rollback_key(provider, tmp_path):
    value = fixture(tmp_path)
    def register(public, role):
        if provider == 'pia':
            value.request({'action': 'pia_register', 'public_key': public, 'peer': role})
        else:
            with value.store.lock():
                value.register('proton', public, [role])
    register(PUBLIC_A, 'a')
    register(PUBLIC_B, 'b')
    entries = value.network.applied[-1]['registrations'][provider]
    assert {entry['public_key']: entry['peers'] for entry in entries} == {
        PUBLIC_A: ['a'], PUBLIC_B: ['b']}
    # Re-registering the A key on B revokes only B's old key and unions A+B.
    register(PUBLIC_A, 'b')
    entries = value.network.applied[-1]['registrations'][provider]
    assert len(entries) == 1 and entries[0]['public_key'] == PUBLIC_A and entries[0]['peers'] == ['a', 'b']
    # Replacing A leaves B's previous, still-valid rollback generation alone.
    register(PUBLIC_B, 'a')
    entries = value.network.applied[-1]['registrations'][provider]
    assert {entry['public_key']: entry['peers'] for entry in entries} == {
        PUBLIC_A: ['b'], PUBLIC_B: ['a']}


def test_mullvad_device_replacement_still_revokes_shared_old_key(tmp_path):
    value = fixture(tmp_path)
    value.request({'action': 'mullvad_register', 'public_key': PUBLIC_A})
    value.request({'action': 'mullvad_register', 'public_key': PUBLIC_B})
    entries = value.network.applied[-1]['registrations']['mullvad']
    assert len(entries) == 1 and entries[0]['public_key'] == PUBLIC_B and entries[0]['peers'] == ['a', 'b']


@pytest.mark.parametrize('payload', [
    {'action': 'exec', 'command': 'touch /tmp/not-permitted'}, {'action': 'mullvad_devices', 'extra': True},
    {'action': 'mullvad_register', 'public_key': 'not-a-key'},
    {'action': 'mullvad_register', 'private_key': PRIVATE_A},
    {'action': 'pia_register', 'public_key': PUBLIC_A, 'peer': 'other'},
    {'action': 'mullvad_delete', 'device_id': '../state.json'},
])
def test_rpc_contract_rejects_arbitrary_commands_and_private_key_fields(tmp_path, payload):
    value = fixture(tmp_path)
    with pytest.raises(peer.FixtureError):
        value.request(payload)
    assert value.network.applied == []


def test_wireguard_configuration_uses_stdin_preserves_each_provider_key(tmp_path):
    value = fixture(tmp_path)
    calls = []
    network = peer.Network(config(), value.store, execute=lambda args, **kw: calls.append((args, kw)) or b'')
    network.validate_owned = lambda: None
    state = value.state
    state['registrations']['mullvad'] = [{'public_key': PUBLIC_A, 'peers': ['a', 'b']}]
    state['registrations']['pia'] = [{'public_key': PUBLIC_B, 'peers': ['a']}]
    network.apply_keys(state)
    configs = [kw['data'] for args, kw in calls if 'setconf' in args]
    assert len(configs) == 2
    assert PUBLIC_A.encode() in configs[0] and PUBLIC_B.encode() in configs[0]
    assert PUBLIC_A.encode() in configs[1] and PUBLIC_B.encode() not in configs[1]
    assert PRIVATE_A.encode() in configs[0] and PRIVATE_B.encode() in configs[1]
    assert PRIVATE_A not in str([args for args, _ in calls])
    assert all(args[-1] == '/dev/stdin' for args, _ in calls if 'setconf' in args)
    assert PRIVATE_A not in json.dumps(value.public_status())
    assert 'token' not in value.public_status()


def client_input():
    return {'run_id': IDENTIFIER, 'endpoint': '172.16.135.80:51820',
            'configuration': f'[Interface]\nPrivateKey = {PRIVATE_A}\nAddress = 10.77.0.2/24\nDNS = 10.77.0.1\n'
                             f'[Peer]\nPublicKey = {PUBLIC_A}\nEndpoint = 172.17.0.2:51820\nAllowedIPs = 0.0.0.0/0\n'}


def test_client_configuration_is_fixed_routes_and_endpoint_not_shell():
    result = peer.client_configuration(client_input(), config())
    assert 'Endpoint = 172.16.135.80:51820' in result
    assert '0.0.0.0/0' not in result
    assert 'fd99::1/128' in result
    assert 'PostUp' not in result


@pytest.mark.parametrize('mutation', ['shell', 'private-duplicate', 'peer-duplicate', 'wrong-address', 'wrong-endpoint'])
def test_client_rejects_injected_config(mutation):
    value = client_input()
    if mutation == 'shell':
        value['configuration'] = value['configuration'].replace('[Peer]', 'PostUp = touch /tmp/not-permitted\n[Peer]')
    elif mutation == 'private-duplicate':
        value['configuration'] += 'PublicKey = ' + PUBLIC_B
    elif mutation == 'peer-duplicate':
        value['configuration'] += '[Peer]\nPublicKey = ' + PUBLIC_B
    elif mutation == 'wrong-address':
        value['configuration'] = value['configuration'].replace('10.77.0.2', '10.77.0.3')
    else:
        value['endpoint'] = '8.8.8.8:51820'
    with pytest.raises(peer.FixtureError):
        peer.client_configuration(value, config())


def owned_network(tmp_path):
    store = peer.Store(IDENTIFIER, root=tmp_path)
    store.directory(create=True)
    network = peer.Network(config(), store)
    current = {role: {'lo': 1, 'uplink': 2} for role in peer.ROLES}
    calls = []
    def ns(role, *args, data=None):
        calls.append((role, args, data))
        if args[:4] == ('ip', 'link', 'add', 'wg-client'):
            current['client']['wg-client'] = 3
        if args[:4] == ('ip', '-j', 'link', 'show'):
            names = [args[-1]] if 'dev' in args else list(current[role])
            return json.dumps([{'ifname': name, 'ifindex': current[role][name]} for name in names]).encode()
        return b''
    network.ns = ns
    network._inode = lambda _role: [1, 10]
    network._ifindex = lambda _link: 7
    network._namespace_links = lambda role: dict(current[role])
    store.write('ownership.json', {'names': network.names, 'links': network.links,
                                   'inodes': {role: [1, 10] for role in peer.ROLES},
                                   'ifindexes': {role: 7 for role in peer.ROLES},
                                   'namespace_ifindexes': {role: dict(links) for role, links in current.items()}})
    return network, store, current, calls


def test_client_is_up_before_routes_and_reconciles_only_same_owned_interface(tmp_path):
    network, store, current, calls = owned_network(tmp_path)
    peer.configure_client(client_input(), config(), store, network)
    up = next(index for index, (_, args, _) in enumerate(calls)
              if args == ('ip', 'link', 'set', 'wg-client', 'up'))
    routes = [index for index, (_, args, _) in enumerate(calls) if 'route' in args]
    assert routes and all(index > up for index in routes)
    assert store.read('client.json') == {'ifindex': 3}
    calls.clear()
    peer.configure_client(client_input(), config(), store, network)
    assert not any(args[:3] == ('ip', 'link', 'add') for _, args, _ in calls)
    assert all('replace' in args for _, args, _ in calls if 'route' in args or 'address' in args)
    assert PRIVATE_A not in str([args for _, args, _ in calls])
    calls.clear()
    current['client']['wg-client'] = 99
    with pytest.raises(peer.FixtureError, match='fixture_resource_conflict'):
        peer.configure_client(client_input(), config(), store, network)
    assert not calls  # No mutation, private transfer, or adoption after replacement.


def test_readonly_ownership_projection_has_only_validated_public_facts(tmp_path):
    network, store, current, calls = owned_network(tmp_path)
    current['client']['wg-client'] = 3
    store.write('client.json', {'ifindex': 3})
    result = network.ownership_projection('client')
    assert result == {'run_id': IDENTIFIER, 'role': 'client', 'namespace': network.names['client'],
                      'namespace_inode': [1, 10], 'host_link': network.links['client'], 'host_ifindex': 7,
                      'interface_ifindexes': {'lo': 1, 'uplink': 2, 'wg-client': 3}}
    assert calls == []
    assert 'token' not in result and PRIVATE_A not in json.dumps(result)
    with pytest.raises(peer.FixtureError, match='fixture_request_invalid'):
        network.ownership_projection('../foreign')
    current['a']['foreign-interface'] = 99
    with pytest.raises(peer.FixtureError, match='fixture_resource_conflict'):
        network.ownership_projection('client')


def fault_network(tmp_path):
    network, store, current, calls = owned_network(tmp_path)
    for role in ('a', 'b'):
        current[role]['wg-peer'] = 3
    ownership = store.read('ownership.json')
    ownership['namespace_ifindexes'] = {role: dict(links) for role, links in current.items()}
    store.write('ownership.json', ownership)
    original = network.ns
    tables = {'a': None, 'b': None}
    generation = [100]
    up = {'a': True, 'b': True}
    def ns(role, *args, data=None):
        if args[:1] != ('nft',):
            if args == ('ip', '-j', 'link', 'show', 'dev', 'wg-peer'):
                calls.append((role, args, data))
                return json.dumps([{'ifname': 'wg-peer', 'ifindex': current[role]['wg-peer'],
                                    'flags': ['UP'] if up[role] else []}]).encode()
            if args[:5] == ('ip', 'link', 'set', 'wg-peer', 'down'):
                up[role] = False
            elif args[:5] == ('ip', 'link', 'set', 'wg-peer', 'up'):
                up[role] = True
            return original(role, *args, data=data)
        calls.append((role, args, data))
        if args == ('nft', '-j', 'list', 'ruleset'):
            return json.dumps({'nftables': tables[role] or []}).encode()
        assert args == ('nft', '-f', '/dev/stdin')
        script = data.decode()
        table = 'd6_fault_' + IDENTIFIER.replace('-', '')[:10]
        if f'delete table inet {table}' in script:
            tables[role] = None
        if f'create table inet {table}' in script:
            generation[0] += 1
            tables[role] = [{'table': {'family': 'inet', 'name': table, 'handle': generation[0]}},
                            {'rule': {'family': 'inet', 'table': table, 'handle': generation[0] + 1,
                                      'expr': [{'synthetic_fixed_script': script}]}}]
        return b''
    network.ns = ns
    return network, store, current, calls, tables


def fault(role, action):
    return {'run_id': IDENTIFIER, 'role': role, 'action': action}


def test_faults_are_per_peer_bounded_owned_and_idempotent(tmp_path):
    network, store, current, calls, tables = fault_network(tmp_path)
    controller = peer.FaultController(network)
    assert controller.apply(fault('a', 'dataplane_off'))['faults'] == {
        'handshake_off': False, 'dataplane_off': True, 'dns_off': False}
    assert controller.apply(fault('b', 'handshake_off'))['faults']['handshake_off']
    assert not any(args[:4] == ('ip', 'link', 'set', 'wg-peer') and 'down' in args for _role, args, _data in calls)
    assert current['a']['wg-peer'] == current['b']['wg-peer'] == 3
    assert controller.apply(fault('b', 'dns_off'))['faults']['dns_off']
    assert tables['a'] is not None and tables['b'] is not None
    writes_before = len([entry for entry in calls if entry[1] == ('nft', '-f', '/dev/stdin')])
    controller.apply(fault('a', 'dataplane_off'))
    assert len([entry for entry in calls if entry[1] == ('nft', '-f', '/dev/stdin')]) == writes_before
    controller.apply(fault('a', 'dataplane_on'))
    assert tables['a'] is None and tables['b'] is not None
    assert peer.fault_state(store)['b']['handshake_off']
    controller.apply(fault('b', 'dns_on'))
    assert tables['b'] is not None
    assert controller.apply(fault('b', 'handshake_on'))['faults'] == {
        'handshake_off': False, 'dataplane_off': False, 'dns_off': False}
    scripts = b'\n'.join(data for _role, args, data in calls if args == ('nft', '-f', '/dev/stdin'))
    assert b'iifname "wg-peer" oifname "target" ip daddr 1.1.1.1 drop' in scripts
    assert b'udp dport 51820 drop' in scripts and b'udp sport 51820 drop' in scripts
    assert b'udp dport 53 drop' in scripts and b'tcp dport 53 drop' in scripts
    assert b'd6_fixture' not in scripts and b'flush' not in scripts
    assert all(role in ('a', 'b') for role, _args, _data in calls)
    assert not any('sysctl' in args or 'route' in args for _role, args, _data in calls)


@pytest.mark.parametrize('payload', [fault('client', 'dns_off'), fault('a', 'arbitrary'),
                                     {**fault('a', 'dns_off'), 'command': 'arbitrary'},
                                     {**fault('a', 'dns_off'), 'run_id': 'foreign'}])
def test_fault_rejects_non_contract_before_any_command(tmp_path, payload):
    network, _store, _current, calls, _tables = fault_network(tmp_path)
    with pytest.raises(peer.FixtureError, match='fixture_request_invalid'):
        peer.FaultController(network).apply(payload)
    assert calls == []


def test_fault_never_adopts_collision_or_tampered_owned_policy(tmp_path):
    network, _store, _current, calls, tables = fault_network(tmp_path)
    controller = peer.FaultController(network)
    tables['a'] = [{'table': {'family': 'inet', 'name': controller.table, 'handle': 77}}]
    with pytest.raises(peer.FixtureError, match='fixture_resource_conflict'):
        controller.apply(fault('a', 'handshake_off'))
    assert not any(args[0] == 'ip' or '-f' in args for _role, args, _data in calls)
    tables['a'] = None
    controller.apply(fault('a', 'dns_off'))
    tables['a'][1]['rule']['expr'] = [{'foreign': 'tampered'}]
    calls.clear()
    with pytest.raises(peer.FixtureError, match='fixture_resource_conflict'):
        controller.apply(fault('a', 'dns_on'))
    assert not any('-f' in args for _role, args, _data in calls)


def test_fault_refuses_replaced_interface_before_policy_lookup(tmp_path):
    network, _store, current, calls, _tables = fault_network(tmp_path)
    current['a']['wg-peer'] = 99
    with pytest.raises(peer.FixtureError, match='fixture_resource_conflict'):
        peer.FaultController(network).apply(fault('a', 'dns_off'))
    assert calls == []


def test_registration_does_not_clear_handshake_fault(tmp_path):
    network, _store, _current, calls, _tables = fault_network(tmp_path)
    controller = peer.FaultController(network)
    controller.apply(fault('b', 'handshake_off'))
    state = {'keys': {'a': {'private_key': PRIVATE_A}, 'b': {'private_key': PRIVATE_B}},
             'registrations': {name: [] for name in peer.ADDRESSES}}
    calls.clear()
    network.apply_keys(state)
    assert not any(args[:4] == ('ip', 'link', 'set', 'wg-peer') and 'down' in args for _role, args, _data in calls)
    assert ('a', ('ip', 'link', 'set', 'wg-peer', 'up'), None) in calls
    assert ('b', ('ip', 'link', 'set', 'wg-peer', 'up'), None) in calls


def test_unusable_inner_dataplane_keeps_outer_handshake_and_interface_observer_available(tmp_path):
    network, _store, current, calls, _tables = fault_network(tmp_path)
    result = peer.FaultController(network).apply(fault('b', 'dataplane_off'))
    assert result['faults'] == {'handshake_off': False, 'dataplane_off': True, 'dns_off': False}
    script = next(data for role, args, data in calls if role == 'b' and args == ('nft', '-f', '/dev/stdin'))
    assert b'input iifname "wg-peer" drop' in script
    assert b'forward iifname "wg-peer" oifname "target" ip daddr 1.1.1.1 drop' in script
    assert b'51820' not in script and b'output udp' not in script
    assert not any(args[:4] == ('ip', 'link', 'set', 'wg-peer') for _role, args, _data in calls)
    assert current['b']['wg-peer'] == 3


def test_dns_only_fault_does_not_blackhole_other_inner_dataplane(tmp_path):
    network, _store, _current, calls, _tables = fault_network(tmp_path)
    peer.FaultController(network).apply(fault('a', 'dns_off'))
    script = next(data for role, args, data in calls if role == 'a' and args == ('nft', '-f', '/dev/stdin'))
    assert b'input udp dport 53 drop' in script and b'input tcp dport 53 drop' in script
    assert b'iifname "wg-peer" drop' not in script and b'51820' not in script


def test_failed_fault_transaction_cannot_claim_success_or_delete_primary_policy(tmp_path):
    network, store, _current, calls, _tables = fault_network(tmp_path)
    original = network.ns
    def ns(role, *args, data=None):
        if args == ('nft', '-f', '/dev/stdin'):
            assert b'd6_fixture' not in data and b'flush' not in data
            raise peer.FixtureError('fixture_command_failed')
        return original(role, *args, data=data)
    network.ns = ns
    with pytest.raises(peer.FixtureError, match='fixture_command_failed'):
        peer.FaultController(network).apply(fault('a', 'dataplane_off'))
    assert not (store.path / 'faults.json').exists()
    assert not any(args[:3] == ('ip', 'link', 'set') for _role, args, _data in calls)


def test_clock_rpc_reads_only_public_boot_identity_without_state_access(tmp_path, monkeypatch):
    value = fixture(tmp_path)
    boot = 'd6145666-0000-4000-aaaa-111111111111'
    def read(path, *_args, **_kwargs):
        assert str(path) == '/proc/sys/kernel/random/boot_id'
        return boot + '\n'
    monkeypatch.setattr(peer.Path, 'read_text', read)
    monkeypatch.setattr(peer.time, 'time_ns', lambda: 123456789)
    monkeypatch.setattr(value.store, 'lock', lambda **_kw: pytest.fail('clock acquired state lock'))
    monkeypatch.setattr(value.store, 'read', lambda *_args: pytest.fail('clock read private provider state'))
    assert value.request({'action': 'clock', 'run_id': IDENTIFIER}) == {
        'reference_ns': 123456789, 'boot_id': boot}
    assert value.network.applied == []
    for payload in ({'action': 'clock'}, {'action': 'clock', 'run_id': 'foreign'},
                    {'action': 'clock', 'run_id': IDENTIFIER, 'extra': True}):
        with pytest.raises(peer.FixtureError, match='fixture_request_invalid'):
            value.request(payload)


def test_network_plan_scope_source_routes_and_no_host_firewall(tmp_path):
    store = peer.Store(IDENTIFIER, root=tmp_path)
    store.directory(create=True)
    calls = []
    def execute(args, **kwargs):
        calls.append((args, kwargs))
        return b'[]'
    network = peer.Network(config(), store, execute=execute)
    network.preflight = lambda: None
    network._inode = lambda role: [1, peer.ROLES.index(role)]
    network._ifindex = lambda link: list(network.links.values()).index(link)
    network._namespace_links = lambda _role: {'lo': 1, 'uplink': 2}
    network.setup()
    for role, number in [('a', 241), ('b', 242)]:
        route = ['ip', 'netns', 'exec', network.names[role], 'ip', 'route', 'add', '172.16.135.80/32',
                 'via', f'169.254.{number}.1', 'dev', 'uplink', 'src', peer.ENDPOINTS[role]]
        assert (route, {'data': None}) in calls
        alias_index = next(i for i, (args, _) in enumerate(calls)
                           if args[-4:] == ['add', peer.ENDPOINTS[role] + '/32', 'dev', 'lo'])
        assert alias_index < next(i for i, (args, _) in enumerate(calls) if args == route)
    assert all(args[:3] == ['ip', 'netns', 'exec'] for args, _ in calls if 'nft' in args or 'sysctl' in args)
    assert not any('default' in args or 'delete' in args or 'replace' in args for args, _ in calls)
    policies = b'\n'.join(kw['data'] for args, kw in calls if 'nft' in args)
    assert b'iifname "wg-peer" oifname "target" ip daddr 1.1.1.1 masquerade' in policies
    assert b'policy drop' in policies


def test_debian_empty_namespace_listing_is_not_a_json_error(tmp_path, monkeypatch):
    monkeypatch.setattr(peer.Path, 'read_text', lambda _path: '1')
    calls = []
    def execute(arguments, **_kwargs):
        calls.append(arguments)
        return b'' if arguments == ['ip', '-j', 'netns', 'list'] else b'[]'
    network = peer.Network(config(), peer.Store(IDENTIFIER, root=tmp_path), execute=execute)
    network.preflight()
    assert calls[0] == ['ip', '-j', 'netns', 'list']


def test_resource_inode_change_is_never_adopted(tmp_path):
    store = peer.Store(IDENTIFIER, root=tmp_path)
    store.directory(create=True)
    network = peer.Network(config(), store)
    store.write('ownership.json', {'names': network.names, 'links': network.links,
                                   'inodes': {role: [1, 2] for role in peer.ROLES},
                                   'ifindexes': {role: 5 for role in peer.ROLES},
                                   'namespace_ifindexes': {role: {'wg-peer': 6} for role in peer.ROLES}})
    network._inode = lambda _role: [1, 3]
    network._ifindex = lambda _link: 5
    with pytest.raises(peer.FixtureError, match='fixture_resource_conflict'):
        network.validate_owned()


def test_replaced_same_name_wireguard_is_never_adopted(tmp_path):
    store = peer.Store(IDENTIFIER, root=tmp_path)
    store.directory(create=True)
    network = peer.Network(config(), store)
    store.write('ownership.json', {'names': network.names, 'links': network.links,
                                   'inodes': {role: [1, 2] for role in peer.ROLES},
                                   'ifindexes': {role: 5 for role in peer.ROLES},
                                   'namespace_ifindexes': {role: {'wg-peer': 6} for role in peer.ROLES}})
    network._inode = lambda _role: [1, 2]
    network._ifindex = lambda _link: 5
    network._namespace_links = lambda _role: {'wg-peer': 7}
    with pytest.raises(peer.FixtureError, match='fixture_resource_conflict'):
        network.validate_owned()


def test_dns_udp_tcp_framing_and_malformed_questions():
    query = struct.pack('!HHHHHH', 7, 0x100, 1, 0, 0, 0) + b'\x07example\x03com\x00\x00\x01\x00\x01'
    response = peer.dns_answer(query)
    assert response[:2] == query[:2] and response[-4:] == b'\x01\x01\x01\x01'
    assert peer.dns_answer(query + b'x') is None
    assert peer.dns_answer(query[:12] + b'\xc0\x0c\x00\x01\x00\x01') is None


def test_command_failure_redacts_output_and_private_stdin(monkeypatch):
    def failed(args, **kwargs):
        assert PRIVATE_A not in str(args)
        return SimpleNamespace(returncode=1, stdout=PRIVATE_A.encode(), stderr=b'synthetic secret sentinel')
    monkeypatch.setattr(peer.subprocess, 'run', failed)
    with pytest.raises(peer.FixtureError) as error:
        peer.command(['wg', 'setconf', 'wg-peer', '/dev/stdin'], data=PRIVATE_A.encode())
    assert str(error.value) == 'fixture_command_failed'


def test_namespace_services_refuse_host_namespace_before_bind(monkeypatch):
    monkeypatch.setattr(peer.Path, 'stat', lambda _path: SimpleNamespace(st_ino=42))
    monkeypatch.setattr(peer.socketserver, 'UDPServer', lambda *_a, **_kw: pytest.fail('host UDP bind'))
    with pytest.raises(peer.FixtureError, match='fixture_namespace_required'):
        peer.namespace_services('target')


def test_http_fixed_registration_contract_source_token_and_bounds(tmp_path, capsys):
    value = fixture(tmp_path)
    # A local-only ephemeral listener with injected test client IP; no LAN or VM.
    value.config['candidate_vm_address'] = '127.0.0.1'
    server = peer.RegistrationServer(value, address=('127.0.0.1', 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def request(body, *, token=None, path='/upstream', content_type='application/json'):
        connection = http.client.HTTPConnection(*server.server_address, timeout=2)
        try:
            connection.request('POST', path, body, {'Authorization': token or 'Bearer ' + value.config['token'],
                                                    'Content-Type': content_type})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()
    try:
        status, result = request(json.dumps({'action': 'mullvad_register', 'public_key': PUBLIC_A}))
        assert status == 200 and result['result']['pubkey'] == PUBLIC_A
        clock = json.dumps({'action': 'clock', 'run_id': IDENTIFIER})
        status, result = request(clock)
        assert status == 200 and set(result['result']) == {'reference_ns', 'boot_id'}
        assert type(result['result']['reference_ns']) is int and result['result']['reference_ns'] > 0
        assert peer.run_id(result['result']['boot_id']) == result['result']['boot_id']
        assert request(clock, token='Bearer denied')[0] == 403
        assert request('{"action":"clock","run_id":"foreign"}')[0] == 400
        assert request('{}', token='Bearer denied')[0] == 403
        assert request('{}', path='/arbitrary')[0] == 403
        assert request('x' * 4097)[0] == 400
        assert request('{"action":"pia_token","action":"mullvad_devices"}')[0] == 400
        assert request('{}', content_type='text/plain')[0] == 400
        value.config['candidate_vm_address'] = '172.16.135.80'
        assert request('{"action":"pia_token"}')[0] == 403
        assert request(clock)[0] == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert value.config['token'] not in str(capsys.readouterr())
    assert PRIVATE_A not in str(capsys.readouterr())


@pytest.mark.parametrize('role', ['peer', 'target'])
def test_namespace_udp_binds_query_destination_so_echo_and_dns_replies_preserve_source(monkeypatch, role):
    monkeypatch.setattr(peer.Path, 'stat', lambda path: SimpleNamespace(st_ino=42 if str(path) == '/proc/self/ns/net' else 43))
    servers = []
    class Server:
        def __init__(self, address, handler):
            self.server_address, self.handler = address, handler
            servers.append(self)
        def serve_forever(self):
            pass
    udp = []
    def udp_server(address, handler):
        server = Server(address, handler)
        udp.append(server)
        return server
    monkeypatch.setattr(peer.socketserver, 'UDPServer', udp_server)
    monkeypatch.setattr(peer.socketserver, 'TCPServer', Server)
    monkeypatch.setattr(peer.threading.Thread, 'start', lambda _thread: None)
    def finished(_event):
        raise peer.FixtureError('fixture_service_failed')
    monkeypatch.setattr(peer.threading.Event, 'wait', finished)
    with pytest.raises(peer.FixtureError, match='fixture_service_failed'):
        peer.namespace_services(role)
    expected = [(address, 53) for address in ('10.64.0.1', '10.65.0.1', '10.66.0.1')]
    if role == 'target':
        expected += [('1.1.1.1', port) for port in (53, 5666, 7777)]
    assert [server.server_address for server in udp] == expected
    for server in udp:
        sent = []
        transport = SimpleNamespace(sendto=lambda answer, client, sent=sent, server=server:
                                    sent.append((server.server_address, answer, client)))
        query = b'\x01\x02' + struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0) + b'\x01a\x00\x00\x01\x00\x01'
        body = query if server.server_address[1] == 53 else b'synthetic-d6-echo'
        server.handler((body, transport), ('10.77.0.2', 55000), server)
        assert sent == [(server.server_address, peer.dns_answer(query) if server.server_address[1] == 53 else body,
                         ('10.77.0.2', 55000))]


def test_catalog_selection_persists_only_public_response_choices_and_is_readback_verified(tmp_path):
    value = fixture(tmp_path)
    before = value.store.read('state.json')
    response = value.request({'action': 'select_catalog', 'mullvad': 'a', 'pia': 'b'})
    assert response == {'run_id': IDENTIFIER, 'catalogs': {'mullvad': ['a'], 'pia': ['b']}}
    restarted = peer.UpstreamFixture(value.config, value.store, value.network)
    assert restarted.request({'action': 'selected_catalog'}) == response
    assert [relay['hostname'] for relay in restarted.request({'action': 'mullvad_relays'})] == ['nl-ams-wg-a']
    assert [server['region']['id'] for server in restarted.request({'action': 'pia_catalog'})] == ['b']
    assert value.store.read('state.json') == before
    assert (value.store.path / 'catalogs.json').stat().st_mode & 0o777 == 0o600
    value.request({'action': 'select_catalog', 'mullvad': 'both', 'pia': 'both'})
    assert len(value.request({'action': 'mullvad_relays'})) == 2


def test_catalog_selection_rejects_wrong_fields_and_tampered_inventory_without_key_changes(tmp_path):
    value = fixture(tmp_path)
    for request in ({'action': 'select_catalog', 'mullvad': 'a', 'pia': 'other'},
                    {'action': 'select_catalog', 'mullvad': 'a', 'pia': 'b', 'command': 'unsafe'}):
        with pytest.raises(peer.FixtureError, match='fixture_request_invalid'):
            value.request(request)
    value.store.write('catalogs.json', {'mullvad': ['a', 'foreign'], 'pia': ['b']})
    with pytest.raises(peer.FixtureError, match='fixture_resource_conflict'):
        value.request({'action': 'pia_catalog'})
