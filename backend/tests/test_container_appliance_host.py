"""Operator preflight rejects unsafe hosts and altered Compose contracts."""
import copy
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('appliance_host', ROOT / 'scripts/check_docker_appliance_host.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
IMAGE = 'sha256:' + 'a' * 64


def configuration():
    return {'services': {'exitlane': {
        'image': IMAGE, 'platform': 'linux/amd64', 'read_only': True, 'init': True,
        'cap_add': ['NET_ADMIN'], 'cap_drop': ['ALL'],
        'security_opt': ['no-new-privileges:true'],
        'devices': [{'source': '/dev/net/tun', 'target': '/dev/net/tun'}],
        'volumes': [{'type': 'volume', 'source': 'exitlane-state', 'target': '/data'}],
        'networks': {'exitlane': None},
        'ports': [{'host_ip': '127.0.0.1', 'published': '8787', 'target': 8787, 'protocol': 'tcp'},
                  {'host_ip': '127.0.0.1', 'published': '51820', 'target': 51820, 'protocol': 'udp'}],
        'sysctls': {'net.ipv4.ip_forward': '1', 'net.ipv6.conf.all.forwarding': '0'},
    }}, 'networks': {'exitlane': {'driver': 'bridge', 'enable_ipv6': False}},
        'volumes': {'exitlane-state': {}}}


@pytest.mark.parametrize('section,field,value,error', [
    ('networks', 'driver', 'host', 'unsafe_compose_network'),
    ('networks', 'external', True, 'unsafe_compose_network'),
    ('networks', 'driver_opts', {'parent': 'eth0'}, 'unsafe_compose_network'),
    ('networks', 'enable_ipv6', True, 'unsafe_compose_network'),
    ('volumes', 'driver_opts', {'type': 'none', 'o': 'bind', 'device': '/'}, 'unsafe_compose_mount'),
    ('volumes', 'external', True, 'unsafe_compose_mount'),
    ('volumes', 'driver', 'foreign-plugin', 'unsafe_compose_mount'),
])
def test_host_network_and_indirect_host_mount_refused(section, field, value, error):
    config = configuration()
    name = 'exitlane' if section == 'networks' else 'exitlane-state'
    config[section][name][field] = value
    with pytest.raises(host.PreflightError, match=error):
        host.validate_compose(config, IMAGE, '127.0.0.1', '127.0.0.1')


@pytest.mark.parametrize('field,value', [
    ('security_opt', ['no-new-privileges:true', 'seccomp=unconfined']),
    ('device_cgroup_rules', ['a *:* rwm']),
    ('volumes_from', ['foreign']),
])
def test_extra_runtime_privilege_surfaces_refused(field, value):
    config = configuration()
    config['services']['exitlane'][field] = value
    with pytest.raises(host.PreflightError, match='unsafe_compose_runtime'):
        host.validate_compose(config, IMAGE, '127.0.0.1', '127.0.0.1')


def test_supported_host_and_minimal_compose():
    host.validate_host('28.1.2', {'OSType': 'linux', 'Architecture': 'x86_64', 'SecurityOptions': []}, 'v2.35.1')
    host.validate_compose(configuration(), IMAGE, '127.0.0.1', '127.0.0.1')


@pytest.mark.parametrize('version', ['27.5.1', '26.1.5', 'latest', '', '28;echo injected'])
def test_old_or_invalid_engine_refused(version):
    with pytest.raises(host.PreflightError, match='docker_engine_28_required'):
        host.validate_host(version, {'OSType': 'linux', 'Architecture': 'amd64'}, '2.35.1')


@pytest.mark.parametrize('facts,compose', [
    ({'OSType': 'windows', 'Architecture': 'amd64'}, '2.35.1'),
    ({'OSType': 'linux', 'Architecture': 'arm64'}, '2.35.1'),
    ({'OSType': 'linux', 'Architecture': 'amd64', 'SecurityOptions': ['name=rootless']}, '2.35.1'),
    ({'OSType': 'linux', 'Architecture': 'amd64'}, '1.29.2'),
])
def test_unsupported_host_or_compose_refused(facts, compose):
    with pytest.raises(host.PreflightError):
        host.validate_host('28.1.2', facts, compose)


@pytest.mark.parametrize('value', ['', '0.0.0.0', '::', '127.0.0.1:8787', 'host.example', '224.0.0.1'])
def test_implicit_or_broad_bind_refused(value):
    with pytest.raises(host.PreflightError):
        host.bind(value)


@pytest.mark.parametrize('change', [
    {'privileged': True}, {'network_mode': 'host'}, {'pid': 'host'}, {'ipc': 'host'},
    {'read_only': False}, {'cap_add': ['NET_ADMIN', 'SYS_ADMIN']},
    {'cap_add': ['NET_ADMIN', 'NET_RAW']}, {'cap_drop': []}, {'init': False},
    {'volumes': [{'type': 'bind', 'source': '/var/run/docker.sock', 'target': '/data'}]},
    {'devices': [{'source': '/dev', 'target': '/dev'}]},
    {'ports': [{'host_ip': '0.0.0.0', 'published': '8787', 'target': 8787, 'protocol': 'tcp'}]},
    {'sysctls': {'net.ipv4.ip_forward': '1', 'net.ipv6.conf.all.forwarding': '1'}},
])
def test_altered_privilege_mount_or_port_refused(change):
    value = copy.deepcopy(configuration())
    value['services']['exitlane'].update(change)
    with pytest.raises(host.PreflightError):
        host.validate_compose(value, IMAGE, '127.0.0.1', '127.0.0.1')


def test_moving_image_refused_before_docker_call(monkeypatch, capsys):
    monkeypatch.setattr(host, 'checked', lambda *args, **kwargs: pytest.fail('Docker must not run'))
    assert host.main(['--image', 'ghcr.io/example/exitlane:latest']) == 1
    assert 'appliance_preflight_failed' in capsys.readouterr().out


def test_host_preflight_only_executes_readonly_commands(monkeypatch, capsys):
    calls = []
    def execute(*args, **kwargs):
        calls.append(args)
        if args[0] == 'version':
            return '28.1.2'
        if args[0] == 'info':
            return {'OSType': 'linux', 'Architecture': 'x86_64'}
        if args[:2] == ('compose', 'version'):
            return {'version': '2.35.1'}
        if args[0] == 'image':
            return [{'Id': IMAGE, 'Architecture': 'amd64', 'Os': 'linux', 'Config': {'Labels': {
                'org.exitlane.runtime': 'container', 'org.exitlane.schema': '1:1',
                'org.exitlane.support': 'experimental', 'org.opencontainers.image.revision': 'a' * 40}}}]
        return configuration()
    monkeypatch.setattr(host, 'checked', execute)
    assert host.main(['--image', IMAGE]) == 0
    assert 'PASS' in capsys.readouterr().out
    assert len(calls) == 5 and all(c[0] in {'version', 'info', 'compose', 'image'} for c in calls)
