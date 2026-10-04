#!/usr/bin/env python3
"""Read-only operator preflight for the v1 D5 Compose surface."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / 'docker/compose.appliance.yml'
IMMUTABLE = re.compile(r'(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64})\Z')


class PreflightError(RuntimeError):
    pass


def checked(*arguments, environment=None):
    try:
        result = subprocess.run(['docker', *arguments], capture_output=True, text=True,
                                timeout=15, check=False, env=environment)
        if result.returncode:
            raise PreflightError('docker_preflight_command_failed')
        return json.loads(result.stdout)
    except (OSError, TimeoutError, subprocess.TimeoutExpired, ValueError):
        raise PreflightError('docker_preflight_command_failed') from None


def bind(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise PreflightError('explicit_ipv4_bind_required') from None
    if address.version != 4 or address.is_unspecified or address.is_multicast:
        raise PreflightError('explicit_ipv4_bind_required')
    return str(address)


def validate_host(version, info, compose_version):
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9._-]+)?', version)
    if match is None or int(match[1]) < 28:
        raise PreflightError('docker_engine_28_required')
    if not isinstance(compose_version, str) or not re.match(r'^v?2\.\d+\.\d+', compose_version):
        raise PreflightError('compose_v2_required')
    if (info.get('OSType') != 'linux' or info.get('Architecture') not in {'x86_64', 'amd64'}
            or any('rootless' in value for value in info.get('SecurityOptions', []))):
        raise PreflightError('rootful_linux_amd64_required')


def validate_compose(configuration, image, management, ingress):
    services = configuration.get('services', {})
    if set(services) != {'exitlane'}:
        raise PreflightError('unexpected_compose_service')
    service = services['exitlane']
    if (service.get('image') != image or service.get('privileged', False)
            or any(service.get(field) for field in ('network_mode', 'pid', 'ipc', 'userns_mode',
                                                  'entrypoint', 'command', 'cgroup_parent'))
            or not service.get('read_only') or not service.get('init')
            or service.get('cap_add') != ['NET_ADMIN'] or service.get('cap_drop') != ['ALL']
            or service.get('platform') != 'linux/amd64'
            or service.get('security_opt') != ['no-new-privileges:true']
            or service.get('device_cgroup_rules') or service.get('volumes_from')):
        raise PreflightError('unsafe_compose_runtime')
    networks = configuration.get('networks', {})
    if (set(service.get('networks', {})) != {'exitlane'} or set(networks) != {'exitlane'}
            or networks['exitlane'].get('driver') != 'bridge'
            or networks['exitlane'].get('enable_ipv6') is not False
            or any(networks['exitlane'].get(field) for field in ('external', 'driver_opts', 'ipam'))):
        raise PreflightError('unsafe_compose_network')
    volumes = service.get('volumes', [])
    if (len(volumes) != 1 or volumes[0].get('type') != 'volume'
            or volumes[0].get('target') != '/data' or volumes[0].get('source') != 'exitlane-state'):
        raise PreflightError('unsafe_compose_mount')
    definitions = configuration.get('volumes', {})
    if (set(definitions) != {'exitlane-state'}
            or definitions['exitlane-state'].get('driver', 'local') != 'local'
            or any(definitions['exitlane-state'].get(field) for field in ('external', 'driver_opts'))):
        raise PreflightError('unsafe_compose_mount')
    devices = service.get('devices', [])
    if len(devices) != 1:
        raise PreflightError('unsafe_compose_device')
    device = devices[0]
    if isinstance(device, str):
        valid_device = device in {'/dev/net/tun:/dev/net/tun', '/dev/net/tun:/dev/net/tun:rwm'}
    else:
        valid_device = device.get('source') == device.get('target') == '/dev/net/tun'
    if not valid_device:
        raise PreflightError('unsafe_compose_device')
    published = service.get('ports', [])
    ports = {(item.get('host_ip'), str(item.get('published')), item.get('target'),
              item.get('protocol')) for item in published}
    if len(published) != 2 or ports != {(management, '8787', 8787, 'tcp'), (ingress, '51820', 51820, 'udp')}:
        raise PreflightError('unsafe_compose_ports')
    sysctls = service.get('sysctls', {})
    if (str(sysctls.get('net.ipv4.ip_forward')) != '1'
            or str(sysctls.get('net.ipv6.conf.all.forwarding')) != '0'
            or set(sysctls) - {'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding',
                               'net.ipv6.conf.default.forwarding', 'net.ipv4.ping_group_range'}):
        raise PreflightError('unsafe_compose_sysctls')


def validate_existing_resources(configuration):
    for kind, section, key in (('volume', 'volumes', 'exitlane-state'),
                               ('network', 'networks', 'exitlane')):
        name = configuration[section][key].get('name')
        if not isinstance(name, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name) is None:
            raise PreflightError('resolved_resource_name_required')
        try:
            listed = subprocess.run(['docker', kind, 'ls', '--quiet', '--filter',
                                     'name=^' + re.escape(name) + '$'], capture_output=True,
                                    text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise PreflightError('docker_preflight_command_failed') from None
        if listed.returncode:
            raise PreflightError('docker_preflight_command_failed')
        if not listed.stdout.strip():
            continue  # Compose may create the canonical private resource.
        if kind == 'volume' and listed.stdout.strip() != name:
            raise PreflightError('docker_resource_inventory_invalid')
        facts = checked(kind, 'inspect', name)[0]
        if kind == 'volume':
            if facts.get('Driver') != 'local' or facts.get('Options') or facts.get('Scope') != 'local':
                raise PreflightError('unsafe_existing_volume')
        elif (facts.get('Driver') != 'bridge' or facts.get('Options') or facts.get('Internal')
              or facts.get('EnableIPv6') or facts.get('Scope') != 'local'):
            raise PreflightError('unsafe_existing_network')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default=os.getenv('EXITLANE_IMAGE', ''))
    parser.add_argument('--management-bind', default=os.getenv('EXITLANE_MANAGEMENT_BIND', '127.0.0.1'))
    parser.add_argument('--ingress-bind', default=os.getenv('EXITLANE_INGRESS_BIND', '127.0.0.1'))
    args = parser.parse_args(argv)
    try:
        if IMMUTABLE.fullmatch(args.image) is None:
            raise PreflightError('immutable_image_identity_required')
        management, ingress = bind(args.management_bind), bind(args.ingress_bind)
        version = checked('version', '--format', '{{json .Server.Version}}')
        info = checked('info', '--format', '{{json .}}')
        compose_version = checked('compose', 'version', '--format', 'json').get('version')
        validate_host(version, info, compose_version)
        image = checked('image', 'inspect', args.image)[0]
        labels = image.get('Config', {}).get('Labels', {})
        if (image.get('Architecture') != 'amd64' or image.get('Os') != 'linux'
                or labels.get('org.exitlane.runtime') != 'container'
                or labels.get('org.exitlane.schema') != '1:1'
                or labels.get('org.exitlane.support') != 'v1'
                or re.fullmatch(r'[0-9a-f]{40}', labels.get('org.opencontainers.image.revision', '')) is None):
            raise PreflightError('appliance_image_contract_required')
        environment = dict(os.environ, EXITLANE_IMAGE=args.image,
                           EXITLANE_MANAGEMENT_BIND=management, EXITLANE_INGRESS_BIND=ingress)
        config = checked('compose', '-f', str(COMPOSE), 'config', '--format', 'json',
                         environment=environment)
        validate_compose(config, args.image, management, ingress)
        validate_existing_resources(config)
        print(json.dumps({'preflight': 'PASS', 'support': 'v1', 'engine': version,
                          'image': image['Id'], 'management_bind': management, 'ingress_bind': ingress}))
        return 0
    except PreflightError as error:
        print('appliance_preflight_failed: ' + str(error))
        return 1
    except (KeyError, TypeError, IndexError):
        print('appliance_preflight_failed')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
