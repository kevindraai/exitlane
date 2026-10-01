#!/usr/bin/env python3
"""Resumable D6 restart component driver; never a complete D6 support claim.

Inputs are root-only JSON files: HostHarness configuration; captures containing
{run_id,captures,candidate_epochs}; session containing {run_id,cookie}. Run one
next stage, or all pending stages. Interrupted/failed rows require inspection;
they are never retried automatically. No credentials enter argv/environment.

Continuous packet acceptance uses the existing independent external witnesses.
Optional candidate namespace observers MUST stop and reach dead/failed before
any restart preparation: otherwise their namespace FD could keep old interfaces
alive artificially. Candidate host observations remain supplemental epochs; a
reboot gap is explicit, never accepted as zero traffic. Reboot requires the
coordinator's owned persistent archive helper when such an epoch is present.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from pathlib import Path

from container_host import HostHarness, QualificationError

STAGES = ('parent_crash', 'container_restart', 'daemon_restart', 'daemon_live_restore', 'host_reboot')
EXTERNAL_ROLES = {'wan', 'client', 'provider-a', 'provider-b', 'target'}
OUTSTANDING = ('worker_crash_external_receipt', 'pia_runtime', 'proton_runtime',
               'provider_failure_switch_rollback', 'dns_failure_udp_tcp', 'ipv6_attempts',
               'backup_restore', 'container_recreation_image_replacement', 'docker_bridge_recreation')
MAX_INPUT = 128 * 1024
MAX_RECEIPT = 128 * 1024 * 1024
_ROOT_UID = 0  # Tests substitute their fixture UID; no CLI/config override exists.


class MatrixError(RuntimeError):
    pass


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise MatrixError('matrix_input_invalid')
        value[key] = item
    return value


def private_json(path, *, maximum=MAX_INPUT):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        facts = os.fstat(descriptor)
        if (not stat.S_ISREG(facts.st_mode) or facts.st_uid != _ROOT_UID
                or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_size > maximum):
            raise MatrixError('matrix_input_unsafe')
        with os.fdopen(descriptor, 'rb') as source:
            descriptor = None
            raw = source.read(maximum + 1)
        if len(raw) > maximum:
            raise MatrixError('matrix_input_unsafe')
        value = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(value, dict):
            raise MatrixError('matrix_input_invalid')
        return value
    except (OSError, ValueError, UnicodeError):
        raise MatrixError('matrix_input_invalid') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def validate_handles(value, identifier):
    if not isinstance(value, dict) or set(value) != {'run_id', 'captures', 'candidate_epochs'} or value['run_id'] != identifier:
        raise MatrixError('matrix_handles_invalid')
    captures, epochs = value['captures'], value['candidate_epochs']
    if not isinstance(captures, list) or not isinstance(epochs, list) or len(captures) != 5 or len(epochs) > 2:
        raise MatrixError('matrix_handles_invalid')
    if any(not isinstance(handle, dict) for handle in captures + epochs):
        raise MatrixError('matrix_handles_invalid')
    if {handle.get('role') for handle in captures} != EXTERNAL_ROLES:
        raise MatrixError('matrix_handles_invalid')
    prefix = 'ed6-' + identifier.replace('-', '')[:10] + '-'
    names = {'client': prefix + 'client', 'provider-a': prefix + 'a',
             'provider-b': prefix + 'b', 'target': prefix + 'target', 'wan': None}
    units = set()
    for handle in captures + epochs:
        if handle.get('kind') != 'capture':
            raise MatrixError('matrix_handles_invalid')
        root = handle.get('root')
        unit = handle.get('unit')
        if (not isinstance(root, str) or re.fullmatch('/run/exitlane-d6-[0-9a-f]{32}', root) is None
                or unit != 'exitlane-d6-capture-' + root.rsplit('-', 1)[1] + '.service' or unit in units):
            raise MatrixError('matrix_handles_invalid')
        units.add(unit)
        if handle in captures:
            if handle.get('host', 'peer') != 'peer' or handle.get('namespace') != names[handle['role']]:
                raise MatrixError('matrix_handles_invalid')
        elif (handle.get('host') != 'candidate' or handle.get('role') not in {'candidate-host', 'candidate-namespace'}
              or type(handle.get('namespace')) is not bool
              or handle['namespace'] != (handle['role'] == 'candidate-namespace')):
            raise MatrixError('matrix_handles_invalid')
    if len({handle['role'] for handle in epochs}) != len(epochs):
        raise MatrixError('matrix_handles_invalid')
    return captures, epochs


def session_cookie(value, identifier):
    if (not isinstance(value, dict) or set(value) != {'run_id', 'cookie'} or value['run_id'] != identifier
            or not isinstance(value['cookie'], str)
            or re.fullmatch('exitlane_session=[A-Za-z0-9_-]{20,256}', value['cookie']) is None):
        raise MatrixError('matrix_session_invalid')
    return value['cookie']


class Receipts:
    def __init__(self, root):
        self.root = Path(root)
        try:
            self.root.mkdir(mode=0o700, exist_ok=True)
            facts = self.root.lstat()
            if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != _ROOT_UID or stat.S_IMODE(facts.st_mode) != 0o700:
                raise MatrixError('matrix_receipts_unsafe')
        except OSError:
            raise MatrixError('matrix_receipts_unsafe') from None

    def write(self, name, value):
        if re.fullmatch(r'[a-z][a-z0-9_-]{0,80}\.json', name) is None:
            raise MatrixError('matrix_receipts_unsafe')
        temporary = self.root / ('.' + name + '.' + secrets.token_hex(8))
        target = self.root / name
        try:
            if os.path.lexists(target):
                private_json(target, maximum=MAX_RECEIPT)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            size = 0
            digest = hashlib.sha256()
            with os.fdopen(fd, 'wb') as destination:
                for part in json.JSONEncoder(sort_keys=True, allow_nan=False).iterencode(value):
                    raw = part.encode()
                    size += len(raw)
                    if size > MAX_RECEIPT:
                        raise MatrixError('matrix_receipts_too_large')
                    digest.update(raw)
                    destination.write(raw)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, target)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return {'filename': name, 'sha256': digest.hexdigest(), 'bytes': size}
        except (OSError, ValueError, TypeError):
            raise MatrixError('matrix_receipts_failed') from None
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()

    @contextlib.contextmanager
    def lock(self):
        fd = None
        try:
            fd = os.open(self.root / 'matrix.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            facts = os.fstat(fd)
            if not stat.S_ISREG(facts.st_mode) or facts.st_uid != _ROOT_UID or stat.S_IMODE(facts.st_mode) != 0o600:
                raise MatrixError('matrix_receipts_unsafe')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except OSError:
            raise MatrixError('matrix_already_running') from None
        finally:
            if fd is not None:
                os.close(fd)


class RestartMatrix:
    def __init__(self, harness, receipts, captures, epochs):
        self.harness, self.receipts, self.captures = harness, receipts, captures
        self.initial_epochs = epochs
        self.state = None

    def _open(self):
        identity = {'run_id': self.harness.config['run_id'], 'image': self.harness.config['image'],
                    'revision': self.harness.config['revision'],
                    'configuration_sha256': hashlib.sha256(json.dumps(self.harness.config, sort_keys=True).encode()).hexdigest(),
                    'handles_sha256': hashlib.sha256(json.dumps(self.captures, sort_keys=True).encode()).hexdigest()}
        path = self.receipts.root / 'matrix.json'
        if os.path.lexists(path):
            state = private_json(path)
            if (set(state) != {'identity', 'candidate_epochs', 'stages', 'other_components', 'd6', 'production_support'}
                    or state.get('identity') != identity or not isinstance(state.get('stages'), dict)
                    or set(state['stages']) != set(STAGES)
                    or not all(isinstance(row, dict) for row in state['stages'].values())
                    or state.get('other_components') != {name: 'OUTSTANDING' for name in OUTSTANDING}
                    or state.get('d6') != 'OUTSTANDING' or state.get('production_support') is not False):
                raise MatrixError('matrix_resume_identity_mismatch')
            validate_handles({'run_id': identity['run_id'], 'captures': self.captures,
                              'candidate_epochs': state['candidate_epochs']}, identity['run_id'])
            if any(row.get('status') not in {'PENDING', 'PACKET_COMPONENT_PASS'} for row in state['stages'].values()):
                raise MatrixError('matrix_failed_or_interrupted_requires_inspection')
            self.state = state
        else:
            self.state = {'identity': identity, 'candidate_epochs': self.initial_epochs,
                          'stages': {name: {'status': 'PENDING'} for name in STAGES},
                          'other_components': {name: 'OUTSTANDING' for name in OUTSTANDING},
                          'd6': 'OUTSTANDING', 'production_support': False}
            self.receipts.write('matrix.json', self.state)

    def _authenticated(self):
        value = self.harness.api('/api/auth/session')
        if value.get('status') != 200 or value.get('body', {}).get('authenticated') is not True:
            raise MatrixError('matrix_authentication_required')

    def _epochs_snapshot(self, stage, suffix):
        values = []
        for handle in self.state['candidate_epochs']:
            values.append({'handle': handle, 'evidence': self.harness.evidence(handle)})
        return self.receipts.write(stage + '-' + suffix + '-epochs.json', {'epochs': values})

    def _stop_namespace_epochs(self, phase):
        retained = []
        for handle in self.state['candidate_epochs']:
            if handle['namespace']:
                self.harness.control(handle, phase, stop=True)
                self.harness.wait(lambda handle=handle: self.harness.command(self.harness.candidate,
                    ['systemctl', 'show', handle['unit'], '--property=SubState', '--value'])['stdout'].strip()
                    in {'dead', 'failed'}, phase + '-namespace-observer-stopped', timeout=15)
            else:
                retained.append(handle)
        self.state['candidate_epochs'] = retained

    def _epoch_ready(self, handle, phase):
        try:
            value = self.harness.evidence(handle)
            return value.get('phase') == phase and bool(value.get('captures')) and all(
                facts.get('ready') is True and facts.get('polls', 0) >= 2 for facts in value['captures'].values())
        except (QualificationError, OSError, ValueError, KeyError, TypeError):
            return False

    def _stage(self, stage):
        phase = 'm-' + stage.replace('_', '-') + '-' + secrets.token_hex(4)
        row = {'status': 'RUNNING', 'phase': phase, 'fault': stage, 'started_ns': time.time_ns(),
               'candidate_namespace_gap': 'not_started'}
        self.state['stages'][stage] = row
        self.receipts.write('matrix.json', self.state)
        h = self.harness
        h.last_packet_evidence = None
        had_namespace = any(value['namespace'] for value in self.state['candidate_epochs'])
        had_host = any(not value['namespace'] for value in self.state['candidate_epochs'])
        try:
            h.preflight()
            self._authenticated()
            if h.config.get('allow_host_restart') is not True:
                raise MatrixError('matrix_host_fault_not_authorized')
            row['before_network'] = self.receipts.write(stage + '-before-network.json', h.network_snapshot())
            row['before_epochs'] = self._epochs_snapshot(stage, 'before')
            self._stop_namespace_epochs(phase)
            row['candidate_namespace_gap'] = ('observer stopped before fault to release namespace FD'
                                              if had_namespace else 'not_configured')
            # This may restart Docker, but never occurs within packet pressure.
            if stage in {'daemon_restart', 'daemon_live_restore'}:
                h.configure_daemon_mode(stage == 'daemon_live_restore')
                self._authenticated()
                row['daemon_mode_preparation'] = {'live_restore_enabled': stage == 'daemon_live_restore',
                                                   'outside_measured_pressure': True}
            for handle in self.state['candidate_epochs']:
                h.control(handle, phase)
            if stage == 'host_reboot' and had_host:
                archive = getattr(h, 'archive_candidate_capture', None)
                if archive is None:
                    raise MatrixError('matrix_reboot_archive_required')
                row['before_reboot_archives'] = [archive(handle) for handle in self.state['candidate_epochs']]
            self.receipts.write('matrix.json', self.state)
            # HostHarness owns pressure, the actual fault, recovery and complete
            # packet validation. Supplemental epochs cannot replace that proof.
            result = h.packet_phase(phase, self.captures, fault=stage)
            if (not isinstance(result, dict) or result.get('receipt', {}).get('accepted') is not True
                    or result['receipt'].get('phase') != phase):
                raise MatrixError('matrix_packet_acceptance_unproven')
            row['packet_evidence'] = self.receipts.write(stage + '-packets.json', result)
            row['after_network'] = self.receipts.write(stage + '-after-network.json', h.network_snapshot())
            self._authenticated()
            if stage == 'host_reboot':
                self.state['candidate_epochs'] = []  # Old /run epoch is lost, not a zero.
                if had_host:
                    self.state['candidate_epochs'].append(h.candidate_capture(namespace=False))
            if had_namespace:
                self.state['candidate_epochs'].append(h.candidate_capture(namespace=True))
            for handle in self.state['candidate_epochs']:
                h.control(handle, phase)
                h.wait(lambda handle=handle: self._epoch_ready(handle, phase),
                       phase + '-candidate-epoch-ready', timeout=20)
            row['after_epochs'] = self._epochs_snapshot(stage, 'after')
            row['harness_metadata'] = self.receipts.write(stage + '-metadata.json', {'receipts': h.receipts})
            row.update(status='PACKET_COMPONENT_PASS', completed_ns=time.time_ns())
            self.receipts.write('matrix.json', self.state)
        except BaseException:  # noqa: BLE001 -- preserve interrupted evidence, never stringify private errors
            row.update(status='FAILED', completed_ns=time.time_ns(), error='matrix_stage_failed')
            evidence = getattr(h, 'last_packet_evidence', None)
            if evidence is not None:
                row['failed_packet_evidence'] = self.receipts.write(stage + '-failed-packets.json', evidence)
            else:
                row['packet_evidence_unavailable'] = True
            row['harness_metadata'] = self.receipts.write(stage + '-metadata.json', {'receipts': h.receipts})
            self.receipts.write('matrix.json', self.state)
            raise MatrixError('matrix_stage_failed') from None

    def run(self, stage='next'):
        if stage not in (*STAGES, 'next', 'all'):
            raise MatrixError('matrix_stage_invalid')
        with self.receipts.lock():
            self._open()
            pending = [name for name in STAGES if self.state['stages'][name]['status'] == 'PENDING']
            if stage in STAGES and (not pending or stage != pending[0]):
                raise MatrixError('matrix_stage_not_next')
            for selected in pending if stage == 'all' else pending[:1]:
                self._stage(selected)
            return {'result': 'PARTIAL', 'd6': 'OUTSTANDING', 'production_support': False,
                    'run_id': self.harness.config['run_id'],
                    'stages': {name: value['status'] for name, value in self.state['stages'].items()},
                    'other_components': self.state['other_components']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--captures', type=Path, required=True)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--receipts-dir', type=Path, required=True)
    parser.add_argument('--stage', choices=(*STAGES, 'next', 'all'), default='next')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print('matrix_root_required', file=sys.stderr)
        return 77
    try:
        h = HostHarness(private_json(args.config))
        captures, epochs = validate_handles(private_json(args.captures), h.config['run_id'])
        h.cookie = session_cookie(private_json(args.session), h.config['run_id'])
        runner = RestartMatrix(h, Receipts(args.receipts_dir), captures, epochs)
        print(json.dumps(runner.run(args.stage), sort_keys=True))
        return 0
    except (MatrixError, QualificationError, OSError, ValueError, TypeError, KeyError):
        print('matrix_failed_inspect_private_receipts', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
