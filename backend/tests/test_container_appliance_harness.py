"""Qualification transport retains authentication headers and bounds failures."""
import http.server
import importlib.util
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'appliance_harness', ROOT / 'scripts/qualification/container_appliance.py')
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


def test_http_probe_preserves_all_cookies_and_selects_live_session():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for cookie in ('exitlane_session=; Max-Age=0',
                           'exitlane_mfa_challenge=synthetic-challenge; Secure',
                           'exitlane_session=synthetic-session; Secure'):
                self.send_header('Set-Cookie', cookie)
            self.end_headers()
            self.wfile.write(b'{"ready":true}')

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        result = subprocess.run([sys.executable, '-c', harness.HTTP],
                                input=json.dumps({'address': '127.0.0.1',
                                                  'port': server.server_port, 'path': '/'}),
                                capture_output=True, text=True, timeout=10, check=True)
        response = json.loads(result.stdout)
        assert response['status'] == 200 and response['body'] == {'ready': True}
        assert len(response['cookies']) == 3
        assert harness.ApplianceHarness.cookie(response) == 'exitlane_session=synthetic-session'
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()


def test_deleted_authentication_cookies_cannot_pass_gate():
    with pytest.raises(RuntimeError, match='live synthetic authentication cookie missing'):
        harness.ApplianceHarness.cookie({'cookies': ['exitlane_session=; Max-Age=0']})


def test_docker_error_does_not_disclose_captured_child_material(monkeypatch):
    material = 'synthetic-private-fixture'
    monkeypatch.setattr(harness.subprocess, 'run', lambda *_args, **_kwargs:
                        subprocess.CompletedProcess(['docker'], 1, material, material))
    with pytest.raises(RuntimeError) as error:
        harness.ApplianceHarness.docker('inspect', 'owned-fixture')
    assert material not in str(error.value)


def test_http_credentials_use_stdin_not_process_arguments():
    instance = object.__new__(harness.ApplianceHarness)
    calls = []

    def python(name, source, *, data):
        calls.append((name, source, data))
        return subprocess.CompletedProcess([], 0, '{"status":200}', '')

    instance.python = python
    instance.request('owned-client', '192.0.2.1', '/api/auth/login', method='POST',
                     body={'password': 'synthetic-password'}, cookie='synthetic-cookie')
    assert 'synthetic-password' not in calls[0][1]
    assert 'synthetic-cookie' not in calls[0][1]
    assert json.loads(calls[0][2])['body']['password'] == 'synthetic-password'
