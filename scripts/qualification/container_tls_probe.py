"""Loopback TLS qualification using installed production provider clients.

Only endpoints and test-process trust inputs change. No production verifier is
replaced; certificate rejection must retain its real OpenSSL verification code.
Private fixture material exists only inside a temporary directory and is removed.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.server
import json
import os
import ssl
import sys
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from exitlane.providers import mullvad, pia_api

CLIENTS = ("mullvad", "pia_public", "pia_pinned")
CONDITIONS = ("valid", "unknown_ca", "wrong_hostname", "expired")
VERIFY_CODES = {"unknown_ca": 20, "wrong_hostname": 62, "expired": 10}
PUBLIC_BODY = {"synthetic": True}
PUBLIC_KEY = base64.b64encode(b"s" * 32).decode()
PINNED_BODY = {
    "status": "OK",
    "peer_ip": "10.2.0.2/32",
    "server_key": PUBLIC_KEY,
    "server_port": 51820,
    "dns_servers": ["10.2.0.1"],
}
SCOPE = "synthetic loopback TLS only; no live provider, routing, packet, host or support acceptance"


class ProbeError(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise ProbeError(code)


def certificate_codes(error):
    """Inspect private exception chains, including suppressed PIA context.

    No message matching: timeout, refused connection and unrelated wrapper errors
    can never substitute for a real certificate-verification error.
    """
    pending, seen, codes = [error], set(), []
    while pending and len(seen) < 16:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, ssl.SSLCertVerificationError):
            codes.append(item.verify_code)
        for name in ("__cause__", "__context__", "reason"):
            nested = getattr(item, name, None)
            if isinstance(nested, BaseException):
                pending.append(nested)
    return codes


def validate_failure(client, condition, error, before, after):
    require(condition != "valid", "tls_positive_control_failed")
    expected_type = (
        mullvad.MullvadApiError if client == "mullvad" else pia_api.PiaApiError
    )
    require(type(error) is expected_type, "tls_unexpected_client_failure")
    require(
        error.code == str(error) == "provider_api_unavailable",
        "tls_unsafe_error_projection",
    )
    require(
        certificate_codes(error) == [VERIFY_CODES[condition]],
        "tls_certificate_rejection_unproven",
    )
    require(before == after, "tls_invalid_certificate_received_http")


def private_file(path, value):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)


def authority(now, common_name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def leaf(now, condition, authority_key, ca):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostname = "wrong.invalid" if condition == "wrong_hostname" else "localhost"
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(
            now + datetime.timedelta(days=-1 if condition == "expired" else 1)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                authority_key.public_key()
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(authority_key, hashes.SHA256())
    )
    return key, certificate


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.received += 1
        body = json.dumps(
            PINNED_BODY if self.path.startswith("/addKey?") else PUBLIC_BODY
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Server(http.server.HTTPServer):
    allow_reuse_address = True

    def __init__(self, context):
        super().__init__(("127.0.0.1", 1337), Handler)
        self.received = 0
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def handle_error(self, *_args):
        pass


def request(client):
    if client == "mullvad":
        return mullvad.MullvadApi()._request_sync("/qualification")
    if client == "pia_public":
        return json.loads(
            pia_api.PiaApi()._public_request(
                "https://localhost:1337/qualification", maximum=1024
            )
        )
    if client == "pia_pinned":
        server = pia_api.PiaServer(
            "synthetic", "Synthetic", "NL", "localhost", "127.0.0.1", "127.0.0.1"
        )
        value = pia_api.PiaApi()._add_key_sync(
            server, "synthetic-qualification-token", PUBLIC_KEY
        )
        return {
            "synthetic": value.peer_ip == "10.2.0.2/32"
            and value.server_key == PUBLIC_KEY
            and value.server_port == 51820
            and value.dns_address == "10.2.0.1"
        }
    raise ProbeError("tls_unknown_client")


def qualify(checks):
    environment = dict(os.environ)
    original_origin, original_ca = mullvad.API_ORIGIN, pia_api.CA_PATH
    # Qualification-only endpoint/trust selection, never a service trust-store edit.
    os.environ.clear()
    os.environ.update({"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp"})
    try:
        with tempfile.TemporaryDirectory(prefix="exitlane-tls-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            now = datetime.datetime.now(datetime.timezone.utc)
            ca_key, ca = authority(now, "ExitLane synthetic trusted CA")
            _, unrelated_ca = authority(now, "ExitLane synthetic unrelated CA")
            trusted, unrelated = root / "trusted.pem", root / "unrelated.pem"
            private_file(trusted, ca.public_bytes(serialization.Encoding.PEM))
            private_file(
                unrelated, unrelated_ca.public_bytes(serialization.Encoding.PEM)
            )
            (root / "empty-cas").mkdir(mode=0o700)
            for condition in CONDITIONS:
                key, certificate = leaf(now, condition, ca_key, ca)
                key_file, certificate_file = (
                    root / (condition + ".key"),
                    root / (condition + ".pem"),
                )
                private_file(
                    key_file,
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    ),
                )
                private_file(
                    certificate_file,
                    certificate.public_bytes(serialization.Encoding.PEM),
                )
                trust = unrelated if condition == "unknown_ca" else trusted
                os.environ["SSL_CERT_FILE"] = str(trust)
                os.environ["SSL_CERT_DIR"] = str(root / "empty-cas")
                pia_api.CA_PATH = trust
                mullvad.API_ORIGIN = "https://localhost:1337"
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certificate_file, key_file)
                with Server(context) as server:
                    worker = threading.Thread(
                        target=server.serve_forever,
                        kwargs={"poll_interval": 0.02},
                        daemon=True,
                    )
                    worker.start()
                    try:
                        for client in CLIENTS:
                            before = server.received
                            try:
                                result = request(client)
                            except Exception as error:  # noqa: BLE001 - unknown failures must be rejected
                                validate_failure(
                                    client, condition, error, before, server.received
                                )
                            else:
                                require(
                                    condition == "valid",
                                    "tls_invalid_certificate_accepted",
                                )
                                require(
                                    result == PUBLIC_BODY
                                    and server.received == before + 1,
                                    "tls_positive_control_failed",
                                )
                            checks.append(
                                {
                                    "client": client,
                                    "condition": condition,
                                    "result": "PASS",
                                    "http_requests": server.received - before,
                                    "verify_code": VERIFY_CODES.get(condition),
                                }
                            )
                    finally:
                        server.shutdown()
                        worker.join(timeout=5)
                        require(not worker.is_alive(), "tls_server_cleanup_failed")
    finally:
        mullvad.API_ORIGIN, pia_api.CA_PATH = original_origin, original_ca
        os.environ.clear()
        os.environ.update(environment)


def main():
    checks = []
    result = {
        "type": "provider-tls-loopback",
        "scope": SCOPE,
        "checks": checks,
        "openssl": ssl.OPENSSL_VERSION,
        "python": sys.version.split()[0],
        "clients_sha256": {
            name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for name, module in (("mullvad", mullvad), ("pia_api", pia_api))
        },
    }
    try:
        qualify(checks)
    except ProbeError as error:
        # Preserve the failed-positive-control distinction without raw exceptions.
        code = (
            "tls_positive_control_failed"
            if str(error) == "tls_positive_control_failed"
            else "tls_probe_failed"
        )
        result.update({"result": "FAIL", "code": code})
        print(json.dumps(result, sort_keys=True))
        return 1
    except Exception:  # noqa: BLE001 - terminal fixed-error output boundary
        # No certificate, key, request, arbitrary exception or transport output.
        result.update({"result": "FAIL", "code": "tls_probe_failed"})
        print(json.dumps(result, sort_keys=True))
        return 1
    result.update({"result": "PASS", "code": None})
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
