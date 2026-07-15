"""Closes the remaining ~6% uncovered signer error branches.

Every line below maps to a real, observed coverage gap (verified with
``pytest --cov --cov-report=term-missing`` prior to writing this file):

  client.py
    67  AttestedCapture.to_dict happy path (dict shape + "valid": True)
    84  CaptureClient ctor rejects neither sock_path nor (host, port)
    100 CaptureClient.capture raises RuntimeError on a {"error": ...} response
    154 client._recv_json raises on a truncated (sub-4-byte) frame header
    160 client._recv_json raises on a truncated frame body
  service.py
    37  SigningService.public_key property
    83  serve_path finally: unlink existing socket up front
    96  serve_path finally: srv.close()
    97  serve_path finally: unlink socket on teardown
    98  (guarded unlink — covered by the teardown path above)
    111 serve_tcp except branch (bad request over TCP)
    112 serve_tcp error frame sent to client
    113 serve_tcp finally: srv.close()
    114 (finally block — covered above)
    124 service._recv_json raises on truncated frame header
    130 service._recv_json raises on truncated frame body
"""
from __future__ import annotations

import os
import queue
import socket as _socket
import struct
import threading

import pytest

from provenance_gate_signer import CaptureClient, SigningService, generate_keypair
from provenance_gate_signer.client import _recv_json as _client_recv_json
from provenance_gate_signer.client import _send_json
from provenance_gate_signer.keys import sign, verify
from provenance_gate_signer.service import _recv_json as _service_recv_json


@pytest.fixture
def keypair():
    priv, pub = generate_keypair()
    return priv, pub


def test_attested_capture_to_dict_shape():
    # client.py:67 — the serialised dict is what gets written to disk / shown
    # to an auditor; its shape and "valid": True flag must be exact.
    priv, pub = generate_keypair()
    content = "$ true\n[exit 0]"
    cap = __import__(
        "provenance_gate_signer.client", fromlist=["AttestedCapture"]
    ).AttestedCapture(
        content=content,
        command=("true",),
        exit_code=0,
        signature=sign(priv, content.encode()),
        pubkey=pub,
    )
    d = cap.to_dict()
    assert d["kind"] == "AttestedCapture"
    assert d["content"] == content
    assert d["valid"] is True
    assert "signature" in d and "pubkey" in d


def test_capture_client_requires_endpoint():
    # client.py:84 — constructing with no endpoint must raise.
    with pytest.raises(ValueError):
        CaptureClient()  # type: ignore[call-arg]


def test_capture_client_raises_on_service_error(short_sock, keypair):
    # client.py:100 — when the service returns {"error": ...} the client must
    # surface it as a RuntimeError rather than building a bogus capture.
    sock = short_sock

    # Serve exactly one connection that replies with an error frame, then stop.
    ready: queue.Queue[int] = queue.Queue()

    def _feed_error() -> None:
        srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        srv.bind(sock)
        srv.listen(1)
        ready.put(1)
        srv.settimeout(2)
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        with conn:
            _send_json(conn, {"error": "boom: command not allowed"})
        srv.close()
        if os.path.exists(sock):
            os.unlink(sock)

    t = threading.Thread(target=_feed_error, daemon=True)
    t.start()
    ready.get(timeout=5)
    client = CaptureClient(sock_path=sock)
    with pytest.raises(RuntimeError) as exc:
        client.capture(["true"])
    assert "boom" in str(exc.value)
    t.join(timeout=2)


class _FakeConn:
    """Deterministic stand-in for a socket: returns the queued byte chunks then EOF.

    Exercises the real `_recv_json` logic (header length check, body loop,
    truncated-frame raises) without depending on OS socketpair EOF semantics,
    which behave inconsistently across platforms under the test runner.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def recv(self, n: int) -> bytes:  # intentionally socket-shaped
        if not self._chunks:
            return b""  # EOF
        chunk = self._chunks.pop(0)
        return chunk[:n]


def test_client_recv_truncated_header_raises():
    # client.py:154 — a frame header shorter than 4 bytes is rejected.
    conn = _FakeConn([b"\x00\x01"])  # only 2 bytes, then EOF
    with pytest.raises(ValueError):
        _client_recv_json(conn)


def test_client_recv_truncated_body_raises():
    # client.py:160 — declared length exceeds what the connection delivers.
    conn = _FakeConn([struct.pack("!I", 100) + b"short"])  # claims 100, sends 9
    with pytest.raises(ValueError):
        _client_recv_json(conn)


def test_service_public_key_property(keypair):
    # service.py:37
    priv, pub = keypair
    svc = SigningService(priv, pub)
    assert svc.public_key == pub


def test_service_unlink_existing_socket_on_bind(short_sock, keypair):
    # service.py:83 — serve_path must remove a stale socket file before bind.
    priv, pub = keypair
    sock = short_sock
    # Pre-create a stale (non-listening) socket file.
    _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM).bind(sock)

    svc = SigningService(priv, pub)
    t = threading.Thread(target=svc.serve_path, args=(sock,), daemon=True)
    t.start()
    # Wait for the server to be genuinely listening. serve_path sets _ready
    # after bind()+listen(); polling the file alone races bind() vs listen().
    if not svc._ready.wait(timeout=5):
        raise RuntimeError("signing service socket never appeared: " + sock)
    try:
        client = CaptureClient(sock_path=sock)
        cap = client.capture(["true"])
        assert cap.is_valid(public_key=pub)
    finally:
        svc.shutdown()
        t.join(timeout=2)


def test_service_tcp_bad_request_error_frame(keypair):
    # service.py:111/112 — a malformed TCP frame is answered with an error
    # frame instead of crashing the serve loop.
    priv, pub = keypair
    svc = SigningService(priv, pub)
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    t = threading.Thread(target=svc.serve_tcp, args=("127.0.0.1", port), daemon=True)
    t.start()
    try:
        raw = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        raw.connect(("127.0.0.1", port))
        raw.sendall(struct.pack("!I", 4) + b"nope")
        resp = raw.recv(4096)
        raw.close()
        assert b"error" in resp
        client = CaptureClient(host="127.0.0.1", port=port)
        cap = client.capture(["true"])
        assert cap.is_valid(public_key=pub)
    finally:
        svc.shutdown()
        t.join(timeout=2)


def test_service_recv_truncated_header_raises():
    # service.py:124 — the service-side frame reader rejects a short header.
    conn = _FakeConn([b"\x00"])  # 1 byte only
    with pytest.raises(ValueError):
        _service_recv_json(conn)


def test_service_recv_truncated_body_raises():
    # service.py:130 — declared length exceeds what the socket delivers.
    conn = _FakeConn([struct.pack("!I", 50) + b"partial"])
    with pytest.raises(ValueError):
        _service_recv_json(conn)


def test_verify_rejects_non_base64():
    # Exercise the verify() exception branch used by the security tests: a
    # non-base64 string must return False, never raise.
    _, pub = generate_keypair()
    assert verify(pub, b"msg", "not valid base64!!!") is False


def test_keys_scalarmult_neutral_and_identity_add():
    # Edge branches in the projective ladder: scalar 0 -> neutral point, and
    # adding the neutral (identity) point leaves the point unchanged.
    from provenance_gate_signer.keys import (
        _G,
        _edwards_add,
        _edwards_add_proj,
        _from_proj,
        _scalarmult,
        _to_proj,
    )

    assert _scalarmult(_G, 0) == (0, 1)
    # identity + P == P (also drives the z==0 early-return in _from_proj when
    # the accumulated point is the neutral).
    p = _edwards_add((0, 1), _G)
    assert p == _G
    # projective identity add round-trips through _from_proj with z != 0 fine,
    # and identity-as-projective added to G stays G.
    assert _from_proj(_edwards_add_proj(_to_proj((0, 1)), _to_proj(_G))) == _G
    # defensive neutral branch in _from_proj when z == 0
    assert _from_proj((1, 1, 0)) == (0, 1)
