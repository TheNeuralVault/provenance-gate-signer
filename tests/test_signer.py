"""Tests for provenance_gate_signer.

These are T1: they run real Ed25519 signing, a real local socket round-trip
to a real SigningService process, real subprocess execution, and assert that:
  - a compromised agent (holding only the public key + client) CANNOT forge T1,
  - tampered content is rejected,
  - output is genuinely signed by the service, not the agent.
"""

from __future__ import annotations

import os
import threading

import pytest

from provenance_gate_signer import (
    AttestedCapture,
    CaptureClient,
    ServiceVerifier,
    SigningService,
    generate_keypair,
)


@pytest.fixture
def keypair():
    priv, pub = generate_keypair()
    return priv, pub


@pytest.fixture
def service_thread(tmp_path, keypair):
    """Spin up a real SigningService on a UNIX socket in a background thread."""
    import time

    priv, pub = keypair
    sock = str(tmp_path / "sign.sock")
    svc = SigningService(priv, pub)
    t = threading.Thread(target=svc.serve_path, args=(sock,), daemon=True)
    t.start()
    # wait until the socket actually exists (avoid connect-before-bind race)
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.01)
    else:
        raise RuntimeError("signing service socket never appeared: " + sock)
    return sock, pub


# --------------------------------------------------------------------------
# key layer
# --------------------------------------------------------------------------

def test_keypair_roundtrip_and_no_private_from_public(keypair):
    priv, pub = keypair
    assert len(priv) == 32 and len(pub) == 32
    from provenance_gate_signer.keys import sign, verify
    sig = sign(priv, b"hello")
    assert verify(pub, b"hello", sig)
    assert not verify(pub, b"tampered", sig)


def test_client_cannot_sign_locally(keypair):
    """The agent-side client holds only the public key and CANNOT mint T1.

    This is the core security property: forging evidence requires the private
    key, which lives only in the SigningService process. The CaptureClient must
    never carry the private key nor expose a signing method.
    """
    _, _ = keypair
    # A client is constructed against a socket endpoint; it never receives the
    # private key — only signed output over the wire.
    client = CaptureClient(sock_path="/tmp/does-not-need-to-exist.sock")
    assert not hasattr(client, "sign")
    assert not hasattr(client, "private_key")
    assert not hasattr(client, "capture_local")
    # The SigningService is the only place the private key exists; the client
    # receives signed output over the socket, never the key itself.
    assert not isinstance(client, SigningService)


# --------------------------------------------------------------------------
# service: real execution + real signing
# --------------------------------------------------------------------------

def test_service_runs_command_and_signs(service_thread):
    sock, pub = service_thread
    client = CaptureClient(sock_path=sock)
    cap = client.capture(["python", "-c", "print('ok')"])
    assert cap.exit_code == 0
    assert "ok" in cap.content
    # signed by the service's real key
    assert cap.is_valid(public_key=pub)
    # and the embedded pubkey matches what we trust
    assert cap.pubkey == pub


def test_service_signature_fails_under_wrong_key(service_thread):
    sock, _ = service_thread
    client = CaptureClient(sock_path=sock)
    cap = client.capture(["true"])
    _, other_pub = generate_keypair()
    assert not cap.is_valid(public_key=other_pub)


# --------------------------------------------------------------------------
# the core security claim: in-process adversary cannot forge T1
# --------------------------------------------------------------------------

def test_inprocess_adversary_cannot_forge(service_thread):
    """An attacker with only the public key + client cannot mint a valid T1.

    They try to hand-craft an AttestedCapture claiming a passing test run.
    ServiceVerifier must reject it because they lack the private key.
    """
    sock, pub = service_thread
    client = CaptureClient(sock_path=sock)

    # Attacker fabricates a "passing" capture locally.
    forged = AttestedCapture(
        content="$ pytest\nPASSED\n[exit 0]",
        command=("pytest",),
        exit_code=0,
        signature="whatever",  # they cannot compute a valid sig
        pubkey=pub,
    )
    verifier = ServiceVerifier(pub)
    assert verifier.verify(forged) is False

    # Contrast: a genuine capture from the service verifies.
    real = client.capture(["python", "-c", "print('real')"])
    assert verifier.verify(real) is True


def test_tampered_content_rejected(service_thread):
    sock, pub = service_thread
    client = CaptureClient(sock_path=sock)
    cap = client.capture(["python", "-c", "print('a')"])
    tampered = AttestedCapture(
        content=cap.content + "\n[exit 1]",
        command=cap.command,
        exit_code=cap.exit_code,
        signature=cap.signature,
        pubkey=cap.pubkey,
    )
    assert tampered.is_valid(public_key=pub) is False


def test_wrong_signer_key_rejected(service_thread):
    sock, _ = service_thread
    client = CaptureClient(sock_path=sock)
    cap = client.capture(["true"])
    _, other_pub = generate_keypair()
    verifier = ServiceVerifier(other_pub)
    assert verifier.verify(cap) is False


# --------------------------------------------------------------------------
# integration with core EvidenceArtifact (no core modification)
# --------------------------------------------------------------------------

def test_attested_capture_to_core_artifact(service_thread):
    sock, _ = service_thread
    client = CaptureClient(sock_path=sock)
    cap = client.capture(["python", "-c", "print('x')"])
    art = cap.to_t1_artifact()
    assert art.tier.name == "T1"
    assert art.source == "attested_capture"
    assert art.content["exit_code"] == 0
    # the signer pubkey is embedded for downstream audit
    assert art.content["signer_pubkey"]


def test_core_artifact_rejects_bad_signature(keypair):
    _, pub = keypair
    bad = AttestedCapture(
        content="x", command=("c",), exit_code=0,
        signature="z", pubkey=pub,
    )
    with pytest.raises(ValueError):
        bad.to_t1_artifact()


# --------------------------------------------------------------------------
# TCP transport path (covers serve_tcp)
# --------------------------------------------------------------------------

def test_tcp_transport(keypair):
    priv, pub = keypair
    svc = SigningService(priv, pub)
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    t = threading.Thread(target=svc.serve_tcp, args=("127.0.0.1", port), daemon=True)
    t.start()
    client = CaptureClient(host="127.0.0.1", port=port)
    cap = client.capture(["true"])
    assert cap.is_valid(public_key=pub)
