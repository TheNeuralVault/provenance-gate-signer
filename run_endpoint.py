"""Exact signing-service endpoint for provenance-gate-signer.

Runs SigningService as a SEPARATE privileged process holding the Ed25519
private key. The agent process connects over TCP to this exact endpoint and
can only REQUEST captures; it never sees the private key.

Endpoint: 127.0.0.1:8731  (fixed, not ephemeral)
"""
from __future__ import annotations

from provenance_gate_signer import SigningService, generate_keypair

HOST, PORT = "127.0.0.1", 8731


def main() -> None:
    priv, pub = generate_keypair()
    print(f"SIGNING SERVICE listening on {HOST}:{PORT}", flush=True)
    print(f"SIGNER PUBKEY={pub.hex()}", flush=True)
    SigningService(priv, pub).serve_tcp(HOST, PORT)


if __name__ == "__main__":
    main()
