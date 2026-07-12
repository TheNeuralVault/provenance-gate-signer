"""Live client against the exact endpoint 127.0.0.1:8731."""
from __future__ import annotations

from provenance_gate_signer import CaptureClient, ServiceVerifier

HOST, PORT = "127.0.0.1", 8731


def main() -> None:
    client = CaptureClient(host=HOST, port=PORT)
    cap = client.capture(["python", "-c", "print('hello from attested capture')"])

    # The client only ever has the public key (embedded in the capture).
    verifier = ServiceVerifier(cap.pubkey)
    ok = verifier.verify(cap)
    print("CAPTURE.exit_code :", cap.exit_code)
    print("CAPTURE.content   :", cap.content.strip())
    print("VERIFY (client pk):", ok)

    artifact = cap.to_t1_artifact()
    print("ARTIFACT.tier     :", artifact.tier.name)
    assert ok and artifact.tier.name == "T1"
    print("LIVE ENDPOINT OK")


if __name__ == "__main__":
    main()
