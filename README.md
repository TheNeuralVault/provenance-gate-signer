# provenance-gate-signer

Out-of-process Ed25519 signing extension that **closes the in-process adversary
gap** in [provenance-gate](https://github.com/TheNeuralVault/provenance-gate)
**without modifying the core package**.

## The problem it solves

Core `provenance-gate` signs captured evidence with a *process-local* HMAC key
(see `capture.py` / `SECURITY.md`). Any code running inside the same process
can read that key and forge T1 evidence. `provenance-gate-signer` moves signing
to a **separate privileged process** that holds an Ed25519 private key the agent
process never sees.

## How it works

```
 agent process                 signing service (separate, privileged)
 --------------                ---------------------------------------
 CaptureClient  --request-->  SigningService
   (pubkey only)  <--signed--   runs cmd, signs with PRIVATE key
                 real output
```

- The signing service is the **only** place the private key exists.
- The agent can only *request* capture; it cannot mint a valid signature.
- Verification uses the service's **public** key (`ServiceVerifier`), so
  verifiers never need the private key.

## Usage

```python
# terminal A — run the privileged signing service (key never leaves here)
from provenance_gate_signer import run_service
run_service("/tmp/sign.sock")   # generates + holds Ed25519 key

# terminal B — agent side (public key only)
from provenance_gate_signer import CaptureClient, ServiceVerifier
client = CaptureClient(sock_path="/tmp/sign.sock")
cap = client.capture(["pytest", "-q"])          # runs in the service, signed
assert ServiceVerifier(cap.pubkey).verify(cap)  # True

# drop into core's governance unchanged:
artifact = cap.to_t1_artifact()                 # core EvidenceArtifact(T1)
```

A compromised agent process holding only the client + public key **cannot**
forge a passing T1 capture: it lacks the private key (see
`tests/test_signer.py::test_inprocess_adversary_cannot_forge`).

## Status

v0.1.0 — functional sketch, fully tested. Core `provenance-gate` is **not**
modified; this is a composable extension.
