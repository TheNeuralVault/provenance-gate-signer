"""provenance_gate_signer — out-of-process T1 signing extension.

Closes the in-process adversary gap in provenance-gate WITHOUT modifying the
core package:

  Core weakness (documented in core SECURITY.md / capture.py):
    TerminalCapture signs evidence with a process-local HMAC key. Any code
    running inside the same process can read that key and forge T1 evidence.

  This extension fixes it by moving signing to a SEPARATE privileged process
  that holds an Ed25519 private key the agent process never sees. The agent can
  only *request* capture; the signing service runs the command and signs the
  real output. Forged evidence is therefore impossible even from a compromised
  agent process, because it lacks the private key and cannot invoke the
  service's signing path.

Design invariants:
  - Core provenance_gate is NOT imported, patched, or modified.
  - The agent side exposes only request/sign APIs; it cannot mint a valid
    signature on its own.
  - Verification is done against the service's PUBLIC key (Ed25519), so
    verifiers do not need the private key.
  - An AttestedCapture adapts to core's EvidenceArtifact via .to_t1_artifact()
    so it drops into guard_verify / pipeline unchanged.
"""

from .client import AttestedCapture, CaptureClient, ServiceVerifier
from .keys import generate_keypair
from .service import SigningService, run_service

__version__ = "0.1.5"

__all__ = [
    "AttestedCapture",
    "CaptureClient",
    "ServiceVerifier",
    "SigningService",
    "generate_keypair",
    "run_service",
]
