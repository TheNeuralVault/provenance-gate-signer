"""Agent-side client for the signing service.

Crucially, this module CANNOT mint a valid T1 signature: it holds only the
public key and sends capture requests to the service. A compromised agent
process using only this code can at most send requests and receive honestly
signed real output — it cannot forge evidence, because the private key lives
in the separate service process.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from .keys import verify

if TYPE_CHECKING:
    from provenance_gate.evidence import EvidenceArtifact


@dataclass(frozen=True)
class AttestedCapture:
    """A capture result signed by the (separate) signing service.

    Drop-in compatible with core's SignedEvidence for the purposes that
    matter: it exposes content / command / exit_code / signature and a
    to_t1_artifact() that produces a core EvidenceArtifact (Tier.T1).
    """

    content: str
    command: tuple[str, ...]
    exit_code: int
    signature: str
    pubkey: bytes

    def is_valid(self, *, public_key: bytes) -> bool:
        """Verify the signature against the supplied service public key."""
        return verify(public_key, self.content.encode("utf-8"), self.signature)

    def to_t1_artifact(self, source: str = "attested_capture") -> EvidenceArtifact:
        """Build a core EvidenceArtifact(Tier.T1) from this attested capture.

        Raises ValueError if the signature is invalid for the given key.
        Importing core lazily keeps this extension decoupled from it.
        """
        if not self.is_valid(public_key=self.pubkey):
            raise ValueError("attested capture signature invalid")
        from provenance_gate.evidence import EvidenceArtifact
        from provenance_gate.tiers import Tier

        return EvidenceArtifact(
            tier=Tier.T1,
            source=source,
            content={
                "command": list(self.command),
                "exit_code": self.exit_code,
                "content": self.content,
                "signer_pubkey": base64.b64encode(self.pubkey).decode("ascii"),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "AttestedCapture",
            "command": list(self.command),
            "exit_code": self.exit_code,
            "content": self.content,
            "signature": self.signature,
            "pubkey": base64.b64encode(self.pubkey).decode("ascii"),
            "valid": True,
        }


class CaptureClient:
    """Talks to a running SigningService over a local socket."""

    def __init__(self, sock_path: str | None = None,
                 host: str | None = None, port: int | None = None) -> None:
        if sock_path is None and not (host and port):
            raise ValueError("provide sock_path or (host, port)")
        self.sock_path = sock_path
        self.host = host
        self.port = port

    def capture(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        timeout: int = 300,
        env: dict[str, str] | None = None,
    ) -> AttestedCapture:
        req = {"cmd": list(cmd), "cwd": cwd, "timeout": timeout, "env": env}
        resp = self._request(req)
        if "error" in resp:
            raise RuntimeError(f"signing service error: {resp['error']}")
        return AttestedCapture(
            content=resp["content"],
            command=tuple(resp["command"]),
            exit_code=resp["exit_code"],
            signature=resp["signature"],
            pubkey=base64.b64decode(resp["pubkey"]),
        )

    # ----- transport -----

    def _connect(self) -> socket.socket:
        if self.sock_path:
            return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _request(self, req: dict[str, Any]) -> dict[str, Any]:
        s = self._connect()
        try:
            if self.sock_path:
                s.connect(self.sock_path)
            else:
                assert self.host is not None and self.port is not None
                s.connect((self.host, self.port))
            _send_json(s, req)
            return _recv_json(s)
        finally:
            s.close()


class ServiceVerifier:
    """Validates AttestedCapture signatures against a trusted public key.

    This is what downstream governance (e.g. a guard_verify replacement or a
    wrapper) should use instead of core's process-local verify_signature.
    """

    def __init__(self, public_key: bytes) -> None:
        self._pub = public_key

    def verify(self, cap: AttestedCapture) -> bool:
        # Reject if the capture was signed by a different key than trusted.
        if cap.pubkey != self._pub:
            return False
        return cap.is_valid(public_key=self._pub)


# --------------------------------------------------------------------------
# frame helpers (mirror service.py; kept local to avoid import cycle)
# --------------------------------------------------------------------------

def _recv_json(conn: socket.socket) -> dict[str, Any]:
    raw = conn.recv(4)
    if len(raw) < 4:
        raise ValueError("truncated frame header")
    (n,) = struct.unpack("!I", raw)
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ValueError("truncated frame body")
        buf += chunk
    return cast("dict[str, Any]", json.loads(buf.decode("utf-8")))


def _send_json(conn: socket.socket, obj: dict[str, Any]) -> None:
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack("!I", len(data)) + data)
