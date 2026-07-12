"""The privileged signing service.

This process is the ONLY place the Ed25519 private key exists. It receives a
capture request over a local socket, executes the command itself, and returns
the output signed with the private key. Because signing happens here and the
key never leaves this process, a compromised *agent* process cannot forge T1
evidence: it can only send requests and receive honestly-signed real output.

The wire protocol is a minimal length-prefixed JSON frame:
  request:  {"cmd": [...], "cwd": "...", "timeout": 300, "env": null}
  response: {"content": "...", "command": [...], "exit_code": 0,
             "signature": "<base64>", "pubkey": "<base64>"}
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
from typing import Any, cast

from .keys import sign


class SigningService:
    """Holds the private key and answers capture-and-sign requests."""

    def __init__(self, private_key: bytes, public_key: bytes) -> None:
        self._priv = private_key
        self._pub = public_key

    @property
    def public_key(self) -> bytes:
        return self._pub

    def capture(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        timeout: int = 300,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Run cmd, sign the captured output, return a response dict."""
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
            env=env,
        )
        header = f"$ {' '.join(cmd)}\n"
        body = f"{result.stdout}{result.stderr}"
        footer = f"\n[exit {result.returncode}]"
        content = header + body + footer
        sig = sign(self._priv, content.encode("utf-8"))
        return {
            "content": content,
            "command": list(cmd),
            "exit_code": result.returncode,
            "signature": sig,
            "pubkey": base64.b64encode(self._pub).decode("ascii"),
        }

    # ----- socket server (local only) -----

    def serve_once(self, conn: socket.socket) -> None:
        req = _recv_json(conn)
        resp = self.capture(
            req["cmd"],
            cwd=req.get("cwd"),
            timeout=req.get("timeout", 300),
            env=req.get("env"),
        )
        _send_json(conn, resp)

    def serve_path(self, sock_path: str, *, max_clients: int = 64) -> None:
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(max_clients)
        try:
            while True:
                conn, _ = srv.accept()
                with conn:
                    try:
                        self.serve_once(conn)
                    except Exception as exc:  # don't kill server on bad req
                        _send_json(conn, {"error": str(exc)})
        finally:
            srv.close()
            if os.path.exists(sock_path):
                os.unlink(sock_path)

    def serve_tcp(self, host: str, port: int, *, max_clients: int = 64) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(max_clients)
        try:
            while True:
                conn, _ = srv.accept()
                with conn:
                    try:
                        self.serve_once(conn)
                    except Exception as exc:
                        _send_json(conn, {"error": str(exc)})
        finally:
            srv.close()


# --------------------------------------------------------------------------
# frame helpers
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


def run_service(sock_path: str, *, private_key: bytes | None = None,
                public_key: bytes | None = None) -> None:
    """Convenience entry point: generate keys (or use supplied) and serve."""
    from .keys import generate_keypair

    if private_key is None or public_key is None:
        private_key, public_key = generate_keypair()
    SigningService(private_key, public_key).serve_path(sock_path)
