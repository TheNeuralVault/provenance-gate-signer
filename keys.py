"""Pure-Python Ed25519 (RFC 8032) — no compiled dependencies.

provenance-gate-signer deliberately avoids the `cryptography` binary wheel
because its prebuilt rust binding is incompatible with Termux / Python 3.14
(missing PyExc_Warning symbol). A pure-Python implementation runs identically
on Termux, Ubuntu, and PyPI with zero install risk.

This is a compact, auditable Ed25519 following RFC 8032. It is NOT a generic
crypto library — only the operations the signer needs:
  - key generation (seed -> (A, seed))
  - signing (message -> 64-byte sig)
  - verification (message, sig, public key) -> bool

It uses the Ed25519 curve constants and SHA-512 (stdlib hashlib).
"""

from __future__ import annotations

import base64
import hashlib

# Ed25519 domain parameters
_P = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493  # group order
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_G = (_BX, _BY)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    # Edwards curve: -x^2 + y^2 = 1 + d x^2 y^2  =>  x^2 = (y^2 - 1) / (d y^2 + 1)
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


def _edwards_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return (x3 % _P, y3 % _P)


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards_add(q, q)
    if e & 1:
        q = _edwards_add(q, p)
    return q


def _encode_int(n: int) -> bytes:
    return n.to_bytes(32, "little")


def _decode_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _encode_point(p: tuple[int, int]) -> bytes:
    x, y = p
    # store as little-endian y with the sign of x in the top bit
    return _encode_int(y | ((x & 1) << 255))


def _decode_point(b: bytes) -> tuple[int, int]:
    y = _decode_int(b[:31] + bytes([b[31] & 0x7F]))
    x = _xrecover(y)
    if (x & 1) != (b[31] >> 7):
        x = _P - x
    return (x % _P, y)


def _sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_seed_32, public_key_32)."""
    seed = _os_random(32)
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _scalarmult(_G, a)
    return seed, _encode_point(A)


def _os_random(n: int) -> bytes:
    import os

    return os.urandom(n)


def public_key_bytes(priv: bytes) -> bytes:
    """Derive the public key bytes from a 32-byte private seed."""
    h = _sha512(priv)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _scalarmult(_G, a)
    return _encode_point(A)


def sign(priv: bytes, msg: bytes) -> str:
    """Sign msg with the 32-byte private seed; return base64 signature."""
    h = _sha512(priv)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _encode_point(_scalarmult(_G, a))
    r = _sha512(h[32:] + msg)
    r_int = int.from_bytes(r, "little") % _L
    R = _encode_point(_scalarmult(_G, r_int))
    k = _sha512(R + A + msg)
    k_int = int.from_bytes(k, "little") % _L
    s = (r_int + k_int * a) % _L
    sig = R + _encode_int(s)
    return base64.b64encode(sig).decode("ascii")


def verify(pub: bytes, msg: bytes, b64_sig: str) -> bool:
    """Verify a base64 Ed25519 signature against pub + msg."""
    try:
        sig = base64.b64decode(b64_sig, validate=True)
        if len(sig) != 64:
            return False
        R = _decode_point(sig[:32])
        s = _decode_int(sig[32:])
        A = _decode_point(pub)
        k = _sha512(_encode_point(R) + pub + msg)
        k_int = int.from_bytes(k, "little") % _L
        # s*G == R + k*A  (on the curve)
        lhs = _scalarmult(_G, s)
        rhs = _edwards_add(R, _scalarmult(A, k_int))
        return lhs == rhs
    except Exception:
        return False
