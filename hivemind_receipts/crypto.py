# SPDX-License-Identifier: Apache-2.0
"""Pure-Python ES256 (ECDSA P-256) and Ed25519 verification; SHA-256/HMAC via
hashlib. Enough for full offline receipt verification with no dependencies.

PRODUCTION SIGNING MUST NOT USE THE PURE-PYTHON SIGNERS IN client.py: their
scalar arithmetic is not constant-time and leaks through timing. They exist
for test keys and conformance work only (and say so at runtime); production
issuers sign through KMS/HSM or the platform crypto (see the TypeScript
LocalSigner/KmsSigner)."""
from __future__ import annotations
import hashlib, hmac as _hmac

# --- P-256 ------------------------------------------------------------------
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _add(p, q):
    if p is None: return q
    if q is None: return p
    x1, y1 = p; x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0: return None
    if p == q:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)


def _mul(k: int, point):
    r = None
    while k:
        if k & 1: r = _add(r, point)
        point = _add(point, point); k >>= 1
    return r


def es256_verify(pub_xy: tuple[int, int], msg: bytes, sig64: bytes) -> bool:
    if len(sig64) != 64: return False
    r, s = int.from_bytes(sig64[:32], "big"), int.from_bytes(sig64[32:], "big")
    if not (1 <= r < _N and 1 <= s < _N): return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _N)
    point = _add(_mul(z * w % _N, (_GX, _GY)), _mul(r * w % _N, pub_xy))
    return point is not None and point[0] % _N == r


def es256_public(priv: int) -> tuple[int, int]:
    return _mul(priv, (_GX, _GY))


def es256_sign(priv: int, msg: bytes) -> bytes:
    digest = hashlib.sha256(msg).digest()
    z = int.from_bytes(digest, "big")
    # RFC 6979 HMAC-SHA256 deterministic nonce
    x = priv.to_bytes(32, "big")
    h1 = (z % _N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = _hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = _hmac.new(k, v, hashlib.sha256).digest()
    k = _hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = _hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = _hmac.new(k, v, hashlib.sha256).digest()
        nonce = int.from_bytes(v, "big")
        if 1 <= nonce < _N:
            r = _mul(nonce, (_GX, _GY))[0] % _N
            if r:
                s = pow(nonce, -1, _N) * (z + r * priv) % _N
                if s:
                    if s > _N // 2: s = _N - s
                    return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        k = _hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = _hmac.new(k, v, hashlib.sha256).digest()


# --- Ed25519 (RFC 8032) --------------------------------------------------------
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, -1, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0: x = (x * _I) % _Q
    if x % 2: x = _Q - x
    return x


_BY = (4 * pow(5, -1, _Q)) % _Q
_B = (_xrecover(_BY), _BY)


def _edwards(p, q):
    x1, y1 = p; x2, y2 = q
    den = pow(1 + _D * x1 * x2 * y1 * y2, -1, _Q)
    den2 = pow(1 - _D * x1 * x2 * y1 * y2, -1, _Q)
    return (((x1 * y2 + x2 * y1) * den) % _Q, ((y1 * y2 + x1 * x2) * den2) % _Q)


def _scalarmult(p, e: int):
    if e == 0: return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards(q, q)
    return _edwards(q, p) if e & 1 else q


def _decode_point(b: bytes):
    # RFC 8032 section 5.1.3 decoding: y must be canonical (< q) and the
    # encoding of x=0 with the sign bit set MUST fail (Wycheproof tc151).
    y = int.from_bytes(b, "little") & (2**255 - 1)
    if y >= _Q:
        raise ValueError("non-canonical y")
    x = _xrecover(y)
    sign = b[31] >> 7
    if x % _Q == 0 and sign == 1:
        raise ValueError("x=0 with sign bit set")
    if (x & 1) != sign: x = _Q - x
    return (x, y)


def _encode_point(p) -> bytes:
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_verify(pub32: bytes, msg: bytes, sig64: bytes) -> bool:
    try:
        if len(pub32) != 32 or len(sig64) != 64: return False
        r_bytes, s = sig64[:32], int.from_bytes(sig64[32:], "little")
        if s >= _L: return False
        a = _decode_point(pub32)
        h = int.from_bytes(hashlib.sha512(r_bytes + pub32 + msg).digest(), "little")
        sb = _scalarmult(_B, s)
        ra = _edwards(_decode_point(r_bytes), _scalarmult(a, h))
        return _encode_point(sb) == _encode_point(ra)
    except Exception:
        return False


def ed25519_sign(seed32: bytes, msg: bytes) -> tuple[bytes, bytes]:
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8; a |= 1 << 254
    pub = _encode_point(_scalarmult(_B, a))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little")
    r_enc = _encode_point(_scalarmult(_B, r))
    s = (r + int.from_bytes(hashlib.sha512(r_enc + pub + msg).digest(), "little") * a) % _L
    return pub, r_enc + s.to_bytes(32, "little")
