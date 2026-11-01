# SPDX-License-Identifier: Apache-2.0
"""Deterministic CBOR (RFC 8949 core deterministic encoding), strict decoder."""
from __future__ import annotations


class Tag:
    def __init__(self, tag: int, value):
        self.tag, self.value = tag, value

    def __repr__(self):
        return f"Tag({self.tag}, {self.value!r})"


def _head(major: int, n: int, out: bytearray) -> None:
    m = major << 5
    if n < 24:
        out.append(m | n)
    elif n <= 0xFF:
        out += bytes([m | 24, n])
    elif n <= 0xFFFF:
        out.append(m | 25); out += n.to_bytes(2, "big")
    elif n <= 0xFFFFFFFF:
        out.append(m | 26); out += n.to_bytes(4, "big")
    elif n <= 0xFFFFFFFFFFFFFFFF:
        out.append(m | 27); out += n.to_bytes(8, "big")
    else:
        raise ValueError("CBOR integer out of range")


def _enc(v, out: bytearray) -> None:
    if v is None:
        out.append(0xF6)
    elif v is False:
        out.append(0xF4)
    elif v is True:
        out.append(0xF5)
    elif isinstance(v, int):
        _head(0, v, out) if v >= 0 else _head(1, -1 - v, out)
    elif isinstance(v, str):
        b = v.encode("utf-8"); _head(3, len(b), out); out += b
    elif isinstance(v, (bytes, bytearray)):
        _head(2, len(v), out); out += bytes(v)
    elif isinstance(v, Tag):
        _head(6, v.tag, out); _enc(v.value, out)
    elif isinstance(v, (list, tuple)):
        _head(4, len(v), out)
        for x in v: _enc(x, out)
    elif isinstance(v, dict):
        encoded = []
        for k, val in v.items():
            kb = bytearray(); _enc(k, kb)
            encoded.append((bytes(kb), val))
        encoded.sort(key=lambda e: (len(e[0]), e[0]))
        for i in range(1, len(encoded)):
            if encoded[i][0] == encoded[i - 1][0]:
                raise ValueError("CBOR: duplicate map key")
        _head(5, len(encoded), out)
        for kb, val in encoded:
            out += kb; _enc(val, out)
    else:
        raise ValueError(f"CBOR: unsupported {type(v)}")


def dumps(v) -> bytes:
    out = bytearray(); _enc(v, out); return bytes(out)


class _Reader:
    def __init__(self, buf: bytes):
        self.buf, self.pos = buf, 0

    def byte(self) -> int:
        if self.pos >= len(self.buf): raise ValueError("CBOR: unexpected end")
        b = self.buf[self.pos]; self.pos += 1; return b

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf): raise ValueError("CBOR: unexpected end")
        b = self.buf[self.pos:self.pos + n]; self.pos += n; return b

    def arg(self, ai: int) -> int:
        if ai < 24: return ai
        if ai == 24:
            v = self.byte()
            if v < 24: raise ValueError("CBOR: non-shortest form")
            return v
        widths = {25: 2, 26: 4, 27: 8}
        if ai not in widths: raise ValueError("CBOR: indefinite/reserved")
        v = int.from_bytes(self.take(widths[ai]), "big")
        if v < {2: 256, 4: 65536, 8: 4294967296}[widths[ai]]:
            raise ValueError("CBOR: non-shortest form")
        return v

    def value(self, depth: int = 0):
        if depth > 64: raise ValueError("CBOR: nesting too deep")
        ib = self.byte(); major, ai = ib >> 5, ib & 0x1F
        if major == 0: return self.arg(ai)
        if major == 1: return -1 - self.arg(ai)
        if major == 2: return self.take(self.arg(ai))
        if major == 3: return self.take(self.arg(ai)).decode("utf-8")
        if major == 4: return [self.value(depth + 1) for _ in range(self.arg(ai))]
        if major == 5:
            out, prev = {}, None
            for _ in range(self.arg(ai)):
                start = self.pos
                k = self.value(depth + 1)
                kb = self.buf[start:self.pos]
                if prev is not None:
                    if kb == prev: raise ValueError("CBOR: duplicate key")
                    if (len(prev), prev) > (len(kb), kb): raise ValueError("CBOR: keys out of order")
                prev = kb
                out[k] = self.value(depth + 1)
            return out
        if major == 6: return Tag(self.arg(ai), self.value(depth + 1))
        if ai == 20: return False
        if ai == 21: return True
        if ai == 22: return None
        raise ValueError("CBOR: floats not in the receipts profile")


def loads(buf: bytes):
    r = _Reader(bytes(buf))
    v = r.value()
    if r.pos != len(buf): raise ValueError("CBOR: trailing bytes")
    return v
