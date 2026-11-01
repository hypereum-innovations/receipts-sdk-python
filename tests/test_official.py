# SPDX-License-Identifier: Apache-2.0
"""Official vectors against the PURE-Python Ed25519/ECDSA implementations:
RFC 8032 sign+verify and Wycheproof validity decisions. These are the
independent oracles for the hand-written code. Slow (pure Python points) but
decisive. Run: python3 test_official.py
"""
import json, sys, warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hivemind_receipts.crypto import ed25519_sign, ed25519_verify, es256_sign, es256_verify  # noqa: E402

_LOCAL_BASE = Path(__file__).resolve().parent / "vectors/official-vectors"
BASE = _LOCAL_BASE if _LOCAL_BASE.is_dir() else Path(__file__).resolve().parent / "vectors/official-vectors"
hexb = bytes.fromhex


def der_to_p1363(der: bytes) -> bytes:
    assert der[0] == 0x30
    i = 2
    if der[1] & 0x80:
        i = 2 + (der[1] & 0x7F)
    parts = []
    for _ in range(2):
        assert der[i] == 0x02
        ln = der[i + 1]
        v = der[i + 2:i + 2 + ln]
        i += 2 + ln
        v = v.lstrip(b"\x00") or b"\x00"
        parts.append(v.rjust(32, b"\x00"))
    if i != len(der):
        raise ValueError("trailing")
    return b"".join(parts)


def run():
    failures = []
    rfc = json.loads((BASE / "rfc8032.json").read_text())
    for idx, v in enumerate(rfc["vectors"], 1):
        pub, sig = ed25519_sign(hexb(v["sk"]), hexb(v["msg"]))
        ok = pub.hex() == v["pk"] and sig.hex() == v["sig"] and ed25519_verify(hexb(v["pk"]), hexb(v["msg"]), hexb(v["sig"]))
        print(("PASS" if ok else "FAIL"), f"RFC8032 test {idx} (sign+verify, pure python)")
        if not ok:
            failures.append(f"rfc8032-{idx}")

    wyche_ed = json.loads((BASE / "wycheproof-ed25519.json").read_text())
    checked = 0
    for g in wyche_ed["testGroups"]:
        pk = hexb(g["publicKey"]["pk"])
        for t in g["tests"]:
            if t["result"] == "acceptable":
                continue
            got = ed25519_verify(pk, hexb(t["msg"]), hexb(t["sig"]))
            checked += 1
            if got != (t["result"] == "valid"):
                failures.append(f"wyche-ed-{t['tcId']}")
    print(f"Wycheproof Ed25519: {checked} decisive cases, {len([f for f in failures if f.startswith('wyche-ed')])} failures")

    wyche_ec = json.loads((BASE / "wycheproof-ecdsa-p256-sha256.json").read_text())
    checked = 0
    for g in wyche_ec["testGroups"]:
        xy = (int.from_bytes(hexb(g["publicKey"]["wx"]), "big"),
              int.from_bytes(hexb(g["publicKey"]["wy"]), "big"))
        for t in g["tests"]:
            if t["result"] == "acceptable":
                continue
            flags = t.get("flags", [])
            comment = (t.get("comment") or "").lower()
            if any(f in flags for f in ("InvalidEncoding", "MissingZero", "BerEncodedSignature")):
                continue
            if any(w in comment for w in ("encoding", "tag value", "appending", "indefinite", "length of")):
                continue
            try:
                got = es256_verify(xy, hexb(t["msg"]), der_to_p1363(hexb(t["sig"])))
            except Exception:
                got = False
            checked += 1
            if got != (t["result"] == "valid"):
                failures.append(f"wyche-ec-{t['tcId']}")
            if checked >= 60:
                break
        if checked >= 60:
            break
    print(f"Wycheproof ECDSA (first {checked}): {len([f for f in failures if f.startswith('wyche-ec')])} failures")

    # RFC 6979 signing sanity: sign then verify, and determinism.
    sig1 = es256_sign(4242424242, b"deterministic nonce check")
    sig2 = es256_sign(4242424242, b"deterministic nonce check")
    from hivemind_receipts.crypto import es256_public
    if sig1 != sig2 or not es256_verify(es256_public(4242424242), b"deterministic nonce check", sig1):
        failures.append("rfc6979-determinism")

    if failures:
        raise SystemExit(f"FAILURES: {failures[:20]}")
    print("python pure-crypto official vectors: ALL PASS")


def test_official():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        run()


if __name__ == "__main__":
    run()
