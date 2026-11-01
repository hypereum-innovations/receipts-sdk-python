# SPDX-License-Identifier: Apache-2.0
"""Class-1 offline verifier: COSE_Sign1, capsule, disclosure, RFC 9162
inclusion against a C2SP signed-note checkpoint with witness quorum."""
from __future__ import annotations
import base64, hashlib, json
from dataclasses import dataclass, field
from .cbor import dumps, loads, Tag
from .capsule import parse_capsule, verify_disclosure
from .crypto import ed25519_verify, es256_verify


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _leaf(data: bytes) -> bytes:
    return _sha256(b"\x00" + data)


def _node(left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01" + left + right)


def verify_inclusion(leaf: bytes, tree_size: int, leaf_index: int, hashes: list[bytes], root: bytes) -> bool:
    if leaf_index >= tree_size or tree_size < 1:
        return False
    fn, sn, r = leaf_index, tree_size - 1, leaf
    for p in hashes:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = _node(p, r)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1; sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first_size, second_size, hashes, first_root, second_root):
    if first_size == second_size:
        return not hashes and first_root == second_root
    if first_size < 1 or first_size >= second_size:
        return False
    if first_size & (first_size - 1) == 0:
        hashes = [first_root, *hashes]
    if not hashes:
        return False
    fn, sn = first_size - 1, second_size - 1
    while fn % 2 == 1:
        fn >>= 1; sn >>= 1
    fr = sr = hashes[0]
    for c in hashes[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = _node(c, fr); sr = _node(c, sr)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1; sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1; sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


def verify_batch_inclusion(capsule_bytes, proof, batch_root_hex):
    return verify_inclusion(_leaf(capsule_bytes), proof["treeSize"], proof["leafIndex"],
                            [bytes(h) for h in proof["hashes"]], bytes.fromhex(batch_root_hex))


def _sig_structure(ctx: str, prot: bytes, aad: bytes, payload: bytes) -> bytes:
    return dumps([ctx, prot, aad, payload])


@dataclass
class ParsedSign1:
    raw: bytes
    prot_bytes: bytes
    prot: dict
    unprot: dict
    payload: bytes | None
    signature: bytes

    @property
    def alg(self) -> int:
        return int(self.prot.get(1, 0))

    @property
    def kid(self) -> str:
        k = self.prot.get(4, b"")
        return k.decode() if isinstance(k, bytes) else str(k)


def parse_sign1(data: bytes) -> ParsedSign1:
    v = loads(data)
    if isinstance(v, Tag):
        assert v.tag == 18, "expected COSE_Sign1 tag"
        v = v.value
    prot_bytes, unprot, payload, sig = v
    prot = loads(prot_bytes) if prot_bytes else {}
    return ParsedSign1(data, prot_bytes, prot, unprot or {}, payload, sig)


def verify_sign1(parsed: ParsedSign1, pub, alg: int, detached: bytes | None = None, aad: bytes = b"") -> bool:
    payload = parsed.payload if parsed.payload is not None else detached
    if payload is None:
        raise ValueError("detached payload required")
    to_verify = _sig_structure("Signature1", parsed.prot_bytes, aad, payload)
    if alg == -7:
        x, y = pub
        return es256_verify((int.from_bytes(x, "big"), int.from_bytes(y, "big")), to_verify, parsed.signature)
    if alg == -8:
        return ed25519_verify(pub, to_verify, parsed.signature)
    raise ValueError(f"unsupported alg {alg}")


def public_from_cose_key(cose_key: dict):
    kty = cose_key.get(1)
    kid_raw = cose_key.get(2, b"")
    kid = kid_raw.decode() if isinstance(kid_raw, bytes) else str(kid_raw)
    if kty == 2:
        return kid, -7, (cose_key[-2], cose_key[-3])
    if kty == 1:
        return kid, -8, cose_key[-2]
    raise ValueError("unsupported COSE key type")


def _note_key_id(name: str, key_type: int, raw: bytes) -> bytes:
    return _sha256(name.encode() + b"\n" + bytes([key_type]) + raw)[:4]


def parse_note_verifier(s: str):
    first = s.index("+")
    second = s.index("+", first + 1)
    name, key_id_hex, key_b64 = s[:first], s[first + 1:second], s[second + 1:]
    key_bytes = base64.b64decode(key_b64)
    return name, bytes.fromhex(key_id_hex), key_bytes[0], key_bytes[1:]


@dataclass
class TrustRoots:
    issuers: dict = field(default_factory=dict)      # kid -> (pub, alg, tier, display, revoked)
    log_keys: dict = field(default_factory=dict)     # kid -> (pub, alg)
    note_verifiers: list = field(default_factory=list)
    witness_quorum: int = 0
    witness_names: set = field(default_factory=set)
    raw_json: dict = field(default_factory=dict)


def load_trust_file(path_or_dict) -> TrustRoots:
    data = json.load(open(path_or_dict)) if isinstance(path_or_dict, (str,)) else path_or_dict
    trust = TrustRoots(note_verifiers=data.get("note_verifiers", []), raw_json=json.loads(json.dumps(data)))
    for i in data.get("issuers", []):
        kid, alg, pub = public_from_cose_key(loads(base64.urlsafe_b64decode(i["cose_key"] + "==")))
        trust.issuers[i["kid"]] = (pub, alg, i.get("tier", "T0"), i.get("display", ""), False)
    for l in data.get("log_keys", []):
        kid, alg, pub = public_from_cose_key(loads(base64.urlsafe_b64decode(l["cose_key"] + "==")))
        trust.log_keys[l["kid"]] = (pub, alg)
    wp = data.get("witness_policy") or {}
    trust.witness_quorum = int(wp.get("quorum", 0))
    trust.witness_names = {w["name"] for w in wp.get("witnesses", [])}
    return trust


def parse_checkpoint(text: str):
    head, sig_block = text.split("\n\n", 1)
    body = head + "\n"
    lines = head.split("\n")
    origin, size, root = lines[0], int(lines[1]), base64.b64decode(lines[2])
    sigs = []
    for line in sig_block.split("\n"):
        if not line:
            continue
        assert line.startswith("— ")
        rest = line[2:]
        name, b64 = rest.split(" ", 1)
        raw = base64.b64decode(b64)
        sigs.append((name, raw[:4], raw[4:]))
    return origin, size, root, body, sigs


def verify_receipt(statement: bytes, trust: TrustRoots, checkpoint_text: str | None = None,
                   disclosure: dict | None = None, consistency_chain=None, batch=None) -> dict:
    checks: list[tuple[str, str, str]] = []

    def check(name, ok, detail):
        checks.append((name, "pass" if ok else "fail", detail))
        return ok

    parsed = parse_sign1(statement)
    issuer = trust.issuers.get(parsed.kid)
    if not issuer:
        check("issuer_identity", False, f"unknown issuer kid {parsed.kid}")
        return {"verdict": "FAILED", "checks": checks}
    pub, alg, tier, display, revoked = issuer
    check("issuer_identity", not revoked, f"{tier} — {display}")
    check("signature", alg == parsed.alg and verify_sign1(parsed, pub, alg), "COSE signature")
    capsule = None
    try:
        capsule = parse_capsule(parsed.payload) if parsed.payload else None
        check("capsule", capsule is not None, str(capsule["capsule_id"]) if capsule else "missing payload")
    except Exception as e:
        is_batch = False
        if parsed.payload:
            try:
                is_batch = loads(parsed.payload).get("profile") == "urn:hivemind:receipts:capsule-batch:1"
            except Exception:
                pass
        if is_batch:
            check("capsule", True, "capsule batch payload (member check below)")
        else:
            check("capsule", False, str(e))
    if capsule and disclosure:
        check("disclosure", verify_disclosure(capsule, disclosure), "salted commitments")

    receipts = parsed.unprot.get(394) or []
    if not receipts:
        check("inclusion", False, "no COSE receipt attached")
    elif not checkpoint_text:
        check("inclusion", False, "no checkpoint supplied")
    else:
        origin, size, root, body, sigs = parse_checkpoint(checkpoint_text)
        # leaf bytes = the statement without receipts, re-encoded
        unprot = dict(parsed.unprot); unprot.pop(394, None); unprot.pop(-25900, None)
        leaf_bytes = dumps(Tag(18, [parsed.prot_bytes, unprot, parsed.payload, parsed.signature]))
        leaf = _leaf(leaf_bytes)
        verified = False
        for rb in receipts:
            rp = parse_sign1(rb)
            if rp.prot.get(395) != 1:
                continue
            vdp = rp.unprot.get(396) or rp.prot.get(396) or {}
            inc = vdp.get(-1)
            if not inc:
                continue
            if isinstance(inc[0], (bytes, bytearray)):
                # RFC 9942 form: bstr-wrapped CBOR [size, index, [path]]
                from .cbor import loads as _loads
                content = _loads(bytes(inc[0]))
                inc = [content[0], content[1], *content[2]]
            if inc[0] > size:
                continue
            log_entry = trust.log_keys.get(rp.kid)
            if not log_entry:
                continue
            lpub, lalg = log_entry
            if verify_sign1(rp, lpub, lalg, detached=root) and verify_inclusion(leaf, inc[0], inc[1], [bytes(h) for h in inc[2:]], root):
                verified = True
                break
            if consistency_chain and inc[0] == consistency_chain["proof"]["firstSize"]:
                old_root = consistency_chain["root_at_receipt"]
                if (verify_sign1(rp, lpub, lalg, detached=old_root)
                        and verify_inclusion(leaf, inc[0], inc[1], [bytes(h) for h in inc[2:]], old_root)
                        and verify_consistency(consistency_chain["proof"]["firstSize"],
                                               consistency_chain["proof"]["secondSize"],
                                               [bytes(h) for h in consistency_chain["proof"]["hashes"]],
                                               old_root, root)):
                    verified = True
                    break
        check("inclusion", verified, f"leaf in {origin}@{size}")
        verifiers = [parse_note_verifier(v) for v in trust.note_verifiers]
        log_ok = False
        valid_witnesses = set()
        for name, key_id, sig in sigs:
            match = next((v for v in verifiers if v[0] == name and v[1] == key_id), None)
            if not match:
                continue
            _, _, key_type, raw = match
            if key_type == 1:
                log_ok = ed25519_verify(raw, body.encode(), sig)
            elif key_type == 4 and len(sig) == 72:
                ts = int.from_bytes(sig[:8], "big")
                msg = f"cosignature/v1\ntime {ts}\n{body}".encode()
                if ed25519_verify(raw, msg, sig[8:]):
                    valid_witnesses.add(name)
        check("checkpoint_signature", log_ok, "log signed checkpoint")
        if trust.witness_quorum:
            counted = valid_witnesses & trust.witness_names if trust.witness_names else valid_witnesses
            check("witness_quorum", len(counted) >= trust.witness_quorum,
                  f"{len(counted)} cosignatures, quorum {trust.witness_quorum}")
        if capsule and capsule.get("assurance", {}).get("ledger_mode") == "anchored":
            check("anchored_claim", verified, "anchored implies verified receipt")
    if batch is not None and parsed.payload:
        try:
            batch_payload = loads(parsed.payload)
            ok = verify_batch_inclusion(batch["capsule_bytes"], batch["proof"],
                                        str(batch_payload["batch_root"]).removeprefix("sha256:"))
            inner = parse_capsule(batch["capsule_bytes"]) if ok else None
            check("batch_inclusion", ok and inner is not None, "capsule in batch root")
            if ok:
                capsule = inner
        except Exception as e:
            check("batch_inclusion", False, str(e))
    verdict = "FAILED" if any(s == "fail" for _, s, _ in checks) else "VERIFIED"
    return {"verdict": verdict, "checks": [{"check": n, "status": s, "detail": d} for n, s, d in checks],
            "capsule_id": capsule["capsule_id"] if capsule else None}


def _find_rust_verifier_bin() -> str:
    import os
    from pathlib import Path
    repo_root = Path(__file__).resolve().parent
    env_bin = os.environ.get("HIVEMIND_VERIFY_RS_BIN", "")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    candidates = [
        str(repo_root / "receipts-verify-rs/target/release/hivemind-receipts-verify"),
        str(repo_root / "receipts-verify-rs/target/debug/hivemind-receipts-verify"),
        str(repo_root / "dist-receipts-release/hv"),
    ]
    valid = [c for c in candidates if os.path.isfile(c) and os.access(c, os.X_OK)]
    if valid:
        valid.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return valid[0]
    raise FileNotFoundError("hivemind-receipts-verify binary not found; build receipts-verify-rs first")


def verify_via_rust_core(
    statement: bytes,
    trust: TrustRoots | dict | str,
    checkpoint_text: str | None = None,
    disclosure: dict | None = None,
    hv_bin: str | None = None,
) -> dict:
    """
    Invoke the canonical Rust verifier (`receipts-verify-rs`) via CLI/JSON bridge
    to guarantee 100% parity across all extensions (RFC 3161, SD-JWT, ERS, Cedar, CEL).
    """
    import os
    import subprocess
    import tempfile

    bin_path = hv_bin or _find_rust_verifier_bin()
    if isinstance(trust, TrustRoots):
        trust_dict = json.loads(json.dumps(trust.raw_json))
        active_issuers = [
            entry for entry in trust_dict.get("issuers", [])
            if entry.get("kid") in trust.issuers and not trust.issuers[entry["kid"]][4]
        ]
        trust_dict["issuers"] = active_issuers
    elif isinstance(trust, str):
        trust_dict = json.loads(open(trust).read()) if os.path.isfile(trust) else json.loads(trust)
    else:
        trust_dict = trust

    with tempfile.TemporaryDirectory(prefix="hv_py_bridge_") as tmpdir:
        stmt_path = os.path.join(tmpdir, "statement.scitt")
        trust_path = os.path.join(tmpdir, "trust.json")
        with open(stmt_path, "wb") as f:
            f.write(statement)
        with open(trust_path, "w", encoding="utf-8") as f:
            json.dump(trust_dict, f)

        cmd = [bin_path, "verify", stmt_path, "--trust", trust_path, "--json"]
        if checkpoint_text:
            cp_path = os.path.join(tmpdir, "checkpoint.txt")
            with open(cp_path, "w", encoding="utf-8") as f:
                f.write(checkpoint_text)
            cmd.extend(["--checkpoint", cp_path])
        if disclosure is not None:
            disc_path = os.path.join(tmpdir, "disclosure.json")
            with open(disc_path, "w", encoding="utf-8") as f:
                json.dump(disclosure, f)
            cmd.extend(["--disclosure", disc_path])

        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if not proc.stdout.strip():
            return {
                "verdict": "FAILED",
                "checks": [{"check": "rust_core", "status": "fail", "detail": proc.stderr.strip()}],
                "capsule_id": None,
            }
        return json.loads(proc.stdout)

