# SPDX-License-Identifier: Apache-2.0
"""HTTP client + local COSE signing (ES256 via RFC 6979, Ed25519).

WARNING: Es256Signer/Ed25519Signer here are pure-Python and NOT
constant-time. Use them only with throwaway test keys. Production issuers
must sign through a KMS/HSM-backed signer implementing the same interface.
Every sign() call emits a UserWarning so this cannot happen silently."""
from __future__ import annotations
import base64, json, urllib.request, warnings
from .cbor import dumps, Tag
from .capsule import build_capsule
from .crypto import ed25519_sign, es256_public, es256_sign


class Es256Signer:
    alg = -7

    def __init__(self, private_int: int, kid: str):
        self._d, self.kid = private_int, kid

    def sign(self, data: bytes) -> bytes:
        warnings.warn("pure-Python ES256 signing is not constant-time; test keys only", UserWarning, stacklevel=2)
        return es256_sign(self._d, data)

    def cose_key(self) -> bytes:
        x, y = es256_public(self._d)
        return dumps({1: 2, 2: self.kid.encode(), 3: -7, -1: 1,
                      -2: x.to_bytes(32, "big"), -3: y.to_bytes(32, "big")})


class Ed25519Signer:
    alg = -8

    def __init__(self, seed32: bytes, kid: str):
        self._seed, self.kid = seed32, kid
        self._pub, _ = ed25519_sign(seed32, b"")

    def sign(self, data: bytes) -> bytes:
        warnings.warn("pure-Python Ed25519 signing is not constant-time; test keys only", UserWarning, stacklevel=2)
        return ed25519_sign(self._seed, data)[1]

    def cose_key(self) -> bytes:
        return dumps({1: 1, 2: self.kid.encode(), 3: -8, -1: 6, -2: self._pub})


def cose_sign1(signer, payload: bytes, content_type: str,
               cwt: tuple[str, str, int] | None = None) -> bytes:
    prot = {1: signer.alg, 3: content_type, 4: signer.kid.encode()}
    if cwt:
        prot[15] = {1: cwt[0], 2: cwt[1], 6: cwt[2]}
    prot_bytes = dumps(prot)
    sig = signer.sign(dumps(["Signature1", prot_bytes, b"", payload]))
    return dumps(Tag(18, [prot_bytes, {}, payload, sig]))


class ReceiptsClient:
    def __init__(self, base_url: str, signer, issuer: str = "urn:hivemind:issuer:self"):
        self.base = base_url.rstrip("/")
        self.signer = signer
        self.issuer = issuer

    def _post(self, path: str, data: bytes, content_type: str):
        req = urllib.request.Request(self.base + path, data=data, method="POST",
                                     headers={"Content-Type": content_type})
        with urllib.request.urlopen(req) as res:  # noqa: S310 - caller-controlled base URL
            return res.status, dict(res.headers), res.read()

    def register_self_serve(self):
        body = json.dumps({"cose_key": base64.urlsafe_b64encode(self.signer.cose_key()).rstrip(b"=").decode()}).encode()
        status, _, data = self._post("/issuers/selfserve", body, "application/json")
        assert status == 201, data
        return json.loads(data)

    def authorize(self, action: dict, approval_digest: str = "") -> dict:
        req = {
            "subject": {"type": "Agent", "id": action.get("subject_id", "agent")},
            "action": {"name": action["method"]},
            "resource": {"type": "Tool", "id": action["method"]},
            "context": {"risk_tier": action.get("risk_tier", "read"),
                        "approval_digest": approval_digest, "kill_switch": False},
        }
        status, _, data = self._post("/authz/evaluate", json.dumps(req).encode(), "application/json")
        assert status == 200, data
        return json.loads(data)

    def record(self, action: dict, verdict: str, observed_response=None):
        capsule, capsule_bytes, disclosure = build_capsule(
            method=action["method"], kind=action.get("kind", "tool"),
            risk_tier=action.get("risk_tier", "read"),
            request_args=action.get("args"),
            principal_subject=action.get("principal_subject", "unknown"),
            verdict=verdict, observed_response=observed_response,
            ledger_mode="anchored",
        )
        import time
        statement = cose_sign1(
            self.signer, capsule_bytes,
            "application/vnd.hivemind.agent-action-capsule+cbor",
            (self.issuer, capsule["action_id"], int(time.time())),
        )
        status, headers, data = self._post("/transparency/entries", statement, "application/cose")
        assert status == 201, data
        return {"capsule": capsule, "disclosure": disclosure,
                "transparent_statement": data,
                "leaf_index": int(headers.get("x-leaf-index", "-1"))}

    def checkpoint(self) -> str:
        with urllib.request.urlopen(self.base + "/transparency/checkpoint") as res:  # noqa: S310
            return res.read().decode()
