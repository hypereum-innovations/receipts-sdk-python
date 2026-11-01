# SPDX-License-Identifier: Apache-2.0
"""Agent Action Capsule: build, parse, salted commitments, disclosures."""
from __future__ import annotations
import hashlib, hmac, os, time
from .cbor import dumps, loads

PROFILE = "urn:hivemind:receipts:capsule:1"
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(now_ms: int | None = None) -> str:
    t = int(time.time() * 1000) if now_ms is None else now_ms
    time_part = ""
    for _ in range(10):
        time_part = _ALPHABET[t % 32] + time_part; t //= 32
    r = int.from_bytes(os.urandom(10), "big")
    rand = ""
    for _ in range(16):
        rand = _ALPHABET[r % 32] + rand; r //= 32
    return time_part + rand


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def salted_commitment(salt: bytes, field: str, value) -> str:
    mac = hmac.new(salt, digestmod=hashlib.sha256)
    mac.update(field.encode()); mac.update(b"\x00"); mac.update(dumps(value))
    return "sha256:" + mac.hexdigest()


def build_capsule(*, agent=None, principal_subject=None, method="tool", kind="tool",
                  risk_tier="read", request_args=None, verdict="executed",
                  observed_response=None, disposition=None, issued_at=None,
                  salt: bytes | None = None, **extra):
    """Returns (capsule_dict, capsule_bytes, disclosure_dict)."""
    salt = salt or os.urandom(32)
    if len(salt) != 32:
        raise ValueError("salt must be 256 bits")
    core = {
        "profile": PROFILE,
        "action_id": ulid(),
        "agent": agent or {},
        "principal": {"subject_commitment": salted_commitment(salt, "principal.subject", principal_subject)},
        "operation": {"kind": kind, "method": method, "risk_tier": risk_tier},
        "request_digest": salted_commitment(salt, "request", request_args),
        "verdict_class": verdict,
        "disposition": disposition or {},
        "causality": extra.get("causality", {}),
        "assurance": {"ledger_mode": extra.get("ledger_mode", "standalone"), "attestation_mode": "none"},
        "privacy": {"disclosure_policy_id": "io.hivemind.disclosure.default",
                    "salt_commitment": digest_of(salt)},
        "issued_at": issued_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if verdict == "executed":
        core["effect"] = {"status": "confirmed" if observed_response is not None else "asserted"}
        if observed_response is not None:
            core["effect"]["response_digest"] = salted_commitment(salt, "response", observed_response)
    else:
        core["effect"] = {"status": "none"}
    for key in ("criteria_ref", "model", "runtime", "extensions", "retry_of"):
        src = {"criteria_ref": "criteria_ref"}.get(key, key)
        if extra.get(src) is not None:
            core[key] = extra[src]
    capsule_id = digest_of(dumps(core))
    capsule = dict(core, capsule_id=capsule_id)
    fields = {"principal.subject": principal_subject, "request": request_args}
    if observed_response is not None:
        fields["response"] = observed_response
    import base64
    disclosure = {"capsule_id": capsule_id,
                  "salt": base64.urlsafe_b64encode(salt).rstrip(b"=").decode(),
                  "fields": fields}
    return capsule, dumps(capsule), disclosure


def parse_capsule(data: bytes) -> dict:
    capsule = loads(data)
    if not isinstance(capsule, dict) or capsule.get("profile") != PROFILE:
        raise ValueError("bad capsule profile")
    capsule_id = capsule.get("capsule_id")
    core = {k: v for k, v in capsule.items() if k != "capsule_id"}
    if digest_of(dumps(core)) != capsule_id:
        raise ValueError("capsule_id mismatch")
    if capsule.get("effect", {}).get("status") == "confirmed" and not capsule["effect"].get("response_digest"):
        raise ValueError("invariant 2 violated")
    return capsule


def verify_disclosure(capsule: dict, disclosure: dict) -> bool:
    import base64
    salt = base64.urlsafe_b64decode(disclosure["salt"] + "==")
    if disclosure.get("capsule_id") != capsule["capsule_id"]:
        return False
    if digest_of(salt) != capsule["privacy"]["salt_commitment"]:
        return False
    expected = {
        "principal.subject": capsule["principal"]["subject_commitment"],
        "request": capsule["request_digest"],
        "response": (capsule.get("effect") or {}).get("response_digest"),
        "effect.summary": (capsule.get("effect") or {}).get("summary_commitment"),
        "operation.target": (capsule.get("operation") or {}).get("target_commitment"),
    }
    for field, commitment in expected.items():
        if field in disclosure.get("fields", {}):
            if not commitment or salted_commitment(salt, field, disclosure["fields"][field]) != commitment:
                return False
    return True
