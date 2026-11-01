# SPDX-License-Identifier: Apache-2.0
"""Unified 4-Verb Python SDK & Offline Verifier (`intent`, `outcome`, `confirm`, `verify`).

Provides the canonical 4-verb Receipts API for Python agents and verifiers:
- `intent(...)`: Emit a COSE_Sign1 pre-action `intent` capsule
- `outcome(...)`: Emit a COSE_Sign1 post-action `outcome` capsule linked to `intent`
- `confirm(...)`: Emit a COSE_Sign1 external `confirmation` statement (`urn:hivemind:receipts:confirmation:1`)
- `verify(...)`: Offline verification of receipts, confirmations, and transparency proofs
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .capsule import (
    PROFILE as CAPSULE_PROFILE_URI,
    build_capsule,
    digest_of,
    parse_capsule,
    salted_commitment,
    verify_disclosure,
)
from .cbor import Tag, dumps, loads
from .client import Ed25519Signer, Es256Signer, ReceiptsClient, cose_sign1
from .verify import (
    ParsedSign1,
    TrustRoots,
    load_trust_file,
    parse_sign1,
    public_from_cose_key,
    verify_receipt,
    verify_sign1,
    verify_via_rust_core,
)

CAPSULE_MEDIA_TYPE = "application/vnd.hivemind.capsule+cbor"
CONFIRMATION_PROFILE_URI = "urn:hivemind:receipts:confirmation:1"
CONFIRMATION_MEDIA_TYPE = "application/vnd.hivemind.confirmation+cbor"

ReceiptSigner = Ed25519Signer | Es256Signer


@dataclass
class EmittedReceipt:
    capsule: dict[str, Any]
    capsule_bytes: bytes
    statement: bytes
    capsule_id: str
    action_id: str
    disclosure: dict[str, Any]


@dataclass
class EmittedConfirmation:
    payload: dict[str, Any]
    statement: bytes
    confirmation_digest: str


@dataclass
class UnifiedVerifyResult:
    ok: bool
    verdict: str
    kind: str
    capsule: dict[str, Any] | None = None
    confirmation: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    reason: str | None = None


def intent(
    *,
    signer: ReceiptSigner,
    agent: str,
    method: str,
    args: Any = None,
    kind: str = "tool",
    risk_tier: str = "write",
    issuer: str = "urn:hivemind:issuer:self",
    subject: Any = None,
    trace_id: str | None = None,
    extensions: dict[str, Any] | None = None,
) -> EmittedReceipt:
    """Emit a signed pre-action `intent` receipt capsule."""
    ext = dict(extensions or {})
    ext["io.hivemind.phase"] = "intent"
    extra: dict[str, Any] = {"extensions": ext}
    if trace_id:
        extra["causality"] = {"trace_id": trace_id}

    capsule_dict, capsule_bytes, disclosure_dict = build_capsule(
        agent={"key_thumbprint": agent},
        principal_subject=subject if subject is not None else {"actor_id": agent},
        method=method,
        kind=kind,
        risk_tier=risk_tier,
        request_args=args if args is not None else {},
        verdict="executed",
        observed_response={"phase": "intent", "method": method},
        disposition={"authority": issuer},
        **extra,
    )
    action_id = str(capsule_dict["action_id"])
    stmt = cose_sign1(
        signer,
        capsule_bytes,
        content_type=CAPSULE_MEDIA_TYPE,
        cwt=(issuer, action_id, int(time.time())),
    )
    return EmittedReceipt(
        capsule=capsule_dict,
        capsule_bytes=capsule_bytes,
        statement=stmt,
        capsule_id=str(capsule_dict["capsule_id"]),
        action_id=action_id,
        disclosure=disclosure_dict,
    )


def outcome(
    *,
    signer: ReceiptSigner,
    agent: str,
    method: str,
    args: Any = None,
    verdict: str = "executed",
    response: Any = None,
    intent_receipt: EmittedReceipt | None = None,
    intent_digest: str | None = None,
    kind: str = "tool",
    risk_tier: str = "write",
    issuer: str = "urn:hivemind:issuer:self",
    subject: Any = None,
    trace_id: str | None = None,
    extensions: dict[str, Any] | None = None,
) -> EmittedReceipt:
    """Emit a signed post-action `outcome` receipt capsule linked to a prior `intent`."""
    linked_digest = intent_digest or (intent_receipt.capsule_id if intent_receipt else None)
    ext = dict(extensions or {})
    ext["io.hivemind.phase"] = "outcome"
    if linked_digest:
        ext["io.hivemind.intent_digest"] = linked_digest

    causality: dict[str, Any] = {}
    if trace_id:
        causality["trace_id"] = trace_id
    if linked_digest:
        causality["parent_capsule_ids"] = [linked_digest]

    extra: dict[str, Any] = {"extensions": ext}
    if causality:
        extra["causality"] = causality

    observed = (response if response is not None else {"status": "ok"}) if verdict == "executed" else None

    capsule_dict, capsule_bytes, disclosure_dict = build_capsule(
        agent={"key_thumbprint": agent},
        principal_subject=subject if subject is not None else {"actor_id": agent},
        method=method,
        kind=kind,
        risk_tier=risk_tier,
        request_args=args if args is not None else {},
        verdict=verdict,
        observed_response=observed,
        disposition={"authority": issuer},
        **extra,
    )
    action_id = str(capsule_dict["action_id"])
    stmt = cose_sign1(
        signer,
        capsule_bytes,
        content_type=CAPSULE_MEDIA_TYPE,
        cwt=(issuer, action_id, int(time.time())),
    )
    return EmittedReceipt(
        capsule=capsule_dict,
        capsule_bytes=capsule_bytes,
        statement=stmt,
        capsule_id=str(capsule_dict["capsule_id"]),
        action_id=action_id,
        disclosure=disclosure_dict,
    )


def confirm(
    *,
    signer: ReceiptSigner,
    capsule_id: str,
    system: str,
    event: str,
    state: str,
    object_id: str | None = None,
    at: str | None = None,
    evidence_kind: str = "connector_observation",
    evidence_digest: str | None = None,
    level: str = "W2",
    witness: str | None = None,
    fields: dict[str, Any] | None = None,
) -> EmittedConfirmation:
    """Emit a signed external `confirmation` statement (`urn:hivemind:receipts:confirmation:1`)."""
    at_iso = at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ev_digest = evidence_digest or digest_of(f"{system}:{event}:{state}".encode("utf-8"))
    witness_uri = witness or f"urn:hivemind:witness:{system}"
    obs: dict[str, Any] = {"event": event, "state": state, "at": at_iso}
    if object_id:
        obs["object_id"] = object_id
    if fields:
        obs["fields"] = fields

    payload: dict[str, Any] = {
        "profile": CONFIRMATION_PROFILE_URI,
        "capsule_id": capsule_id,
        "source": {"system": system},
        "observation": obs,
        "evidence": {"kind": evidence_kind, "digest": ev_digest},
        "level": level,
        "witness": witness_uri,
    }
    stmt = cose_sign1(
        signer,
        dumps(payload),
        content_type=CONFIRMATION_MEDIA_TYPE,
        cwt=(witness_uri, capsule_id, int(time.time())),
    )
    return EmittedConfirmation(
        payload=payload,
        statement=stmt,
        confirmation_digest=digest_of(stmt),
    )


def _resolve_verifier_key(key_or_signer: Any) -> tuple[Any, int]:
    """Extract (pub, alg) from a COSE key dict/bytes, Signer, or raw public key."""
    if hasattr(key_or_signer, "cose_key") and callable(key_or_signer.cose_key):
        _, alg, pub = public_from_cose_key(loads(key_or_signer.cose_key()))
        return pub, alg
    if isinstance(key_or_signer, (bytes, bytearray)) and len(key_or_signer) == 32:
        return bytes(key_or_signer), -8
    if isinstance(key_or_signer, dict):
        _, alg, pub = public_from_cose_key(key_or_signer)
        return pub, alg
    if isinstance(key_or_signer, tuple) and len(key_or_signer) == 2:
        return key_or_signer, -7
    raise ValueError("Unsupported verifier_public_key format")


def verify(
    statement: bytes,
    *,
    trust_roots: TrustRoots | None = None,
    verifier_public_key: Any = None,
    checkpoint: str | None = None,
    disclosure: dict[str, Any] | None = None,
    expected_capsule_id: str | None = None,
) -> UnifiedVerifyResult:
    """Offline verification of a receipt bundle or confirmation statement."""
    try:
        parsed: ParsedSign1 = parse_sign1(statement)
    except Exception as exc:
        return UnifiedVerifyResult(
            ok=False,
            verdict="FAILED",
            kind="receipt",
            reason=f"cose_parse_failed: {exc}",
        )

    content_type = str(parsed.prot.get(3, ""))
    if "confirmation" in content_type:
        if verifier_public_key is None:
            return UnifiedVerifyResult(
                ok=False,
                verdict="FAILED",
                kind="confirmation",
                reason="missing verifier_public_key for confirmation statement",
            )
        try:
            pub, alg = _resolve_verifier_key(verifier_public_key)
            sig_ok = alg == parsed.alg and verify_sign1(parsed, pub, alg)
        except Exception as exc:
            return UnifiedVerifyResult(
                ok=False,
                verdict="FAILED",
                kind="confirmation",
                reason=f"confirmation signature verification error: {exc}",
            )
        if not sig_ok:
            return UnifiedVerifyResult(
                ok=False,
                verdict="FAILED",
                kind="confirmation",
                reason="confirmation COSE_Sign1 signature invalid",
            )
        if not parsed.payload:
            return UnifiedVerifyResult(
                ok=False,
                verdict="FAILED",
                kind="confirmation",
                reason="confirmation payload missing",
            )
        decoded = loads(parsed.payload)
        if not isinstance(decoded, dict) or decoded.get("profile") != CONFIRMATION_PROFILE_URI:
            return UnifiedVerifyResult(
                ok=False,
                verdict="FAILED",
                kind="confirmation",
                reason="invalid confirmation profile",
            )
        if expected_capsule_id and decoded.get("capsule_id") != expected_capsule_id:
            return UnifiedVerifyResult(
                ok=False,
                verdict="FAILED",
                kind="confirmation",
                reason="confirmation capsule_id mismatch",
            )
        return UnifiedVerifyResult(
            ok=True,
            verdict="VERIFIED",
            kind="confirmation",
            confirmation=decoded,
        )

    if trust_roots is not None:
        report = verify_receipt(
            statement,
            trust_roots,
            checkpoint_text=checkpoint,
            disclosure=disclosure,
        )
        capsule_obj = parse_capsule(parsed.payload) if parsed.payload else None
        return UnifiedVerifyResult(
            ok=report.get("verdict") == "VERIFIED",
            verdict=str(report.get("verdict", "FAILED")),
            kind="receipt",
            capsule=capsule_obj,
            report=report,
        )

    if verifier_public_key is not None:
        try:
            pub, alg = _resolve_verifier_key(verifier_public_key)
            sig_ok = alg == parsed.alg and verify_sign1(parsed, pub, alg)
            capsule_obj = parse_capsule(parsed.payload) if (sig_ok and parsed.payload) else None
            if sig_ok and disclosure is not None and capsule_obj is not None:
                if not verify_disclosure(capsule_obj, disclosure):
                    return UnifiedVerifyResult(
                        ok=False,
                        verdict="FAILED",
                        kind="receipt",
                        capsule=capsule_obj,
                        reason="disclosure verification failed",
                    )
        except Exception as exc:
            return UnifiedVerifyResult(
                ok=False,
                verdict="FAILED",
                kind="receipt",
                reason=f"receipt verification error: {exc}",
            )
        return UnifiedVerifyResult(
            ok=sig_ok,
            verdict="VERIFIED" if sig_ok else "FAILED",
            kind="receipt",
            capsule=capsule_obj,
            reason=None if sig_ok else "COSE_Sign1 signature invalid",
        )

    return UnifiedVerifyResult(
        ok=False,
        verdict="FAILED",
        kind="receipt",
        reason="either trust_roots or verifier_public_key is required",
    )


__all__ = [
    "CAPSULE_MEDIA_TYPE",
    "CAPSULE_PROFILE_URI",
    "CONFIRMATION_MEDIA_TYPE",
    "CONFIRMATION_PROFILE_URI",
    "Ed25519Signer",
    "EmittedConfirmation",
    "EmittedReceipt",
    "Es256Signer",
    "ReceiptsClient",
    "TrustRoots",
    "UnifiedVerifyResult",
    "confirm",
    "digest_of",
    "intent",
    "load_trust_file",
    "outcome",
    "salted_commitment",
    "verify",
    "verify_receipt",
    "verify_via_rust_core",
]
