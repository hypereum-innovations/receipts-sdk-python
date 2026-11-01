# SPDX-License-Identifier: Apache-2.0
"""Hivemind Receipts — Python SDK (standard library only).

Offline Class-1 verification of SCITT agent-action receipts plus capsule
building and an HTTP registration client. Cryptographic verification
(ES256 and Ed25519) is implemented in pure Python on top of hashlib/hmac so
the verifier runs anywhere Python does, with no native dependencies.
"""
from .cbor import dumps, loads
from .capsule import build_capsule, parse_capsule, verify_disclosure
from .verify import verify_receipt, TrustRoots, load_trust_file
from .client import ReceiptsClient

__all__ = [
    "dumps", "loads", "build_capsule", "parse_capsule", "verify_disclosure",
    "verify_receipt", "TrustRoots", "load_trust_file", "ReceiptsClient",
]
__version__ = "0.1.0"
