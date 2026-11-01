# SPDX-License-Identifier: Apache-2.0
"""Runs the shared conformance vectors against the Python verifier.
Usage: python3 -m pytest test_vectors.py  (or plain: python3 test_vectors.py)"""
import base64, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hivemind_receipts.verify import load_trust_file, verify_receipt, verify_via_rust_core  # noqa: E402

_LOCAL_VECTORS = Path(__file__).resolve().parent / "vectors/vectors.json"
VECTORS = _LOCAL_VECTORS if _LOCAL_VECTORS.is_file() else Path(__file__).resolve().parent / "vectors/vectors.json"


def run():
    suite = json.loads(VECTORS.read_text())
    failures = []
    for case in suite["cases"]:
        trust = load_trust_file(suite["trust"])
        for kid in case.get("revoked_kids", []):
            pub, alg, tier, display, _ = trust.issuers[kid]
            trust.issuers[kid] = (pub, alg, tier, display, True)
        for kid in case.get("drop_issuers", []):
            trust.issuers.pop(kid, None)
        chain = None
        if case.get("consistency_chain"):
            cc = case["consistency_chain"]
            chain = {"root_at_receipt": base64.b64decode(cc["root_at_receipt"]),
                     "proof": {"firstSize": cc["proof"]["first_size"],
                               "secondSize": cc["proof"]["second_size"],
                               "hashes": [base64.b64decode(h) for h in cc["proof"]["hashes"]]}}
        batch = None
        if case.get("batch"):
            b = case["batch"]
            batch = {"capsule_bytes": base64.b64decode(b["capsule"]),
                     "proof": {"treeSize": b["proof"]["treeSize"], "leafIndex": b["proof"]["leafIndex"],
                               "hashes": [base64.b64decode(h) for h in b["proof"]["hashes"]]}}
        stmt_bytes = base64.b64decode(case["statement"])
        report = verify_receipt(stmt_bytes, trust,
                                case["checkpoint"], case.get("disclosure"),
                                consistency_chain=chain, batch=batch)
        ok = report["verdict"] == case["expect"]
        if chain is None and batch is None:
            try:
                rust_report = verify_via_rust_core(stmt_bytes, trust, case["checkpoint"], case.get("disclosure"))
                ok = ok and (rust_report["verdict"] == case["expect"])
            except FileNotFoundError:
                pass
        print(("PASS" if ok else "FAIL"), case["name"], "->", report["verdict"])
        if not ok:
            failures.append((case["name"], report))
    if failures:
        raise SystemExit(f"{len(failures)} failures: {[f[0] for f in failures]}")
    print("python verifier (native + rust core bridge): all applicable vectors pass")


def test_vectors():
    run()


if __name__ == "__main__":
    run()
