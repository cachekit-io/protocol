#!/usr/bin/env python3
"""Mutation tests: the interop/v2 vectors fail a reader that computes the ratio product in 32 bits.

The spec's >=64-bit rule is only enforceable if some published vector fails a reader
that breaks it. Until fixture 1.1.0 none did: every interop-v2 vector was under 300 B,
and a 32-bit product goes wrong only from 2,147,484 B (signed) or 4,294,968 B (unsigned).
So this suite swaps the reference reader's ratio product for three non-conforming ones
and checks two things for each:
  - every hex-pinned container, reject and encryption-plaintext vector still passes
    (the gap was real; the AAD and crypto-reject groups never reach the product), and
  - `lz4_ratio_product_wraps_32_bits` fails, by name.
It also drops that vector, substitutes one whose declared payload_len lies about a small
payload, and substitutes a method-0 container of the same size (which never reaches the
ratio bound), and checks the coverage guard in _self_check fires on all three.
Same doctrine as test_check_spec_duplication.py: a guard not shown to fail is no guard.
Nothing here touches test-vectors/interop-v2.json.

Run: python3 tools/test_interop_v2_reference.py     (exit 1 on any failure)
"""

from __future__ import annotations

import copy
import importlib.util
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

TOOL = Path(__file__).resolve().parent / "interop-v2-reference.py"
SPEC = importlib.util.spec_from_file_location("iv2", TOOL)
iv2 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(iv2)

VECTOR = "lz4_ratio_product_wraps_32_bits"
U32 = 1 << 32


def overflow_rejects(n: int) -> int:
    """Rejects on 32-bit overflow instead of widening (`checked_mul` on u32 + REJECT)."""
    product = iv2.MAX_RATIO * n
    if product >= U32:
        raise iv2.V2Error("ratio product overflows u32")
    return product


# name -> non-conforming ratio product; each must differ from the real one at the vector.
MUTANTS: dict[str, Callable[[int], int]] = {
    "u32 wrap": iv2.ratio_bound_u32_wrapped,
    "i32 wrap": lambda n: (iv2.MAX_RATIO * n + (1 << 31)) % U32 - (1 << 31),
    "u32 reject-on-overflow": overflow_rejects,
}


def assert_hex_vectors_pass(built: dict) -> None:
    """Container, reject and encryption-plaintext vectors, read with whatever ratio_bound is patched in."""
    for cv in built["container_vectors"]:
        got = iv2.decode_container(bytes.fromhex(cv["container_hex"]))
        iv2._require(got.hex() == cv["value_msgpack_hex"], f"{cv['name']} misdecoded")
    for rv in built["reject_vectors"]:
        iv2._expect_structural_reject(rv)
    iv2.decode_container(bytes.fromhex(built["encryption_vectors"][0]["plaintext_hex"]))


def self_check_fails(built: dict, needle: str) -> str | None:
    try:
        iv2._self_check(built)
    except (iv2.SelfCheckError, iv2.V2Error) as e:
        return None if needle in str(e) else f"raised, but message lacks {needle!r}: {e}"
    return "did not raise"


def main() -> int:
    built = iv2._build()
    results: list[str | None] = []

    try:
        iv2._self_check(built)
    except (iv2.SelfCheckError, iv2.V2Error) as e:
        sys.exit(f"FAIL baseline: unmutated self-check fails: {e}")

    for name, mutant in MUTANTS.items():
        with patch.object(iv2, "ratio_bound", mutant):
            try:
                assert_hex_vectors_pass(built)
            except (iv2.SelfCheckError, iv2.V2Error) as e:
                results.append(f"{name}: a hex-pinned vector already catches it, so the gap premise is wrong: {e}")
            if failure := self_check_fails(built, f"constructed vector {VECTOR} rejected"):
                results.append(f"{name}: {failure}")

    dropped = copy.deepcopy(built)
    dropped["constructed_container_vectors"] = [v for v in dropped["constructed_container_vectors"] if v["name"] != VECTOR]
    if len(dropped["constructed_container_vectors"]) == len(built["constructed_container_vectors"]):
        sys.exit(f"FAIL coverage test names no vector: {VECTOR}")  # a rename must not pass vacuously
    if failure := self_check_fails(dropped, "no constructed vector fails a reader"):
        results.append(f"drop {VECTOR}: {failure}")

    # A vector whose declared payload_len says "past the threshold" over a small real
    # payload must not satisfy the coverage guard: it is measured from the bytes.
    small = next(c for c in built["container_vectors"] if c["name"] == "lz4_roundtrip_compressible")
    liar = copy.deepcopy(built)
    liar["constructed_container_vectors"] = [{
        **built["constructed_container_vectors"][0],
        "original_size": small["original_size"],
        "container_len": len(small["container_hex"]) // 2,
        "container_construction": [{"hex": small["container_hex"], "count": 1}],
        "value_construction": [{"hex": small["value_msgpack_hex"], "count": 1}],
    }]
    if failure := self_check_fails(liar, "disagree with its bytes"):
        results.append(f"declared payload_len over a small payload: {failure}")

    # A method-0 container of the same size never reaches the ratio bound, so a 32-bit
    # reader passes it; it must not satisfy the coverage guard either.
    n = built["constructed_container_vectors"][0]["payload_len"]
    stored_value = [{"hex": "c6" + (n - 5).to_bytes(4, "big").hex(), "count": 1}, {"hex": "00", "count": n - 5}]
    stored = iv2.encode_container(iv2.METHOD_NONE, n, iv2.construct(stored_value))
    method0 = copy.deepcopy(built)
    method0["constructed_container_vectors"] = [{
        **built["constructed_container_vectors"][0],
        "method": iv2.METHOD_NONE,
        "original_size": n,
        "container_len": len(stored),
        "container_construction": [{"hex": stored[: len(stored) - n + 5].hex(), "count": 1}, stored_value[1]],
        "value_construction": stored_value,
    }]
    if failure := self_check_fails(method0, "no constructed vector fails a reader"):
        results.append(f"method-0 container at the threshold: {failure}")

    failures = [f for f in results if f]
    if failures:
        sys.exit("\n".join(f"FAIL {f}" for f in failures))
    logging.info("interop-v2 mutation suite: %d 32-bit readers caught, coverage guard fires", len(MUTANTS))
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    sys.exit(main())
