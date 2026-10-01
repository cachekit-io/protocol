#!/usr/bin/env python3
"""Mutation tests: the interop/v2 vectors fail a reader that computes the ratio product in 32 bits.

The spec's >=64-bit rule is only enforceable if some published vector fails a reader
that breaks it. Until fixture 1.1.0 none did: every interop-v2 vector was under 300 B,
and a 32-bit product goes wrong only from 2,147,484 B (signed) or 4,294,968 B (unsigned).
So this suite swaps the reference reader's ratio check for four non-conforming ones
(three 32-bit products, and a 32-bit product behind a fast path that accepts
original_size <= payload_len) and checks two things for each:
  - every hex-pinned container, reject and encryption-plaintext vector still passes
    (the gap was real; the AAD and crypto-reject groups never reach the product), and
  - `lz4_ratio_product_wraps_32_bits` fails, by name.
It also drops that vector, substitutes one whose declared payload_len lies about a small
payload, a method-0 container of the same size (which never reaches the ratio bound), and
a literals-only block of the same size (whose original is smaller than its payload, so the
fast path passes it), and checks the coverage guard in _self_check fires on all four.
Last, it checks the seam's own comparison directly, one byte either side of 1000:1. No
real-bytes vector can do that (LZ4 expands at most about 255:1), so without it a reader
with no ratio check, or a strict `<`, would pass every vector here.
It also feeds the LZ4 block decoder two blocks that each break one LZ4 end-of-block rule,
and checks both are rejected by name while a short literals-only block still decodes.
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


def overflow_rejects(original: int, n: int) -> bool:
    """Rejects on 32-bit overflow instead of widening (`checked_mul` on u32 + REJECT)."""
    product = iv2.MAX_RATIO * n
    if product >= U32:
        raise iv2.V2Error("ratio product overflows u32")
    return original <= product


u32 = iv2.ratio_bound_u32_wrapped

# name -> non-conforming ratio check; each must disagree with the real one at the vector.
MUTANTS: dict[str, Callable[[int, int], bool]] = {
    "u32 wrap": lambda original, n: original <= u32(n),
    "i32 wrap": lambda original, n: original <= (iv2.MAX_RATIO * n + (1 << 31)) % U32 - (1 << 31),
    "u32 reject-on-overflow": overflow_rejects,
    # Only a vector whose original is larger than its payload catches this one.
    "u32 wrap after an original <= payload fast path": lambda original, n: original <= n or original <= u32(n),
}


def ratio_edge_failures(built: dict) -> list[str]:
    """The ratio bound one byte either side of 1000:1, read with whatever within_ratio is patched in."""
    payload = bytes.fromhex(next(c for c in built["container_vectors"] if c["name"] == "lz4_roundtrip_compressible")["payload_hex"])
    edge = iv2.MAX_RATIO * len(payload)
    failures = []
    for original, must_reject in ((edge + 1, True), (edge, False)):
        # Neither size is the payload's real one, so both reject; only the reason differs.
        try:
            iv2.decode_container(iv2.encode_container(iv2.METHOD_LZ4_BLOCK, original, payload))
            reason = ""
        except iv2.V2Error as e:
            reason = str(e)
        if ("compression ratio exceeds" in reason) != must_reject:
            failures.append(f"original_size {original} ({'over' if must_reject else 'at'} 1000:1): got {reason!r}")
    return failures


# name -> a seam whose comparison is wrong but which no vector catches.
SEAM_MUTANTS: dict[str, Callable[[int, int], bool]] = {
    "no ratio check": lambda _original, _n: True,
    "strict < at exactly 1000:1": lambda original, n: original < iv2.MAX_RATIO * n,
}


# LZ4 end-of-block rules. Each block is valid LZ4 except for the one rule it names, so a
# decoder that skips that rule decodes it to `original`. liblz4 rejects both blocks.
# A: 14 literals, a 10-byte match at offset 10 ending at byte 24, 2 literals (26 bytes).
EOB_A = bytes([0xE6]) + bytes(range(14)) + b"\x0a\x00" + bytes([0x20]) + b"\xfe\xff"
EOB_A_ORIGINAL = bytes(range(14)) + bytes(range(4, 14)) + b"\xfe\xff"
# B: 11 literals, a 4-byte match at offset 1 starting at byte 11, 7 literals (22 bytes).
EOB_B = bytes([0xB0]) + b"A" * 11 + b"\x01\x00" + bytes([0x70]) + b"BCDEFGH"
EOB_B_ORIGINAL = b"A" * 15 + b"BCDEFGH"
EOB_CASES = [
    ("block A (last 5 bytes must be literals)", EOB_A, EOB_A_ORIGINAL, "last 5 bytes"),
    ("block B (last match must start >= 12 bytes before the end)", EOB_B, EOB_B_ORIGINAL, "within 12 bytes"),
]


def end_of_block_failures() -> list[str]:
    """Both rule-breaking blocks are rejected by name; a short literals-only block still decodes."""
    failures = []
    for name, block, original, needle in EOB_CASES:
        try:
            iv2.lz4_block_decompress(block, len(original))
            failures.append(f"{name}: decoded, but it breaks an LZ4 end-of-block rule")
        except iv2.V2Error as e:
            if needle not in str(e):
                failures.append(f"{name}: raised, but message lacks {needle!r}: {e}")
    short = b"twelve bytes"  # under 13 bytes: too short for any match, still valid as literals
    try:
        if iv2.lz4_block_decompress(iv2.lz4_block_compress(short), len(short)) != short:
            failures.append("short literals-only block: decoded to the wrong bytes")
    except iv2.V2Error as e:
        failures.append(f"short literals-only block: rejected: {e}")
    return failures


def assert_hex_vectors_pass(built: dict) -> None:
    """Container, reject and encryption-plaintext vectors, read with whatever within_ratio is patched in."""
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
        with patch.object(iv2, "within_ratio", mutant):
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
    if failure := self_check_fails(dropped, "no constructed vector fails every 32-bit ratio reader"):
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
    if failure := self_check_fails(method0, "no constructed vector fails every 32-bit ratio reader"):
        results.append(f"method-0 container at the threshold: {failure}")

    # A literals-only block of the same size (the pre-1.3.0 vector) decodes to slightly
    # less than its payload, so the fast-path reader passes it; nor may it satisfy the guard.
    ext, last = divmod(n - 17, 256)
    original = 15 + 255 * ext + last
    value_head = "c6" + (original - 5).to_bytes(4, "big").hex()
    head = iv2.encode_container(iv2.METHOD_LZ4_BLOCK, original, b"")[:-2].hex() + "c6" + n.to_bytes(4, "big").hex()
    literals_only = copy.deepcopy(built)
    literals_only["constructed_container_vectors"] = [{
        **built["constructed_container_vectors"][0],
        "original_size": original,
        "container_len": len(head) // 2 + n,
        "container_construction": [
            {"hex": head + "f0", "count": 1},
            {"hex": "ff", "count": ext},
            {"hex": f"{last:02x}{value_head}", "count": 1},
            {"hex": "00", "count": original - 5},
        ],
        "value_construction": [{"hex": value_head, "count": 1}, {"hex": "00", "count": original - 5}],
    }]
    with patch.object(iv2, "within_ratio", MUTANTS["u32 wrap after an original <= payload fast path"]):
        try:
            iv2.decode_container(iv2.construct(literals_only["constructed_container_vectors"][0]["container_construction"]))
        except iv2.V2Error as e:
            results.append(f"literals-only block: the fast-path reader rejects it, so the case proves nothing: {e}")
    if failure := self_check_fails(literals_only, "no constructed vector fails every 32-bit ratio reader"):
        results.append(f"literals-only block at the threshold: {failure}")

    results.extend(end_of_block_failures())
    results.extend(f"conforming reader at the 1000:1 edge: {f}" for f in ratio_edge_failures(built))
    for name, mutant in SEAM_MUTANTS.items():
        with patch.object(iv2, "within_ratio", mutant):
            if not ratio_edge_failures(built):
                results.append(f"{name}: the 1000:1 edge check does not catch it")

    failures = [f for f in results if f]
    if failures:
        sys.exit("\n".join(f"FAIL {f}" for f in failures))
    logging.info(
        "interop-v2 mutation suite: %d 32-bit readers and %d seam mutants caught, coverage guard fires, "
        "%d LZ4 end-of-block breaks rejected",
        len(MUTANTS),
        len(SEAM_MUTANTS),
        len(EOB_CASES),
    )
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    sys.exit(main())
