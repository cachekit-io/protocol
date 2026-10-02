#!/usr/bin/env python3
"""Mutation tests for decode-bounds-reference.py's fail-closed guards.

Same doctrine as test_wire_format_reference.py: poison the input and watch each guard
fire, so a guard that degrades to always-pass is caught before `verify` is trusted.
Nothing here touches test-vectors/decode-bounds.json.

Run: python3 tools/test_decode_bounds_reference.py     (exit 1 on any failure)
"""

from __future__ import annotations

import copy
import importlib.util
import logging
import subprocess
import sys
import types
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

TOOL = Path(__file__).resolve().parent / "decode-bounds-reference.py"
SPEC = importlib.util.spec_from_file_location("dbr", TOOL)
dbr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dbr)


def expect_raises(name: str, fn: Callable[[], object], needle: str) -> str | None:
    try:
        fn()
    except ValueError as e:
        return None if needle in str(e) else f"{name}: raised but message lacks {needle!r}: {e}"
    return f"{name}: did not raise"


def with_recipes(doc: dict) -> Callable[[], object]:
    """Run verify() with build() patched to agree with `doc`, so only the tag checks stand."""
    def run() -> object:
        with patch.object(dbr, "build", lambda: copy.deepcopy(doc)):
            return dbr.verify(doc)
    return run


def with_msgpack(unpackb: Callable[[bytes], object] | None, doc: dict, *, require_extras: bool = False) -> Callable[[], object]:
    """Run verify() against a fake msgpack module (None = import blocked)."""
    def run() -> object:
        fake = None
        if unpackb is not None:
            fake = types.ModuleType("msgpack")
            fake.unpackb, fake.version = unpackb, (0, 0, 0)
        with patch.dict(sys.modules, {"msgpack": fake}):
            return dbr.verify(doc, require_extras=require_extras)
    return run


def raise_memory_error(_: bytes) -> None:
    raise MemoryError


def raise_value_error(_: bytes) -> None:
    raise ValueError("stock limit")  # noqa: TRY003


# hex -> (nesting_depth, declared_slots, complete, array_depth): one row per framing rule walk() implements.
WALK_TABLE = {
    "05": (0, 0, True, 0),                       # positive fixint
    "7f": (0, 0, True, 0),                       # last positive fixint, not a fixmap
    "e0": (0, 0, True, 0),                       # negative fixint
    "a3616263": (0, 3, True, 0),                 # fixstr: length in the type byte
    "a1ff": (0, 1, True, 0),                     # framing only: invalid UTF-8 is still complete
    "b0" + "41" * 16: (0, 16, True, 0),          # fixstr mask 0x1f
    "d90141": (0, 1, True, 0),                   # str8
    "c403010203": (0, 3, True, 0),               # bin8
    "c702054142": (0, 2, True, 0),               # ext8: length, type byte, payload
    "d40100": (0, 0, True, 0),                   # fixext1 declares no slots
    "d801" + "00" * 16: (0, 0, True, 0),         # fixext16
    "cf" + "00" * 8: (0, 0, True, 0),            # uint64
    "ca00000000": (0, 0, True, 0),               # float32
    "cb" + "00" * 8: (0, 0, True, 0),            # float64
    "cc00": (0, 0, True, 0),                     # uint8
    "cd0000": (0, 0, True, 0),                   # uint16
    "ce00000000": (0, 0, True, 0),               # uint32
    "d000": (0, 0, True, 0),                     # int8
    "d10000": (0, 0, True, 0),                   # int16
    "d200000000": (0, 0, True, 0),               # int32
    "d3" + "00" * 8: (0, 0, True, 0),            # int64
    "d5" + "00" * 3: (0, 0, True, 0),            # fixext2: type byte + 2
    "d6" + "00" * 5: (0, 0, True, 0),            # fixext4
    "d7" + "00" * 9: (0, 0, True, 0),            # fixext8
    "cf00": (0, 0, False, 0),                    # fixed payload cut short
    "90": (1, 0, True, 1),                       # empty array still counts a level
    "81a0c0": (1, 2, True, 0),                   # fixmap: one level, two slots
    "8f": (1, 30, False, 0),                     # fixmap mask 0x0f
    "9181a0c0": (2, 3, True, 1),                 # map inside array: array_depth counts arrays only
    "81a091c0": (2, 3, True, 1),                 # array inside map: an open map is not an open array
    "9291c091c0": (2, 4, True, 2),               # sibling arrays: a closed array leaves the count
    "92dc0000": (2, 2, False, 2),                # truncated with the sum inside the budget
    "dc00": (0, 0, False, 0),                    # length field cut short
    "c0c0": (0, 0, False, 0),                    # trailing byte: not one document
}


# hex -> (per_header_fits, u32_add_fits, u32_mul_fits): the near-miss models on their boundaries.
FLAG_TABLE = {
    "92c0c0": (True, True, True),                # backed: every model passes
    "93c0c0": (False, False, False),             # claim 3 fits len 3, not the 2 bytes after the header
    "91ddffffffff": (False, True, False),        # running sum 1 + (2^32 - 1) wraps to 0
    "df80000000": (False, False, True),          # map term 2 x 2^31 wraps to 0 in 32 bits
    "ddffffffffdd00000001": (False, False, False),  # the first term alone exceeds the budget
}


def walk_table() -> list[str | None]:
    out: list[str | None] = []
    for hx, want in WALK_TABLE.items():
        w = dbr.walk(bytes.fromhex(hx))
        got = (w["nesting_depth"], w["declared_slots"], w["complete"], w["array_depth"])
        out.append(None if got == want else f"walk {hx}: {got} != {want}")
    for hx, want in FLAG_TABLE.items():
        w = dbr.walk(bytes.fromhex(hx))
        got = (w["per_header_fits"], w["u32_add_fits"], w["u32_mul_fits"])
        out.append(None if got == want else f"walk flags {hx}: {got} != {want}")
    out.append(expect_raises("walk 0xc1", lambda: dbr.walk(b"\xc1"), "never used"))
    return out


def cli_rejects(name: str, *args: str) -> str | None:
    """The CLI must exit non-zero on anything it does not understand (fail closed)."""
    rc = subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, check=False).returncode
    return None if rc != 0 else f"{name}: exit 0 for {args}"


def main() -> None:
    good = dbr.build()
    results: list[str | None] = []

    dbr.verify(good)  # baseline: the real recipes pass

    drifted = copy.deepcopy(good)
    drifted["reject_vectors"][0]["input_hex"] = "c0" + drifted["reject_vectors"][0]["input_hex"][2:]
    results.append(expect_raises("file drift", lambda: dbr.verify(drifted), "differs from the recipes"))

    lied_depth = copy.deepcopy(good)
    lied_depth["reject_vectors"][0]["nesting_depth"] = 5  # hand-entered tag disagrees with the bytes
    results.append(expect_raises("depth vs walk", with_recipes(lied_depth), "nesting_depth differs from the walk"))

    lied_slots = copy.deepcopy(good)
    lied_slots["reject_vectors"][-1]["declared_slots"] = 1
    results.append(expect_raises("slots vs walk", with_recipes(lied_slots), "declared_slots differs from the walk"))

    bad_depth = copy.deepcopy(good)
    bad_depth["reject_vectors"][0]["reject_reasons"] = ["overclaim"]  # nests past the ceiling, untagged
    results.append(expect_raises("depth tag", with_recipes(bad_depth), "depth tag mismatch"))

    complete = copy.deepcopy(good)  # the truncated fixarray made whole, still tagged 'overclaim'
    complete["reject_vectors"][-1] = dbr.recipe("fixarray_short_by_one", "", "95", 1, "c0" * 5,
                                                depth=1, slots=5, reasons=["overclaim"])
    results.append(expect_raises("overclaim tag", with_recipes(complete), "overclaim tag mismatch"))

    deep_accept = copy.deepcopy(good)
    deep_accept["accept_vectors"][0] = dbr.recipe("nested_fixarray_depth_33", "", "91", dbr.MIN_DEPTH_FLOOR + 1, "c0",
                                                  depth=dbr.MIN_DEPTH_FLOOR + 1, slots=dbr.MIN_DEPTH_FLOOR + 1, reasons=[])
    del deep_accept["accept_vectors"][0]["reject_reasons"]
    results.append(expect_raises("accept floor", with_recipes(deep_accept), "deeper than the floor"))

    cut_accept = copy.deepcopy(good)
    at = next(i for i, v in enumerate(cut_accept["accept_vectors"]) if v["name"] == "array16_256_backed_nils")
    cut_accept["accept_vectors"][at] = dbr.recipe("array16_256_backed_nils", "", "dc" + dbr.u16(256), 1, "c0" * 255,
                                                 depth=1, slots=256, reasons=[])
    del cut_accept["accept_vectors"][at]["reject_reasons"]
    results.append(expect_raises("accept complete", with_recipes(cut_accept), "not one complete document"))

    untagged = copy.deepcopy(good)  # a complete document filed as a reject vector with no reason
    untagged["reject_vectors"].append(dbr.recipe("fixarray_untagged", "", "91", 1, "c0", depth=1, slots=1, reasons=[]))
    def untagged_stdlib() -> object:
        with patch.object(dbr, "build", lambda: copy.deepcopy(untagged)):
            return with_msgpack(None, untagged)()
    results.append(expect_raises("empty reject_reasons", untagged_stdlib, "no reject_reasons"))

    # Coverage: dropping exactly one discriminating vector must fire its guard.
    def without(name: str, *twins: dict) -> dict:
        doc = copy.deepcopy(good)
        kept = [v for v in doc["reject_vectors"] if v["name"] != name]
        if len(kept) != len(doc["reject_vectors"]) - 1:
            sys.exit(f"FAIL coverage test names no vector: {name}")  # a typo must not pass vacuously
        doc["reject_vectors"] = kept + list(twins)
        return doc
    for name, needle in (("nested_array16_each_header_fits_sum_overclaims", "per-header checks pass"),
                         ("array32_sum_wraps_u32_small_first", "32-bit running sum"),
                         ("map32_half_claim_wraps_u32_mul", "map term computed in 32 bits"),
                         ("nested_fixarray_depth_1025_complete", "complete array spine"),
                         ("nested_fixmap_depth_1025_complete", "complete map spine")):
        results.append(expect_raises(f"coverage: drop {name}", with_recipes(without(name)), needle))

    # Each coverage refinement must bind: swap the vector for a twin that breaks only that refinement.
    a16 = "dc" + dbr.u16(2000)
    ceil = dbr.MAX_DEPTH_CEILING
    for name, twin, needle in (
        ("nested_array16_each_header_fits_sum_overclaims",  # per-header fits, but one level deep
         dbr.recipe("t", "", "92", 1, "a1c0", depth=1, slots=3, reasons=["overclaim"]), "per-header checks pass"),
        ("nested_array16_each_header_fits_sum_overclaims",  # per-header fits, but at the depth floor
         dbr.recipe("t", "", a16, dbr.MIN_DEPTH_FLOOR, "c0" * 2000, depth=dbr.MIN_DEPTH_FLOOR,
                    slots=dbr.MIN_DEPTH_FLOOR * 2000, reasons=["overclaim"]), "per-header checks pass"),
        ("nested_fixarray_depth_1025_complete",  # a trailing byte: not one complete document
         dbr.recipe("t", "", "91", ceil + 1, "c0c0", depth=ceil + 1, slots=ceil + 1, reasons=["depth"]),
         "complete array spine"),
        ("nested_fixmap_depth_1025_complete",
         dbr.recipe("t", "", "81a0", ceil + 1, "c0c0", depth=ceil + 1, slots=2 * (ceil + 1), reasons=["depth"]),
         "complete map spine"),
        ("nested_fixmap_depth_1025_complete",  # complete, but two levels past the ceiling
         dbr.recipe("t", "", "81a0", ceil + 2, "c0", depth=ceil + 2, slots=2 * (ceil + 2), reasons=["depth"]),
         "complete map spine"),
    ):
        results.append(expect_raises(f"coverage: twin of {name}", with_recipes(without(name, twin)), needle))

    # Negative controls: a near-miss model forced to always pass must be caught.
    real_walk = dbr.walk
    for flag in ("per_header_fits", "u32_add_fits", "u32_mul_fits"):
        def forced(data: bytes, flag: str = flag) -> dict:
            return {**real_walk(data), flag: True}
        with patch.object(dbr, "walk", forced):
            results.append(expect_raises(f"control: {flag} always true", with_recipes(good), "the model is vacuous"))

    results.extend(walk_table())

    results.append(expect_raises("require-extras", with_msgpack(None, good, require_extras=True), "not importable"))
    results.append(expect_raises("decoded reject", with_msgpack(lambda _: None, good), "decoded a reject vector"))
    results.append(expect_raises("OOM not counted as reject", with_msgpack(raise_memory_error, good), "violated failure_mode"))
    results.append(expect_raises("rejected accept", with_msgpack(raise_value_error, good), "rejected an accept vector"))
    results.append(cli_rejects("flag typo", "verify", "--require-extra"))
    results.append(cli_rejects("unknown mode", "bogus"))
    results.append(cli_rejects("two modes", "verify", "generate"))

    failures = [f for f in results if f]
    if failures:
        sys.exit("\n".join(f"FAIL {f}" for f in failures))  # stderr + exit 1, the tool's own fatal path
    logging.info("decode-bounds mutation suite: %d guards fire as required", len(results))


if __name__ == "__main__":
    # stdout, message-only: the same handler decode-bounds-reference.py installs.
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    main()
