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
    cut_accept["accept_vectors"][1] = dbr.recipe("array16_256_backed_nils", "", "dc" + dbr.u16(256), 1, "c0" * 255,
                                                 depth=1, slots=256, reasons=[])
    del cut_accept["accept_vectors"][1]["reject_reasons"]
    results.append(expect_raises("accept complete", with_recipes(cut_accept), "not one complete document"))

    # Coverage: drop every vector that separates each near-miss reader and watch its guard fire.
    def without(test: Callable[[dict, dict], bool]) -> dict:
        doc = copy.deepcopy(good)
        doc["reject_vectors"] = [v for v in doc["reject_vectors"]
                                 if not test(v, dbr.walk(bytes.fromhex(v["input_hex"])))]
        return doc
    results.append(expect_raises("coverage: sum", with_recipes(without(
        lambda v, w: w["per_header_fits"] and v["reject_reasons"] == ["overclaim"])), "whole-document sum"))
    results.append(expect_raises("coverage: u32", with_recipes(without(
        lambda v, w: w["u32_sum_fits"])), "32-bit running sum"))
    results.append(expect_raises("coverage: depth", with_recipes(without(
        lambda v, w: v["nesting_depth"] == dbr.MAX_DEPTH_CEILING + 1)), "one level past the depth ceiling"))

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
