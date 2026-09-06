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

    bad_depth = copy.deepcopy(good)
    bad_depth["reject_vectors"][0]["nesting_depth"] = 5  # tagged 'depth' but no longer deeper than the ceiling
    results.append(expect_raises("depth tag", with_recipes(bad_depth), "depth tag mismatch"))

    bad_slots = copy.deepcopy(good)
    bad_slots["reject_vectors"][-1]["declared_slots"] = 1  # tagged 'overclaim' but no longer over-claims
    results.append(expect_raises("overclaim tag", with_recipes(bad_slots), "overclaim tag mismatch"))

    deep_accept = copy.deepcopy(good)
    deep_accept["accept_vectors"][0]["nesting_depth"] = dbr.MIN_DEPTH_FLOOR + 1
    results.append(expect_raises("accept floor", with_recipes(deep_accept), "deeper than the floor"))

    results.append(expect_raises("require-extras", with_msgpack(None, good, require_extras=True), "not importable"))
    results.append(expect_raises("decoded reject", with_msgpack(lambda _: None, good), "decoded a reject vector"))
    results.append(expect_raises("OOM not counted as reject", with_msgpack(raise_memory_error, good), "violated failure_mode"))
    results.append(cli_rejects("flag typo", "verify", "--require-extra"))
    results.append(cli_rejects("unknown mode", "bogus"))
    results.append(cli_rejects("two modes", "verify", "generate"))
    results.append(cli_rejects("generate with extras", "generate", "--require-extras"))

    failures = [f for f in results if f]
    if failures:
        sys.exit("\n".join(f"FAIL {f}" for f in failures))  # stderr + exit 1, the tool's own fatal path
    logging.info("decode-bounds mutation suite: %d guards fire as required", len(results))


if __name__ == "__main__":
    # stdout, message-only: the same handler decode-bounds-reference.py installs.
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    main()
