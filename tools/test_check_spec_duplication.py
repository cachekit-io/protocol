#!/usr/bin/env python3
"""Mutation tests for check-spec-duplication.py.

A drift guard that cannot be shown to FAIL is indistinguishable from a guard that
reports OK unconditionally -- and this one guards prose, where the plausible
mutation is a one-word edit to a single copy, not a structural break. So each case
below poisons a copy of the real spec tree and asserts the guard notices.

Run: python3 tools/test_check_spec_duplication.py     (exit 1 on any failure)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CHECKER = HERE / "check-spec-duplication.py"
WIRE = "spec/wire-format.md"
INTEROP = "spec/interop-v2.md"

# The obligation sentence, present in both copies -- the realistic drift target.
MUST = "The ratio product MUST be computed in **at least 64-bit unsigned integers**"


def edit(rel: str, old: str, new: str, *, once: bool = True) -> Callable[[Path], None]:
    def mutate(root: Path) -> None:
        path = root / rel
        text = path.read_text(encoding="utf-8")
        if text.count(old) < 1:
            raise SystemExit(f"test setup broken: {old!r} not in {rel}")
        path.write_text(text.replace(old, new, 1 if once else -1), encoding="utf-8")

    return mutate


def empty_block(rel: str, block_id: str) -> Callable[[Path], None]:
    """Delete every line strictly between the block's two sentinel lines."""

    def mutate(root: Path) -> None:
        path = root / rel
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        begin = next(i for i, ln in enumerate(lines) if f"BEGIN shared-block: {block_id}" in ln)
        end = next(i for i, ln in enumerate(lines) if f"END shared-block: {block_id}" in ln)
        path.write_text("".join(lines[: begin + 1] + lines[end:]), encoding="utf-8")

    return mutate


def swap_sentinels(rel: str, block_id: str) -> Callable[[Path], None]:
    def mutate(root: Path) -> None:
        path = root / rel
        text = path.read_text(encoding="utf-8")
        begin, end = f"BEGIN shared-block: {block_id}", f"END shared-block: {block_id}"
        text = text.replace(begin, "\0").replace(end, begin).replace("\0", end)
        path.write_text(text, encoding="utf-8")

    return mutate


RULE = "ratio-product-rule"
PSEUDO = "ratio-product-pseudocode"
DRIFT = "differs between"

# (name, mutate(root) -> None, expected exit, substring the output MUST contain)
# The substring pins WHICH branch fired: a case that exits 1 through the wrong
# branch would otherwise pass while the branch it names is dead code.
CASES: list[tuple[str, Callable[[Path], None], int, str]] = [
    ("unmodified tree", lambda _: None, 0, "OK — 2 shared block(s)"),
    # --- must be CAUGHT (exit 1) ---
    (
        "one copy weakened to 32-bit (the LAB-2594 bug, re-armed)",
        edit(INTEROP, "at least 64-bit unsigned integers", "at least 32-bit unsigned integers"),
        1,
        DRIFT,
    ),
    ("MUST downgraded to SHOULD in one copy", edit(WIRE, MUST, MUST.replace("MUST", "SHOULD")), 1, DRIFT),
    (
        "sentence deleted from one copy",
        edit(INTEROP, "The bound MUST be computed by **multiplication**.", ""),
        1,
        DRIFT,
    ),
    (
        "pseudocode widening reverted in one copy",
        edit(WIRE, "uint64(compressed_size)", "compressed_size"),
        1,
        f"shared-block '{PSEUDO}' differs",
    ),
    ("BEGIN sentinel removed", edit(WIRE, f"BEGIN shared-block: {RULE}", "x"), 1, "exactly 1 BEGIN sentinel"),
    ("END sentinel removed", edit(INTEROP, f"END shared-block: {RULE}", "x"), 1, "exactly 1 END sentinel"),
    ("END sentinel moved before BEGIN", swap_sentinels(WIRE, RULE), 1, "END sentinel precedes BEGIN"),
    ("whole block emptied in one copy", empty_block(WIRE, RULE), 1, "block is empty"),
    ("pseudocode block emptied in one copy", empty_block(INTEROP, PSEUDO), 1, "block is empty"),
    (
        # A global rename empties the operand out of the block, so the
        # normalisation has nothing to key on and MUST NOT be trusted.
        "operand renamed away so normalisation would key on nothing",
        edit(WIRE, "compressed_size", "csize", once=False),
        1,
        "never mentions its operand",
    ),
    (
        # A single in-block rename leaves the operand present but the prose
        # unequal -- the diff path, not the operand-missing path.
        "operand renamed at one site inside the block",
        edit(WIRE, "promote `compressed_size` to", "promote `csize` to"),
        1,
        DRIFT,
    ),
]


def run_case(name: str, mutate: Callable[[Path], None], expected: int, needle: str) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        (root / "spec").mkdir(parents=True)
        for rel in (WIRE, INTEROP):
            shutil.copyfile(ROOT / rel, root / rel)
        mutate(root)
        proc = subprocess.run(
            [sys.executable, str(CHECKER), str(root)],
            capture_output=True,
            text=True,
        )
    output = proc.stdout + proc.stderr
    if proc.returncode == expected and needle in output:
        print(f"  ok   {name} (exit {proc.returncode})")
        return True
    print(
        f"  FAIL {name}: expected exit {expected} with {needle!r}, got {proc.returncode}\n"
        f"       stdout: {proc.stdout.strip()}\n"
        f"       stderr: {proc.stderr.strip()[:300]}"
    )
    return False


def main() -> int:
    if not CHECKER.exists():
        print(f"checker not found: {CHECKER}", file=sys.stderr)
        return 1
    results = [run_case(*case) for case in CASES]
    failed = results.count(False)
    if failed:
        print(f"\n{failed}/{len(results)} mutation case(s) failed", file=sys.stderr)
        return 1
    print(f"\nall {len(results)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
