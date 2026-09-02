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


# (name, mutate(root) -> None, expected_exit)
CASES: list[tuple[str, Callable[[Path], None], int]] = [
    ("unmodified tree", lambda root: None, 0),
    # --- must be CAUGHT (exit 1) ---
    (
        "one copy weakened to 32-bit (the LAB-2594 bug, re-armed)",
        edit(INTEROP, "at least 64-bit unsigned integers", "at least 32-bit unsigned integers"),
        1,
    ),
    (
        "MUST downgraded to SHOULD in one copy",
        edit(WIRE, MUST, MUST.replace("MUST", "SHOULD")),
        1,
    ),
    (
        "sentence deleted from one copy",
        edit(
            INTEROP,
            "The bound MUST be computed by **multiplication**.",
            "",
        ),
        1,
    ),
    ("BEGIN sentinel removed", edit(WIRE, "<!-- BEGIN shared-block:", "<!-- x "), 1),
    ("END sentinel removed", edit(INTEROP, "<!-- END shared-block:", "<!-- x "), 1),
    (
        # A global rename empties the operand out of the block, so the
        # normalisation has nothing to key on and MUST NOT be trusted.
        "operand renamed away so normalisation would key on nothing",
        edit(WIRE, "compressed_size", "csize", once=False),
        1,
    ),
    (
        # A single in-block rename leaves the operand present but the prose
        # unequal -- the diff path, not the operand-missing path.
        "operand renamed at one site inside the block",
        edit(WIRE, "promote `compressed_size` to", "promote `csize` to"),
        1,
    ),
    ("whole block emptied in one copy", edit(WIRE, MUST, ""), 1),
]


def run_case(name: str, mutate: Callable[[Path], None], expected: int) -> bool:
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
    if proc.returncode == expected:
        print(f"  ok   {name} (exit {proc.returncode})")
        return True
    print(
        f"  FAIL {name}: expected exit {expected}, got {proc.returncode}\n"
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
