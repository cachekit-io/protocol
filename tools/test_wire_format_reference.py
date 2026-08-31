#!/usr/bin/env python3
"""Regression test for wire-format-reference.py's -O refusal.

Every integrity check in that tool is an `assert`, so `python -O` strips all of
them: `verify` would report "all N vector pairs verified" having verified
nothing, and `generate` would rewrite the fixture every SDK conforms against
with its input checks removed. A one-line guard in `main()` is all that stands
between the tool and a vacuous pass — and a guard with no test is one refactor
away from being deleted by someone who cannot see what it holds up.

Run: python3 tools/test_wire_format_reference.py     (exit 1 on any failure)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "wire-format-reference.py"

# (name, python flags, argv, expected_exit)
CASES = [
    # Positive control: without -O the tool must still do its job, otherwise a
    # guard that refuses everything would pass the two cases below.
    ("verify, assertions on", [], ["verify"], 0),
    # The regression itself: both commands must refuse, not just `verify`.
    ("verify under -O", ["-O"], ["verify"], 1),
    ("generate under -O", ["-O"], ["generate"], 1),
    # -OO strips docstrings as well as asserts; same refusal must hold.
    ("verify under -OO", ["-OO"], ["verify"], 1),
]


def main() -> int:
    failures = []
    for name, flags, argv, expected in CASES:
        proc = subprocess.run(
            [sys.executable, *flags, str(TOOL), *argv],
            capture_output=True,
            text=True,
        )
        ok = proc.returncode == expected
        # An -O run must say why it refused; a bare non-zero exit could just as
        # easily be an unrelated crash, which would let the guard rot unnoticed.
        if ok and flags and "assertions disabled" not in proc.stderr:
            ok = False
            name += " (exited 1 but not via the guard)"
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: expected exit {expected}, got {proc.returncode}")
        if not ok:
            failures.append(name)

    if failures:
        print(f"\n{len(failures)} case(s) failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"\nall {len(CASES)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
