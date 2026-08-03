#!/usr/bin/env python3
"""Mutation tests for check-version-floors.py.

The guard's own history is why this exists: the first version passed a snapshot
hidden behind an ASCII-hyphen placeholder, passed an empty version cell, and
rejected a perfectly valid backticked floor. A guard nobody tested against
mutations is a guard that reports OK.

Run: python3 tools/test_check_version_floors.py     (exit 1 on any failure)
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKER = HERE / "check-version-floors.py"
MATRIX = HERE.parent / "sdk-feature-matrix.md"

RS_FLOOR = "| cachekit-rs | `cachekit-rs` (crates.io) | 0.6.0+ | Rust 1.85+ | ✅ Production |"
PHP_ROW = "| cachekit-php | \u2014 | \u2014 | PHP 8.1+ | \U0001f51c Development |"

# (name, mutate(text) -> text, expected_exit)
CASES: list[tuple[str, Callable[[str], str], int]] = [
    ("unmodified matrix", lambda t: t, 0),
    # --- must be CAUGHT (exit 1) ---
    ("bare snapshot", lambda t: t.replace(RS_FLOOR, RS_FLOOR.replace("0.6.0+", "0.6.0")), 1),
    (
        "snapshot + ASCII-hyphen placeholders in another row",
        lambda t: t.replace(RS_FLOOR, RS_FLOOR.replace("0.6.0+", "0.6.0")).replace(
            PHP_ROW, "| cachekit-php | - | - | PHP 8.1+ | 🔜 Development |"
        ),
        1,
    ),
    (
        "snapshot in a row that itself holds a hyphen cell",
        lambda t: t.replace(RS_FLOOR, "| cachekit-rs | - | 0.6.0 | Rust 1.85+ | - |"),
        1,
    ),
    ("empty version cell", lambda t: t.replace(RS_FLOOR, "| cachekit-rs | `cachekit-rs` |  | Rust 1.85+ | ✅ |"), 1),
    ("row trimmed below the version column", lambda t: t.replace(RS_FLOOR, "| cachekit-rs | `cachekit-rs` |"), 1),
    (
        "snapshot on a row with no leading pipe",
        lambda t: t.replace(RS_FLOOR, "cachekit-rs | `cachekit-rs` (crates.io) | 0.6.0 | Rust 1.85+ | ✅ |"),
        1,
    ),
    ("prerelease snapshot", lambda t: t.replace(RS_FLOOR, RS_FLOOR.replace("0.6.0+", "0.7.0-rc.1")), 1),
    ("garbage version", lambda t: t.replace(RS_FLOOR, RS_FLOOR.replace("0.6.0+", "latest")), 1),
    # --- must PASS (exit 0): legitimate forms that are still floors ---
    ("backticked floor", lambda t: t.replace(RS_FLOOR, RS_FLOOR.replace("0.6.0+", "`0.6.0+`")), 0),
    ("bold floor", lambda t: t.replace(RS_FLOOR, RS_FLOOR.replace("0.6.0+", "**0.6.0+**")), 0),
    ("prerelease floor", lambda t: t.replace(RS_FLOOR, RS_FLOOR.replace("0.6.0+", "0.7.0-rc.1+")), 0),
    (
        "en-dash placeholder",
        lambda t: t.replace(PHP_ROW, "| cachekit-php | \u2013 | \u2013 | PHP 8.1+ | \U0001f51c |"),
        0,
    ),
    (
        "floor carrying a footnote marker",
        lambda t: t.replace(RS_FLOOR, RS_FLOOR.replace("0.6.0+", "0.6.0+¹⁷")),
        0,
    ),
    (
        "snapshot hidden in a second table under the same heading",
        lambda t: t.replace(
            PHP_ROW,
            PHP_ROW
            + "\n\nAnd a second table:\n\n| SDK | Package | Version |\n| :--- | :--- | :--- |\n"
            "| cachekit-rs | `cachekit-rs` | 0.5.0 |",
        ),
        1,
    ),
    # --- must ERROR rather than silently pass ---
    ("heading removed", lambda t: t.replace("## SDK Overview", "## Overview Of SDKs"), 1),
    (
        "version column renamed away",
        lambda t: t.replace("| SDK | Package | Version | Language | Status |", "| SDK | Package | Rev | Language | Status |"),
        1,
    ),
]


def run(text: str) -> int:
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as fh:
        fh.write(text)
        path = fh.name
    try:
        return subprocess.run(
            [sys.executable, str(CHECKER), path], capture_output=True, text=True
        ).returncode
    finally:
        Path(path).unlink(missing_ok=True)


def main() -> int:
    base = MATRIX.read_text(encoding="utf-8")
    failures = []
    for name, mutate, expected in CASES:
        mutated = mutate(base)
        if name != "unmodified matrix" and mutated == base:
            failures.append(f"{name}: mutation was a no-op; the anchor text moved, fix this test")
            continue
        got = run(mutated)
        verdict = "ok" if got == expected else "FAIL"
        print(f"  [{verdict}] {name}: expected exit {expected}, got {got}")
        if got != expected:
            failures.append(f"{name}: expected {expected}, got {got}")

    if failures:
        print(f"\n{len(failures)} case(s) failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"\nall {len(CASES)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
