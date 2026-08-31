#!/usr/bin/env python3
"""Mutation tests for wire-format-reference.py's fail-closed guards.

Two classes, both proven reachable by execution rather than argued from reading
(LAB-903: do not reason about a conformance gate, poison the fixture and watch it):

  1. -O refusal. Every integrity check in that tool is an `assert`, so `python -O`
     strips all of them: `verify` would report "all N vector pairs verified" having
     verified nothing, and `generate` would rewrite the fixture every SDK conforms
     against with its input checks removed. The guard sits at MODULE scope, not in
     `main()`, because importing the module walks straight past a CLI-only guard.

  2. generate's append-only refusal. Rebuilding `vectors` from the legacy set alone
     silently drops any committed vector that is not a derived twin — and `verify`'s
     orphan FAIL names `generate` as the remedy, so the repair step completed the
     data loss. test-vectors/wire-format.json is vendored and sha256-pinned by 4+
     SDKs; a deletion here is invisible until an SDK's coverage has already shrunk.

A guard with no mutation test is one refactor away from being deleted by someone
who cannot see what it holds up.

Run: python3 tools/test_wire_format_reference.py     (exit 1 on any failure)
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE / "wire-format-reference.py"
FIXTURE = HERE.parent / "test-vectors" / "wire-format.json"

# A vector whose legacy base is dropped by a bad merge, leaving an orphan twin.
# LAB-868's width-boundary vector: the only bin16 coverage in the fleet.
ORPHANED_BASE = "width_boundary_bin16"


def _run(flags: list[str], argv: list[str], tool: Path = TOOL) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *flags, str(tool), *argv], capture_output=True, text=True
    )


def _scratch(tmp: Path, drop: str | None = None) -> Path:
    """Mirror tool + fixture into a scratch tree so mutations never touch the repo."""
    (tmp / "tools").mkdir()
    (tmp / "test-vectors").mkdir()
    shutil.copy(TOOL, tmp / "tools" / TOOL.name)
    fixture = json.loads(FIXTURE.read_text())
    if drop:
        fixture["vectors"] = [v for v in fixture["vectors"] if v["name"] != drop]
    (tmp / "test-vectors" / FIXTURE.name).write_text(json.dumps(fixture, indent=2) + "\n")
    return tmp / "tools" / TOOL.name


def check_optimised_refusals() -> list[str]:
    """-O must stop every entry point, including `import`."""
    failures = []
    # Positive control: without -O the tool must still work, otherwise a guard that
    # refuses everything would pass every case below.
    cases = [
        ("verify, assertions on", [], ["verify"], 0),
        ("verify under -O", ["-O"], ["verify"], 1),
        ("generate under -O", ["-O"], ["generate"], 1),
        ("verify under -OO", ["-OO"], ["verify"], 1),
    ]
    for name, flags, argv, expected in cases:
        proc = _run(flags, argv)
        ok = proc.returncode == expected
        # An -O run must say why it refused; a bare non-zero exit could be an
        # unrelated crash, which would let the guard rot behind a passing test.
        if ok and flags and "assertions disabled" not in proc.stderr:
            ok, name = False, name + " (exited 1 but not via the guard)"
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: expected exit {expected}, got {proc.returncode}")
        if not ok:
            failures.append(name)

    # The guard is at module scope precisely so this path cannot skip it.
    probe = "import importlib.util as u;s=u.spec_from_file_location('w',r'%s');m=u.module_from_spec(s);s.loader.exec_module(m);print('RAN',m.verify())"
    proc = subprocess.run(
        [sys.executable, "-O", "-c", probe % TOOL], capture_output=True, text=True
    )
    ok = proc.returncode != 0 and "assertions disabled" in proc.stderr
    print(f"  [{'ok' if ok else 'FAIL'}] import under -O refuses: got exit {proc.returncode}")
    if not ok:
        failures.append("import under -O bypassed the guard")
    return failures


def check_generate_is_append_only() -> list[str]:
    """generate must refuse to drop a committed vector, not silently erase it."""
    failures = []
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        tool = _scratch(tmp, drop=ORPHANED_BASE)
        before = json.loads((tmp / "test-vectors" / FIXTURE.name).read_text())
        proc = _run([], ["generate"], tool=tool)
        after = json.loads((tmp / "test-vectors" / FIXTURE.name).read_text())

        refused = proc.returncode == 1 and "REFUSED" in proc.stderr
        print(f"  [{'ok' if refused else 'FAIL'}] generate refuses to drop a committed vector: exit {proc.returncode}")
        if not refused:
            failures.append("generate did not refuse to drop a committed vector")

        # The refusal must be a no-op on disk, not a refusal after the write.
        untouched = before == after
        print(f"  [{'ok' if untouched else 'FAIL'}] refusal left the fixture byte-untouched")
        if not untouched:
            failures.append("generate mutated the fixture despite refusing")

        # Positive control: on an intact fixture, generate is still a working no-op.
        tool2 = _scratch(Path(tempfile.mkdtemp(dir=td)))
        proc2 = _run([], ["generate"], tool=tool2)
        ok2 = proc2.returncode == 0
        print(f"  [{'ok' if ok2 else 'FAIL'}] generate still succeeds on an intact fixture: exit {proc2.returncode}")
        if not ok2:
            failures.append("generate broke on an intact fixture")
    return failures


def check_flag_rejections() -> list[str]:
    """A flag accepted-and-ignored on the fixture-writing path is a fail-open."""
    failures = []
    for name, argv, expected in [
        ("generate --require-extras rejected", ["generate", "--require-extras"], 2),
        ("unknown command rejected", ["bogus"], 2),
        ("typo'd flag rejected", ["verify", "--require-extra"], 2),
    ]:
        proc = _run([], argv)
        ok = proc.returncode == expected
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: expected exit {expected}, got {proc.returncode}")
        if not ok:
            failures.append(name)
    return failures


def main() -> int:
    failures = []
    for label, check in (
        ("-O refusal", check_optimised_refusals),
        ("generate append-only", check_generate_is_append_only),
        ("flag rejection", check_flag_rejections),
    ):
        print(f"{label}:")
        failures += check()

    if failures:
        print(f"\n{len(failures)} case(s) failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("\nall cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
