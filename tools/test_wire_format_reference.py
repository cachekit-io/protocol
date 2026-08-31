#!/usr/bin/env python3
"""Mutation tests for wire-format-reference.py's fail-closed guards.

Every class below is proven reachable by execution rather than argued from reading
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

  3. Whole-file properties, which every per-vector check is structurally blind to
     because they all iterate the fixture's own vector list (LAB-1751 panel round 3;
     all three exited 0 before the guards existed):
       - the base-vector SET. Dropping a legacy base AND its `_bin` twin together net
         to zero in generate's append-only diff, so `verify` reported "all 6 vector
         pairs verified" and `generate` wrote the shrunken fixture.
       - the fixture's declared `limits` block, which SDKs read their bounds from and
         which nothing compared against the spec's Security Limits table.
       - the pinned bytes of an encode-divergent vector. The lz4 tripwire asserts only
         "differs from liblz4's output" — a one-bit check any other valid LZ4 block
         satisfies, so a re-pin to unrelated bytes passed.

A guard with no mutation test is one refactor away from being deleted by someone
who cannot see what it holds up.

SAFETY: every invocation that could reach `generate` runs against a scratch mirror,
never the repo's sha256-pinned fixture. A regressed guard must fail this suite, not
rewrite the vendored artifact — this suite is CI's first step, so it runs before
anything else has confirmed the tool is sane. `main` asserts the repo fixture is
byte-identical after the whole run.

Run: python3 tools/test_wire_format_reference.py     (exit 1 on any failure)
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE / "wire-format-reference.py"
FIXTURE = HERE.parent / "test-vectors" / "wire-format.json"

# A vector whose legacy base is dropped by a bad merge, leaving an orphan twin.
# LAB-868's width-boundary vector: the only bin16 coverage in the fleet.
ORPHANED_BASE = "width_boundary_bin16"


class _ModuleLoadError(RuntimeError):
    """The reference tool could not be loaded as a module (message lives here per TRY003)."""

    def __init__(self, tool: Path) -> None:
        super().__init__(f"cannot load {tool} as a module")


# The realistic bad-merge shape the orphan case does NOT cover: base and twin go
# together, so the append-only diff is empty.
DROPPED_PAIR = "large_compressible"


def _run(flags: list[str], argv: list[str], tool: Path = TOOL) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *flags, str(tool), *argv], capture_output=True, text=True
    )


def _scratch(tmp: Path, mutate: Callable[[dict], None] | None = None) -> Path:
    """Mirror tool + fixture into a scratch tree so mutations never touch the repo."""
    (tmp / "tools").mkdir(parents=True, exist_ok=True)
    (tmp / "test-vectors").mkdir(parents=True, exist_ok=True)
    shutil.copy(TOOL, tmp / "tools" / TOOL.name)
    fixture = json.loads(FIXTURE.read_text())
    if mutate:
        mutate(fixture)
    (tmp / "test-vectors" / FIXTURE.name).write_text(json.dumps(fixture, indent=2) + "\n")
    return tmp / "tools" / TOOL.name


def _drop(*names: str) -> Callable[[dict], None]:
    def mutate(fixture: dict) -> None:
        fixture["vectors"] = [v for v in fixture["vectors"] if v["name"] not in names]

    return mutate


def _expect(
    failures: list[str],
    label: str,
    proc: subprocess.CompletedProcess,
    expected: int,
    marker: str | None = None,
) -> None:
    """Assert exit code and, when given, that the refusal came from the right guard.

    The marker is not decoration: python itself exits 2 on a bad script path and 1 on
    an unhandled traceback, so an exit-code-only assertion passes vacuously when the
    invocation never reached the guard at all.
    """
    ok = proc.returncode == expected
    if ok and marker and marker not in (proc.stdout + proc.stderr):
        ok, label = False, f"{label} (exited {expected} but not via the guard)"
    print(f"  [{'ok' if ok else 'FAIL'}] {label}: expected exit {expected}, got {proc.returncode}")
    if not ok:
        failures.append(label)


def check_optimised_refusals() -> list[str]:
    """-O must stop every entry point, including `import`."""
    failures = []
    with tempfile.TemporaryDirectory() as td:
        # `generate` under -O is run against a scratch mirror: if the guard regresses,
        # the write lands on a throwaway copy instead of the vendored fixture.
        scratch_tool = _scratch(Path(td) / "opt")
        # Byte snapshot, taken BEFORE the invocations and of the scratch file itself:
        # comparing parsed JSON would call a reformatting rewrite "byte-untouched",
        # and comparing against the repo fixture would compare the wrong file (the
        # mirror is re-serialised by _scratch, so it is not byte-identical to it).
        scratch_fixture = scratch_tool.parent.parent / "test-vectors" / FIXTURE.name
        pristine_scratch = scratch_fixture.read_bytes()
        cases = [
            # Positive control: without -O the tool must still work, otherwise a guard
            # that refuses everything would pass every case below.
            ("verify, assertions on", [], ["verify"], 0, TOOL, None),
            ("verify under -O", ["-O"], ["verify"], 1, TOOL, "assertions disabled"),
            ("generate under -O", ["-O"], ["generate"], 1, scratch_tool, "assertions disabled"),
            ("verify under -OO", ["-OO"], ["verify"], 1, TOOL, "assertions disabled"),
        ]
        for name, flags, argv, expected, tool, marker in cases:
            _expect(failures, name, _run(flags, argv, tool=tool), expected, marker)

        # The scratch fixture must be untouched even though the invocation asked to
        # write it — proves the -O refusal precedes the write, not follows it.
        untouched = scratch_fixture.read_bytes() == pristine_scratch
        print(f"  [{'ok' if untouched else 'FAIL'}] -O generate wrote nothing")
        if not untouched:
            failures.append("generate under -O rewrote the fixture before refusing")

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
        for label, mutate, marker in (
            ("orphan twin (base dropped)", _drop(ORPHANED_BASE), "REFUSED"),
            (f"whole pair dropped ({DROPPED_PAIR})", _drop(DROPPED_PAIR, f"{DROPPED_PAIR}_bin"), "REFUSED"),
        ):
            tmp = Path(tempfile.mkdtemp(dir=td))
            tool = _scratch(tmp, mutate=mutate)
            fixture_path = tmp / "test-vectors" / FIXTURE.name
            before = fixture_path.read_bytes()
            proc = _run([], ["generate"], tool=tool)
            _expect(failures, f"generate refuses: {label}", proc, 1, marker)

            # The refusal must be a no-op on disk, not a refusal after the write.
            # Bytes, not parsed JSON: a rewrite that only reorders keys or reindents
            # is still a write, and the claim below says byte-untouched.
            untouched = before == fixture_path.read_bytes()
            print(f"  [{'ok' if untouched else 'FAIL'}] refusal left the fixture byte-untouched: {label}")
            if not untouched:
                failures.append(f"generate mutated the fixture despite refusing: {label}")

        # Positive control: on an intact fixture, generate is still a working no-op.
        tool2 = _scratch(Path(tempfile.mkdtemp(dir=td)))
        _expect(failures, "generate still succeeds on an intact fixture", _run([], ["generate"], tool=tool2), 0)
    return failures


def check_whole_file_properties() -> list[str]:
    """Drift no per-vector check can see: the vector set, the limits block, the pins."""
    failures = []

    def repin_divergent(fixture: dict) -> None:
        """Swap the divergent vector's compressed_data for a DIFFERENT valid LZ4 block.

        All-literals encoding: token litlen nibble 15 + extension bytes, matchlen 0.
        liblz4 decompresses it to the same input, and it differs from liblz4's own
        output, so every check except the byte-pin accepts it.
        """
        base = next(v for v in fixture["vectors"] if v["name"] == DROPPED_PAIR)
        twin = next(v for v in fixture["vectors"] if v["name"] == f"{DROPPED_PAIR}_bin")
        inp = bytes.fromhex(base["input_hex"])
        rem = len(inp) - 15
        alt = bytes([0xF0]) + bytes([255] * (rem // 255) + [rem % 255]) + inp
        for vec, encoding in ((base, "int-array"), (twin, "bin")):
            env = _encode(alt, base, encoding)
            vec["envelope_hex"] = env.hex()
            vec["envelope_size"] = len(env)

    def _encode(data: bytes, base: dict, encoding: str) -> bytes:
        import importlib.util as u

        spec = u.spec_from_file_location("_wfr", TOOL)
        if spec is None or spec.loader is None:
            raise _ModuleLoadError(TOOL)
        mod = u.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _d, checksum, size, fmt, _e = mod.decode_envelope(bytes.fromhex(base["envelope_hex"]))
        return mod.encode_envelope(data, checksum, size, fmt, encoding=encoding)

    def limits_drift(fixture: dict) -> None:
        fixture["limits"]["max_uncompressed_size"] = 1

    def limits_missing(fixture: dict) -> None:
        del fixture["limits"]["max_compression_ratio"]

    def unclassifiable(fixture: dict) -> None:
        next(v for v in fixture["vectors"] if v["name"] == "simple_string_bin")["envelope_encoding"] = "bin16"

    cases = [
        (
            f"dropped pair is not 'all 6 verified' ({DROPPED_PAIR})",
            _drop(DROPPED_PAIR, f"{DROPPED_PAIR}_bin"),
            "base-vector set drifted",
        ),
        (
            f"dropped pair is not 'all 6 verified' ({ORPHANED_BASE})",
            _drop(ORPHANED_BASE, f"{ORPHANED_BASE}_bin"),
            "base-vector set drifted",
        ),
        ("fixture limits may not contradict the spec table", limits_drift, "limits' drifted"),
        ("a missing declared limit is drift, not a skip", limits_missing, "limits' drifted"),
        ("divergent vector keeps its pinned bytes", repin_divergent, "no longer carries its pinned"),
        ("unusable fixture fails by name, not by traceback", unclassifiable, "simple_string_bin"),
    ]
    with tempfile.TemporaryDirectory() as td:
        for label, mutate, marker in cases:
            tool = _scratch(Path(tempfile.mkdtemp(dir=td)), mutate=mutate)
            _expect(failures, label, _run([], ["verify"], tool=tool), 1, marker)
    return failures


def check_flag_rejections() -> list[str]:
    """A flag accepted-and-ignored on the fixture-writing path is a fail-open."""
    failures = []
    with tempfile.TemporaryDirectory() as td:
        # Scratch mirror: `generate --require-extras` is one regressed guard away from
        # writing the fixture, and this suite is the first thing CI runs.
        tool = _scratch(Path(td) / "flags")
        fixture_path = tool.parent.parent / "test-vectors" / FIXTURE.name
        before = fixture_path.read_bytes()
        for name, argv, expected, marker in [
            ("generate --require-extras rejected", ["generate", "--require-extras"], 2, "not valid for"),
            ("unknown command rejected", ["bogus"], 2, "Usage:"),
            ("typo'd flag rejected", ["verify", "--require-extra"], 2, "Usage:"),
        ]:
            _expect(failures, name, _run([], argv, tool=tool), expected, marker)

        untouched = before == fixture_path.read_bytes()
        print(f"  [{'ok' if untouched else 'FAIL'}] no rejected invocation wrote the fixture")
        if not untouched:
            failures.append("a rejected invocation still wrote the fixture")
    return failures


def main() -> int:
    pristine = FIXTURE.read_bytes()
    failures = []
    for label, check in (
        ("-O refusal", check_optimised_refusals),
        ("generate append-only", check_generate_is_append_only),
        ("whole-file properties", check_whole_file_properties),
        ("flag rejection", check_flag_rejections),
    ):
        print(f"{label}:")
        failures += check()

    # Belt and braces on the whole suite: nothing here may touch the vendored artifact.
    if FIXTURE.read_bytes() != pristine:
        print("\nFATAL: the suite modified test-vectors/wire-format.json", file=sys.stderr)
        failures.append("suite modified the repo fixture")

    if failures:
        print(f"\n{len(failures)} case(s) failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("\nall cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
