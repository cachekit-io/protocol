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

  4. The ratio-product width rule. The reader's ratio check is swapped, in process,
     for four 32-bit ones (u32 wrap, i32 wrap, reject on u32 overflow, and u32 wrap
     that skips the product when original_size <= compressed_size). Each must pass
     every pinned vector and reject `envelope_ratio_product_wraps_32_bits`. A dropped
     or altered constructed vector must fail `verify` by name, and a wrong checksum
     must fail wherever `xxhash` is importable (the stdlib leg cannot see it).

  5. The reader's own reject branches, called directly: each of the 8 checksum bytes
     flipped in turn (xxhash leg), an envelope over the envelope cap, an original_size
     over the size cap, an empty compressed_data, the ratio bound at 1000:1 + 1 B
     (rejected) and exactly 1000:1 (inside the bound, so the reader must get past it),
     and a truncated envelope. Each reject must fail at its own step with its own
     message, and the exact-bound case with anything but the ratio message, so
     deleting or loosening one branch fails this suite even where a later check would
     also reject. Step 3's compressed_data cap is not covered: compressed_data is a
     strict slice of the envelope step 1 already bounded, so no input reaches it.

  6. The fixture's `reject_vectors`. The conforming reader rejects each at its named
     step. Then each bound (size cap, zero length, ratio, checksum, output length) is
     dropped from the reader in turn, and across every vector in the file only that
     bound's vector may change outcome, to accepted or to a later step. verify must
     fail a dropped, added or altered reject vector by name, and generate must refill
     a missing group byte-identically without dropping a committed entry.

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

import ast
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
TOOL = HERE / "wire-format-reference.py"
FIXTURE = HERE.parent / "test-vectors" / "wire-format.json"
# The tool loads its LZ4 decoder from interop-v2-reference.py, which loads interop-reference.py.
IMPORTED_TOOLS = (HERE / "interop-v2-reference.py", HERE / "interop-reference.py")

# A vector whose legacy base is dropped by a bad merge, leaving an orphan twin.
# LAB-868's width-boundary vector: the only bin16 coverage in the fleet.
ORPHANED_BASE = "width_boundary_bin16"


class _GuardNotFoundError(RuntimeError):
    """A mutant's guard does not match exactly one `if` in read_envelope (message per TRY003)."""

    def __init__(self, fragment: str, hits: int) -> None:
        super().__init__(f"read_envelope guard {fragment!r} matches {hits} `if` statements, not 1")


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
    for tool in (TOOL, *IMPORTED_TOOLS):
        shutil.copy(tool, tmp / "tools" / tool.name)
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
        mod = _load_tool()
        _d, checksum, size, fmt, _e = mod.decode_envelope(bytes.fromhex(base["envelope_hex"]))
        return mod.encode_envelope(data, checksum, size, fmt, encoding=encoding)

    def limits_drift(fixture: dict) -> None:
        fixture["limits"]["max_uncompressed_size"] = 1

    def limits_missing(fixture: dict) -> None:
        del fixture["limits"]["max_compression_ratio"]

    def unclassifiable(fixture: dict) -> None:
        vec = next((v for v in fixture["vectors"] if v["name"] == "simple_string_bin"), None)
        if vec is None:
            raise KeyError("fixture has no simple_string_bin to mutate")
        vec["envelope_encoding"] = "bin16"

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


def _load_tool(drop_guard: str | None = None) -> ModuleType:
    """Load the tool as a module; with `drop_guard`, minus the one `if` in read_envelope
    whose condition contains that source fragment.

    The mutant is the reader itself with one bound deleted, not a patched seam, so a
    bound moved out of the reader is not silently left in place. A fragment matching no
    `if`, or more than one, raises: a refactor must fail this suite, not pass it vacuously.
    """
    tree = ast.parse(TOOL.read_text(encoding="utf-8"))
    if drop_guard is not None:
        reader = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "read_envelope")
        hits = [n for n in reader.body if isinstance(n, ast.If) and drop_guard in ast.unparse(n.test)]
        if len(hits) != 1:
            raise _GuardNotFoundError(drop_guard, len(hits))
        reader.body.remove(hits[0])
    mod = ModuleType("_wfr_reader")
    mod.__file__ = str(TOOL)
    exec(compile(tree, str(TOOL), "exec"), mod.__dict__)  # noqa: S102 - the repo's own tool
    return mod


def check_32_bit_ratio_readers() -> list[str]:
    """Four 32-bit ratio checks pass every pinned vector and fail the constructed one.

    The spec's >=64-bit rule is enforceable only if a published vector fails a reader
    that breaks it. Before fixture 1.2.0 none did: the largest envelope was 478 B.
    """
    failures = []
    mod = _load_tool()
    fixture = json.loads(FIXTURE.read_text())
    pinned = [(v["name"], bytes.fromhex(v["envelope_hex"]), bytes.fromhex(v["input_hex"])) for v in fixture["vectors"]]
    wrap = next((v for v in fixture.get("constructed_vectors", []) if v["name"] == mod.WRAP_VECTOR), None)
    if wrap is None:
        return [f"fixture has no {mod.WRAP_VECTOR}: the mutation suite would pass vacuously"]
    wrap_env = mod.iv2.construct(wrap["envelope_construction"])
    wrap_input = mod.iv2.construct(wrap["input_construction"])
    xxh3_64 = mod._load_xxh3()

    u32 = mod.iv2.ratio_bound_u32_wrapped

    def overflow_rejects(original: int, n: int) -> bool:
        """Rejects on 32-bit overflow instead of widening (`checked_mul` on u32 + REJECT)."""
        if mod.MAX_RATIO * n >= 1 << 32:
            raise mod.EnvelopeReject(5, "ratio product overflows u32")
        return original <= mod.MAX_RATIO * n

    mutants: dict[str, Callable[[int, int], bool]] = {
        "u32 wrap": lambda original, n: original <= u32(n),
        "i32 wrap": lambda original, n: original <= (mod.MAX_RATIO * n + (1 << 31)) % (1 << 32) - (1 << 31),
        "u32 reject-on-overflow": overflow_rejects,
        # Only a vector whose original is larger than its compressed data catches this one.
        "u32 wrap after an original <= compressed fast path": lambda original, n: original <= n or original <= u32(n),
    }

    def report(ok: bool, label: str) -> None:
        print(f"  [{'ok' if ok else 'FAIL'}] {label}")
        if not ok:
            failures.append(label)

    # Positive control: the conforming reader accepts everything, or the cases below prove nothing.
    report(
        all(mod.read_envelope(env, xxh3_64) == inp for _n, env, inp in pinned)
        and mod.read_envelope(wrap_env, xxh3_64) == wrap_input,
        "conforming reader accepts every vector",
    )
    for name, mutant in mutants.items():
        with patch.object(mod, "within_ratio", mutant):
            try:
                missed = [n for n, env, inp in pinned if mod.read_envelope(env, xxh3_64) != inp]
            except ValueError as e:
                missed = [f"raised {e!r}"]
            report(not missed, f"{name}: every pinned vector still passes (the gap was real) {missed or ''}")
            try:
                mod.read_envelope(wrap_env, xxh3_64)
                caught = False
            except mod.EnvelopeReject as e:
                caught = e.step == 5 and "ratio" in str(e)
            report(caught, f"{name}: {mod.WRAP_VECTOR} rejected as a ratio bomb")

    # The stdlib leg takes the checksum on trust, so a wrong one must fail wherever
    # xxhash is importable (CI's optional-deps leg), or every SDK re-vendor would
    # fail this accept vector for the wrong reason.
    if xxh3_64 is None:
        print("  [skip] wrong checksum rejected: xxhash not importable (CI's optional-deps leg runs it)")
    else:
        wrong = mod.build_wrap_threshold_vector(lambda _original: bytes(8))
        try:
            mod._verify_constructed(wrong, xxh3_64, None, None)
            rejected = False
        except AssertionError as e:
            rejected = "checksum" in str(e)
        report(rejected, "wrong checksum rejected with xxhash")
    return failures


# Each bound of read_envelope that a reject vector isolates: the source fragment of its
# guard (for _load_tool) and the vector whose outcome dropping it must change. The step-9
# length bound lives in the LZ4 decoder, so its mutant swaps the decoder instead.
READER_BOUNDS = {
    "step 4 size cap": ("original_size > MAX_UNCOMPRESSED_SIZE", "reject_original_size_over_cap"),
    "step 5 zero length": ("len(data) == 0", "reject_zero_length_compressed_data"),
    "step 5 ratio bound": ("within_ratio(", "reject_ratio_bomb"),
    "step 8 checksum": ("xxh3_64(out) != checksum", "reject_checksum_mismatch"),
}
LENGTH_BOUND = ("step 6/9 output length", "reject_decompressed_length_mismatch")
_SHORT_OUTPUT = re.compile(r"LZ4 output length (\d+) != original_size")


def _outcomes(mod: ModuleType, vectors: list[tuple[str, bytes, bytes | None]], xxh3_64) -> dict[str, str]:
    """name -> "accepted", "accepted wrong output", "step N" or "raised ..." for every vector."""
    out = {}
    for name, env, want in vectors:
        try:
            got = mod.read_envelope(env, xxh3_64)
            # A reject vector (want None) has no right output: any acceptance is the finding.
            out[name] = "accepted" if want is None or got == want else "accepted wrong output"
        except mod.EnvelopeReject as e:
            out[name] = f"step {e.step}"
        except Exception as e:  # noqa: BLE001 - any other escape is itself the finding
            out[name] = f"raised {e!r}"
    return out


def check_reader_rejects() -> list[str]:
    """Each reject branch of read_envelope fires at its own step, directly and through
    the fixture's reject_vectors, and dropping one bound changes exactly its vector.

    Direct cases: every published accept vector passes every bound, so without them a
    deleted branch stays green whenever a later check (the ratio bound, the LZ4 decoder)
    rejects the same envelope at another step. The ratio pair pins the bound's own
    logic, which the 32-bit mutants replace wholesale and so cannot: `return True`, a
    strict `<` or a looser division form each fails one of the two. Step 3 is not
    covered; see the module docstring.

    Mutants: the conforming reader must reject each reject vector at its named step.
    Then each bound is dropped from the reader in turn, and across every vector in the
    file (pinned, constructed, reject) the only outcome that may change is that bound's
    vector, to accepted or to a later step. That is the fixture's claim, and what an SDK
    test relies on when it asserts the step (spec/wire-format.md 'Reject vectors').
    """
    failures = []
    mod = _load_tool()
    fixture = json.loads(FIXTURE.read_text())
    base = next((v for v in fixture["vectors"] if v["name"] == "simple_string_bin"), None)
    if base is None:
        return ["fixture has no simple_string_bin: the reject cases would not run"]
    env = bytes.fromhex(base["envelope_hex"])
    data, checksum, size, fmt, _encoding = mod.decode_envelope(env)
    xxh3_64 = mod._load_xxh3()

    def report(ok: bool, label: str) -> None:
        print(f"  [{'ok' if ok else 'FAIL'}] {label}")
        if not ok:
            failures.append(label)

    def expect(label: str, envelope: bytes, step: int, marker: str, xxh3=None, *, absent: bool = False) -> None:
        """Pass on a rejection at `step` carrying `marker`, or, with `absent`, any rejection without it."""
        try:
            mod.read_envelope(envelope, xxh3)
            got, at = "accepted", None
        except mod.EnvelopeReject as e:
            got, at = str(e), e.step
        except ValueError as e:
            got, at = f"{type(e).__name__}: {e}", None
        ok = (got != "accepted" and marker not in got) if absent else (at == step and marker in got)
        report(ok, f"{label}: {got}")

    if xxh3_64 is None:
        print("  [skip] flipped checksum bytes: xxhash not importable (CI's optional-deps leg runs it)")
    else:
        # Every byte, so a compare over only part of the checksum fails too.
        for i in range(len(checksum)):
            flipped = checksum[:i] + bytes([checksum[i] ^ 0x01]) + checksum[i + 1 :]
            expect(
                f"checksum byte {i} flipped rejected",
                mod.encode_envelope(data, flipped, size, fmt, encoding="bin"),
                8,
                "checksum mismatch",
                xxh3_64,
            )
    # The envelope cap is 512 MiB; lowering it for one call avoids a 512 MiB allocation.
    with patch.object(mod, "MAX_COMPRESSED_SIZE", len(env) - 1):
        expect("envelope over the envelope cap rejected", env, 1, "envelope exceeds max compressed size")
    expect(
        "original_size over the size cap rejected",
        mod.encode_envelope(data, checksum, mod.MAX_UNCOMPRESSED_SIZE + 1, fmt, encoding="bin"),
        4,
        "original_size exceeds max uncompressed size",
    )
    expect(
        "empty compressed_data rejected",
        mod.encode_envelope(b"", checksum, 0, fmt, encoding="bin"),
        5,
        "zero-length compressed_data",
    )
    expect(
        "original_size one byte over 1000:1 rejected by the ratio bound",
        mod.encode_envelope(data, checksum, mod.MAX_RATIO * len(data) + 1, fmt, encoding="bin"),
        5,
        "compression ratio exceeds",
    )
    # Exactly 1000:1 is inside the bound, so the reader must get past it. The data does
    # not decode to that length, so it still rejects, just never as a ratio bomb.
    expect(
        "original_size at exactly 1000:1 passes the ratio bound",
        mod.encode_envelope(data, checksum, mod.MAX_RATIO * len(data), fmt, encoding="bin"),
        5,
        "compression ratio exceeds",
        absent=True,
    )
    expect("truncated envelope rejected at decode", env[:-1], 2, "malformed envelope")

    # --- the fixture's reject_vectors, and one mutant per bound ---
    rejects = {v["name"]: v for v in fixture.get("reject_vectors", [])}
    wanted = {vector for _fragment, vector in READER_BOUNDS.values()} | {LENGTH_BOUND[1]}
    if set(rejects) != wanted:
        return [*failures, f"fixture reject_vectors {sorted(rejects)} != the bounds' vectors {sorted(wanted)}"]
    vectors: list[tuple[str, bytes, bytes | None]] = [
        (v["name"], bytes.fromhex(v["envelope_hex"]), bytes.fromhex(v["input_hex"])) for v in fixture["vectors"]
    ]
    vectors += [
        (v["name"], mod.iv2.construct(v["envelope_construction"]), mod.iv2.construct(v["input_construction"]))
        for v in fixture.get("constructed_vectors", [])
    ]
    vectors += [(n, bytes.fromhex(v["envelope_hex"]), None) for n, v in rejects.items()]
    conforming = _outcomes(mod, vectors, xxh3_64)
    for name, got in conforming.items():
        if name in rejects:
            step = rejects[name]["reject_step"]
            if step == 8 and xxh3_64 is None:
                continue  # the stdlib reader cannot run step 8
            report(got == f"step {step}", f"conforming reader: {name} rejected at step {step} ({got})")
        elif got != "accepted":
            report(False, f"conforming reader: {name} accepted ({got})")

    def lenient_decoder(strict: Callable[[bytes, int], bytes]) -> Callable[[bytes, int], bytes]:
        """The decoder minus its final length check: returns a short output, as liblz4 does."""

        def decode(block: bytes, original_size: int) -> bytes:
            try:
                return strict(block, original_size)
            except ValueError as e:  # V2Error, of the mutant's own iv2 instance
                short = _SHORT_OUTPUT.match(str(e))
                if short is None:
                    raise
                return strict(block, int(short.group(1)))

        return decode

    mutants: list[tuple[str, str, ModuleType]] = []
    for label, (fragment, vector) in READER_BOUNDS.items():
        if vector == "reject_checksum_mismatch" and xxh3_64 is None:
            print(f"  [skip] mutant without {label}: xxhash not importable (CI's optional-deps leg runs it)")
            continue
        try:
            mutants.append((label, vector, _load_tool(drop_guard=fragment)))
        except _GuardNotFoundError as e:
            report(False, f"mutant without {label}: {e}")
    length_mutant = _load_tool()
    length_mutant.iv2.lz4_block_decompress = lenient_decoder(length_mutant.iv2.lz4_block_decompress)
    mutants.append((*LENGTH_BOUND, length_mutant))

    for label, vector, mutant in mutants:
        got = _outcomes(mutant, vectors, xxh3_64)
        changed = sorted(n for n in got if got[n] != conforming[n])
        named = rejects[vector]["reject_step"]
        moved = got[vector] == "accepted" or (
            got[vector].startswith("step ") and int(got[vector].split()[1]) > named
        )
        report(
            changed == [vector] and moved,
            f"mutant without {label}: only {vector} changes (step {named} -> {got[vector]}); changed {changed}",
        )
    return failures


def check_reject_group() -> list[str]:
    """verify fails a dropped, added or altered reject vector by name; generate refills the group."""
    failures = []

    def drop_one(fixture: dict) -> None:
        fixture["reject_vectors"] = [v for v in fixture["reject_vectors"] if v["name"] != "reject_ratio_bomb"]

    def add_one(fixture: dict) -> None:
        fixture["reject_vectors"].append(dict(fixture["reject_vectors"][0], name="reject_extra"))

    def no_group(fixture: dict) -> None:
        del fixture["reject_vectors"]

    def alter_bytes(fixture: dict) -> None:
        vec = next(v for v in fixture["reject_vectors"] if v["name"] == "reject_checksum_mismatch")
        vec["envelope_hex"] = vec["envelope_hex"].replace("986ccc8a", "986dcc8a", 1)

    def alter_step(fixture: dict) -> None:
        vec = next(v for v in fixture["reject_vectors"] if v["name"] == "reject_original_size_over_cap")
        vec["reject_step"] = 5

    cases = [
        ("dropped reject vector is set drift", drop_one, "reject-vector set drifted"),
        ("added reject vector is set drift", add_one, "reject-vector set drifted"),
        ("missing reject group is set drift", no_group, "reject-vector set drifted"),
        ("altered reject bytes fail by name", alter_bytes, "FAIL reject_checksum_mismatch"),
        ("altered reject step fails by name", alter_step, "FAIL reject_original_size_over_cap"),
    ]
    with tempfile.TemporaryDirectory() as td:
        for label, mutate, marker in cases:
            tool = _scratch(Path(tempfile.mkdtemp(dir=td)), mutate=mutate)
            _expect(failures, label, _run([], ["verify"], tool=tool), 1, marker)

        # generate rebuilds a missing group exactly as committed, and keeps a committed
        # vector it has no builder for (append-only), which verify then fails by name.
        committed = json.loads(FIXTURE.read_text())["reject_vectors"]
        for label, mutate, want in (
            ("generate rebuilds a missing reject group byte-identically", no_group, committed),
            ("generate keeps an unknown committed reject vector", add_one, None),
        ):
            tool = _scratch(Path(tempfile.mkdtemp(dir=td)), mutate=mutate)
            _expect(failures, label, _run([], ["generate"], tool=tool), 0)
            got = json.loads((tool.parent.parent / "test-vectors" / FIXTURE.name).read_text())["reject_vectors"]
            ok = got == want if want is not None else [v["name"] for v in got][-1] == "reject_extra"
            print(f"  [{'ok' if ok else 'FAIL'}] {label}: group as expected after generate")
            if not ok:
                failures.append(f"{label}: group wrong after generate")
    return failures


def check_constructed_group() -> list[str]:
    """verify fails a dropped or altered constructed vector, by name."""
    failures = []

    def drop_constructed(fixture: dict) -> None:
        fixture["constructed_vectors"] = []

    def shrink(fixture: dict) -> None:
        # A block one 255-run shorter: compressed_size falls below the wrap threshold.
        fixture["constructed_vectors"][0]["envelope_construction"][1]["count"] -= 1

    def no_group(fixture: dict) -> None:
        del fixture["constructed_vectors"]

    def note_drift(fixture: dict) -> None:
        fixture["construction_note"] = "x"

    cases = [
        ("dropped constructed vector is set drift", drop_constructed, "constructed-vector set drifted"),
        ("missing constructed group is set drift", no_group, "constructed-vector set drifted"),
        ("altered construction differs from the builder", shrink, "differs from what the builder derives"),
        ("construction_note drift fails", note_drift, "construction_note drifted"),
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
        ("32-bit ratio readers", check_32_bit_ratio_readers),
        ("reader reject branches", check_reader_rejects),
        ("constructed group", check_constructed_group),
        ("reject group", check_reject_group),
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
