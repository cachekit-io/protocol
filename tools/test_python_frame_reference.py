#!/usr/bin/env python3
"""Mutation suite for python-frame-reference.py verify: `twin_of` machinery (LAB-3967) and envelope checks.

Design and rationale: python-frame-reference.py, "Twin declarations". This
suite mutates a copy of the COMMITTED fixture and proves verify() fails on
exactly the mutated field, that the drop-`twin_of` exit stays green without
loosening any byte comparison, that generate() warns and never raises
(LAB-1203 deadlock pin), and that _upsert() carries the declaration across
rebuilds. Stdlib only, no framework.

Run: python3 tools/test_python_frame_reference.py     (exit 1 on any failure)
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("python_frame_reference", HERE / "python-frame-reference.py")
if not (spec and spec.loader):
    # Explicit, not `assert`: a bare assert is stripped under `python -O`, the
    # same trap the generator's own _require() exists to avoid.
    raise ImportError(f"cannot load {HERE / 'python-frame-reference.py'}")
pfr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pfr)

LEGACY_NAME = "default_saas_write_msgpack_bytestorage"
BIN_NAME = LEGACY_NAME + "_bin"
COMMITTED = pfr._load_fixture()

FAILURES = 0


def check(name: str, cond: bool) -> None:
    global FAILURES
    print(f"{'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        FAILURES += 1


def run_verify(doc: dict) -> tuple[int | None, str]:
    """Run pfr.verify() against `doc` written to a temp file; returns (exit code, stdout).

    verify must report bad input as FAIL lines and never raise, whatever the type, so
    any exception is caught here: its traceback is printed and rc is None, which fails
    every check that expects rc == 1.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "python-frame.json"
        path.write_text(json.dumps(doc))
        saved, pfr.VECTOR_PATH = pfr.VECTOR_PATH, path
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = pfr.verify()
        except Exception:  # noqa: BLE001 - any traceback is the failure under test
            traceback.print_exc(file=sys.stdout)  # shows where it raised: verify() or this harness
            return None, ""
        finally:
            pfr.VECTOR_PATH = saved
    return rc, out.getvalue()


def mutated(mutate) -> tuple[dict, dict]:
    """Deep copy of the committed fixture with `mutate(bin_vector)` applied; returns (doc, twin)."""
    doc = copy.deepcopy(COMMITTED)
    twin = next(v for v in doc["frame_vectors"] if v["name"] == BIN_NAME)
    mutate(twin)
    return doc, twin


def flip_last_nibble(h: str) -> str:
    return h[:-1] + ("0" if h[-1] != "0" else "1")


def reorder_header_keys(twin: dict) -> None:
    """Same parsed header, different header BYTES — the ad90a3f finding.

    Re-serialise the header JSON with sorted keys: parse_frame() yields an
    identical dict, so verify's header check passes and ONLY the byte-level
    twin compare can catch it. Header length is unchanged, so HDR_LEN stays valid.
    """
    frame = bytes.fromhex(twin["frame_hex"])
    header, payload = pfr.parse_frame(frame)
    hdr = json.dumps(header, sort_keys=True, separators=(", ", ": ")).encode()
    old_hdr = frame[pfr.PREFIX_LEN : len(frame) - len(payload)]
    if len(hdr) != len(old_hdr) or hdr == old_hdr:
        raise RuntimeError("header key-reorder mutation is not a same-length byte change; test is broken")
    twin["frame_hex"] = (frame[: pfr.PREFIX_LEN] + hdr + payload).hex()


# --- committed fixture: green, and the declaration is actually there to enforce ---
rc, out = run_verify(COMMITTED)
check("committed fixture verifies green", rc == 0)
committed_twin = next(v for v in COMMITTED["frame_vectors"] if v["name"] == BIN_NAME)
check("committed _bin vector declares twin_of the legacy vector", committed_twin.get("twin_of") == LEGACY_NAME)
check(
    "committed _bin description is the generator's (a no-op generate rewrites nothing)",
    committed_twin["description"] == pfr.BIN_DESCRIPTION,
)

# --- verify hard-fails on every field the twin claim covers ---
TWIN_FAIL = "differs beyond envelope encoding"


def env_mutation(field: str, fn):
    def mutate(twin: dict) -> None:
        twin["payload_envelope"][field] = fn(twin["payload_envelope"][field])

    return mutate


MUTATIONS = {
    "value_json": lambda t: t["value_json"].__setitem__("user_id", 43),
    "frame prefix (magic/version/header bytes)": reorder_header_keys,
    "payload_envelope.compressed_data_hex": env_mutation("compressed_data_hex", flip_last_nibble),
    "payload_envelope.checksum_hex": env_mutation("checksum_hex", flip_last_nibble),
    "payload_envelope.original_size": env_mutation("original_size", lambda n: n + 1),
    "payload_envelope.format": env_mutation("format", lambda _: "json"),
    "payload_envelope.inner_msgpack_hex": env_mutation("inner_msgpack_hex", flip_last_nibble),
}
# Fields NO other verify check covers: here the twin gate is the only thing standing.
ONLY_TWIN_GATE = {"value_json", "frame prefix (magic/version/header bytes)"}

for field, mutate in MUTATIONS.items():
    doc, _ = mutated(mutate)
    rc, out = run_verify(doc)
    twin_lines = [line for line in out.splitlines() if line.startswith(f"FAIL {BIN_NAME}") and TWIN_FAIL in line]
    check(f"mutate {field}: verify exits 1", rc == 1)
    check(f"mutate {field}: twin gate names the field", len(twin_lines) == 1 and field in twin_lines[0])
    if field in ONLY_TWIN_GATE:
        fail_lines = [line for line in out.splitlines() if line.startswith("FAIL")]
        check(f"mutate {field}: twin gate is the ONLY check that fires", fail_lines == twin_lines)

# --- value_json compares type-strictly: Python's True == 1 must not pass the twin claim ---
doc, _ = mutated(lambda t: t["value_json"].__setitem__("active", 1))
rc, out = run_verify(doc)
twin_lines = [line for line in out.splitlines() if line.startswith(f"FAIL {BIN_NAME}") and TWIN_FAIL in line]
check("value_json true -> 1 in the twin: verify exits 1", rc == 1)
check("value_json true -> 1 in the twin: twin gate names value_json", len(twin_lines) == 1 and "value_json" in twin_lines[0])
check(
    "value_json true -> 1 in the twin: twin gate is the ONLY check that fires",
    [line for line in out.splitlines() if line.startswith("FAIL")] == twin_lines,
)

# --- original_size compares type-strictly against the envelope bytes ---
def reencode(vec: dict, *, data: bytes | None = None, size: int | None = None) -> None:
    """Rebuild vec's envelope bytes with `data`/`size` swapped in, and keep frame_hex,
    expected_payload_hex and payload_envelope's compressed_data_hex/original_size in step.

    Checksum and LZ4 output length are NOT recomputed: after a size swap the block no
    longer decompresses to original_size bytes. A test that swaps size relies on verify
    running LZ4 only after the drift check passes."""
    penv = vec["payload_envelope"]
    data = bytes.fromhex(penv["compressed_data_hex"]) if data is None else data
    size = penv["original_size"] if size is None else size
    payload = pfr._wire.encode_envelope(
        data, bytes.fromhex(penv["checksum_hex"]), size, penv["format"], encoding=penv["envelope_encoding"]
    )
    vec["frame_hex"] = pfr._frame_prefix_hex(vec) + payload.hex()
    vec["expected_payload_hex"] = payload.hex()
    penv["compressed_data_hex"], penv["original_size"] = data.hex(), size


# Set on BOTH twins, so the twin gate stays quiet and only the drift check can catch it.
# Each bad value is value-equal to the size in the bytes (32.0 == 32, True == 1): that
# equality is the trap. For True the pair is re-encoded at size 1 first.
for bad_size in (32.0, True):
    doc = copy.deepcopy(COMMITTED)
    pair = [v for v in doc["frame_vectors"] if v["name"] in (LEGACY_NAME, BIN_NAME)]
    for v in pair:
        reencode(v, size=int(bad_size))  # a no-op at the committed size
        v["payload_envelope"]["original_size"] = bad_size
    rc, out = run_verify(doc)
    drift = "payload_envelope field(s) disagree with the envelope bytes: original_size"
    # The encoding-coverage floor also fires once both twins fail; that is expected.
    vector_fails = [line for line in out.splitlines() if line.startswith("FAIL") and "envelope-encoding coverage" not in line]
    check(
        f"original_size {bad_size!r} on both twins: verify exits 1, FAILing both vectors on the drift check only",
        rc == 1 and vector_fails == [f"FAIL {v['name']}: {drift}" for v in pair],
    )

# --- a truncated LZ4 block, consistent everywhere else, reaches the decompress FAIL ---
doc = copy.deepcopy(COMMITTED)
twin = next(v for v in doc["frame_vectors"] if v["name"] == BIN_NAME)
del twin["twin_of"]  # the twin claim is not under test; keep its gate out of the output
reencode(twin, data=bytes.fromhex(twin["payload_envelope"]["compressed_data_hex"])[:-4])
rc, out = run_verify(doc)
bin_fails = [line for line in out.splitlines() if line.startswith(f"FAIL {BIN_NAME}:")]
check(
    "truncated LZ4 block, consistent elsewhere: verify exits 1, and LZ4 decompress is the vector's only FAIL",
    rc == 1 and len(bin_fails) == 1 and bin_fails[0].startswith(f"FAIL {BIN_NAME}: LZ4 decompress:"),
)

# --- a header that records no serializer name (s) FAILs; expected_header cannot vouch for it ---
# Applied to both twins, rebuilding header bytes, HDR_LEN and expected_header, so only the s check can fire.
S_FAIL = "frame header must record the serializer name as a non-empty string in 's'"
# label -> (header rewrite, the `got` verify reports)
S_CASES = {
    "s missing": (lambda h: {k: v for k, v in h.items() if k != "s"}, None),
    "s ''": (lambda h: {**h, "s": ""}, ""),
    "s 1": (lambda h: {**h, "s": 1}, 1),
    "header a JSON list": (lambda h: list(h.items()), None),
}
for label, (rewrite, got) in S_CASES.items():
    doc = copy.deepcopy(COMMITTED)
    pair = [v for v in doc["frame_vectors"] if v["name"] in (LEGACY_NAME, BIN_NAME)]
    for v in pair:
        header, payload = pfr.parse_frame(bytes.fromhex(v["frame_hex"]))
        hdr = json.dumps(rewrite(header)).encode()
        v["frame_hex"] = (pfr.MAGIC + bytes([pfr.FRAME_VERSION]) + len(hdr).to_bytes(4, "big") + hdr + payload).hex()
        v["expected_header"] = json.loads(hdr)
    rc, out = run_verify(doc)
    want = [f"FAIL {v['name']}: {S_FAIL}, got {got!r}" for v in pair]
    check(
        f"{label} on both twins: verify exits 1, FAILing both vectors on the s check only",
        rc == 1 and [line for line in out.splitlines() if line.startswith("FAIL")] == want,
    )

# --- expected_header compares type-strictly: 0 must not vouch for a header carrying false ---
doc = copy.deepcopy(COMMITTED)
raw = next(v for v in doc["frame_vectors"] if v["name"] == "raw_payload_frame")
if raw["expected_header"]["m"]["compressed"] is not False:
    raise RuntimeError("raw_payload_frame header no longer carries compressed: false; test is broken")
raw["expected_header"]["m"]["compressed"] = 0
rc, out = run_verify(doc)
check(
    "expected_header compressed 0 vs false in the header bytes: verify exits 1 on a header mismatch only",
    rc == 1 and [line for line in out.splitlines() if line.startswith("FAIL")]
    == ["FAIL raw_payload_frame: header mismatch"],
)

# --- header bytes must be RFC 8259 JSON: NaN/Infinity/-Infinity FAIL as a parse error ---
for token in ("NaN", "Infinity", "-Infinity"):
    doc = copy.deepcopy(COMMITTED)
    raw = next(v for v in doc["frame_vectors"] if v["name"] == "raw_payload_frame")
    header, payload = pfr.parse_frame(bytes.fromhex(raw["frame_hex"]))
    hdr = json.dumps({**header, "v": float(token)}).encode()
    raw["frame_hex"] = (pfr.MAGIC + bytes([pfr.FRAME_VERSION]) + len(hdr).to_bytes(4, "big") + hdr + payload).hex()
    raw["expected_header"] = json.loads(hdr)
    rc, out = run_verify(doc)
    check(
        f"header 'v' {token}: verify exits 1 on a parse error only",
        rc == 1
        and [line for line in out.splitlines() if line.startswith("FAIL")]
        == [f"FAIL raw_payload_frame: parse error: header is not RFC 8259 JSON: non-standard token {token}"],
    )

# --- inner_msgpack_hex is checked against the decompressed bytes, not only twin against twin ---
INNER_FAIL = "decompressed payload does not match payload_envelope.inner_msgpack_hex"
doc, twin = mutated(env_mutation("inner_msgpack_hex", flip_last_nibble))
legacy = next(v for v in doc["frame_vectors"] if v["name"] == LEGACY_NAME)
legacy["payload_envelope"]["inner_msgpack_hex"] = twin["payload_envelope"]["inner_msgpack_hex"]
rc, out = run_verify(doc)
check("same wrong inner_msgpack_hex on both twins: verify exits 1", rc == 1)
check(
    "same wrong inner_msgpack_hex on both twins: both vectors FAIL on the bytes",
    f"FAIL {BIN_NAME}: {INNER_FAIL}" in out and f"FAIL {LEGACY_NAME}: {INNER_FAIL}" in out,
)
doc, twin = mutated(env_mutation("inner_msgpack_hex", flip_last_nibble))
del twin["twin_of"]
rc, out = run_verify(doc)
check("wrong inner_msgpack_hex with twin_of dropped: verify exits 1", rc == 1 and f"FAIL {BIN_NAME}: {INNER_FAIL}" in out)

# --- a non-object payload_envelope is a FAIL line, never an AttributeError traceback ---
for bad in (["not", "an", "object"], "not an object"):
    kind = type(bad).__name__
    doc, _ = mutated(lambda t, bad=bad: t.__setitem__("payload_envelope", bad))
    rc, out = run_verify(doc)
    check(f"{kind} payload_envelope: verify exits 1 with a FAIL line", rc == 1 and "payload_envelope must be an object" in out)
# A present null is a non-object too, not "absent". On a vector outside the twin
# pair nothing else fires and the encoding coverage floor still holds.
doc = copy.deepcopy(COMMITTED)
next(v for v in doc["frame_vectors"] if v["name"] == "raw_payload_frame")["payload_envelope"] = None
rc, out = run_verify(doc)
fail_lines = [line for line in out.splitlines() if line.startswith("FAIL")]
check(
    "null payload_envelope on a non-twin vector: verify exits 1, and its FAIL line is the only one",
    rc == 1 and fail_lines == ["FAIL raw_payload_frame: payload_envelope must be an object, got NoneType"],
)

# --- a dangling declaration is a failure, not a silent skip ---
doc, _ = mutated(lambda t: t.__setitem__("twin_of", "no_such_vector"))
rc, out = run_verify(doc)
check("twin_of naming an unknown vector: verify exits 1", rc == 1)
check("twin_of naming an unknown vector: named in the failure", "unknown vector 'no_such_vector'" in out)

# --- vacuous declarations fail: self-reference, same-encoding decoy, envelope-less base ---
doc, twin = mutated(reorder_header_keys)
twin["twin_of"] = BIN_NAME
rc, out = run_verify(doc)
check("self-referential twin_of on a diverged twin: verify exits 1", rc == 1)
check("self-referential twin_of: failure names the encoding rule", "must differ from its base in encoding" in out)

doc, twin = mutated(reorder_header_keys)
doc["frame_vectors"].append({**copy.deepcopy(committed_twin), "name": "decoy_bin_copy"})
del doc["frame_vectors"][-1]["twin_of"]
twin["twin_of"] = "decoy_bin_copy"
rc, out = run_verify(doc)
check("twin_of pointing at a same-encoding copy: verify exits 1", rc == 1 and "must differ from its base" in out)

doc, twin = mutated(lambda t: t.__setitem__("twin_of", "raw_payload_frame"))
rc, out = run_verify(doc)
check("twin_of pointing at an envelope-less vector: verify exits 1", rc == 1)
check("twin_of pointing at an envelope-less vector: names the missing fields", "lacks" in out and "payload_envelope" in out)

# --- a partial envelope is a clean FAIL line, never a KeyError traceback ---
# inner_msgpack_hex is read by NO other verify check, so only the twin gate can trip on it.
doc, _ = mutated(lambda t: t["payload_envelope"].pop("inner_msgpack_hex"))
rc, out = run_verify(doc)
check("twin lacking an envelope subfield: verify exits 1", rc == 1)
check("twin lacking an envelope subfield: failure names it", "lacks payload_envelope.inner_msgpack_hex" in out)

# JSON null on BOTH sides must not compare equal and pass the claim vacuously.
doc, twin = mutated(lambda t: t["payload_envelope"].__setitem__("inner_msgpack_hex", None))
next(v for v in doc["frame_vectors"] if v["name"] == LEGACY_NAME)["payload_envelope"]["inner_msgpack_hex"] = None
rc, out = run_verify(doc)
check("null envelope subfield on both sides: verify exits 1", rc == 1 and "lacks payload_envelope.inner_msgpack_hex" in out)

# A missing envelope_encoding is "lacking", not a distinct encoding that satisfies "differs in encoding".
doc = copy.deepcopy(COMMITTED)
next(v for v in doc["frame_vectors"] if v["name"] == LEGACY_NAME)["payload_envelope"].pop("envelope_encoding")
rc, out = run_verify(doc)
check(
    "base lacking envelope_encoding: the twin FAILs too, naming it",
    rc == 1 and f"FAIL {BIN_NAME}: twin_of requires envelope vectors on both sides; "
    f"{LEGACY_NAME!r} lacks payload_envelope.envelope_encoding" in out,
)

doc, _ = mutated(lambda t: t.__setitem__("twin_of", [LEGACY_NAME]))
rc, out = run_verify(doc)
check("non-string twin_of: verify exits 1 with a FAIL line", rc == 1 and "must be a vector-name string" in out)

# --- a duplicate name cannot shadow the base ---
doc, twin = mutated(reorder_header_keys)
doc["frame_vectors"].append({**copy.deepcopy(twin), "name": LEGACY_NAME})
del doc["frame_vectors"][-1]["twin_of"]
rc, out = run_verify(doc)
check("duplicate legacy name appended (shadows the base): verify exits 1", rc == 1)
check("duplicate legacy name: failure names duplicates", "duplicate frame vector names" in out)

# --- the protocol-evolution exit: drop the declaration, nothing else loosens ---
# The header-reorder mutation is a byte-level prefix change that every OTHER
# verify check waves through; with twin_of gone it must verify green, and both
# encodings are still observed, so the coverage floor holds without the claim.
doc, twin = mutated(reorder_header_keys)
del twin["twin_of"]
rc, out = run_verify(doc)
check("evolution exit (twin_of dropped): diverged pair verifies green (coverage floor included)", rc == 0)

# --- generate-time: warns, never raises, spells out the exits ---
SYNTH_LEGACY = {
    "name": LEGACY_NAME,
    "value_json": {"a": 1},
    "frame_hex": "aabbccddpayload",
    "expected_payload_hex": "payload",
    "payload_envelope": {
        "compressed_data_hex": "11",
        "checksum_hex": "22",
        "original_size": 3,
        "format": "msgpack",
        "inner_msgpack_hex": "33",
        "envelope_encoding": "int-array",
    },
}
SYNTH_TWIN = {
    **SYNTH_LEGACY,
    "name": BIN_NAME,
    "twin_of": LEGACY_NAME,
    "payload_envelope": {**SYNTH_LEGACY["payload_envelope"], "envelope_encoding": "bin"},
}


def warn_output(vectors: list[dict]) -> tuple[bool, str]:
    buf = io.StringIO()
    raised = False
    try:
        with contextlib.redirect_stderr(buf):
            pfr._warn_twin_divergence(vectors)
    except Exception:  # noqa: BLE001 - generate must never raise here, whatever the type
        traceback.print_exc(file=sys.stdout)
        raised = True
    return raised, buf.getvalue()


raised, err = warn_output([SYNTH_LEGACY, {**SYNTH_LEGACY, "name": BIN_NAME}])
check("generate: no declaration -> silent", not raised and err == "")
raised, err = warn_output([SYNTH_LEGACY, SYNTH_TWIN])
check("generate: identical declared twin -> silent", not raised and err == "")
diverged = {**SYNTH_TWIN, "payload_envelope": {**SYNTH_TWIN["payload_envelope"], "inner_msgpack_hex": "ff"}}
raised, err = warn_output([SYNTH_LEGACY, diverged])
check("generate: diverged declared twin -> does not raise (no generator deadlock)", not raised)
check("generate: warning names the diverging field", "inner_msgpack_hex" in err)
check("generate: warning spells out the drop-twin_of exit", "drop 'twin_of'" in err)
raised, err = warn_output([diverged])
check("generate: dangling twin_of -> warns, does not raise", not raised and "unknown vector" in err)
# Reachable only via generate: verify() indexes frame_hex for every vector before the twin gate runs.
raised, err = warn_output([{k: v for k, v in SYNTH_LEGACY.items() if k != "frame_hex"}, SYNTH_TWIN])
check("generate: base lacking frame_hex -> warns, does not raise", not raised and "lacks frame_hex" in err)
for bad in (["not", "an", "object"], "not an object"):
    raised, err = warn_output([SYNTH_LEGACY, {**SYNTH_TWIN, "payload_envelope": bad}])
    check(
        f"generate: {type(bad).__name__} payload_envelope -> warns, does not raise",
        not raised and "lacks payload_envelope (object)" in err,
    )
raised, err = warn_output([SYNTH_LEGACY, {**SYNTH_TWIN, "value_json": {"a": True}}])
check("generate: value_json 1 vs true -> warns (type-strict compare)", not raised and "value_json" in err)
float_size = {**SYNTH_TWIN["payload_envelope"], "original_size": 3.0}
raised, err = warn_output([SYNTH_LEGACY, {**SYNTH_TWIN, "payload_envelope": float_size}])
check("generate: original_size 3 vs 3.0 -> warns (type-strict compare)", not raised and "original_size" in err)
no_encoding = {k: v for k, v in SYNTH_LEGACY["payload_envelope"].items() if k != "envelope_encoding"}
raised, err = warn_output([{**SYNTH_LEGACY, "payload_envelope": no_encoding}, SYNTH_TWIN])
check(
    "generate: base lacking envelope_encoding -> warns, does not raise",
    not raised and "lacks payload_envelope.envelope_encoding" in err,
)

# --- _upsert: the declaration survives a rebuild and never causes churn ---
committed = [copy.deepcopy(SYNTH_TWIN) | {"generator": "old wheel"}]
built = [{k: v for k, v in SYNTH_TWIN.items() if k != "twin_of"}]
changed = pfr._upsert(committed, built, "new wheel")
check("_upsert: identical content -> no-op despite twin_of/generator on the committed side", changed == [])
check("_upsert: no-op leaves the committed entry untouched", committed[0]["generator"] == "old wheel")
built[0]["payload_envelope"] = {**built[0]["payload_envelope"], "inner_msgpack_hex": "ff"}
changed = pfr._upsert(committed, built, "new wheel")
check("_upsert: rebuilt content -> rewritten", changed == [BIN_NAME] and committed[0]["generator"] == "new wheel")
check("_upsert: rewrite carries twin_of over", committed[0].get("twin_of") == LEGACY_NAME)
changed = pfr._upsert(committed, [{**built[0], "name": "brand_new"}], "new wheel")
check("_upsert: appended vector gains no twin_of", changed == ["brand_new"] and "twin_of" not in committed[1])

if FAILURES:
    print(f"\n{FAILURES} failure(s)")
    sys.exit(1)
print("\nall python-frame twin-gate checks passed")
