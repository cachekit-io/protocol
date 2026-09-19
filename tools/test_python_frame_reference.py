#!/usr/bin/env python3
"""Mutation suite for the `twin_of` machinery in python-frame-reference.py (LAB-3967).

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
COMMITTED = json.loads(pfr.VECTOR_PATH.read_text())

FAILURES = 0


def check(name: str, cond: bool) -> None:
    global FAILURES
    print(f"{'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        FAILURES += 1


def run_verify(doc: dict) -> tuple[int, str]:
    """Run pfr.verify() against `doc` written to a temp file; returns (exit code, stdout)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "python-frame.json"
        path.write_text(json.dumps(doc))
        saved, pfr.VECTOR_PATH = pfr.VECTOR_PATH, path
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = pfr.verify()
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
ONLY_TWIN_GATE = {"value_json", "frame prefix (magic/version/header bytes)", "payload_envelope.inner_msgpack_hex"}

for field, mutate in MUTATIONS.items():
    doc, _ = mutated(mutate)
    rc, out = run_verify(doc)
    twin_lines = [line for line in out.splitlines() if line.startswith(f"FAIL {BIN_NAME}") and TWIN_FAIL in line]
    check(f"mutate {field}: verify exits 1", rc == 1)
    check(f"mutate {field}: twin gate names the field", len(twin_lines) == 1 and field in twin_lines[0])
    if field in ONLY_TWIN_GATE:
        fail_lines = [line for line in out.splitlines() if line.startswith("FAIL")]
        check(f"mutate {field}: twin gate is the ONLY check that fires", fail_lines == twin_lines)

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
    except ValueError:
        raised = True
    return raised, buf.getvalue()


raised, err = warn_output([SYNTH_LEGACY, {**SYNTH_LEGACY, "name": BIN_NAME}])
check("generate: no declaration -> silent", not raised and err == "")
raised, err = warn_output([SYNTH_LEGACY, SYNTH_TWIN])
check("generate: identical declared twin -> silent", not raised and err == "")
diverged = {**SYNTH_TWIN, "payload_envelope": {**SYNTH_LEGACY["payload_envelope"], "inner_msgpack_hex": "ff"}}
raised, err = warn_output([SYNTH_LEGACY, diverged])
check("generate: diverged declared twin -> does not raise (no generator deadlock)", not raised)
check("generate: warning names the diverging field", "inner_msgpack_hex" in err)
check("generate: warning spells out the drop-twin_of exit", "drop 'twin_of'" in err)
raised, err = warn_output([diverged])
check("generate: dangling twin_of -> warns, does not raise", not raised and "unknown vector" in err)

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
