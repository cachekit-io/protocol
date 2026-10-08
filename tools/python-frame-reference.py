#!/usr/bin/env python3
"""Reference tool for test-vectors/python-frame.json (Python CK v3 frame).

The CK v3 frame is the Python SDK's auto-mode storage container
(spec/wire-format.md, "SDK Storage Containers"). It is Python-SDK-internal:
other SDKs never decode it — these vectors exist so a non-Python reader can
*identify* Python auto-mode entries and fail with a diagnostic instead of
misparsing, and so the documented layout is pinned against the real
implementation.

Modes:
    verify    (default) stdlib-only. Re-parses every frame vector with an
              independent minimal parser (no cachekit import) and checks the
              expected header/payload (the header must be UTF-8 RFC 8259
              JSON, so malformed JSON, non-UTF-8 bytes and NaN/Infinity
              tokens FAIL; so does JSON this interpreter's json module
              refuses, an integer past its digit limit or nesting past
              its depth limit, as the Python SDK's reader cannot read it
              either; and it must record the serializer
              name as a non-empty string in `s`) and the ByteStorage envelope down
              to the LZ4-decompressed inner msgpack (inner_msgpack_hex);
              checks every error vector is rejected, by the check its
              `rejected_by` names (the serializer-name check included: a
              frame that records no name is a mismatch for every reader),
              that each write under an alias equals the canonical write
              byte for byte, that each name-check pair carries the default
              write's payload under another recorded name, and that each
              encrypted_read_vectors frame parses, claims what it declares
              and matches its pinned sha256. Runs in CI. It does not
              decode the inner msgpack, so value_json is checked against the
              decoded value only by tools/frame-crosscheck.mjs (Node).
    generate  Upserts the vector file by vector name (LAB-1203): every vector
              the installed wheel can reproduce is rebuilt, and rewritten only
              if its content actually changed; every other committed vector is
              left byte-untouched. The fixture is edited in place, never
              rebuilt from scratch, so dropping a committed vector is
              structurally impossible. Requires the real `cachekit` package
              (PyPI wheel with the Rust core) plus `msgpack`; the Arrow vector
              is rebuilt only when `pyarrow` + `pandas` are importable and is
              otherwise left as committed. A wheel emitting protocol 1.1 `bin`
              envelopes rebuilds the `_bin` twin of the default-path vector; a
              legacy (array-of-ints) wheel rebuilds the legacy original — the
              vector a wheel cannot produce is simply not touched. Every
              generated frame is round-tripped through the real cachekit-py
              deserialization path before being written, and every vector
              declaring `twin_of` is checked against its base (stderr warning
              only — see "Twin declarations" below; `verify` is the gate).
              Every error vector is proven rejected by cachekit-py's read path at
              its named check, and every encrypted_read_vectors frame proven to
              fail closed under the encrypted reader. That group is
              build-missing-only: its ciphertext carries a random nonce.

Twin declarations (LAB-3967):
    A frame vector may carry `"twin_of": "<vector name>"` — the operator's
    standing claim that it differs from the named base ONLY in envelope
    encoding (value, frame-prefix bytes, compressed bytes, checksum, size,
    format and inner msgpack all identical). The claim lives in the fixture,
    not in this code, because from the bytes alone "the wheel drifted" and
    "the protocol legitimately moved while the legacy vector stayed frozen"
    are indistinguishable. `generate` never adds or removes the field; a
    rebuild carries it over. When the default write path genuinely moves,
    the exit is to drop `twin_of` from the regenerated vector in the same
    commit — a reviewable fixture diff — and `verify` stays green with every
    byte comparison intact and both encodings still observed.

The independent parser below implements exactly the layout documented in
spec/wire-format.md:

    MAGIC b"CK" | VERSION u8 (=3) | HDR_LEN u32-BE | HEADER (UTF-8 JSON) | PAYLOAD

The ByteStorage envelope codec is NOT reimplemented here: encode/decode come
from tools/wire-format-reference.py, the single shared implementation of the
encoding these fixtures exist to pin (stdlib-only, so `verify` stays
dependency-free). LZ4 decompression of compressed_data likewise comes from
tools/interop-v2-reference.py's strict block decoder, which rejects truncation,
bad offsets and any output length other than original_size: a reader-lenient
decoder here would silently weaken the inner_msgpack_hex check.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from collections.abc import Callable
from types import ModuleType
from typing import NoReturn

VECTOR_PATH = Path(__file__).resolve().parent.parent / "test-vectors" / "python-frame.json"

MAGIC = b"CK"
FRAME_VERSION = 3
PREFIX_LEN = 7  # magic(2) + version(1) + header_len(4)

# Generator-owned text for the `_bin` default-path vector. It describes; it makes
# no twin claim — that claim is the operator-owned `twin_of` field, so dropping
# the field is a durable exit the next `generate` cannot revert by rewriting text.
BIN_DESCRIPTION = (
    "Default @cache write (StandardSerializer, integrity on) from a protocol 1.1 wheel: the "
    "ByteStorage envelope's compressed_data is msgpack bin (serde_bytes) instead of the legacy "
    "array of integers. Readers MUST accept both encodings; the legacy encoding stays pinned by "
    "default_saas_write_msgpack_bytestorage. When this vector carries 'twin_of', that field — not "
    "this text — is the claim that the two differ only in envelope encoding, and verify enforces it."
)


def _load_tool(filename: str, module_name: str) -> ModuleType:
    """Load a sibling stdlib-only reference tool as a module (hyphenated filename)."""
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_wire = _load_tool("wire-format-reference.py", "wire_format_reference")
_lz4_block_decompress = _load_tool("interop-v2-reference.py", "interop_v2_reference").lz4_block_decompress


class FrameError(ValueError):
    """A frame the parser rejects, tagged with the check that rejected it (error vectors' `rejected_by`)."""

    def __init__(self, reason: str, check: str = "header"):
        super().__init__(reason)
        self.check = check


def _require(condition: bool, what: str) -> None:
    """Generation-time invariant that survives ``python -O``.

    ``assert`` is stripped under ``-O``; a silently skipped check here could
    write a corrupt vector into the cross-SDK source of truth, so these
    invariants must always execute.
    """
    if not condition:
        raise ValueError(f"generation invariant violated: {what}")


def _load_fixture() -> dict:
    try:
        return json.loads(VECTOR_PATH.read_text())
    except OSError as exc:
        print(f"cannot read fixture {VECTOR_PATH}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    except json.JSONDecodeError as exc:
        print(f"fixture {VECTOR_PATH} is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def parse_frame(frame: bytes) -> tuple[dict, bytes]:
    """Independent CK v3 frame parser (deliberately not importing cachekit)."""
    if frame[:2] != MAGIC:
        raise FrameError("not a CK frame (missing 0x43 0x4B magic)", "magic")
    if len(frame) < PREFIX_LEN:
        raise FrameError(f"truncated frame: {len(frame)} bytes < {PREFIX_LEN}-byte fixed prefix", "prefix_length")
    version = frame[2]
    if version != FRAME_VERSION:
        raise FrameError(f"unsupported frame version {version} (expected {FRAME_VERSION})", "version")
    hdr_len = int.from_bytes(frame[3:7], "big")
    header_end = PREFIX_LEN + hdr_len
    if header_end > len(frame):
        raise FrameError(f"declared header length {hdr_len} exceeds frame ({len(frame)} bytes)", "header_length")
    try:
        header = json.loads(frame[PREFIX_LEN:header_end].decode("utf-8"), parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise FrameError(f"header is not UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FrameError(f"header is not valid JSON: {exc}") from exc
    except FrameError:
        raise  # _reject_constant's own error; FrameError is a ValueError, so it must not be re-wrapped below
    except ValueError as exc:  # an integer past sys.get_int_max_str_digits(); it has no class of its own
        raise FrameError(f"header exceeds this interpreter's JSON limits: {exc}") from exc
    except RecursionError as exc:  # its text names the interpreter's depth or stack size, so it is not echoed
        raise FrameError("header exceeds this interpreter's JSON limits: nested too deeply") from exc
    return header, frame[header_end:]


def _reject_constant(token: str) -> NoReturn:
    """json.loads accepts NaN/Infinity/-Infinity; RFC 8259 has no such tokens, and the Node leg rejects them."""
    raise FrameError(f"header is not RFC 8259 JSON: non-standard token {token}")


def _require_serializer_name(header: object) -> None:
    """spec/cache-key-format.md (KEY-5): a frame that records no serializer name is a mismatch for every reader.

    Same rule as cachekit-py's reader, which refuses it while unwrapping the frame: the header's `s` must be a
    non-empty str, nothing else.
    """
    ser = header.get("s") if isinstance(header, dict) else None
    if type(ser) is not str or not ser:
        raise FrameError(f"frame header records no serializer name in 's' (got {ser!r})", "serializer_name")


# The write every frame claim below is measured against: the default @cache write as protocol 1.1 wheels emit it.
DEFAULT_WRITE = "default_saas_write_msgpack_bytestorage_bin"

# Name-check pairs (spec/cache-key-format.md, KEY-4 and KEY-5): frames whose header records another serializer name
# than the default write's, over the default write's payload and metadata. A reader configured with "default" that
# skipped the name check, or resolved the recorded name through its own alias table, would decode each one to the
# value, so planting it under that reader isolates the check. Checked here so that a rebuilt frame cannot drift into
# one that only a decode error rejects. std_recorded_as_given_frame is constructed: what a writer that records an
# alias as given would store.
NAME_CHECK_PAIRS = {
    "auto_serializer_write": "auto",
    "standard_serializer_instance_write": "StandardSerializer",
    "std_recorded_as_given_frame": "std",
}

# Writes under each alias spelling (KEY-7, KEY-8) of a value AutoSerializer and StandardSerializer write differently.
# generate proves each equals the canonical name's write byte for byte; verify holds their payloads apart, so a
# writer that picks the serializer by the raw spelling, or records the alias as given, fails one of them.
ALIAS_WRITES = ("std_alias_write", "pythonic_alias_write")

# The serializer name and compressed flag each write records (KEY-3, ENC-10), so a frame rebuilt or edited into
# another configuration's cannot pass for this one.
WRITE_CLAIMS = {
    DEFAULT_WRITE: ("default", True),
    "arrow_dataframe_write": ("arrow", True),
    "auto_serializer_write": ("auto", True),
    "standard_serializer_instance_write": ("StandardSerializer", True),
    "std_alias_write": ("default", True),
    "pythonic_alias_write": ("auto", True),
    "integrity_checking_off_write": ("default", False),
    "arrow_compression_off_write": ("ArrowSerializer", False),
}


def _frame_claim_failures(by_name: dict[str, dict]) -> list[str]:
    """Why the name-check pairs or the alias writes no longer hold, one line each; empty when every claim holds."""
    lines = []
    base = by_name.get(DEFAULT_WRITE)
    for name, recorded in NAME_CHECK_PAIRS.items():
        vec = by_name.get(name)
        if vec is None or base is None:
            lines.append(f"{name}: the name-check pair needs both {name} and {DEFAULT_WRITE}")
            continue
        header, base_header = vec.get("expected_header"), base.get("expected_header")
        if not isinstance(header, dict) or header.get("s") != recorded:
            lines.append(f"{name}: must record the serializer name {recorded!r} over {DEFAULT_WRITE}'s payload")
        elif not isinstance(base_header, dict) or json.dumps(header.get("m"), sort_keys=True) != json.dumps(
            base_header.get("m"), sort_keys=True
        ):
            lines.append(f"{name}: metadata differs from {DEFAULT_WRITE}'s, so a reader that skips the name check may not decode it")
        elif vec.get("expected_payload_hex") != base.get("expected_payload_hex"):
            lines.append(f"{name}: payload differs from {DEFAULT_WRITE}'s, so a reader that skips the name check may not decode it")
    std, pythonic = (by_name.get(name) for name in ALIAS_WRITES)
    if std is None or pythonic is None:
        lines.append(f"{ALIAS_WRITES[0]}: the alias writes need both {' and '.join(ALIAS_WRITES)}")
    elif std.get("expected_payload_hex") == pythonic.get("expected_payload_hex"):
        lines.append(f"{ALIAS_WRITES[0]}: same payload as {ALIAS_WRITES[1]}, so the alias writes cannot show which serializer wrote them")
    for name, (recorded, compressed) in WRITE_CLAIMS.items():
        vec = by_name.get(name)
        header = vec.get("expected_header") if vec is not None else None
        meta = header.get("m") if isinstance(header, dict) else None
        if vec is None:
            lines.append(f"{name}: missing")
        elif not isinstance(meta, dict) or header.get("s") != recorded or meta.get("compressed") is not compressed:
            lines.append(f"{name}: must record the serializer name {recorded!r} and compressed {str(compressed).lower()}")
    # The flag says what the write's container did: a ByteStorage envelope compresses, a plain MessagePack payload does not.
    for name, vec in by_name.items():
        header = vec.get("expected_header")
        meta = header.get("m") if isinstance(header, dict) else None
        flag = meta.get("compressed") if isinstance(meta, dict) else None
        if "payload_envelope" in vec and flag is not True:
            lines.append(f"{name}: a ByteStorage envelope payload records compressed true, not {flag!r}")
        elif "payload_envelope" not in vec and "value_json" in vec and flag is not False:
            lines.append(f"{name}: a plain MessagePack payload records compressed false, not {flag!r}")
    return lines


# Fields a twin must share with its base. envelope_encoding must DIFFER, so it is
# not listed here; _twin_divergence requires its presence separately.
_TWIN_ENVELOPE_FIELDS = ("compressed_data_hex", "checksum_hex", "original_size", "format", "inner_msgpack_hex")


def _frame_prefix_hex(vec: dict) -> str:
    """Everything before the payload: magic, version, header length, header bytes."""
    return vec["frame_hex"][: len(vec["frame_hex"]) - len(vec["expected_payload_hex"])]


def _twin_divergence(twin: dict, by_name: dict[str, dict]) -> str | None:
    """Why `twin` is not an encoding-only twin of its `twin_of` base; None when the claim holds.

    "Differs ONLY in envelope encoding" entails "differs in envelope encoding":
    a declaration pointing at itself, or at a same-encoding copy under another
    name, is vacuous and fails here rather than passing green. The frame prefix
    is compared at the BYTE level, not as parsed JSON — a wheel that reorders or
    reformats the header JSON is a byte-level non-twin that a dict compare would
    wave through. Shared by verify() (hard fail) and generate() (warning), so
    the two can never drift apart on what "twin" means. Never raises on a
    malformed declaration or a vector missing (or null in) a compared field:
    the reason names what is lacking, so verify prints a FAIL line, not a
    traceback.
    """
    if not isinstance(twin["twin_of"], str):
        return f"twin_of must be a vector-name string, got {twin['twin_of']!r}"
    base = by_name.get(twin["twin_of"])
    if base is None:
        return f"twin_of names unknown vector {twin['twin_of']!r}"
    for side in (twin, base):
        missing = [k for k in ("value_json", "frame_hex", "expected_payload_hex") if side.get(k) is None]
        env = side.get("payload_envelope")
        if isinstance(env, dict):
            # envelope_encoding too: a missing one would otherwise count as a
            # distinct encoding and satisfy "differs in encoding" vacuously.
            required = ("envelope_encoding", *_TWIN_ENVELOPE_FIELDS)
            missing += [f"payload_envelope.{f}" for f in required if env.get(f) is None]
        else:
            missing.append("payload_envelope (object)")
        if missing:
            return f"twin_of requires envelope vectors on both sides; {side['name']!r} lacks {', '.join(missing)}"
    twin_env, base_env = twin["payload_envelope"], base["payload_envelope"]
    if twin_env["envelope_encoding"] == base_env["envelope_encoding"]:
        return (
            f"declared twin_of {base['name']!r} but both carry envelope_encoding "
            f"{twin_env['envelope_encoding']!r} — a twin must differ from its base in encoding"
        )
    mismatches: list[str] = []
    # Serialised, not `!=`: Python has True == 1 == 1.0, so a twin carrying
    # `1` against a base carrying `true` would compare equal.
    if json.dumps(twin["value_json"], sort_keys=True) != json.dumps(base["value_json"], sort_keys=True):
        mismatches.append("value_json")
    if _frame_prefix_hex(twin) != _frame_prefix_hex(base):
        mismatches.append("frame prefix (magic/version/header bytes)")
    # Type-strict for the same reason: 32.0 == 32 would hide a divergent original_size.
    mismatches += [
        f"payload_envelope.{field}"
        for field in _TWIN_ENVELOPE_FIELDS
        if type(twin_env[field]) is not type(base_env[field]) or twin_env[field] != base_env[field]
    ]
    if not mismatches:
        return None
    return f"declared twin_of {base['name']!r} but differs beyond envelope encoding: " + ", ".join(mismatches)


def _envelope_failure(env: object, payload: bytes) -> tuple[str | None, str | None]:
    """Why `payload` fails its `payload_envelope` declaration, else (None, the observed encoding).

    Guard clauses, one per check, in the order a reader depends on them: each
    later check assumes the earlier ones held. Returns the reason instead of
    printing, like _twin_divergence, and never raises on a malformed vector.
    Explicit returns, not `assert`: `python -O` strips asserts.
    """
    if not isinstance(env, dict):
        return f"payload_envelope must be an object, got {type(env).__name__}", None
    declared = env.get("envelope_encoding")
    if declared is None:
        return "payload_envelope must declare envelope_encoding ('bin' or 'int-array')", None
    # Shared, stdlib-only codec (wire-format-reference.py), so the no-dependency
    # CI leg proves the protocol 1.1 dual-read property on its own instead of
    # delegating it to the Node cross-check. decode_envelope also enforces the
    # exclusions from the 1.1 flip: checksum stays an array of 8 integers and
    # format stays a fixstr, in BOTH encodings.
    try:
        data, checksum, size, fmt, actual = _wire.decode_envelope(payload)
    except ValueError as e:
        return f"envelope decode: {e}", None
    if actual != declared:
        return f"compressed_data is {actual}, vector declares {declared}", None
    # decode_envelope tolerates reader-lenient forms no rmp_serde writer emits
    # (array16/array32 outer header, non-shortest uints); re-encode byte-fidelity
    # pins the canonical writer form, incl. the fixarray(4) marker.
    if _wire.encode_envelope(data, checksum, size, fmt, encoding=actual) != payload:
        return "envelope is not in canonical shortest-form encoding (re-encode differs)", None
    drifted = [
        fname
        for fname, got in (
            ("compressed_data_hex", data.hex()),
            ("checksum_hex", checksum.hex()),
            ("original_size", size),
            ("format", fmt),
        )
        # Type-strict: 32.0 == 32 (and True == 1) in Python, but a typed reader
        # rejects a non-integer size.
        if type(env.get(fname)) is not type(got) or env.get(fname) != got
    ]
    if drifted:
        return f"payload_envelope field(s) disagree with the envelope bytes: {', '.join(drifted)}", None
    # Checked against the bytes, not only twin against twin: two twins carrying
    # the same wrong value (or one vector with no twin) must still fail here.
    try:
        inner = _lz4_block_decompress(data, size)
    except ValueError as e:
        return f"LZ4 decompress: {e}", None
    if env.get("inner_msgpack_hex") != inner.hex():
        return "decompressed payload does not match payload_envelope.inner_msgpack_hex", None
    return None, actual


def _arrow_detection_failures(det: object, payload: bytes) -> list[str]:
    """Why `payload` fails its `arrow_detection` declaration; empty when it holds.

    A malformed declaration is one reason, never a traceback. The two byte
    checks are independent, so both are reported when both fail.
    """
    if not isinstance(det, dict):
        return [f"arrow_detection must be an object, got {type(det).__name__}"]
    # `type(...) is int`, not isinstance: bool is an int subclass, and JSON true
    # is not an offset. Non-negative, because a negative slice reads from the end.
    # Non-empty magic and a positive checksum length: an empty slice compares
    # equal to an empty declaration, so either would verify green unchecked.
    shape = {
        "checksum_len": lambda v: type(v) is int and v > 0,
        "checksum_hex": lambda v: type(v) is str,
        "ipc_magic_offset": lambda v: type(v) is int and v >= 0,
        "ipc_magic": lambda v: type(v) is str and v != "" and v.isascii(),
    }
    bad = [field for field, ok in shape.items() if field not in det or not ok(det[field])]
    if bad:
        return [
            (
                "arrow_detection needs checksum_len as a positive integer, ipc_magic_offset as a non-negative "
                f"integer, checksum_hex as a string and ipc_magic as a non-empty ASCII string; "
                f"missing or wrong type: {', '.join(bad)}"
            )
        ]
    # Else a payload shorter than checksum_len slices short and a short
    # checksum_hex could still match it.
    if len(det["checksum_hex"]) != 2 * det["checksum_len"]:
        return [
            (
                f"arrow_detection checksum_hex has {len(det['checksum_hex'])} hex digits, "
                f"checksum_len {det['checksum_len']} needs {2 * det['checksum_len']}"
            )
        ]
    failures = []
    off = det["ipc_magic_offset"]
    magic = det["ipc_magic"].encode("ascii")
    if payload[off : off + len(magic)] != magic:
        failures.append(f"Arrow IPC magic not found at payload offset {off}")
    if payload[: det["checksum_len"]].hex() != det["checksum_hex"]:
        failures.append("Arrow envelope checksum prefix mismatch")
    return failures


def verify() -> int:
    doc = _load_fixture()
    failures = 0
    observed_encodings: set[str] = set()
    by_name = {v["name"]: v for v in doc["frame_vectors"]}
    if len(by_name) != len(doc["frame_vectors"]):
        # twin_of resolves by name; a duplicate would silently shadow the real
        # base. _upsert refuses duplicates at generate time — verify must too.
        print("FAIL fixture: duplicate frame vector names")
        failures += 1

    for vec in doc["frame_vectors"]:
        name = vec["name"]
        frame = bytes.fromhex(vec["frame_hex"])
        vec_failed = 0
        try:
            header, payload = parse_frame(frame)
        except FrameError as e:
            print(f"FAIL {name}: parse error: {e}")
            failures += 1
            continue
        # Compared as canonical JSON, not with !=: 0 == False and 1.0 == 1 in Python,
        # so a loose compare would let expected_header vouch for header bytes it misstates.
        if json.dumps(header, sort_keys=True) != json.dumps(vec["expected_header"], sort_keys=True):
            print(f"FAIL {name}: header mismatch\n  got      {header}\n  expected {vec['expected_header']}")
            vec_failed += 1
        # spec/cache-key-format.md: an entry that records no serializer name is a
        # mismatch. Same rule as cachekit-py's reader: a non-empty str, nothing else.
        ser = header.get("s") if isinstance(header, dict) else None
        if type(ser) is not str or not ser:
            print(f"FAIL {name}: frame header must record the serializer name as a non-empty string in 's', got {ser!r}")
            vec_failed += 1
        if "expected_payload_hex" in vec and payload.hex() != vec["expected_payload_hex"]:
            print(f"FAIL {name}: payload mismatch")
            vec_failed += 1
        # Keyed on presence, not on None or truthiness: a present null, {} or []
        # is malformed, not "absent", so it cannot skip the checks below.
        if "payload_envelope" in vec:
            why, encoding = _envelope_failure(vec["payload_envelope"], payload)
            if why:
                print(f"FAIL {name}: {why}")
                vec_failed += 1
            else:
                # Only a fully verified envelope counts toward the coverage floor.
                observed_encodings.add(encoding)
        if "arrow_detection" in vec:
            for why in _arrow_detection_failures(vec["arrow_detection"], payload):
                print(f"FAIL {name}: {why}")
                vec_failed += 1
        if "twin_of" in vec:
            # CI gate for the twin claim (LAB-3967). Hard fail: the operator's
            # exit is dropping the declaration, never loosening this compare.
            why = _twin_divergence(vec, by_name)
            if why:
                print(f"FAIL {name}: {why}")
                vec_failed += 1
        failures += vec_failed
        if not vec_failed:
            print(f"ok   {name}")

    for vec in doc["error_vectors"]:
        name = vec["name"]
        frame = bytes.fromhex(vec["frame_hex"])
        if name == "ck_frame_fed_to_interop_reader":
            # Semantics: a strict single-document MessagePack reader must reject
            # this (0x43 = fixint 67 followed by trailing bytes). Structural
            # check only — full msgpack strictness is pinned by the generator
            # (msgpack-python raises ExtraData) and by tools/frame-crosscheck.mjs.
            if frame[:2] != MAGIC or len(frame) <= 1:
                print(f"FAIL {name}: vector is not a CK frame")
                failures += 1
            else:
                print(f"ok   {name} (CK-prefixed, multi-byte: not a single msgpack document)")
            continue
        want = vec.get("rejected_by")
        try:
            header, _ = parse_frame(frame)
            _require_serializer_name(header)
        except FrameError as e:
            # A boundary vector is only worth its bytes if the check it sits on rejects it:
            # a later check rejecting it instead is the reader the vector exists to catch.
            # Required, so no vector can be rejected by whatever check happens to fire.
            if e.check != want:
                print(f"FAIL {name}: rejected by the {e.check} check, not {want!r} (rejected_by): {e}")
                failures += 1
            else:
                print(f"ok   {name} (rejected by the {want} check)")
        else:
            print(f"FAIL {name}: expected rejection, parsed successfully")
            failures += 1

    for line in _frame_claim_failures(by_name):
        print(f"FAIL {line}")
        failures += 1

    failures += _verify_encrypted_reads(doc)

    # Coverage floor. Protocol 1.1 is "writers emit bin, readers accept legacy
    # FOREVER"; that dual-read guarantee is only proven while the fixture carries
    # a vector in each encoding. Without this, deleting the bin twin — or the
    # legacy vector that is the legacy-read proof — leaves the gate green.
    for want in ("int-array", "bin"):
        if want not in observed_encodings:
            print(f"FAIL envelope-encoding coverage: no frame vector exercises the {want} envelope encoding")
            failures += 1

    if failures:
        print(f"\n{failures} failure(s)")
        return 1
    print("\nall python-frame vectors verified")
    return 0


# A cache configured for encryption reads every encrypted_read_vectors frame and MUST fail
# closed (spec/wire-format.md, the CK frame CAUTION). The reader resolves its own tenant.
ENCRYPTED_READER_FIELDS = ("master_key_hex", "tenant_id", "tenant_source", "cache_key")


# sha256 of each encrypted-read frame, pinned in code. `generate` proves each frame fails
# closed against cachekit-py, but CI runs only `verify`, which cannot run the SDK's read
# path or AES-GCM. Without the pin, a frame swapped for bytes that authenticate nowhere,
# with its declared payload updated to match, or a dropped group, still verified green.
# The group is build-missing-only, so a pin changes only with a deliberate rebuild.
ENCRYPTED_READ_PINS = {
    "forged_plaintext_encrypted_false": "7e155990f82212403ad3e194077ca2e9b6d22dcd2c2a4c8be844d009c55ed786",
    "forged_plaintext_orjson": "887544092fc08040d0a1652b8ec7a50095d610a7d513cf58c5479790507cb647",
    "ciphertext_key_not_in_keyring": "323b270b4b67860213afd2c6bc0ecddb52f01958f6d6702ff6a3b1715a026c25",
    "ciphertext_other_tenant": "2ee0a5c536698672380fbc8b2300b87fda1f14e4d1fdc5f56a813423936caeb6",
    "ciphertext_plain_msgpack_not_envelope": "506a07d4cfe66adc03f2b1a1483f7378e55d6084845600ccde505a6624719e67",
    "ciphertext_plain_msgpack_claims_uncompressed": "542cf03a05b0e90b1a7e159523ce279ceb69e0365c99c8b5343fcf3ff57943a8",
}


def _verify_encrypted_reads(doc: dict) -> int:
    """Checks on the encrypted-read group; the fail-closed outcome is proven by `generate`.

    stdlib cannot run the SDK's read path, so verify pins the bytes `generate` proved: the
    set of vectors and each frame's sha256 (ENCRYPTED_READ_PINS), and the reader, which must
    equal ENCRYPTED_READER. It also checks what the bytes claim: each frame parses, records a
    serializer name, matches its declared header and payload, and its header claims what the
    vector's `header_claims` says (plaintext or ciphertext).
    """
    vectors = doc.get("encrypted_read_vectors", [])
    failures = 0
    if not isinstance(vectors, list):
        print(f"FAIL encrypted_read_vectors: must be a list, got {type(vectors).__name__}")
        vectors, failures = [], 1
    shaped = [v for v in vectors if isinstance(v, dict) and type(v.get("name")) is str and type(v.get("frame_hex")) is str]
    if len(shaped) != len(vectors):
        print("FAIL encrypted_read_vectors: every vector needs a string name and frame_hex")
        failures += 1
    vectors = shaped
    names = sorted(v["name"] for v in vectors)
    if names != sorted(ENCRYPTED_READ_PINS):
        print(f"FAIL encrypted_read_vectors: set drifted — fixture {names} != pinned {sorted(ENCRYPTED_READ_PINS)}")
        failures += 1
    if doc.get("encrypted_reader") != ENCRYPTED_READER:
        print("FAIL encrypted_reader: differs from ENCRYPTED_READER, the reader generate proved the frames against")
        failures += 1
    reader = doc.get("encrypted_reader")
    bad = [f for f in ENCRYPTED_READER_FIELDS if not isinstance(reader, dict) or type(reader.get(f)) is not str]
    try:
        key_ok = not bad and len(bytes.fromhex(reader["master_key_hex"])) == 32 and reader["tenant_source"] == "reader"
    except ValueError:
        key_ok = False
    if not key_ok:
        print(
            f"FAIL encrypted_reader: needs {', '.join(ENCRYPTED_READER_FIELDS)} as strings, a 32-byte master key "
            "and tenant_source reader"
        )
        failures += 1
    for vec in vectors:
        name = vec["name"]
        try:
            frame = bytes.fromhex(vec["frame_hex"])
            header, payload = parse_frame(frame)
        except ValueError as e:  # bad hex, or a FrameError
            print(f"FAIL {name}: parse error: {e}")
            failures += 1
            continue
        why = []
        digest = hashlib.sha256(frame).hexdigest()
        if name in ENCRYPTED_READ_PINS and digest != ENCRYPTED_READ_PINS[name]:
            why.append(f"frame sha256 {digest} differs from its pin; rebuild with generate and re-pin deliberately")
        if json.dumps(header, sort_keys=True) != json.dumps(vec.get("expected_header"), sort_keys=True):
            why.append("header mismatch")
        if payload.hex() != vec.get("expected_payload_hex"):
            why.append("payload mismatch")
        ser = header.get("s") if isinstance(header, dict) else None
        if type(ser) is not str or not ser:
            why.append("no serializer name in 's'")
        meta = header.get("m") if isinstance(header, dict) else None
        claims = "ciphertext" if isinstance(meta, dict) and meta.get("encrypted") is True else "plaintext"
        if vec.get("header_claims") != claims:
            why.append(f"header claims {claims}, vector declares {vec.get('header_claims')!r}")
        if vec.get("outcome") != "fail_closed":
            why.append(f"outcome must be fail_closed, got {vec.get('outcome')!r}")
        for w in why:
            print(f"FAIL {name}: {w}")
        failures += len(why)
        if not why:
            print(f"ok   {name} (header claims {claims}; an encrypted reader fails closed)")
    return failures


VALUE = {"user_id": 42, "name": "cachekit", "active": True}
# A value AutoSerializer and StandardSerializer write differently: AutoSerializer marks the tuple, StandardSerializer
# writes it as an array and reads it back as a list. The alias writes hold it, so their bytes show which serializer
# wrote them.
TUPLE_VALUE = {"pair": (1, "two")}


def _build_default_path_vector() -> dict:
    """Build the default-@cache-write vector from the installed cachekit wheel.

    The vector's name follows the envelope encoding the wheel emits:
    "bin" (msgpack 0xc4/0xc5/0xc6, protocol 1.1 writers) builds the `_bin`
    twin, "int-array" (legacy array-of-ints writers) builds the legacy
    original. Every frame is round-tripped through the real cachekit-py
    deserialization path before being returned.
    """
    return _build_envelope_vector("default")


def _build_envelope_vector(
    serializer: object, name: str | None = None, description: str | None = None, value: object = None, read_back: object = None
) -> dict:
    """A write of `value` (VALUE by default) through a handler configured with `serializer` (a name or an instance).

    With no `name`, it is the default write, named for the envelope encoding the wheel emits. The frame is
    round-tripped through cachekit-py's own read path, under the same configuration, which must return `read_back`
    (the value itself by default). value_json is the envelope's inner MessagePack decoded, what a reader of the bytes
    sees: a tuple AutoSerializer marks reads back as a tuple, but value_json holds its marker map.
    """
    import msgpack  # third-party; generation only

    from cachekit._rust_serializer import ByteStorage
    from cachekit.cache_handler import CacheSerializationHandler
    from cachekit.serializers.wrapper import SerializationWrapper

    value = VALUE if value is None else value
    handler = CacheSerializationHandler(serializer)
    frame = handler.serialize_data(value, cache_key="python-frame-vector")
    read = handler.deserialize_data(frame, cache_key="python-frame-vector")
    _require(read == (value if read_back is None else read_back) and type(read) is type(value), "cachekit-py round-trip mismatch")
    payload_mv, meta, ser_name = SerializationWrapper.unwrap(frame)
    payload = bytes(payload_mv)
    inner, fmt = ByteStorage("msgpack").retrieve(payload)
    inner = bytes(inner)
    value_json = msgpack.unpackb(inner)
    _require(fmt == "msgpack" and json.loads(json.dumps(value_json)) == value_json, "ByteStorage.retrieve round-trip mismatch")
    # Shared codec (wire-format-reference.py). decode_envelope enforces the
    # protocol 1.1 flip exclusions — checksum must stay an array of 8 integers
    # and format a fixstr — so a wheel drifting either field fails here.
    data, checksum, original_size, env_fmt, encoding = _wire.decode_envelope(payload)
    _require(env_fmt == fmt, "envelope format field disagrees with ByteStorage.retrieve")
    # Codec fidelity against the real wheel: the shared encoder must reproduce
    # the wheel's envelope byte-identically, or codec and wheel have drifted.
    _require(
        _wire.encode_envelope(data, checksum, original_size, env_fmt, encoding=encoding) == payload,
        "shared envelope codec does not reproduce the wheel's envelope bytes",
    )
    default_header, _ = parse_frame(frame)
    _require(default_header["m"] == meta and default_header["s"] == ser_name, "frame header disagrees with unwrap metadata")
    if encoding == "bin":
        encoding_note = (
            "rmp_serde positional fixarray(4); compressed_data encodes as msgpack bin "
            "(serde_bytes, protocol 1.1); checksum [u8;8] stays an array of integers"
        )
        if name is None:
            name, description = DEFAULT_WRITE, BIN_DESCRIPTION
    else:
        encoding_note = (
            "rmp_serde::to_vec positional fixarray(4); Vec<u8>/[u8;8] fields encode as msgpack arrays of integers"
        )
        if name is None:
            name = "default_saas_write_msgpack_bytestorage"
            description = (
                "Exact stored bytes for a default @cache write (StandardSerializer, integrity on): "
                "CK v3 frame wrapping the ByteStorage envelope of the MessagePack-encoded value. "
                "This is what any backend — including the SaaS — receives from cachekit-py in auto mode."
            )
    return {
        "name": name,
        "description": description,
        "value_json": value_json,
        "frame_hex": frame.hex(),
        "expected_header": default_header,
        "expected_payload_hex": payload.hex(),
        "payload_envelope": {
            "encoding": encoding_note,
            "envelope_encoding": encoding,
            "compressed_data_hex": data.hex(),
            "checksum_hex": checksum.hex(),
            "original_size": original_size,
            "format": env_fmt,
            "inner_msgpack_hex": inner.hex(),
        },
    }


def _build_integrity_off_vector() -> dict:
    """VALUE written by StandardSerializer with integrity checking off: plain MessagePack, no envelope, compressed false."""
    import msgpack  # third-party; generation only

    from cachekit.cache_handler import CacheSerializationHandler

    handler = CacheSerializationHandler("default", enable_integrity_checking=False)
    frame = handler.serialize_data(VALUE, cache_key="python-frame-vector")
    _require(handler.deserialize_data(frame, cache_key="python-frame-vector") == VALUE, "integrity-off round-trip mismatch")
    header, payload = parse_frame(frame)
    _require(msgpack.unpackb(payload) == VALUE, "integrity-off payload is not the value's plain MessagePack")
    _require(header["m"]["compressed"] is False, "integrity-off write records compressed other than false")
    return {
        "name": "integrity_checking_off_write",
        "description": (
            "The same value written by StandardSerializer with integrity checking off (@cache(integrity_checking=False), "
            "key suffix 0s): the payload is the value's plain MessagePack, with no ByteStorage envelope, and the header "
            "records compressed false, which is what an encrypted write of it authenticates in its AAD "
            "(spec/encryption.md: the AAD inputs reflect what the write produced)."
        ),
        "value_json": VALUE,
        "frame_hex": frame.hex(),
        "expected_header": header,
        "expected_payload_hex": payload.hex(),
    }


def _upsert(committed: list[dict], built: list[dict], generator_stamp: str) -> list[str]:
    """Replace committed vectors the wheel rebuilt (matched by name); append new names.

    Never removes anything: a vector this run did not rebuild stays exactly as
    committed, so dropping a committed vector is structurally impossible. A
    rebuilt vector whose content matches the committed one (ignoring its
    per-vector 'generator' provenance and any operator-owned 'twin_of'
    declaration) keeps the committed entry byte-untouched — a no-op `generate`
    leaves the fixture byte-identical. A rewrite carries 'twin_of' over
    unchanged: the wheel knows nothing about it, and generate never adds or
    drops it — that is the operator's reviewable move. Returns the names of
    the vectors actually rewritten or added.
    """
    index = {v["name"]: i for i, v in enumerate(committed)}
    _require(len(index) == len(committed), "committed fixture has duplicate vector names")
    changed: list[str] = []
    for vec in built:
        i = index.get(vec["name"])
        old = committed[i] if i is not None else {}
        if i is not None and {k: v for k, v in old.items() if k not in ("generator", "twin_of")} == vec:
            continue
        carried = {"twin_of": old["twin_of"]} if "twin_of" in old else {}
        stamped = {**vec, **carried, "generator": generator_stamp}
        if i is None:
            index[vec["name"]] = len(committed)
            committed.append(stamped)
        else:
            committed[i] = stamped
        changed.append(vec["name"])
    return changed


def _warn_twin_divergence(frame_vectors: list[dict]) -> None:
    """Warn (never raise) when a declared twin diverges from its base beyond encoding.

    A warning, not a `_require()` invariant: the legacy (array-of-ints) wheel is
    gone from every installable release, so the legacy vector can never be
    regenerated, and a hard failure here would permanently deadlock `generate`
    the first time the default write path legitimately moves (LAB-1203).
    verify() is the gate; this is the operator's early sight of what
    verify will reject, with the two legitimate exits spelled out.
    """
    by_name = {v["name"]: v for v in frame_vectors}
    for vec in frame_vectors:
        if "twin_of" not in vec:
            continue
        why = _twin_divergence(vec, by_name)
        if why:
            print(
                f"warning: {vec['name']}: {why}\n"
                "  `verify` will FAIL this fixture. Two legitimate exits: fix the wheel/codec so the "
                "rebuilt vector matches its base again, or — if the default write path genuinely "
                "moved — drop 'twin_of' from this vector in the same commit as the regenerated bytes.",
                file=sys.stderr,
            )


# cachekit-py's own message for each frame check (cachekit/serializers/wrapper.py), so
# generate proves the real reader rejects each error vector at the check it pins. A
# non-CK value falls through to cachekit-py's legacy JSON path, which refuses it.
_PY_REJECTION = {
    "prefix_length": "Truncated cache envelope frame",
    "version": "Unsupported cache envelope frame version",
    "header_length": "Invalid cache envelope header length",
    "magic": "Corrupt cache envelope",
    "serializer_name": "records no serializer name",
}


def _build_error_vectors(raw_frame: bytes, default_vec: dict) -> list[dict]:
    """Build the error vectors, each checked against the REAL implementation.

    Separate from generate() so the frame-vector flow and the error-vector flow
    read independently. Every vector here is proven to be rejected by
    cachekit-py's read path, at the check its `rejected_by` names, before it can
    be written, and the interop vector is proven to be rejected by a strict
    msgpack reader. The boundary vectors carry the real default-write header, so
    a reader that skips their check reaches the value instead of tripping over an
    empty header.
    """
    import msgpack  # third-party; generation only

    from cachekit.cache_handler import CacheSerializationHandler

    frame = bytes.fromhex(default_vec["frame_hex"])
    header_end = PREFIX_LEN + int.from_bytes(frame[3:PREFIX_LEN], "big")
    header, payload = parse_frame(frame)

    def reframed(new_header: dict) -> str:
        """The default write with another header, in cachekit-py's JSON layout (default separators)."""
        raw = json.dumps(new_header).encode("utf-8")
        return (MAGIC + bytes([FRAME_VERSION]) + len(raw).to_bytes(4, "big") + raw + payload).hex()

    built_errors = [
        {
            "name": "truncated_frame",
            "frame_hex": "434b03",
            "error": "shorter than the 7-byte fixed prefix (magic + version + header length)",
            "rejected_by": "prefix_length",
        },
        {
            "name": "unsupported_frame_version",
            "frame_hex": "434b04000000027b7d",
            "error": "frame version 4 (only version 3 is defined)",
            "rejected_by": "version",
        },
        {
            "name": "header_overrun",
            "frame_hex": "434b03000000ff7b7d",
            "error": "declared header length (255) exceeds the bytes present in the frame",
            "rejected_by": "header_length",
        },
        {
            "name": "truncated_frame_one_short",
            "frame_hex": frame[: PREFIX_LEN - 1].hex(),
            "error": (
                "6 bytes, one short of the 7-byte fixed prefix: the default write's magic, version and the first "
                "three bytes of its header length"
            ),
            "rejected_by": "prefix_length",
        },
        {
            "name": "unsupported_frame_version_2",
            "frame_hex": (frame[:2] + b"\x02" + frame[3:]).hex(),
            "error": (
                f"{default_vec['name']} with frame version 2, one below the only defined version. A reader that "
                "rejects only versions above 3 returns the value, because header and payload are intact"
            ),
            "rejected_by": "version",
        },
        {
            "name": "unsupported_frame_version_4",
            "frame_hex": (frame[:2] + b"\x04" + frame[3:]).hex(),
            "error": (
                f"{default_vec['name']} with frame version 4, one above the only defined version. A reader that "
                "rejects only versions below 3 returns the value, because header and payload are intact"
            ),
            "rejected_by": "version",
        },
        {
            "name": "header_overrun_by_one",
            "frame_hex": (frame[:3] + (header_end - PREFIX_LEN + 1).to_bytes(4, "big") + frame[PREFIX_LEN:header_end]).hex(),
            "error": (
                f"{default_vec['name']}'s prefix and header with no payload, the declared header length one past the "
                "bytes present. A reader that slices the header to the bytes present gets the real header and an "
                "empty payload"
            ),
            "rejected_by": "header_length",
        },
        {
            "name": "bare_envelope_fed_to_frame_reader",
            "frame_hex": default_vec["expected_payload_hex"],
            "error": (
                f"{default_vec['name']}'s payload alone: a bare ByteStorage envelope, cachekit-ts's default "
                "auto-mode container. cachekit-py MUST NOT decode another SDK's container; it has no CK magic"
            ),
            "rejected_by": "magic",
        },
        {
            "name": "plain_msgpack_fed_to_frame_reader",
            "frame_hex": default_vec["payload_envelope"]["inner_msgpack_hex"],
            "error": (
                f"{default_vec['name']}'s value as plain MessagePack, the container of cachekit-rs and of "
                "cachekit-ts with compression off. cachekit-py MUST NOT decode another SDK's container; it has "
                "no CK magic"
            ),
            "rejected_by": "magic",
        },
        {
            "name": "serializer_name_missing",
            "frame_hex": reframed({k: v for k, v in header.items() if k != "s"}),
            "error": (
                f"{default_vec['name']} with no serializer name in its header (no 's'). An entry that records no "
                "serializer name is a mismatch for every reader, so a miss. A reader that treats a nameless frame as "
                "a match returns the value, because the payload is intact"
            ),
            "rejected_by": "serializer_name",
        },
        {
            "name": "serializer_name_empty",
            "frame_hex": reframed({**header, "s": ""}),
            "error": (
                f"{default_vec['name']} with an empty serializer name ('s': \"\"), which records no name either: a "
                "mismatch for every reader, so a miss. A reader that checks only that 's' is present returns the value"
            ),
            "rejected_by": "serializer_name",
        },
    ]
    from cachekit.serializers.base import SerializationError  # every read-path refusal derives from it

    handler = CacheSerializationHandler(serializer_name="default")
    for vec in built_errors:
        try:
            handler.deserialize_data(bytes.fromhex(vec["frame_hex"]), cache_key="python-frame-vector")
        except SerializationError as e:  # the message names the check; a wrong one fails below
            _require(_PY_REJECTION[vec["rejected_by"]] in str(e), f"cachekit-py rejects {vec['name']} elsewhere: {e}")
        else:  # pragma: no cover - generation-time invariant
            raise AssertionError(f"cachekit-py accepted error vector {vec['name']}")
    try:
        msgpack.unpackb(raw_frame)
    except msgpack.exceptions.ExtraData:
        pass  # exactly the trailing-bytes rejection the spec requires
    else:  # pragma: no cover - generation-time invariant
        raise AssertionError("strict msgpack reader accepted a CK frame as one document")
    built_errors.insert(
        3,
        {
            "name": "ck_frame_fed_to_interop_reader",
            "frame_hex": raw_frame.hex(),
            "error": (
                "not a single well-formed MessagePack document: 0x43 is fixint 67, so the frame is one "
                "1-byte document plus trailing bytes. Interop readers MUST consume exactly one document "
                "and reject trailing bytes; on failure, a 0x43 0x4B prefix SHOULD be reported as "
                "'Python-SDK-internal auto-mode entry — not an interop value'"
            ),
        },
    )
    return built_errors


# The encrypted-read group's reader, and the key and tenant its ciphertext vectors were
# sealed under instead. Test-only keys.
# tenant_source "reader": the reader resolves tenant_id for itself, never from the frame
# header, which nothing authenticates.
ENCRYPTED_READER = {
    "master_key_hex": "11" * 32,
    "tenant_id": "00000000-0000-4000-8000-00000000000a",
    "tenant_source": "reader",
    "cache_key": "python-frame-vector",
}
OTHER_MASTER_KEY_HEX = "22" * 32
OTHER_TENANT = "00000000-0000-4000-8000-00000000000b"
# Fixed nonce for the one encrypted-read frame sealed here rather than by cachekit-py, so it is reproducible.
HAND_SEALED_NONCE = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaab")


def _encrypted_handler(master_key_hex: str, tenant: str, *, fail_closed: bool = False, serializer: str = "default"):
    """A cachekit-py handler encrypting as `tenant`, which it resolves itself (multi-tenant mode)."""
    from cachekit.cache_handler import CacheSerializationHandler
    from cachekit.decorators.tenant_context import CallableExtractor

    return CacheSerializationHandler(
        serializer, encryption=True, master_key=master_key_hex, encryption_fail_closed=fail_closed,
        tenant_extractor=CallableExtractor(lambda *_a, **_k: tenant),
    )


def _build_encrypted_read_vectors(default_vec: dict, committed: list[dict]) -> list[dict]:
    """Frames an encrypted cache MUST fail closed on, proven against cachekit-py.

    Build-missing-only: a ciphertext vector carries a random nonce, so rebuilding it
    would rewrite the fixture on every run. Every vector, committed or new, is read by
    the ENCRYPTED_READER under both tamper policies and must never return a value.
    """
    from cachekit.cache_handler import CacheSerializationHandler
    from cachekit.serializers.wrapper import SerializationWrapper

    key = ENCRYPTED_READER["cache_key"]
    value = default_vec["value_json"]
    payload, meta, ser = SerializationWrapper.unwrap(bytes.fromhex(default_vec["frame_hex"]))

    def plaintext_false() -> bytes:
        return SerializationWrapper.wrap(bytes(payload), {**meta, "encrypted": False}, ser)

    def orjson_plaintext() -> bytes:
        return CacheSerializationHandler("orjson", encryption=False).serialize_data(value, cache_key=key)

    def sealed(master_key_hex: str, tenant: str) -> Callable[[], bytes]:
        return lambda: _encrypted_handler(master_key_hex, tenant).serialize_data(value, cache_key=key)

    def plain_msgpack_sealed(compressed: bool = True) -> Callable[[], bytes]:
        return lambda: _plain_msgpack_sealed(compressed)

    def _plain_msgpack_sealed(compressed: bool) -> bytes:
        """The value's plain MessagePack, sealed under the reader's own key and AAD, in a real encrypted write's frame.

        The AAD is rebuilt from that write's header, and must open the write's own ciphertext first. With `compressed`
        false the header and AAD claim an uncompressed write, which the reader, configured for an envelope, must not
        take as its cue. The same frame sealed over the write's ByteStorage envelope must read back as the value, so
        only the container differs.
        """
        from cryptography.exceptions import InvalidTag  # third-party; generation only
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        ev = _load_tool("encryption-verify.py", "encryption_verify")
        reader_key, tenant = ENCRYPTED_READER["master_key_hex"], ENCRYPTED_READER["tenant_id"]
        own = _encrypted_handler(reader_key, tenant).serialize_data(value, cache_key=key)
        header, own_payload = parse_frame(own)
        m = header["m"]
        aad = ev.aad_v3(tenant, key, fmt=m["format"], compressed=m["compressed"], original_type=m.get("original_type"))
        derived = ev.derive_encryption_key(bytes.fromhex(reader_key), tenant)
        try:
            opened = AESGCM(derived).decrypt(own_payload[:12], own_payload[12:], aad)
        except InvalidTag as exc:
            raise ValueError("generation invariant violated: the rebuilt AAD does not open cachekit-py's own write") from exc
        _require(opened == bytes.fromhex(default_vec["expected_payload_hex"]), "the encrypted write's plaintext is not the default envelope")
        prefix = own[: len(own) - len(own_payload)]
        if not compressed:
            raw = json.dumps({**header, "m": {**m, "compressed": False}}).encode("utf-8")
            prefix = MAGIC + bytes([FRAME_VERSION]) + len(raw).to_bytes(4, "big") + raw
            aad = ev.aad_v3(tenant, key, fmt=m["format"], compressed=False, original_type=m.get("original_type"))

        def seal(plaintext: bytes) -> bytes:
            return prefix + HAND_SEALED_NONCE + AESGCM(derived).encrypt(HAND_SEALED_NONCE, plaintext, aad)

        control = _encrypted_handler(reader_key, tenant).deserialize_data(seal(opened), cache_key=key)
        _require(control == value, "the hand-sealed frame over the envelope does not read back as the value")
        return seal(bytes.fromhex(default_vec["payload_envelope"]["inner_msgpack_hex"]))

    builders = {
        "forged_plaintext_encrypted_false": (
            plaintext_false,
            f"{default_vec['name']}'s plaintext payload under a header that adds \"encrypted\": false. An attacker "
            "with backend write access can write this frame. An encrypted cache MUST NOT let the header downgrade "
            "it to the plaintext read path, and MUST fail closed.",
        ),
        "forged_plaintext_orjson": (
            orjson_plaintext,
            "the same value written by cachekit-py's orjson serializer with encryption off: the header names "
            "another serializer (s: orjson) and claims no encryption. An encrypted cache MUST fail closed, whether "
            "it refuses the serializer name or the plaintext claim first.",
        ),
        "ciphertext_key_not_in_keyring": (
            sealed(OTHER_MASTER_KEY_HEX, ENCRYPTED_READER["tenant_id"]),
            "the value sealed by cachekit-py for the reader's tenant under another master key, one the reader's "
            "keyring lacks (its key_fingerprint names that key). The ciphertext does not authenticate under the "
            "reader's key, so the read MUST fail closed, whatever its tamper policy.",
        ),
        "ciphertext_other_tenant": (
            sealed(ENCRYPTED_READER["master_key_hex"], OTHER_TENANT),
            f"the value sealed by cachekit-py under the reader's master key for tenant {OTHER_TENANT}. A reader that "
            f"resolves its own tenant ({ENCRYPTED_READER['tenant_id']}) derives another key and builds another AAD, "
            "so the ciphertext does not authenticate and the read MUST fail closed. A reader that takes the "
            "tenant from the unauthenticated header decrypts it.",
        ),
        "ciphertext_plain_msgpack_not_envelope": (
            plain_msgpack_sealed(),
            f"the value's plain MessagePack ({default_vec['name']}'s inner value, with no ByteStorage envelope), "
            "sealed under the reader's own key, tenant and AAD, in the frame of a real encrypted default write, whose "
            "header claims format msgpack, compressed true and original_type msgpack. The reader is configured for "
            "a ByteStorage envelope, and the container after decryption is the configured one and a parse "
            "mismatch hard-fails (spec/encryption.md), so the read MUST fail closed. A reader that falls back to "
            "plain MessagePack, or picks the container by looking at the bytes, returns the value. Sealed with a "
            "fixed nonce by tools/python-frame-reference.py, which checks that the same frame over the envelope "
            "reads back as the value.",
        ),
        "ciphertext_plain_msgpack_claims_uncompressed": (
            plain_msgpack_sealed(compressed=False),
            "ciphertext_plain_msgpack_not_envelope with its header and AAD claiming compressed false, which plain "
            "MessagePack is: the ciphertext authenticates under the reader's own key and AAD. The reader is configured "
            "for a ByteStorage envelope and the container after decryption is the configured one, never one the stored "
            "flag picks (spec/encryption.md), so the read MUST fail closed. A reader that takes the container from the "
            "flag reads plain MessagePack and returns the value. Sealed with a fixed nonce by "
            "tools/python-frame-reference.py, which checks that the same frame over the envelope reads back as the value.",
        ),
    }
    vectors = list(committed)
    present = {v["name"] for v in vectors}
    for name, (build, description) in builders.items():
        if name in present:
            continue
        frame = build()
        header, body = parse_frame(frame)
        vectors.append(
            {
                "name": name,
                "description": description,
                "frame_hex": frame.hex(),
                "expected_header": header,
                "expected_payload_hex": body.hex(),
                "header_claims": "ciphertext" if header["m"].get("encrypted") is True else "plaintext",
                "outcome": "fail_closed",
            }
        )
    from cachekit.serializers.base import SerializationError  # every read-path refusal derives from it

    reader_key, tenant = ENCRYPTED_READER["master_key_hex"], ENCRYPTED_READER["tenant_id"]
    readers = {fc: _encrypted_handler(reader_key, tenant, fail_closed=fc) for fc in (False, True)}
    for vec in vectors:
        for fail_closed, reader in readers.items():
            try:
                got = reader.deserialize_data(bytes.fromhex(vec["frame_hex"]), cache_key=key)
            except SerializationError:  # a refusal is the fail-closed outcome; anything else is a broken harness
                continue
            raise AssertionError(f"cachekit-py returned {got!r} for {vec['name']} (fail_closed={fail_closed})")
    # Positive control, per policy: each reader reads its own entry, so the refusals above are not a broken reader.
    own = _encrypted_handler(reader_key, tenant).serialize_data(value, cache_key=key)
    for fail_closed, reader in readers.items():
        _require(reader.deserialize_data(own, cache_key=key) == value,
                 f"the encrypted reader (fail_closed={fail_closed}) cannot read its own entry")
    return vectors


def generate() -> int:
    import cachekit
    from cachekit.serializers.wrapper import SerializationWrapper

    doc = _load_fixture()
    built: list[dict] = []

    # 1. Minimal parse vector: real SerializationWrapper.wrap over known raw bytes.
    raw_payload = b"hello, cachekit!"
    raw_meta = {"format": "msgpack", "compressed": False}
    raw_frame = SerializationWrapper.wrap(raw_payload, raw_meta, "default")
    p, m, s = SerializationWrapper.unwrap(raw_frame)
    _require(bytes(p) == raw_payload and m == raw_meta and s == "default", "SerializationWrapper round-trip mismatch")
    # expected_header comes from this tool's own independent parser, so the
    # vector pins what the frame actually contains (incl. the "v" field, which
    # cachekit-py's unwrap drops) rather than a hand-maintained copy.
    raw_header, _ = parse_frame(raw_frame)
    built.append(
        {
            "name": "raw_payload_frame",
            "description": "Minimal frame: SerializationWrapper.wrap over raw bytes. Parse-level vector.",
            "frame_hex": raw_frame.hex(),
            "expected_header": raw_header,
            "expected_payload_hex": raw_payload.hex(),
        }
    )

    # 2. Full default-path SaaS write: value -> msgpack -> ByteStorage envelope
    # -> CK frame. Named by the envelope encoding the wheel emits, so a
    # protocol 1.1 wheel rebuilds the _bin twin and a legacy wheel rebuilds the
    # legacy original — either way the other vector stays as committed.
    default_vec = _build_default_path_vector()
    built.append(default_vec)

    # 2b. Writes that pin the recorded serializer name (spec/cache-key-format.md, KEY-3 to KEY-8): AutoSerializer and a
    # StandardSerializer instance writing the default value, and each alias spelling writing TUPLE_VALUE.
    # NAME_CHECK_PAIRS, ALIAS_WRITES and WRITE_CLAIMS say what verify holds them to; they are measured against the
    # protocol 1.1 default write.
    if default_vec["name"] == DEFAULT_WRITE:
        from cachekit.cache_handler import CacheSerializationHandler
        from cachekit.serializers.base import SerializationError
        from cachekit.serializers.standard_serializer import StandardSerializer

        for serializer, name, description in (
            (
                "auto",
                "auto_serializer_write",
                f"The same value written by AutoSerializer (@cache(serializer=\"auto\")). Its payload and metadata equal "
                f"{DEFAULT_WRITE}'s and only the recorded name differs (s: auto), so a reader configured with "
                "\"default\" that skipped the serializer-name check would decode it to the value. Planted under that "
                "reader, it MUST be a miss (spec/cache-key-format.md).",
            ),
            (
                StandardSerializer(),
                "standard_serializer_instance_write",
                "The same value written by a StandardSerializer() instance (@cache(serializer=StandardSerializer())). "
                "The frame records the bare class name, StandardSerializer, over "
                f"{DEFAULT_WRITE}'s payload and metadata, while the key carries the identity "
                "<custom>:StandardSerializer (code x8542). A reader configured with \"default\" MUST miss on it, and a "
                "reader configured with an instance of the class MUST read it, which one that compares its key "
                "identity instead of the recorded name does not.",
            ),
        ):
            built.append(_build_envelope_vector(serializer, name, description))
        for alias, canonical, name, read_back, description in (
            (
                "std",
                "default",
                "std_alias_write",
                {"pair": [1, "two"]},
                "{\"pair\": (1, \"two\")}, a map holding a tuple, written under the alias std: byte for byte what the "
                "canonical name default writes, so the alias records default and writes StandardSerializer's bytes, which "
                "hold the tuple as an array. AutoSerializer writes the same value differently (pythonic_alias_write), so a "
                "writer that picks the serializer by the raw spelling fails one of the two.",
            ),
            (
                "pythonic",
                "auto",
                "pythonic_alias_write",
                None,
                "{\"pair\": (1, \"two\")} written under the alias pythonic: byte for byte what the canonical name auto "
                "writes, so the alias records auto and writes AutoSerializer's bytes, which mark the tuple "
                "({\"__tuple__\": true, \"value\": [1, \"two\"]}). StandardSerializer writes the same value differently "
                "(std_alias_write).",
            ),
        ):
            vec = _build_envelope_vector(alias, name, description, value=TUPLE_VALUE, read_back=read_back)
            canonical_frame = CacheSerializationHandler(canonical).serialize_data(TUPLE_VALUE, cache_key="python-frame-vector")
            _require(bytes.fromhex(vec["frame_hex"]) == canonical_frame, f"the {alias} write differs from the {canonical} write")
            built.append(vec)
        # What a writer that records an alias as given would store: the default write's bytes under the name std.
        payload_mv, meta, _ = SerializationWrapper.unwrap(bytes.fromhex(default_vec["frame_hex"]))
        recorded_std = SerializationWrapper.wrap(bytes(payload_mv), meta, "std")
        std_header, std_payload = parse_frame(recorded_std)
        built.append(
            {
                "name": "std_recorded_as_given_frame",
                "description": (
                    f"Constructed: {DEFAULT_WRITE}'s payload and metadata under the recorded name std, the frame a writer "
                    "that records an alias as given would store. A reader configured with \"default\" MUST miss on it, "
                    "since it records std, not the canonical name; one that resolves the recorded name through its own "
                    "alias table before it compares returns the value."
                ),
                "value_json": default_vec["value_json"],
                "frame_hex": recorded_std.hex(),
                "expected_header": std_header,
                "expected_payload_hex": std_payload.hex(),
                "payload_envelope": default_vec["payload_envelope"],
            }
        )
        # Each name-check pair is refused by a default-configured reader at the name check, and its payload is one that
        # reader's serializer decodes to the value: only the name check stands between it and the value.
        for vec in built:
            if vec["name"] not in NAME_CHECK_PAIRS:
                continue
            frame = bytes.fromhex(vec["frame_hex"])
            try:
                CacheSerializationHandler("default").deserialize_data(frame, cache_key="python-frame-vector")
            except SerializationError as exc:
                _require("Serializer mismatch" in str(exc), f"cachekit-py refuses {vec['name']} elsewhere: {exc}")
            else:  # pragma: no cover - generation-time invariant
                raise AssertionError(f"a default-configured reader returned a value from {vec['name']}")
            payload_mv, _, _ = SerializationWrapper.unwrap(frame)
            _require(StandardSerializer().deserialize(bytes(payload_mv), None) == VALUE, f"{vec['name']}'s payload does not decode to the value")
        built.append(_build_integrity_off_vector())

    # 3. Arrow path: frame wrapping [8-byte xxHash3-64][Arrow IPC file].
    # Optional: without pandas + pyarrow the committed vector is left untouched.
    try:
        import pandas as pd
        import pyarrow
    except ImportError as exc:
        print(f"note: pandas/pyarrow not importable ({exc}); arrow_dataframe_write left as committed", file=sys.stderr)
    else:
        from cachekit.cache_handler import CacheSerializationHandler

        arrow_handler = CacheSerializationHandler(serializer_name="arrow")
        df = pd.DataFrame({"id": [1, 2], "score": [1.5, 2.5]})
        arrow_frame = arrow_handler.serialize_data(df, cache_key="python-frame-vector")
        rt = arrow_handler.deserialize_data(arrow_frame, cache_key="python-frame-vector")
        _require(rt.equals(df), "Arrow round-trip mismatch")
        a_payload_mv, a_meta, a_ser = SerializationWrapper.unwrap(arrow_frame)
        a_payload = bytes(a_payload_mv)
        _require(a_payload[8:14] == b"ARROW1", "Arrow IPC magic not at documented offset")
        arrow_header, _ = parse_frame(arrow_frame)
        _require(arrow_header["m"] == a_meta and arrow_header["s"] == a_ser, "Arrow frame header disagrees with unwrap metadata")
        from cachekit.serializers.arrow_serializer import ArrowSerializer

        off_handler = CacheSerializationHandler(ArrowSerializer(compression=None))
        off_frame = off_handler.serialize_data(df, cache_key="python-frame-vector")
        _require(off_handler.deserialize_data(off_frame, cache_key="python-frame-vector").equals(df), "uncompressed Arrow round-trip mismatch")
        off_header, off_payload = parse_frame(off_frame)
        _require(off_payload[8:14] == b"ARROW1" and off_header["m"]["compressed"] is False, "uncompressed Arrow write is not what it claims")
        built.append(
            {
                "name": "arrow_compression_off_write",
                "description": (
                    "DataFrame write via an ArrowSerializer(compression=None) instance: CK v3 frame wrapping "
                    "[8-byte xxHash3-64 checksum][Arrow IPC file] with uncompressed buffers. The header records "
                    "compressed false and the bare class name ArrowSerializer; spec/encryption.md gives this write's AAD "
                    "inputs as (\"arrow\", false, original_type=\"arrow\"). Arrow IPC bytes are NOT canonical across "
                    f"pyarrow versions (this vector: pyarrow {pyarrow.__version__}) — verify frame structure and envelope "
                    "detection only, never IPC bytes."
                ),
                "frame_hex": off_frame.hex(),
                "expected_header": off_header,
                "arrow_detection": {
                    "checksum_len": 8,
                    "checksum_hex": off_payload[:8].hex(),
                    "ipc_magic_offset": 8,
                    "ipc_magic": "ARROW1",
                },
            }
        )
        built.append(
            {
                "name": "arrow_dataframe_write",
                "description": (
                    "DataFrame write via ArrowSerializer: CK v3 frame wrapping the Arrow envelope "
                    "[8-byte xxHash3-64 checksum][Arrow IPC file]. Arrow IPC bytes are NOT canonical "
                    f"across pyarrow versions (this vector: pyarrow {pyarrow.__version__}) — verify "
                    "frame structure and envelope detection only, never IPC bytes."
                ),
                "frame_hex": arrow_frame.hex(),
                "expected_header": arrow_header,
                "arrow_detection": {
                    "checksum_len": 8,
                    "checksum_hex": a_payload[:8].hex(),
                    "ipc_magic_offset": 8,
                    "ipc_magic": "ARROW1",
                },
            }
        )

    built_errors = _build_error_vectors(raw_frame, default_vec)
    encrypted = _build_encrypted_read_vectors(default_vec, doc.get("encrypted_read_vectors", []))

    # Upsert by name. The top-level 'generator' (the legacy-vector provenance)
    # is never rewritten; every vector this run rewrites or adds carries its
    # own per-vector 'generator' recording which wheel produced it.
    generator_stamp = (
        f"cachekit {cachekit.__version__} (PyPI wheel; Rust core via PyO3), "
        "generated by tools/python-frame-reference.py generate"
    )
    unstamped = {v["name"] for v in doc["frame_vectors"] + doc["error_vectors"] if "generator" not in v}
    changed = _upsert(doc["frame_vectors"], built, generator_stamp)
    changed += _upsert(doc["error_vectors"], built_errors, generator_stamp)
    added = [v["name"] for v in encrypted if v["name"] not in {c["name"] for c in doc.get("encrypted_read_vectors", [])}]
    if doc.get("encrypted_reader") != ENCRYPTED_READER:
        doc["encrypted_reader"] = ENCRYPTED_READER
        changed.append("encrypted_reader")
    for name in added:
        frame = bytes.fromhex(next(v for v in encrypted if v["name"] == name)["frame_hex"])
        print(f"note: pin {name} in ENCRYPTED_READ_PINS: {hashlib.sha256(frame).hexdigest()}", file=sys.stderr)
    if added:
        doc["encrypted_read_vectors"] = [
            v if v["name"] not in added else {**v, "generator": generator_stamp} for v in encrypted
        ]
        changed += added
    _warn_twin_divergence(doc["frame_vectors"])

    if not changed:
        print(
            f"{VECTOR_PATH} already up to date ({len(built)} frame, {len(built_errors)} error "
            "vectors rebuilt, all identical to committed); nothing written"
        )
        return 0
    if unstamped & set(changed) and not doc["generator"].startswith("mixed provenance"):
        # Rewriting a vector the top-level provenance claim covered would turn
        # that claim into a lie; per-vector 'generator' becomes authoritative.
        doc["generator"] = (
            "mixed provenance — vectors carrying a per-vector 'generator' field record "
            f"their own; all others: {doc['generator']}"
        )
    VECTOR_PATH.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    print(
        f"wrote {VECTOR_PATH} — rewrote/added: {', '.join(changed)} "
        f"({len(doc['frame_vectors'])} frame, {len(doc['error_vectors'])} error, "
        f"{len(doc.get('encrypted_read_vectors', []))} encrypted-read vectors total)"
    )
    return 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if mode in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    if mode == "generate":
        sys.exit(generate())
    if mode == "verify":
        sys.exit(verify())
    print(f"unsupported mode: {mode!r}; expected 'verify' or 'generate'", file=sys.stderr)
    sys.exit(2)
