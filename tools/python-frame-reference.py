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
              expected header/payload; checks every error vector is rejected.
              Runs in CI.
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
dependency-free).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

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


def _load_wire_format_codec() -> ModuleType:
    """Load tools/wire-format-reference.py as a module (hyphenated filename)."""
    path = Path(__file__).resolve().parent / "wire-format-reference.py"
    spec = importlib.util.spec_from_file_location("wire_format_reference", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load envelope codec from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_wire = _load_wire_format_codec()


class FrameError(ValueError):
    pass


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
        raise FrameError("not a CK frame (missing 0x43 0x4B magic)")
    if len(frame) < PREFIX_LEN:
        raise FrameError(f"truncated frame: {len(frame)} bytes < {PREFIX_LEN}-byte fixed prefix")
    version = frame[2]
    if version != FRAME_VERSION:
        raise FrameError(f"unsupported frame version {version} (expected {FRAME_VERSION})")
    hdr_len = int.from_bytes(frame[3:7], "big")
    header_end = PREFIX_LEN + hdr_len
    if header_end > len(frame):
        raise FrameError(f"declared header length {hdr_len} exceeds frame ({len(frame)} bytes)")
    header = json.loads(frame[PREFIX_LEN:header_end].decode("utf-8"))
    return header, frame[header_end:]


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
    the two can never drift apart on what "twin" means.
    """
    base = by_name.get(twin["twin_of"])
    if base is None:
        return f"twin_of names unknown vector {twin['twin_of']!r}"
    for side in (twin, base):
        missing = [k for k in ("value_json", "expected_payload_hex", "payload_envelope") if k not in side]
        if missing:
            return f"twin_of requires envelope vectors on both sides; {side['name']!r} lacks {', '.join(missing)}"
    twin_env, base_env = twin["payload_envelope"], base["payload_envelope"]
    if twin_env.get("envelope_encoding") == base_env.get("envelope_encoding"):
        return (
            f"declared twin_of {base['name']!r} but both carry envelope_encoding "
            f"{twin_env.get('envelope_encoding')!r} — a twin must differ from its base in encoding"
        )
    mismatches: list[str] = []
    if twin["value_json"] != base["value_json"]:
        mismatches.append("value_json")
    if _frame_prefix_hex(twin) != _frame_prefix_hex(base):
        mismatches.append("frame prefix (magic/version/header bytes)")
    mismatches += [
        f"payload_envelope.{field}" for field in _TWIN_ENVELOPE_FIELDS if twin_env[field] != base_env[field]
    ]
    if not mismatches:
        return None
    return f"declared twin_of {base['name']!r} but differs beyond envelope encoding: " + ", ".join(mismatches)


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
        if header != vec["expected_header"]:
            print(f"FAIL {name}: header mismatch\n  got      {header}\n  expected {vec['expected_header']}")
            vec_failed += 1
        if "expected_payload_hex" in vec and payload.hex() != vec["expected_payload_hex"]:
            print(f"FAIL {name}: payload mismatch")
            vec_failed += 1
        env = vec.get("payload_envelope")
        if env:
            declared = env.get("envelope_encoding")
            if declared is None:
                print(f"FAIL {name}: payload_envelope must declare envelope_encoding ('bin' or 'int-array')")
                vec_failed += 1
            else:
                # Shared, stdlib-only codec (wire-format-reference.py), so the
                # no-dependency CI leg proves the protocol 1.1 dual-read
                # property on its own instead of delegating it to the Node
                # cross-check. decode_envelope also enforces the exclusions
                # from the 1.1 flip: checksum stays an array of 8 integers and
                # format stays a fixstr, in BOTH encodings.
                try:
                    data, checksum, size, fmt, actual = _wire.decode_envelope(payload)
                except ValueError as e:
                    print(f"FAIL {name}: envelope decode: {e}")
                    vec_failed += 1
                else:
                    if actual != declared:
                        print(f"FAIL {name}: compressed_data is {actual}, vector declares {declared}")
                        vec_failed += 1
                    elif _wire.encode_envelope(data, checksum, size, fmt, encoding=actual) != payload:
                        # decode_envelope tolerates reader-lenient forms no
                        # rmp_serde writer emits (array16/array32 outer header,
                        # non-shortest uints); re-encode byte-fidelity pins the
                        # canonical writer form, incl. the fixarray(4) marker.
                        print(f"FAIL {name}: envelope is not in canonical shortest-form encoding (re-encode differs)")
                        vec_failed += 1
                    else:
                        drifted = [
                            fname
                            for fname, got in (
                                ("compressed_data_hex", data.hex()),
                                ("checksum_hex", checksum.hex()),
                                ("original_size", size),
                                ("format", fmt),
                            )
                            if env.get(fname) != got
                        ]
                        if drifted:
                            print(f"FAIL {name}: payload_envelope field(s) disagree with the envelope bytes: {', '.join(drifted)}")
                            vec_failed += 1
                        else:
                            observed_encodings.add(actual)
        det = vec.get("arrow_detection")
        if det:
            off = det["ipc_magic_offset"]
            magic = det["ipc_magic"].encode("ascii")
            if payload[off : off + len(magic)] != magic:
                print(f"FAIL {name}: Arrow IPC magic not found at payload offset {off}")
                vec_failed += 1
            if payload[: det["checksum_len"]].hex() != det["checksum_hex"]:
                print(f"FAIL {name}: Arrow envelope checksum prefix mismatch")
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
        try:
            parse_frame(frame)
        except FrameError:
            print(f"ok   {name} (rejected)")
        else:
            print(f"FAIL {name}: expected rejection, parsed successfully")
            failures += 1

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


def _build_default_path_vector() -> dict:
    """Build the default-@cache-write vector from the installed cachekit wheel.

    The vector's name follows the envelope encoding the wheel emits:
    "bin" (msgpack 0xc4/0xc5/0xc6, protocol 1.1 writers) builds the `_bin`
    twin, "int-array" (legacy array-of-ints writers) builds the legacy
    original. Every frame is round-tripped through the real cachekit-py
    deserialization path before being returned.
    """
    import msgpack  # third-party; generation only

    from cachekit._rust_serializer import ByteStorage
    from cachekit.cache_handler import CacheSerializationHandler
    from cachekit.serializers.wrapper import SerializationWrapper

    value = {"user_id": 42, "name": "cachekit", "active": True}
    handler = CacheSerializationHandler(serializer_name="default")
    frame = handler.serialize_data(value, cache_key="python-frame-vector")
    _require(handler.deserialize_data(frame, cache_key="python-frame-vector") == value, "cachekit-py round-trip mismatch")
    payload_mv, meta, ser_name = SerializationWrapper.unwrap(frame)
    payload = bytes(payload_mv)
    inner, fmt = ByteStorage("msgpack").retrieve(payload)
    inner = bytes(inner)
    _require(msgpack.unpackb(inner) == value and fmt == "msgpack", "ByteStorage.retrieve round-trip mismatch")
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
        name = "default_saas_write_msgpack_bytestorage_bin"
        description = BIN_DESCRIPTION
        encoding_note = (
            "rmp_serde positional fixarray(4); compressed_data encodes as msgpack bin "
            "(serde_bytes, protocol 1.1); checksum [u8;8] stays an array of integers"
        )
    else:
        name = "default_saas_write_msgpack_bytestorage"
        description = (
            "Exact stored bytes for a default @cache write (StandardSerializer, integrity on): "
            "CK v3 frame wrapping the ByteStorage envelope of the MessagePack-encoded value. "
            "This is what any backend — including the SaaS — receives from cachekit-py in auto mode."
        )
        encoding_note = (
            "rmp_serde::to_vec positional fixarray(4); Vec<u8>/[u8;8] fields encode as msgpack arrays of integers"
        )
    return {
        "name": name,
        "description": description,
        "value_json": value,
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


def _build_error_vectors(raw_frame: bytes) -> list[dict]:
    """Build the error vectors, each checked against the REAL implementation.

    Separate from generate() so the frame-vector flow and the error-vector flow
    read independently. Every vector here is proven to be rejected by
    cachekit-py before it can be written, and the interop vector is proven to
    be rejected by a strict msgpack reader.
    """
    import msgpack  # third-party; generation only

    from cachekit.serializers.wrapper import SerializationWrapper

    built_errors = [
        {
            "name": "truncated_frame",
            "frame_hex": "434b03",
            "error": "shorter than the 7-byte fixed prefix (magic + version + header length)",
        },
        {
            "name": "unsupported_frame_version",
            "frame_hex": "434b04000000027b7d",
            "error": "frame version 4 (only version 3 is defined)",
        },
        {
            "name": "header_overrun",
            "frame_hex": "434b03000000ff7b7d",
            "error": "declared header length (255) exceeds the bytes present in the frame",
        },
    ]
    for vec in built_errors:
        try:
            SerializationWrapper.unwrap(bytes.fromhex(vec["frame_hex"]))
        except ValueError:
            pass
        else:  # pragma: no cover - generation-time invariant
            raise AssertionError(f"cachekit-py accepted error vector {vec['name']}")
    try:
        msgpack.unpackb(raw_frame)
    except msgpack.exceptions.ExtraData:
        pass  # exactly the trailing-bytes rejection the spec requires
    else:  # pragma: no cover - generation-time invariant
        raise AssertionError("strict msgpack reader accepted a CK frame as one document")
    built_errors.append(
        {
            "name": "ck_frame_fed_to_interop_reader",
            "frame_hex": raw_frame.hex(),
            "error": (
                "not a single well-formed MessagePack document: 0x43 is fixint 67, so the frame is one "
                "1-byte document plus trailing bytes. Interop readers MUST consume exactly one document "
                "and reject trailing bytes; on failure, a 0x43 0x4B prefix SHOULD be reported as "
                "'Python-SDK-internal auto-mode entry — not an interop value'"
            ),
        }
    )
    return built_errors


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
    built.append(_build_default_path_vector())

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

    built_errors = _build_error_vectors(raw_frame)

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
        f"({len(doc['frame_vectors'])} frame, {len(doc['error_vectors'])} error vectors total)"
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
