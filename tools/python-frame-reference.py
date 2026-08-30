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
              deserialization path before being written, and the default-path
              pair must differ ONLY in envelope encoding.

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

VECTOR_PATH = Path(__file__).resolve().parent.parent / "test-vectors" / "python-frame.json"

MAGIC = b"CK"
FRAME_VERSION = 3
PREFIX_LEN = 7  # magic(2) + version(1) + header_len(4)


def _load_wire_format_codec():
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


def verify() -> int:
    doc = _load_fixture()
    failures = 0
    observed_encodings: set[str] = set()

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
        description = (
            "Protocol 1.1 twin of default_saas_write_msgpack_bytestorage: same value, same "
            "default @cache write path, but the ByteStorage envelope's compressed_data is "
            "msgpack bin (serde_bytes) instead of an array of integers. Readers MUST accept "
            "both encodings; the legacy encoding stays pinned by the legacy vector's bytes."
        )
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
    per-vector 'generator' provenance) keeps the committed entry byte-untouched
    — a no-op `generate` leaves the fixture byte-identical. Returns the names
    of the vectors actually rewritten or added.
    """
    index = {v["name"]: i for i, v in enumerate(committed)}
    _require(len(index) == len(committed), "committed fixture has duplicate vector names")
    changed: list[str] = []
    for vec in built:
        i = index.get(vec["name"])
        if i is not None and {k: v for k, v in committed[i].items() if k != "generator"} == vec:
            continue
        stamped = {**vec, "generator": generator_stamp}
        if i is None:
            index[vec["name"]] = len(committed)
            committed.append(stamped)
        else:
            committed[i] = stamped
        changed.append(vec["name"])
    return changed


def _require_twin_equivalence(frame_vectors: list[dict]) -> None:
    """The default-path pair must differ ONLY in envelope encoding.

    The `_bin` twin's description asserts the encoding is the sole delta from
    the legacy vector. Prove it rather than trusting the wheel: a wheel that
    also changed the LZ4 level, msgpack key order, or the frame header would
    upsert a vector that lies about what it isolates, into a fixture
    downstream SDKs pin (LAB-903).
    """
    by_name = {v["name"]: v for v in frame_vectors}
    try:
        legacy = by_name["default_saas_write_msgpack_bytestorage"]
        twin = by_name["default_saas_write_msgpack_bytestorage_bin"]
    except KeyError as exc:
        raise ValueError("generation invariant violated: default-path vector pair incomplete") from exc
    _require(twin["value_json"] == legacy["value_json"], "twin value_json differs from the legacy vector")
    # Header equality must hold at the BYTE level, not just as parsed JSON — a
    # wheel that reorders or reformats the header JSON would otherwise slip a
    # byte-level non-twin past a dict compare. The frame prefix is everything
    # before the payload: magic, version, header length, header bytes.
    legacy_prefix = legacy["frame_hex"][: len(legacy["frame_hex"]) - len(legacy["expected_payload_hex"])]
    twin_prefix = twin["frame_hex"][: len(twin["frame_hex"]) - len(twin["expected_payload_hex"])]
    _require(twin_prefix == legacy_prefix, "twin frame prefix (magic/version/header bytes) differs from the legacy vector")
    for field in ("compressed_data_hex", "checksum_hex", "original_size", "format", "inner_msgpack_hex"):
        _require(
            twin["payload_envelope"][field] == legacy["payload_envelope"][field],
            f"twin payload_envelope.{field} differs from the legacy vector — encoding must be the ONLY delta",
        )


def generate() -> int:
    import msgpack  # third-party; generation only

    from cachekit.serializers.wrapper import SerializationWrapper

    import cachekit

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

    # Error vectors, verified against the REAL implementation as we build them.
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
    _require_twin_equivalence(doc["frame_vectors"])

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
