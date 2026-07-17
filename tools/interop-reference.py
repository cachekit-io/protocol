#!/usr/bin/env python3
"""Reference implementation of CacheKit interop mode (spec/interop-mode.md).

Stdlib-only. This file is the executable companion to the spec:
  - canonical MessagePack encoder (shortest-form, sorted maps)
  - interop argument normalization (number canonicalization, sets, datetimes, UUIDs)
  - interop key generation ({namespace}:{operation}:{args_hash})
  - test-vector generator + self-verifier for ../test-vectors/interop-mode.json

Usage:
    python3 tools/interop-reference.py generate   # rewrite test-vectors/interop-mode.json
    python3 tools/interop-reference.py verify     # re-derive and compare against the JSON

Cross-check with an independent implementation: tools/interop-crosscheck.mjs
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import sys
import uuid as uuid_mod
from datetime import datetime, timezone
from pathlib import Path

SEGMENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

UINT64_MAX = 2**64 - 1
INT64_MIN = -(2**63)
# Exact float64 bounds for the integral-collapse range check. Both are powers
# of two, hence exactly representable; 2^64-1 is NOT (it rounds to 2^64).
F64_UPPER_EXCL = 18446744073709551616.0  # 2^64
F64_LOWER_INCL = -9223372036854775808.0  # -(2^63)


class InteropError(ValueError):
    """Raised for values outside the interop data model."""


# ---------------------------------------------------------------------------
# Canonical MessagePack encoder (args profile)
# ---------------------------------------------------------------------------

def _encode_int(n: int, out: bytearray) -> None:
    if not INT64_MIN <= n <= UINT64_MAX:
        raise InteropError(f"integer out of interop range [-2^63, 2^64-1]: {n}")
    if 0 <= n <= 0x7F:
        out.append(n)
    elif -32 <= n < 0:
        out.append(n & 0xFF)
    elif n > 0:
        if n <= 0xFF:
            out += b"\xcc" + n.to_bytes(1, "big")
        elif n <= 0xFFFF:
            out += b"\xcd" + n.to_bytes(2, "big")
        elif n <= 0xFFFFFFFF:
            out += b"\xce" + n.to_bytes(4, "big")
        else:
            out += b"\xcf" + n.to_bytes(8, "big")
    else:
        if n >= -(2**7):
            out += b"\xd0" + n.to_bytes(1, "big", signed=True)
        elif n >= -(2**15):
            out += b"\xd1" + n.to_bytes(2, "big", signed=True)
        elif n >= -(2**31):
            out += b"\xd2" + n.to_bytes(4, "big", signed=True)
        else:
            out += b"\xd3" + n.to_bytes(8, "big", signed=True)


def _encode_str(s: str, out: bytearray) -> None:
    b = s.encode("utf-8")
    n = len(b)
    if n <= 31:
        out.append(0xA0 | n)
    elif n <= 0xFF:
        out += b"\xd9" + n.to_bytes(1, "big")
    elif n <= 0xFFFF:
        out += b"\xda" + n.to_bytes(2, "big")
    else:
        out += b"\xdb" + n.to_bytes(4, "big")
    out += b


def _encode_bin(b: bytes, out: bytearray) -> None:
    n = len(b)
    if n <= 0xFF:
        out += b"\xc4" + n.to_bytes(1, "big")
    elif n <= 0xFFFF:
        out += b"\xc5" + n.to_bytes(2, "big")
    else:
        out += b"\xc6" + n.to_bytes(4, "big")
    out += b


def _encode_array_header(n: int, out: bytearray) -> None:
    if n <= 15:
        out.append(0x90 | n)
    elif n <= 0xFFFF:
        out += b"\xdc" + n.to_bytes(2, "big")
    else:
        out += b"\xdd" + n.to_bytes(4, "big")


def _encode_map_header(n: int, out: bytearray) -> None:
    if n <= 15:
        out.append(0x80 | n)
    elif n <= 0xFFFF:
        out += b"\xde" + n.to_bytes(2, "big")
    else:
        out += b"\xdf" + n.to_bytes(4, "big")


def _encode_float_canonical(f: float, out: bytearray) -> None:
    """Number canonicalization: integral f64 in [-2^63, 2^64-1] encodes as int."""
    if math.isnan(f) or math.isinf(f):
        raise InteropError("NaN and Infinity are not allowed in interop arguments")
    if f.is_integer() and F64_LOWER_INCL <= f < F64_UPPER_EXCL:
        _encode_int(int(f), out)  # subsumes -0.0 -> int 0
    else:
        out += b"\xcb" + struct.pack(">d", f)


def encode_canonical(value: object, out: bytearray | None = None, *, collapse_floats: bool = True) -> bytes:
    """Canonically encode an interop-model value.

    collapse_floats=True is the ARGS profile (number canonicalization).
    collapse_floats=False is the VALUE profile (floats always float64).
    """
    root = out is None
    if out is None:
        out = bytearray()
    v = value
    if v is None:
        out.append(0xC0)
    elif isinstance(v, bool):
        out.append(0xC3 if v else 0xC2)
    elif isinstance(v, int):
        _encode_int(v, out)
    elif isinstance(v, float):
        if collapse_floats:
            _encode_float_canonical(v, out)
        else:
            if math.isnan(v) or math.isinf(v):
                raise InteropError("NaN and Infinity are not allowed in interop values")
            out += b"\xcb" + struct.pack(">d", v)
    elif isinstance(v, str):
        _encode_str(v, out)
    elif isinstance(v, (bytes, bytearray)):
        _encode_bin(bytes(v), out)
    elif isinstance(v, (list, tuple)):
        _encode_array_header(len(v), out)
        for item in v:
            encode_canonical(item, out, collapse_floats=collapse_floats)
    elif isinstance(v, dict):
        keys = list(v.keys())
        for k in keys:
            if not isinstance(k, str):
                raise InteropError(f"interop map keys must be strings, got {type(k).__name__}")
        # Unicode code point order == UTF-8 byte order; Python sorts str by code point.
        _encode_map_header(len(keys), out)
        for k in sorted(keys):
            _encode_str(k, out)
            encode_canonical(v[k], out, collapse_floats=collapse_floats)
    else:
        raise InteropError(f"type {type(v).__name__} is not in the interop data model")
    return bytes(out) if root else b""


# ---------------------------------------------------------------------------
# Argument normalization (spec: Canonical Argument Normalization)
# ---------------------------------------------------------------------------

class _PreEncoded:
    """A set normalized to its sorted, already-encoded elements."""

    def __init__(self, encoded_elements: list[bytes]):
        self.encoded_elements = encoded_elements


class _TaggedSet:
    """Ordered stand-in for a set (avoids Python hashability limits in vectors)."""

    def __init__(self, elements: list):
        self.elements = elements


def _encode_normalized_element(v: object) -> bytes:
    out = bytearray()
    _encode_normalized(v, out)
    return bytes(out)


def normalize_arg(v: object) -> object:
    """Map a source value into the interop data model. Recursive."""
    if v is None or isinstance(v, (bool, int, str, bytes, bytearray)):
        if isinstance(v, int) and not isinstance(v, bool) and not INT64_MIN <= v <= UINT64_MAX:
            raise InteropError(f"integer out of interop range: {v}")
        return v
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            raise InteropError("NaN and Infinity are not allowed in interop arguments")
        return v
    if isinstance(v, datetime):
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise InteropError("naive datetimes are not allowed in interop arguments")
        # Integer microseconds since epoch, then ONE float64 division by 10^6.
        # IEEE 754 division is exactly specified, so this is bit-identical
        # across languages (see spec: DateTime normalization).
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        delta = v - epoch
        micros = (delta.days * 86400 + delta.seconds) * 10**6 + delta.microseconds
        return micros / 1_000_000.0
    if isinstance(v, uuid_mod.UUID):
        return str(v)  # lowercase hyphenated
    if isinstance(v, (frozenset, set, _TaggedSet)):
        elements = v.elements if isinstance(v, _TaggedSet) else v
        # Sort by encoded bytes (total, language-neutral order); dedupe post-normalization.
        encoded = sorted({_encode_normalized_element(normalize_arg(e)) for e in elements})
        return _PreEncoded(encoded)
    if isinstance(v, (list, tuple)):
        return [normalize_arg(e) for e in v]
    if isinstance(v, dict):
        norm = {}
        for k, val in v.items():
            if not isinstance(k, str):
                raise InteropError(f"interop map keys must be strings, got {type(k).__name__}")
            norm[k] = normalize_arg(val)
        return norm
    raise InteropError(f"type {type(v).__name__} is not in the interop data model")


def _encode_normalized(v: object, out: bytearray) -> None:
    if isinstance(v, _PreEncoded):
        _encode_array_header(len(v.encoded_elements), out)
        for eb in v.encoded_elements:
            out += eb
    elif isinstance(v, list):
        _encode_array_header(len(v), out)
        for item in v:
            _encode_normalized(item, out)
    elif isinstance(v, dict):
        _encode_map_header(len(v), out)
        for k in sorted(v.keys()):
            _encode_str(k, out)
            _encode_normalized(v[k], out)
    else:
        encode_canonical(v, out)


def canonical_args_bytes(args: list | tuple) -> bytes:
    """Encode the flat canonical argument array to canonical MessagePack."""
    out = bytearray()
    normalized = [normalize_arg(a) for a in args]
    _encode_normalized(list(normalized), out)
    return bytes(out)


def args_hash(args: list | tuple) -> str:
    return hashlib.blake2b(canonical_args_bytes(args), digest_size=32).hexdigest()


def interop_key(namespace: str, operation: str, args: list | tuple) -> str:
    for name, seg in (("namespace", namespace), ("operation", operation)):
        if not SEGMENT_RE.match(seg):
            raise InteropError(
                f"invalid interop {name} {seg!r}: must match ^[a-z0-9][a-z0-9._-]{{0,63}}$"
            )
    return f"{namespace}:{operation}:{args_hash(args)}"


# ---------------------------------------------------------------------------
# AAD v0x03 (unchanged from spec/encryption.md; interop pins compressed="False")
# ---------------------------------------------------------------------------

def aad_v3(tenant_id: str, cache_key: str, fmt: str = "msgpack", compressed: bool = False) -> bytes:
    aad = bytearray([0x03])
    for comp in (tenant_id, cache_key, fmt, "True" if compressed else "False"):
        b = comp.encode("utf-8")
        aad += len(b).to_bytes(4, "big") + b
    return bytes(aad)


# ---------------------------------------------------------------------------
# Tagged-JSON input decoding for the vector file
# ---------------------------------------------------------------------------

def from_tagged(v: object) -> object:
    """Decode the vector file's tagged-JSON representation into Python values.

    Single-key objects with a $-prefixed key are typed tags:
      {"$set": [...]}, {"$bytes": "<hex>"}, {"$datetime": "<ISO 8601 with offset>"},
      {"$uuid": "<uuid>"}, {"$float": "<decimal>"}, {"$int": "<decimal>"}
    """
    if isinstance(v, list):
        return [from_tagged(e) for e in v]
    if isinstance(v, dict):
        if len(v) == 1:
            ((k, val),) = v.items()
            if k == "$set":
                return _TaggedSet([from_tagged(e) for e in val])
            if k == "$bytes":
                return bytes.fromhex(val)
            if k == "$datetime":
                return datetime.fromisoformat(val)
            if k == "$uuid":
                return uuid_mod.UUID(val)
            if k == "$float":
                return float(val)
            if k == "$int":
                return int(val)
            if k.startswith("$"):
                raise InteropError(f"unknown tag {k!r}")
        return {k: from_tagged(val) for k, val in v.items()}
    return v


def tagged_args(raw: list) -> list:
    """Decode a vector's args list from tagged JSON."""
    return [from_tagged(e) for e in raw]


# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------

KEY_VECTORS: list[dict] = [
    {
        "name": "empty_args",
        "description": "Zero arguments: canonical encoding of the empty array",
        "namespace": "users",
        "operation": "get_all",
        "args": [],
    },
    {
        "name": "single_int",
        "description": "Issue #1 example: users:get_user with one integer argument",
        "namespace": "users",
        "operation": "get_user",
        "args": [42],
    },
    {
        "name": "uint64_max",
        "description": "Largest interop integer (2^64-1), e.g. a snowflake ID",
        "namespace": "users",
        "operation": "get_user",
        "args": [{"$int": "18446744073709551615"}],
    },
    {
        "name": "int64_min",
        "description": "Smallest interop integer (-2^63)",
        "namespace": "t",
        "operation": "op",
        "args": [{"$int": "-9223372036854775808"}],
    },
    {
        "name": "unicode_string",
        "description": "UTF-8 string, no Unicode normalization applied",
        "namespace": "t",
        "operation": "op",
        "args": ["héllo wörld ✓"],
    },
    {
        "name": "bool_null",
        "description": "Booleans and null",
        "namespace": "t",
        "operation": "op",
        "args": [True, False, None],
    },
    {
        "name": "float_fractional",
        "description": "Non-integral float stays float64",
        "namespace": "t",
        "operation": "op",
        "args": [{"$float": "3.14"}],
    },
    {
        "name": "float_integral_collapse",
        "description": "Number canonicalization: 2.0 encodes as int 2 (must equal single_int_two)",
        "namespace": "t",
        "operation": "op",
        "args": [{"$float": "2.0"}],
    },
    {
        "name": "single_int_two",
        "description": "Int 2 — must produce the same key as float_integral_collapse",
        "namespace": "t",
        "operation": "op",
        "args": [2],
    },
    {
        "name": "negative_zero",
        "description": "-0.0 is integral, collapses to int 0",
        "namespace": "t",
        "operation": "op",
        "args": [{"$float": "-0.0"}],
    },
    {
        "name": "float_large_integral_out_of_range",
        "description": "Integral float 2^64 exceeds uint64 -> stays float64",
        "namespace": "t",
        "operation": "op",
        "args": [{"$float": "18446744073709551616"}],
    },
    {
        "name": "map_key_sort_ascii",
        "description": "Map keys sorted by code point: 'A' (0x41) before 'a' (0x61) before 'b'",
        "namespace": "t",
        "operation": "op",
        "args": [{"b": 2, "a": 1, "A": 3}],
    },
    {
        "name": "map_key_sort_supplementary",
        "description": (
            "Code-point order trap: U+FF61 sorts before U+10000. "
            "JS UTF-16 code-unit sort gets this BACKWARDS (0xD800 < 0xFF61)."
        ),
        "namespace": "t",
        "operation": "op",
        "args": [{"\U00010000": 1, "｡": 2}],
    },
    {
        "name": "nested_map_recursive_sort",
        "description": "Sorting applies at every nesting level",
        "namespace": "t",
        "operation": "op",
        "args": [{"z": {"b": 1, "a": 2}, "a": [1, 2]}],
    },
    {
        "name": "set_int_sorted",
        "description": "Set {3,1,2} -> elements sorted by encoded bytes -> [1,2,3]",
        "namespace": "t",
        "operation": "op",
        "args": [{"$set": [3, 1, 2]}],
    },
    {
        "name": "set_heterogeneous",
        "description": "Set {'b', 10, 'a'} -> byte order puts int 10 (0x0a) before strings",
        "namespace": "t",
        "operation": "op",
        "args": [{"$set": ["b", 10, "a"]}],
    },
    {
        "name": "datetime_fractional",
        "description": "tz-aware datetime -> floor to micros -> one float64 division by 10^6",
        "namespace": "events",
        "operation": "get_by_time",
        "args": [{"$datetime": "2024-01-01T12:30:45.123456+00:00"}],
    },
    {
        "name": "datetime_whole_second",
        "description": "Whole-second datetime yields integral float64 -> collapses to int",
        "namespace": "events",
        "operation": "get_by_time",
        "args": [{"$datetime": "2024-01-01T00:00:00+00:00"}],
    },
    {
        "name": "datetime_non_utc_offset",
        "description": "Non-UTC offset converts to the same instant (+05:30)",
        "namespace": "events",
        "operation": "get_by_time",
        "args": [{"$datetime": "2024-01-01T18:00:45.123456+05:30"}],
    },
    {
        "name": "uuid_lowercased",
        "description": "UUID normalizes to lowercase hyphenated string (input was uppercase)",
        "namespace": "users",
        "operation": "get_by_uuid",
        "args": [{"$uuid": "550E8400-E29B-41D4-A716-446655440000"}],
    },
    {
        "name": "bytes_bin",
        "description": "Bytes encode as msgpack bin (never str family)",
        "namespace": "t",
        "operation": "op",
        "args": [{"$bytes": "deadbeef"}],
    },
    {
        "name": "issue_example_mixed",
        "description": "Issue #1 vector: (42, 'hello', {'b': 2, 'a': 1})",
        "namespace": "t",
        "operation": "op",
        "args": [42, "hello", {"b": 2, "a": 1}],
    },
]

VALUE_VECTORS: list[dict] = [
    {
        "name": "issue_example_object",
        "description": "Issue #1 round-trip vector (canonical: sorted keys)",
        "value": {"name": "alice", "age": 30},
    },
    {
        "name": "float_value_stays_float64",
        "description": "VALUE profile: no number canonicalization, 2.0 stays float64",
        "value": {"$float": "2.0"},
    },
    {
        "name": "mixed_array",
        "description": "Array value with mixed scalars",
        "value": [1, "two", {"$float": "3.5"}, None, True],
    },
    {
        "name": "datetime_sentinel_value",
        "description": "Temporal VALUES use the wire-format.md sentinel map convention",
        "value": {"__datetime__": True, "value": "2024-01-01T12:30:45.123456+00:00"},
    },
]

ERROR_VECTORS: list[dict] = [
    {"name": "reject_nan", "args": [{"$float": "nan"}], "error": "NaN is not allowed"},
    {"name": "reject_infinity", "args": [{"$float": "inf"}], "error": "Infinity is not allowed"},
    {
        "name": "reject_int_overflow",
        "args": [{"$int": "18446744073709551616"}],
        "error": "integer above 2^64-1",
    },
    {
        "name": "reject_int_underflow",
        "args": [{"$int": "-9223372036854775809"}],
        "error": "integer below -2^63",
    },
    {
        "name": "reject_naive_datetime",
        "args": [{"$datetime": "2024-01-01T00:00:00"}],
        "error": "naive datetime (no UTC offset)",
    },
    {
        "name": "reject_uppercase_namespace",
        "namespace": "Users",
        "operation": "get_user",
        "args": [],
        "error": "namespace must match ^[a-z0-9][a-z0-9._-]{0,63}$",
    },
    {
        "name": "reject_colon_in_operation",
        "namespace": "users",
        "operation": "get:user",
        "args": [],
        "error": "operation must match ^[a-z0-9][a-z0-9._-]{0,63}$",
    },
]


def _build() -> dict:
    key_vectors = []
    for v in KEY_VECTORS:
        args = tagged_args(v["args"])
        cab = canonical_args_bytes(args)
        h = hashlib.blake2b(cab, digest_size=32).hexdigest()
        key_vectors.append(
            {
                "name": v["name"],
                "description": v["description"],
                "namespace": v["namespace"],
                "operation": v["operation"],
                "args": v["args"],
                "canonical_args_hex": cab.hex(),
                "args_hash": h,
                "expected_key": f"{v['namespace']}:{v['operation']}:{h}",
            }
        )

    value_vectors = []
    for v in VALUE_VECTORS:
        val = from_tagged(v["value"])
        vb = encode_canonical(val, collapse_floats=False)
        value_vectors.append(
            {
                "name": v["name"],
                "description": v["description"],
                "value": v["value"],
                "canonical_msgpack_hex": vb.hex(),
            }
        )

    # AAD vector binds to the single_int key so the two vectors compose.
    single_int = next(kv for kv in key_vectors if kv["name"] == "single_int")
    aad = aad_v3("cross-sdk-test", single_int["expected_key"])

    return {
        "version": "1.0.0",
        "spec": "spec/interop-mode.md",
        "generator": "tools/interop-reference.py (CPython stdlib)",
        "cross_checked_by": "tools/interop-crosscheck.mjs (independent encoder + @noble/hashes blake2b)",
        "hash_algorithm": "blake2b-256 (digest_size=32, unkeyed) over canonical MessagePack of the flat argument array",
        "key_format": "{namespace}:{operation}:{args_hash}",
        "segment_pattern": "^[a-z0-9][a-z0-9._-]{0,63}$",
        "tagged_json": {
            "note": "Single-key objects with a $-prefixed key are typed input tags; all other JSON maps directly.",
            "$set": "set of tagged values (unordered)",
            "$bytes": "hex-encoded byte string",
            "$datetime": "ISO 8601 with mandatory UTC offset",
            "$uuid": "UUID string (any case on input)",
            "$float": "decimal float literal (JSON numbers are always integers in this file)",
            "$int": "decimal integer literal (for values beyond 2^53, unsafe in JS JSON.parse)",
        },
        "key_vectors": key_vectors,
        "value_vectors": value_vectors,
        "error_vectors": ERROR_VECTORS,
        "aad_vectors": [
            {
                "name": "interop_key_aad",
                "description": "AAD v0x03 over an interop key; format=msgpack, compressed=False (always, in interop mode)",
                "tenant_id": "cross-sdk-test",
                "cache_key": single_int["expected_key"],
                "format": "msgpack",
                "compressed": False,
                "aad_hex": aad.hex(),
            }
        ],
    }


def main() -> int:
    vectors_path = Path(__file__).resolve().parent.parent / "test-vectors" / "interop-mode.json"
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    built = _build()

    # Self-checks: the two intentionally-equal vectors must agree, errors must raise.
    by_name = {v["name"]: v for v in built["key_vectors"]}
    assert by_name["float_integral_collapse"]["args_hash"] == by_name["single_int_two"]["args_hash"], (
        "number canonicalization broken: 2.0 and 2 must hash identically"
    )
    for ev in ERROR_VECTORS:
        try:
            if "namespace" in ev:
                interop_key(ev["namespace"], ev["operation"], tagged_args(ev["args"]))
            else:
                canonical_args_bytes(tagged_args(ev["args"]))
        except (InteropError, ValueError, OverflowError):
            continue
        raise AssertionError(f"error vector {ev['name']} did not raise")

    if cmd == "generate":
        vectors_path.write_text(json.dumps(built, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        print(f"wrote {vectors_path} ({len(built['key_vectors'])} key, "
              f"{len(built['value_vectors'])} value, {len(ERROR_VECTORS)} error vectors)")
        return 0

    on_disk = json.loads(vectors_path.read_text(encoding="utf-8"))
    if on_disk != built:
        print("MISMATCH: test-vectors/interop-mode.json does not match the reference implementation")
        return 1
    print(f"OK: {len(built['key_vectors'])} key vectors, {len(built['value_vectors'])} value vectors, "
          f"{len(ERROR_VECTORS)} error vectors, 1 AAD vector all verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
