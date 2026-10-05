#!/usr/bin/env python3
"""Reference implementation of CacheKit interop mode (spec/interop-mode.md).

Stdlib-only (one optional extra, see below). This file is the executable
companion to the spec:
  - canonical MessagePack encoder (shortest-form, sorted maps)
  - interop argument normalization (number canonicalization, sets, datetimes, UUIDs)
  - interop key generation ({namespace}:{operation}:{args_hash})
  - a value reader that accepts any well-formed document and rejects trailing bytes
  - HKDF-SHA256 key derivation per spec/encryption.md (stdlib hmac/hashlib)
  - test-vector generator + self-verifier for ../test-vectors/interop-mode.json

Usage:
    python3 tools/interop-reference.py generate   # rewrite test-vectors/interop-mode.json
    python3 tools/interop-reference.py verify     # re-derive and compare against the JSON

Two optional-dependency checks deepen `verify` when the packages are importable
(both run in CI, see .github/workflows/verify.yml):
  - `cryptography`: re-verifies the AES-256-GCM seal of the encryption vector
    (stdlib has no AES-GCM; tools/interop-crosscheck.mjs ALWAYS verifies it via
    Node's built-in WebCrypto regardless).
  - `msgpack`: decodes every canonical payload and re-encodes it byte-identically
    (third-encoder conformance with the de-facto shortest-form behavior).

Cross-check with an independent implementation: tools/interop-crosscheck.mjs
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import struct
import sys
import uuid as uuid_mod
from datetime import datetime, timezone
from pathlib import Path

# Implementations MUST full-string match (Python re.match would accept a
# trailing newline because $ matches before it — use fullmatch, never match).
SEGMENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Exact namespace values the grammar admits but the SaaS server parses as a key
# prefix (spec/cache-key-format.md#server-side-requirements): a key starting
# `ns:` or `nsapi:` would be scoped to a namespace named after the operation, or
# rejected. Namespace-only and exact-match — `ns` as an operation, or `nsapix` as
# a namespace, cannot form either prefix.
RESERVED_NAMESPACES = frozenset({"ns", "nsapi"})
# The grammar admits `..` inside a segment, but the server rejects `..` anywhere
# in a key (spec/cache-key-format.md#server-side-requirements, Traversal), so a
# segment containing it would mint a key that fails on every request. The `:`
# delimiters separate the segments and the hash is hex, so any `..` in the key
# lies inside one segment, and checking each segment covers the whole key.
FORBIDDEN_SUBSTRING = ".."

UINT64_MAX = 2**64 - 1
INT64_MIN = -(2**63)
# Exact float64 bounds for the integral-collapse range check. Both are powers
# of two, hence exactly representable; 2^64-1 is NOT (it rounds to 2^64).
F64_UPPER_EXCL = 18446744073709551616.0  # 2^64
F64_LOWER_INCL = -9223372036854775808.0  # -(2^63)


class InteropError(ValueError):
    """Raised for values outside the interop data model."""


class _PreEncoded:
    """A set normalized to its sorted, deduplicated, already-encoded elements."""

    def __init__(self, encoded_elements: list[bytes]) -> None:
        self.encoded_elements = encoded_elements


class _TaggedSet:
    """Ordered stand-in for a set (avoids Python hashability limits in vectors)."""

    def __init__(self, elements: list) -> None:
        self.elements = elements


# ---------------------------------------------------------------------------
# Canonical MessagePack encoder — ONE encoder for both profiles.
# collapse_floats=True is the ARGS profile (number canonicalization);
# collapse_floats=False is the VALUE profile (floats always float64).
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
    elif n >= -(2**7):
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


def _encode(v: object, out: bytearray, *, collapse_floats: bool) -> None:
    if v is None:
        out.append(0xC0)
    elif isinstance(v, bool):
        out.append(0xC3 if v else 0xC2)
    elif isinstance(v, int):
        _encode_int(v, out)
    elif isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            raise InteropError("NaN and Infinity are not allowed in interop mode")
        if collapse_floats and v.is_integer() and F64_LOWER_INCL <= v < F64_UPPER_EXCL:
            _encode_int(int(v), out)  # subsumes -0.0 -> int 0
        else:
            out += b"\xcb" + struct.pack(">d", v)
    elif isinstance(v, str):
        _encode_str(v, out)
    elif isinstance(v, (bytes, bytearray)):
        _encode_bin(bytes(v), out)
    elif isinstance(v, _PreEncoded):
        _encode_array_header(len(v.encoded_elements), out)
        for eb in v.encoded_elements:
            out += eb
    elif isinstance(v, (list, tuple)):
        _encode_array_header(len(v), out)
        for item in v:
            _encode(item, out, collapse_floats=collapse_floats)
    elif isinstance(v, dict):
        keys = list(v.keys())
        for k in keys:
            if not isinstance(k, str):
                raise InteropError(f"interop map keys must be strings, got {type(k).__name__}")
        # Unicode code point order == UTF-8 byte order; Python sorts str by code point.
        _encode_map_header(len(keys), out)
        for k in sorted(keys):
            _encode_str(k, out)
            _encode(v[k], out, collapse_floats=collapse_floats)
    else:
        raise InteropError(f"type {type(v).__name__} is not in the interop data model")


def encode_canonical(value: object, *, collapse_floats: bool = True) -> bytes:
    """Canonically encode an interop-model (or normalized) value."""
    out = bytearray()
    _encode(value, out, collapse_floats=collapse_floats)
    return bytes(out)


# ---------------------------------------------------------------------------
# Value reader (spec: Interop Value Format) — accepts ANY well-formed document,
# canonical or not, and rejects trailing bytes. What a reader returns for the
# two shapes outside the data model is its own business; these stand-ins exist
# so the canonical encoder rejects them by type.
# ---------------------------------------------------------------------------

class DecodedMap:
    """A decoded map with a non-string (or repeated) key, kept as its pairs."""

    def __init__(self, pairs: list[tuple[object, object]]) -> None:
        self.pairs = pairs


class DecodedExt:
    """A decoded ext type: its type code and payload."""

    def __init__(self, code: int, data: bytes) -> None:
        self.code = code
        self.data = data


def _take(data: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if pos + n > len(data):
        raise InteropError("truncated document")
    return data[pos:pos + n], pos + n


def _uint(data: bytes, pos: int, n: int) -> tuple[int, int]:
    raw, pos = _take(data, pos, n)
    return int.from_bytes(raw, "big"), pos


def _decode(data: bytes, pos: int) -> tuple[object, int]:  # noqa: C901, PLR0911, PLR0912
    t, pos = _uint(data, pos, 1)
    if t <= 0x7F:
        return t, pos
    if t >= 0xE0:
        return t - 0x100, pos
    if t <= 0x8F:
        return _decode_map(data, pos, t & 0x0F)
    if t <= 0x9F:
        return _decode_array(data, pos, t & 0x0F)
    if t <= 0xBF:
        raw, pos = _take(data, pos, t & 0x1F)
        return raw.decode("utf-8"), pos
    if t in (0xC0, 0xC2, 0xC3):
        return {0xC0: None, 0xC2: False, 0xC3: True}[t], pos
    if t in (0xC4, 0xC5, 0xC6):
        n, pos = _uint(data, pos, 1 << (t - 0xC4))
        return _take(data, pos, n)
    if t in (0xC7, 0xC8, 0xC9):
        n, pos = _uint(data, pos, 1 << (t - 0xC7))
        code, pos = _take(data, pos, 1)
        payload, pos = _take(data, pos, n)
        return DecodedExt(int.from_bytes(code, "big", signed=True), payload), pos
    if t == 0xCA:
        raw, pos = _take(data, pos, 4)
        return struct.unpack(">f", raw)[0], pos
    if t == 0xCB:
        raw, pos = _take(data, pos, 8)
        return struct.unpack(">d", raw)[0], pos
    if 0xCC <= t <= 0xCF:
        return _uint(data, pos, 1 << (t - 0xCC))
    if 0xD0 <= t <= 0xD3:
        raw, pos = _take(data, pos, 1 << (t - 0xD0))
        return int.from_bytes(raw, "big", signed=True), pos
    if 0xD4 <= t <= 0xD8:
        code, pos = _take(data, pos, 1)
        payload, pos = _take(data, pos, 1 << (t - 0xD4))
        return DecodedExt(int.from_bytes(code, "big", signed=True), payload), pos
    if t in (0xD9, 0xDA, 0xDB):
        n, pos = _uint(data, pos, 1 << (t - 0xD9))
        raw, pos = _take(data, pos, n)
        return raw.decode("utf-8"), pos
    if t in (0xDC, 0xDD):
        n, pos = _uint(data, pos, 2 << (t - 0xDC))
        return _decode_array(data, pos, n)
    if t in (0xDE, 0xDF):
        n, pos = _uint(data, pos, 2 << (t - 0xDE))
        return _decode_map(data, pos, n)
    raise InteropError(f"type byte {t:#04x} is never used")


def _decode_array(data: bytes, pos: int, n: int) -> tuple[list, int]:
    out = []
    for _ in range(n):
        item, pos = _decode(data, pos)
        out.append(item)
    return out, pos


def _decode_map(data: bytes, pos: int, n: int) -> tuple[object, int]:
    pairs = []
    for _ in range(n):
        k, pos = _decode(data, pos)
        v, pos = _decode(data, pos)
        pairs.append((k, v))
    keys = [k for k, _ in pairs]
    if all(isinstance(k, str) for k in keys) and len(set(keys)) == len(keys):
        return dict(pairs), pos
    return DecodedMap(pairs), pos


def decode_value(data: bytes) -> object:
    """Read exactly one MessagePack document, canonical or not; trailing bytes are an error."""
    value, end = _decode(data, 0)
    if end != len(data):
        raise InteropError(f"{len(data) - end} trailing byte(s) after one complete document")
    return value


# ---------------------------------------------------------------------------
# Argument normalization (spec: The Interop Data Model)
# ---------------------------------------------------------------------------

def normalize_arg(v: object) -> object:
    """Map a source value into the interop data model. Recursive."""
    if v is None or isinstance(v, (bool, int, float, str, bytes, bytearray)):
        # Range/NaN/Infinity enforcement lives in ONE place: the encoder
        # (_encode_int / the float branch of _encode), which every path hits.
        return v
    if isinstance(v, datetime):
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise InteropError("naive datetimes are not allowed in interop arguments")
        # Integer microseconds since epoch (floored toward negative infinity —
        # exact for pre-epoch values too), then ONE float64 division by 10^6.
        # IEEE 754 division is exactly specified, so this is bit-identical
        # across languages (see spec: DateTime determinism).
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        delta = v - epoch
        micros = (delta.days * 86400 + delta.seconds) * 10**6 + delta.microseconds
        return micros / 1_000_000.0
    if isinstance(v, uuid_mod.UUID):
        return str(v)  # lowercase hyphenated
    if isinstance(v, (frozenset, set, _TaggedSet)):
        elements = v.elements if isinstance(v, _TaggedSet) else v
        # Sort by encoded bytes (total, language-neutral order); dedupe
        # post-normalization (e.g. {2, 2.0} collapses to a single int 2).
        encoded = sorted({encode_canonical(normalize_arg(e)) for e in elements})
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


def canonical_args_bytes(args: list | tuple) -> bytes:
    """Encode the flat canonical argument array to canonical MessagePack."""
    return encode_canonical([normalize_arg(a) for a in args])


def args_hash(args: list | tuple) -> str:
    return hashlib.blake2b(canonical_args_bytes(args), digest_size=32).hexdigest()


def interop_key(namespace: str, operation: str, args: list | tuple) -> str:
    for name, seg in (("namespace", namespace), ("operation", operation)):
        if not SEGMENT_RE.fullmatch(seg):
            raise InteropError(
                f"invalid interop {name} {seg!r}: must full-string match ^[a-z0-9][a-z0-9._-]{{0,63}}$"
            )
        if FORBIDDEN_SUBSTRING in seg:
            raise InteropError(
                f"invalid interop {name} {seg!r}: must not contain '..' (the server rejects '..' anywhere in a key)"
            )
    if namespace in RESERVED_NAMESPACES:
        raise InteropError(
            f"invalid interop namespace {namespace!r}: 'ns' and 'nsapi' are reserved "
            "(the server parses a key starting 'ns:' or 'nsapi:' as namespace-prefixed)"
        )
    return f"{namespace}:{operation}:{args_hash(args)}"


# ---------------------------------------------------------------------------
# Encryption chain (spec/encryption.md) — HKDF-SHA256 is pure stdlib
# ---------------------------------------------------------------------------

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-Extract + Expand with SHA-256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def construct_salt(domain: str, tenant_salt: str) -> bytes:
    d, t = domain.encode("utf-8"), tenant_salt.encode("utf-8")
    return b"cachekit_v1_" + bytes([len(d)]) + d + len(t).to_bytes(2, "big") + t


def derive_encryption_key(master_key: bytes, tenant_id: str) -> bytes:
    return hkdf_sha256(master_key, construct_salt("encryption", tenant_id), b"encryption")


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(b"key_fingerprint_v1" + key).digest()[:16].hex()


def aad_v3(tenant_id: str, cache_key: str, *, fmt: str = "msgpack", compressed: bool = False) -> bytes:
    """AAD v0x03 per spec/encryption.md; interop mode pins compressed=False."""
    aad = bytearray([0x03])
    for comp in (tenant_id, cache_key, fmt, "True" if compressed else "False"):
        b = comp.encode("utf-8")
        aad += len(b).to_bytes(4, "big") + b
    return bytes(aad)


# Encryption vector constants. The master key and tenant match
# test-vectors/encryption.json, so the derived key (and its fingerprint,
# 96179a9bc881aa7ca83f04b78a66afd3) is the SAME key already pinned there —
# this file's HKDF chain is validated against that published ground truth by
# the fingerprint self-check below. The ciphertext was produced with
# AES-256-GCM (cryptography/OpenSSL) over the plain-MessagePack plaintext of
# the issue_example_object value vector, with the interop_key_aad AAD and the
# fixed nonce below; it is cryptographically re-verified by the optional
# `cryptography` check here and ALWAYS by WebCrypto in interop-crosscheck.mjs.
ENC_MASTER_KEY_HEX = "61" * 32
ENC_TENANT_ID = "cross-sdk-test"
ENC_KEY_FINGERPRINT_HEX = "96179a9bc881aa7ca83f04b78a66afd3"
ENC_NONCE_HEX = "000102030405060708090a0b"
ENC_CIPHERTEXT_HEX = (
    "000102030405060708090a0b"
    "033caf732820ce189e1506f842aebf8cdb6a242eb08c55b6f5a91eb9007b3bd657"
)


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
        "name": "uint_width_ladder",
        "description": "Every unsigned width boundary: 127/128 (fixint/uint8), 255/256 (uint8/uint16), 65535/65536 (uint16/uint32), 4294967295/4294967296 (uint32/uint64)",
        "namespace": "t",
        "operation": "op",
        "args": [127, 128, 255, 256, 65535, 65536, 4294967295, 4294967296],
    },
    {
        "name": "int_width_ladder",
        "description": "Every signed width boundary: -32/-33 (fixint/int8), -128/-129 (int8/int16), -32768/-32769 (int16/int32), -2147483648/-2147483649 (int32/int64)",
        "namespace": "t",
        "operation": "op",
        "args": [-32, -33, -128, -129, -32768, -32769, -2147483648, -2147483649],
    },
    {
        "name": "unicode_string",
        "description": "UTF-8 string, no Unicode normalization applied",
        "namespace": "t",
        "operation": "op",
        "args": ["héllo wörld ✓"],
    },
    {
        "name": "str_width_ladder",
        "description": "String header boundaries by UTF-8 byte length: 31 (fixstr) / 32 (str8) / 255 (str8) / 256 (str16)",
        "namespace": "t",
        "operation": "op",
        "args": ["a" * 31, "b" * 32, "c" * 255, "d" * 256],
    },
    {
        "name": "bin_width_ladder",
        "description": "Binary header boundaries: 255 bytes (bin8) / 256 bytes (bin16)",
        "namespace": "t",
        "operation": "op",
        "args": [{"$bytes": "ab" * 255}, {"$bytes": "cd" * 256}],
    },
    {
        "name": "array_width_boundary",
        "description": "Array header boundary: 15 elements (fixarray) / 16 elements (array16)",
        "namespace": "t",
        "operation": "op",
        "args": [list(range(15)), list(range(16))],
    },
    {
        "name": "map_width_boundary",
        "description": "Map header boundary: 15 keys (fixmap) / 16 keys (map16); zero-padded keys keep the sort order obvious",
        "namespace": "t",
        "operation": "op",
        "args": [
            {f"k{i:02d}": i for i in range(15)},
            {f"k{i:02d}": i for i in range(16)},
        ],
    },
    {
        "name": "root_array16",
        "description": "16 arguments: the ROOT canonical argument array itself uses array16",
        "namespace": "t",
        "operation": "op",
        "args": list(range(16)),
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
        "name": "set_mixed_sign_order",
        "description": "Set {-5, 'a', 1.5}: encoded-byte order is 'a' (0xa1..), 1.5 (0xcb..), -5 (0xfb) — NOT numeric/type-grouped order. Kills 'sort naturally, ints first' implementations.",
        "namespace": "t",
        "operation": "op",
        "args": [{"$set": [-5, "a", {"$float": "1.5"}]}],
    },
    {
        "name": "float_collapse_lower_bound",
        "description": "Inclusive lower collapse bound: float -2^63 MUST collapse to the int64-min encoding (0xd3...), symmetric with the exclusive upper bound vector",
        "namespace": "t",
        "operation": "op",
        "args": [{"$float": "-9223372036854775808"}],
    },
    {
        "name": "set_dedupe_canonicalization",
        "description": "Set {2, 2.0}: number canonicalization makes the encodings identical; dedupe by encoded bytes leaves a single int 2",
        "namespace": "t",
        "operation": "op",
        "args": [{"$set": [2, {"$float": "2.0"}]}],
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
        "description": "Non-UTC offset converts to the same instant (+05:30); key must equal datetime_fractional",
        "namespace": "events",
        "operation": "get_by_time",
        "args": [{"$datetime": "2024-01-01T18:00:45.123456+05:30"}],
    },
    {
        "name": "datetime_pre_epoch",
        "description": "Pre-epoch datetime: negative timestamp (-0.876544), microseconds floored toward negative infinity",
        "namespace": "events",
        "operation": "get_by_time",
        "args": [{"$datetime": "1969-12-31T23:59:59.123456+00:00"}],
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
    {
        "name": "reservation_scope",
        "description": (
            "The ns/nsapi reservation is exact-match and namespace-only: namespace 'nsapix' "
            "(rejected by an ns* or nsapi* prefix match) and operation 'nsapi' stay valid"
        ),
        "namespace": "nsapix",
        "operation": "nsapi",
        "args": [1],
    },
    {
        "name": "lone_dots_stay_valid",
        "description": (
            "Only '..' is forbidden: a lone trailing '.' (namespace 'app.') and non-adjacent dots "
            "(operation 'users.fetch.by_id') stay valid"
        ),
        "namespace": "app.",
        "operation": "users.fetch.by_id",
        "args": [1],
    },
    {
        "name": "segment_max_length",
        "description": (
            "Both segments at the 64-character limit (the longest interop key, 194 characters). The namespace "
            "starts with a digit and holds '-' and '_'; the operation starts with a digit and holds '.', '-' "
            "and '_'. A limit of 63, or a ban on a leading digit or on '-', rejects it"
        ),
        "namespace": "9-lives_" * 8,
        "operation": ("0.op-x_" * 10)[:64],
        "args": [1],
    },
    {
        "name": "map_key_sort_case_across_letters",
        "description": (
            "Code point order puts 'B' (0x42) before 'a' (0x61). A collator (Intl.Collator, localeCompare, "
            "with or without caseFirst 'upper') compares letters first and puts 'a' before 'B'"
        ),
        "namespace": "t",
        "operation": "op",
        "args": [{"a": 1, "B": 2}],
    },
    {
        "name": "map_key_sort_punctuation",
        "description": (
            "Code point order puts 'a-b' ('-' is 0x2d) before 'a_b' ('_' is 0x5f). A collator puts 'a_b' "
            "first: Unicode collation orders '_' before '-'"
        ),
        "namespace": "t",
        "operation": "op",
        "args": [{"a_b": 1, "a-b": 2}],
    },
    {
        "name": "map_key_sort_shorter_key_later",
        "description": (
            "Code point order puts 'ab' before the shorter 'b'. A length-first sort (shorter keys first, as "
            "canonical CBOR orders them, or by the encoded key with its header) puts 'b' first"
        ),
        "namespace": "t",
        "operation": "op",
        "args": [{"b": 1, "ab": 2}],
    },
    {
        "name": "map_key_sort_supplementary_shorter",
        "description": (
            "Code point order puts U+FF61 U+FF61 (6 UTF-8 bytes) before the shorter U+10000 (4 bytes). A "
            "length-first sort and a UTF-16 code-unit sort both put U+10000 first"
        ),
        "namespace": "t",
        "operation": "op",
        "args": [{"\U00010000": 1, "\uff61\uff61": 2}],
    },
    {
        "name": "map_key_proto",
        "description": (
            "'__proto__' is an ordinary string key. A JavaScript normalizer that copies keys by assignment "
            "(out[k] = v) sets the object's prototype instead, drops the key and mints the key of an empty map"
        ),
        "namespace": "t",
        "operation": "op",
        "args": [{"__proto__": 1}],
    },
    {
        "name": "set_in_map_normalized",
        "description": (
            "A set inside a map value holding a tz-aware datetime and an uppercase UUID: each element is "
            "normalized before it is encoded and sorted (the int timestamp 0xce.. sorts before the str 0xd9..). "
            "The valid twin of reject_naive_datetime_nested, so a set path that rejects every datetime fails it"
        ),
        "namespace": "t",
        "operation": "op",
        "args": [
            {"when": {"$set": [{"$uuid": "550E8400-E29B-41D4-A716-446655440000"},
                               {"$datetime": "2024-01-01T00:00:00+00:00"}]}}
        ],
    },
    {
        "name": "int_beyond_float64_precision",
        "description": (
            "2^53+1, -(2^53+1) and 2^63-1, then 2^53+1 again inside a list and a map value: integers inside "
            "int64 that a float64 cannot hold. A TypeScript SDK that turns a BigInt inside int64 into a Number "
            "rounds each one and mints a different key"
        ),
        "namespace": "t",
        "operation": "op",
        "args": [
            {"$int": "9007199254740993"},
            {"$int": "-9007199254740993"},
            {"$int": "9223372036854775807"},
            [{"$int": "9007199254740993"}],
            {"id": {"$int": "9007199254740993"}},
        ],
    },
    {
        "name": "small_int_as_bigint",
        "description": (
            "Small integers passed as {\"$int\": ...} (a BigInt in JavaScript) take the shortest form, the "
            "bytes the same plain integers produce. An encoder that writes every BigInt at the full 9-byte "
            "width mints a different key"
        ),
        "namespace": "t",
        "operation": "op",
        "args": [{"$int": "1"}, {"$int": "-1"}, {"$int": "300"}],
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
    {
        "name": "proto_key_value",
        "description": (
            "A map whose key is '__proto__', an ordinary string key. A JavaScript reader or writer that sets "
            "keys by assignment changes the object's prototype instead and loses the entry"
        ),
        "value": {"__proto__": 1},
    },
    {
        "name": "bom_strings_value",
        "description": (
            "Strings that start with U+FEFF, one short and one of 300 characters: a reader keeps the "
            "character. A UTF-8 decoder left at its default (TextDecoder strips a leading BOM) drops it, "
            "and some MessagePack decoders use one only for longer strings"
        ),
        "value": ["\ufeffbom", "\ufeff" + "x" * 299],
    },
]

ERROR_VECTORS: list[dict] = [
    {"name": "reject_nan", "args": [{"$float": "nan"}], "error": "NaN is not allowed"},
    {
        "name": "reject_infinity",
        "args": [{"$float": "1e999"}],
        "error": "Infinity is not allowed (1e999 overflows to +inf in Python, JS, and Rust float parsers alike)",
    },
    {
        "name": "reject_negative_infinity",
        "args": [{"$float": "-1e999"}],
        "error": "-Infinity is not allowed (independent vector: +Inf rejection does not imply -Inf rejection)",
    },
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
        "error": "namespace must match the segment pattern",
    },
    {
        "name": "reject_colon_in_operation",
        "namespace": "users",
        "operation": "get:user",
        "args": [],
        "error": "operation must match the segment pattern",
    },
    {
        "name": "reject_trailing_newline",
        "namespace": "users\n",
        "operation": "get_user",
        "args": [],
        "error": "segment validation must be a FULL-string match (Python re.match + $ accepts a trailing newline; use fullmatch)",
    },
    {
        "name": "reject_reserved_namespace_ns",
        "namespace": "ns",
        "operation": "get_user",
        "args": [],
        "error": (
            "namespace 'ns' is reserved: the server parses a key starting 'ns:' as namespace-prefixed "
            "(here it would scope the key to a namespace named 'get_user')"
        ),
    },
    {
        "name": "reject_reserved_namespace_nsapi",
        "namespace": "nsapi",
        "operation": "users.fetch_by_id",
        "args": [],
        "error": (
            "namespace 'nsapi' is reserved: the server parses a key starting 'nsapi:' as namespace-prefixed "
            "(rejected whatever the operation, including one the server would 400 on for its '.')"
        ),
    },
    {
        "name": "reject_double_dot_namespace",
        "namespace": "a..b",
        "operation": "get_user",
        "args": [],
        "error": "namespace must not contain '..': the pattern admits it, but the server rejects '..' anywhere in a key",
    },
    {
        "name": "reject_double_dot_operation",
        "namespace": "users",
        "operation": "x..",
        "args": [],
        "error": (
            "operation must not contain '..': the pattern admits it, but the server rejects '..' anywhere in a key "
            "(here at the end of the segment, which a check that skips the last pair misses)"
        ),
    },
    # Segment grammar, rule by rule and on both segments: each vector breaks one rule in one
    # segment, and the other segment is valid.
    {
        "name": "reject_namespace_too_long",
        "namespace": "a" * 65,
        "operation": "get_user",
        "args": [],
        "error": "namespace is 65 characters; the limit is 64 (segment_max_length pins 64 as valid)",
    },
    {
        "name": "reject_operation_too_long",
        "namespace": "users",
        "operation": "b" * 65,
        "args": [],
        "error": "operation is 65 characters; the limit is 64",
    },
    {
        "name": "reject_leading_dot_namespace",
        "namespace": ".users",
        "operation": "get_user",
        "args": [],
        "error": "a segment must start with a letter or digit, not '.'",
    },
    {
        "name": "reject_leading_hyphen_operation",
        "namespace": "users",
        "operation": "-get_user",
        "args": [],
        "error": "a segment must start with a letter or digit, not '-'",
    },
    {
        "name": "reject_leading_underscore_operation",
        "namespace": "users",
        "operation": "_get_user",
        "args": [],
        "error": "a segment must start with a letter or digit, not '_' (a leading \\w admits it)",
    },
    {
        "name": "reject_empty_namespace",
        "namespace": "",
        "operation": "get_user",
        "args": [],
        "error": "a segment holds at least one character",
    },
    {
        "name": "reject_empty_operation",
        "namespace": "users",
        "operation": "",
        "args": [],
        "error": "a segment holds at least one character",
    },
    {
        "name": "reject_non_ascii_digit_namespace",
        "namespace": "users\u0663",
        "operation": "get_user",
        "args": [],
        "error": "U+0663 ARABIC-INDIC DIGIT THREE is not an ASCII digit (Unicode \\d, isdigit and isalnum admit it)",
    },
    {
        "name": "reject_non_ascii_letter_operation",
        "namespace": "users",
        "operation": "caf\u00e9",
        "args": [],
        "error": "U+00E9 is not an ASCII letter (a lowercase or alphanumeric test admits it)",
    },
    {
        "name": "reject_fullwidth_operation",
        "namespace": "users",
        "operation": "\uff47\uff45\uff54_user",
        "args": [],
        "error": "full-width letters are not ASCII: NFKC folds them to 'get_user', and a segment is never normalized",
    },
    {
        "name": "reject_slash_namespace",
        "namespace": "users/v2",
        "operation": "get_user",
        "args": [],
        "error": "'/' is not in the segment character set",
    },
    {
        "name": "reject_space_operation",
        "namespace": "users",
        "operation": "get user",
        "args": [],
        "error": "a space is not in the segment character set",
    },
    {
        "name": "reject_uppercase_operation",
        "namespace": "users",
        "operation": "getUser",
        "args": [],
        "error": "operation must be lowercase",
    },
    {
        "name": "reject_colon_in_namespace",
        "namespace": "users:v2",
        "operation": "get_user",
        "args": [],
        "error": "':' is not in the segment character set (it would add a key segment)",
    },
    {
        "name": "reject_trailing_newline_operation",
        "namespace": "users",
        "operation": "get_user\n",
        "args": [],
        "error": "segment validation must be a FULL-string match, on the operation as on the namespace",
    },
    # Out-of-model values below the top of the argument list: a check that never reaches a
    # nested value passes every top-level error vector above.
    {
        "name": "reject_naive_datetime_nested",
        "args": [{"when": {"$set": [{"$datetime": "2024-01-01T00:00:00"}]}}],
        "error": "naive datetime inside a set inside a map value",
    },
    {
        "name": "reject_nan_nested",
        "args": [[{"x": {"$float": "nan"}}]],
        "error": "NaN inside a map value inside a list",
    },
    {
        "name": "reject_int_overflow_in_list",
        "args": [[1, {"$int": "18446744073709551616"}]],
        "error": "integer above 2^64-1 inside a list",
    },
    {
        "name": "reject_int_underflow_in_map",
        "args": [{"id": {"$int": "-9223372036854775809"}}],
        "error": "integer below -2^63 inside a map value",
    },
    {
        "name": "reject_int_overflow_in_map",
        "args": [{"id": {"$int": "18446744073709551616"}}],
        "error": "integer above 2^64-1 inside a map value (with reject_int_underflow_in_list, each bound is pinned on both paths)",
    },
    {
        "name": "reject_int_underflow_in_list",
        "args": [[1, {"$int": "-9223372036854775809"}]],
        "error": "integer below -2^63 inside a list",
    },
]

# Value reader inputs (spec: Interop Value Format). Accept vectors are well-formed documents no
# canonical writer emits; `value`, where tagged JSON can carry it, is what they decode to.
READER_ACCEPT_VECTORS: list[dict] = [
    {
        "name": "reader_padded_int_widths",
        "description": "Integers in wider forms than the shortest: 42 as uint16, -1 as int32, 1 as uint64",
        "msgpack_hex": "93cd002ad2ffffffffcf0000000000000001",
        "value": [42, -1, 1],
    },
    {
        "name": "reader_padded_headers",
        "description": "Headers wider than needed: an array16 of 3 holding 'abc' as str8, {'a': 1} as map16 and 2 bytes as bin16",
        "msgpack_hex": "dc0003d903616263de0001a16101c50002dead",
        "value": ["abc", {"a": 1}, {"$bytes": "dead"}],
    },
    {
        "name": "reader_unsorted_map_keys",
        "description": "Map keys in the reverse of code point order",
        "msgpack_hex": "82a16202a16101",
        "value": {"b": 2, "a": 1},
    },
    {
        "name": "reader_float32",
        "description": "1.5 as a float32 (0xca), which canonical writers never emit",
        "msgpack_hex": "ca3fc00000",
        "value": {"$float": "1.5"},
    },
    {
        "name": "reader_non_string_map_key",
        "description": (
            "{1: 42}: a map with an integer key. No tagged-JSON value can carry it; a reader must decode it "
            "without error (msgpack-python's unpackb needs strict_map_key=False)"
        ),
        "msgpack_hex": "81012a",
    },
    {
        "name": "reader_ext_type",
        "description": "An application ext type (fixext1, type 1, payload 0x2a). No tagged-JSON value can carry it; a reader must decode it without error",
        "msgpack_hex": "d4012a",
    },
]

READER_REJECT_VECTORS: list[dict] = [
    {
        "name": "reader_trailing_byte",
        "description": (
            "The issue_example_object value followed by one 0x00 byte: a complete document and a trailing "
            "byte, with no CK frame prefix, so only the general trailing-bytes check rejects it. A reader that "
            "strips trailing NUL padding before a strict decode accepts it, so it fails this vector too"
        ),
        "msgpack_hex": "82a36167651ea46e616d65a5616c69636500",
        "error": "trailing bytes after one complete document",
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
                "expected_key": interop_key(v["namespace"], v["operation"], args),
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

    # AAD and encryption vectors bind to the single_int key and the
    # issue_example_object value so the vectors compose end-to-end.
    single_int = next(kv for kv in key_vectors if kv["name"] == "single_int")
    example_value = next(vv for vv in value_vectors if vv["name"] == "issue_example_object")
    aad = aad_v3(ENC_TENANT_ID, single_int["expected_key"])

    return {
        "version": "1.3.0",
        "spec": "spec/interop-mode.md",
        "generator": "tools/interop-reference.py (CPython stdlib)",
        "cross_checked_by": "tools/interop-crosscheck.mjs (independent encoder + @noble/hashes blake2b + WebCrypto HKDF/AES-GCM)",
        "hash_algorithm": "blake2b-256 (digest_size=32, unkeyed) over canonical MessagePack of the flat argument array",
        "key_format": "{namespace}:{operation}:{args_hash}",
        "segment_pattern": "^[a-z0-9][a-z0-9._-]{0,63}$",
        "segment_pattern_note": (
            "Full-string match REQUIRED (Python: re.fullmatch, not re.match — $ matches before a trailing newline). "
            "namespace additionally MUST NOT be exactly 'ns' or 'nsapi' (reserved: the server parses those key "
            "prefixes). The reservation is namespace-only; operation has no reserved values. Neither segment "
            "may contain '..' (the pattern admits it; the server rejects '..' anywhere in a key). A lone '.' "
            "stays valid."
        ),
        "width_coverage_note": (
            "All *16 header boundaries (uint/int widths, str8->str16, bin8->bin16, fixarray->array16, "
            "fixmap->map16, including the root argument array) are pinned by vectors. The *32 tier "
            "(str32/bin32/array32/map32, >=64 KiB or >=65536 elements) is normative and implemented by "
            "both tools but untested-by-design: fixture blobs that size would bloat the file without "
            "exercising different logic (same length-prefix code path, wider field)."
        ),
        "error_vectors_note": (
            "The 'error' field is a human-readable reason for maintainers. Conformance means the input "
            "MUST be rejected with an error; the message text is not normative."
        ),
        "reader_vectors_note": (
            "Inputs for an interop VALUE reader, as raw MessagePack. A reader MUST decode every "
            "reader_accept_vectors document without error: each is well-formed but not canonical (a padded "
            "width, unsorted keys, a float32, a non-string map key, an ext type). Where tagged JSON can carry "
            "it, 'value' is what the document decodes to. A reader MUST reject every reader_reject_vectors "
            "document."
        ),
        "tagged_json": {
            "note": "Single-key objects with a $-prefixed key are typed input tags; all other JSON maps directly.",
            "$set": "set of tagged values (unordered)",
            "$bytes": "hex-encoded byte string",
            "$datetime": "ISO 8601 with mandatory UTC offset",
            "$uuid": "UUID string (any case on input)",
            "$float": (
                "decimal float literal (JSON numbers are always integers in this file). "
                "Error vectors use 'nan' (parses to NaN in Python and JS) and '1e999' "
                "(overflows to +Infinity in Python, JS, and Rust) — never 'inf', which JS parses to NaN. "
                "A JavaScript harness must wrap the parsed Number in a type of its own (tools/interop-crosscheck.mjs "
                "uses a Float class), so the SDK can tell an explicit float from a bare Number, which this file "
                "only ever uses for a safe integer: an integral $float must still reach the SDK as a float "
                "('2.0' stays float64 in a value, and '18446744073709551616' is a float64 argument, where a bare "
                "Number that large must be rejected)."
            ),
            "$int": "decimal integer literal (for values beyond 2^53, unsafe in JS JSON.parse)",
        },
        "key_vectors": key_vectors,
        "value_vectors": value_vectors,
        "error_vectors": ERROR_VECTORS,
        "reader_accept_vectors": READER_ACCEPT_VECTORS,
        "reader_reject_vectors": READER_REJECT_VECTORS,
        "aad_vectors": [
            {
                "name": "interop_key_aad",
                "description": "AAD v0x03 over an interop key; format=msgpack, compressed=False (always, in interop mode)",
                "tenant_id": ENC_TENANT_ID,
                "cache_key": single_int["expected_key"],
                "format": "msgpack",
                "compressed": False,
                "aad_hex": aad.hex(),
            }
        ],
        "encryption_vectors": [
            {
                "name": "interop_encryption_roundtrip",
                "description": (
                    "Full interop encryption round-trip: HKDF-SHA256 per spec/encryption.md "
                    "(same master key + tenant as test-vectors/encryption.json, hence the same "
                    "derived key), AES-256-GCM over the PLAIN MessagePack value bytes (no "
                    "ByteStorage step) with the interop_key_aad AAD and a fixed nonce."
                ),
                "master_key_hex": ENC_MASTER_KEY_HEX,
                "tenant_id": ENC_TENANT_ID,
                "derived_key_fingerprint_hex": ENC_KEY_FINGERPRINT_HEX,
                "cache_key": single_int["expected_key"],
                "format": "msgpack",
                "compressed": False,
                "aad_hex": aad.hex(),
                "plaintext_hex": example_value["canonical_msgpack_hex"],
                "nonce_hex": ENC_NONCE_HEX,
                "ciphertext_hex": ENC_CIPHERTEXT_HEX,
                "ciphertext_layout": "nonce(12) || ciphertext || auth_tag(16)",
            }
        ],
    }


def _segment_fails(seg: str) -> bool:
    return not SEGMENT_RE.fullmatch(seg) or FORBIDDEN_SUBSTRING in seg


def _expect_rejected(label: str, args: list) -> None:
    try:
        canonical_args_bytes(args)
    except (InteropError, ValueError):  # UnicodeEncodeError is a ValueError
        return
    raise AssertionError(f"{label}: must be rejected, was encoded")


def _surrogate_selftest() -> None:
    """Strings must be well-formed Unicode: a lone surrogate is rejected wherever it sits.

    Portable JSON cannot carry a lone surrogate (serde_json rejects it; Rust String is
    immune by construction), so this lives here and in the .mjs self-test, not in a vector.
    """
    for label, args in (
        ("lone high surrogate", ["\ud800"]),
        ("lone low surrogate", ["\udc00"]),
        ("lone surrogate in a map key", [{"\ud800": 1}]),
        ("lone low surrogate in a map key", [{"\udc00": 1}]),
        ("lone surrogate in a nested value", [{"k": ["ok", "\udc00"]}]),
        ("lone surrogate in a set", [_TaggedSet(["\ud800"])]),
    ):
        _expect_rejected(label, args)
    assert canonical_args_bytes(["\U00010000"]) == bytes.fromhex("91a4f0908080"), "a valid pair must still encode"


def _non_string_key_selftest() -> None:
    """Map keys must be strings, at every nesting level. Portable JSON keys are always strings."""
    for label, args in (
        ("int key", [{1: "a"}]),
        ("bytes key", [{b"k": "a"}]),
        ("None key", [{None: "a"}]),
        ("int key in a nested map", [[{"ok": {2: "a"}}]]),
        ("int key in a set element", [_TaggedSet([{3: "a"}])]),
    ):
        _expect_rejected(label, args)
    assert canonical_args_bytes([{"1": "a"}]) == bytes.fromhex("9181a131a161"), "a string key must still encode"


def _out_of_model_selftest() -> None:
    """A value of a type outside the data model is rejected wherever it sits; JSON cannot carry one."""
    for label, args in (
        ("object", [object()]),
        ("complex", [complex(1, 2)]),
        ("object in a list", [[1, object()]]),
        ("object in a map value", [{"k": object()}]),
        ("object in a set", [_TaggedSet([object()])]),
    ):
        _expect_rejected(label, args)


def _reader_check(built: dict) -> None:
    """Every reader accept vector is a well-formed, non-canonical document that decodes to its
    `value`; every reject vector is one complete document followed by trailing bytes."""
    for rv in built["reader_accept_vectors"]:
        raw = bytes.fromhex(rv["msgpack_hex"])
        decoded = decode_value(raw)
        try:
            canonical = encode_canonical(decoded, collapse_floats=False)
        except InteropError:
            canonical = None
        if "value" in rv:
            expected = encode_canonical(from_tagged(rv["value"]), collapse_floats=False)
            assert canonical == expected, f"{rv['name']} does not decode to its value"
        else:
            assert canonical is None, f"{rv['name']} decodes to a value tagged JSON can carry: give it a value"
        assert canonical != raw, f"{rv['name']} is canonical, so it tests nothing value_vectors do not"
    for vv in built["value_vectors"]:  # every canonical value reads back to the same bytes
        raw = bytes.fromhex(vv["canonical_msgpack_hex"])
        assert encode_canonical(decode_value(raw), collapse_floats=False) == raw, f"{vv['name']} does not read back"
    for rv in built["reader_reject_vectors"]:
        raw = bytes.fromhex(rv["msgpack_hex"])
        try:
            decode_value(raw)
        except InteropError:
            pass
        else:
            raise AssertionError(f"{rv['name']} decoded, but must be rejected")
        _, end = _decode(raw, 0)  # the first document is complete: trailing bytes are the only fault
        assert 0 < end < len(raw), f"{rv['name']} must be one complete document and trailing bytes"
        assert not raw.startswith(b"CK"), f"{rv['name']} must not be a CK frame, which python-frame.json covers"
    names = [v["name"] for g in ("key_vectors", "value_vectors", "error_vectors", "reader_accept_vectors",
                                 "reader_reject_vectors") for v in built[g]]
    assert len(names) == len(set(names)), "vector names must be unique across the file"


def _self_check(built: dict) -> None:
    """Assertions that pin the spec's intentional equalities and edge cases."""
    by_name = {v["name"]: v for v in built["key_vectors"]}

    assert by_name["float_integral_collapse"]["args_hash"] == by_name["single_int_two"]["args_hash"], (
        "number canonicalization broken: 2.0 and 2 must hash identically"
    )
    assert by_name["datetime_fractional"]["expected_key"] == by_name["datetime_non_utc_offset"]["expected_key"], (
        "offset normalization broken: same instant must produce the same key"
    )
    assert by_name["set_dedupe_canonicalization"]["canonical_args_hex"] == "919102", (
        "set dedupe broken: {2, 2.0} must encode as a single-element array [2]"
    )
    assert by_name["root_array16"]["canonical_args_hex"].startswith("dc0010"), (
        "root argument array of 16 must use array16"
    )
    pre_epoch = normalize_arg(datetime.fromisoformat("1969-12-31T23:59:59.123456+00:00"))
    assert pre_epoch == -0.876544, f"pre-epoch micros floor broken: {pre_epoch}"
    assert by_name["set_mixed_sign_order"]["canonical_args_hex"] == "9193a161cb3ff8000000000000fb", (
        "set byte-order broken: {-5, 'a', 1.5} must encode as ['a', 1.5, -5]"
    )
    assert by_name["float_collapse_lower_bound"]["canonical_args_hex"] == "91d38000000000000000", (
        "inclusive lower collapse bound broken: float -2^63 must collapse to int64-min"
    )

    assert by_name["small_int_as_bigint"]["canonical_args_hex"] == canonical_args_bytes([1, -1, 300]).hex(), (
        "a small {\"$int\": ...} must encode exactly like the same plain integer"
    )
    max_key = by_name["segment_max_length"]
    assert len(max_key["namespace"]) == len(max_key["operation"]) == 64 and len(max_key["expected_key"]) == 194, (
        "segment_max_length must hold two 64-character segments, the 194-character maximum key"
    )
    for name in ("map_key_sort_case_across_letters", "map_key_sort_punctuation", "map_key_sort_shorter_key_later",
                 "map_key_sort_supplementary_shorter"):
        (arg,) = by_name[name]["args"]
        assert list(arg) != sorted(arg), f"{name} must list its keys out of order, so a no-op sort fails it"

    _surrogate_selftest()
    _non_string_key_selftest()
    _out_of_model_selftest()

    # The '..' vectors must pass the pattern, or they would prove the grammar
    # rather than the extra rule an implementation has to add beside it.
    for name in ("reject_double_dot_namespace", "reject_double_dot_operation"):
        ev = next(e for e in ERROR_VECTORS if e["name"] == name)
        assert SEGMENT_RE.fullmatch(ev["namespace"]) and SEGMENT_RE.fullmatch(ev["operation"]), (
            f"{name} must match segment_pattern so it exercises the '..' rule"
        )
    # Each segment error vector breaks exactly one segment, so it pins one rule on one segment.
    for ev in ERROR_VECTORS:
        if "namespace" in ev:
            bad = [seg for seg in (ev["namespace"], ev["operation"]) if _segment_fails(seg)]
            bad += ["reserved"] if ev["namespace"] in RESERVED_NAMESPACES else []
            assert len(bad) == 1, f"{ev['name']} must break exactly one segment rule, breaks {bad}"

    _reader_check(built)

    for ev in ERROR_VECTORS:
        try:
            if "namespace" in ev:
                interop_key(ev["namespace"], ev["operation"], tagged_args(ev["args"]))
            else:
                canonical_args_bytes(tagged_args(ev["args"]))
        except (InteropError, ValueError, OverflowError):
            continue
        raise AssertionError(f"error vector {ev['name']} did not raise")

    # Third-encoder conformance: when msgpack-python is importable, every
    # canonical payload must decode as well-formed MessagePack AND re-encode
    # (with sorted keys) to the identical bytes — pinning "canonical ==
    # shortest form as emitted by the de-facto encoders". Runs in CI.
    try:
        import msgpack  # noqa: PLC0415
    except ImportError:
        print("note: `msgpack` not installed — third-encoder conformance check skipped")
    else:
        def _resort(x: object) -> object:
            if isinstance(x, dict):
                return {k: _resort(x[k]) for k in sorted(x)}
            if isinstance(x, list):
                return [_resort(e) for e in x]
            return x

        for kv in built["key_vectors"]:
            b = bytes.fromhex(kv["canonical_args_hex"])
            decoded = msgpack.unpackb(b, raw=False, strict_map_key=True)
            assert msgpack.packb(_resort(decoded), use_bin_type=True) == b, (
                f"msgpack-python re-encode mismatch on {kv['name']}"
            )
        for vv in built["value_vectors"]:
            msgpack.unpackb(bytes.fromhex(vv["canonical_msgpack_hex"]), raw=False, strict_map_key=True)
        # A stock reader agrees with this one about every reader vector (strict_map_key
        # off: a non-string key is well-formed MessagePack).
        for rv in built["reader_accept_vectors"]:
            msgpack.unpackb(bytes.fromhex(rv["msgpack_hex"]), raw=False, strict_map_key=False)
        for rv in built["reader_reject_vectors"]:
            try:
                msgpack.unpackb(bytes.fromhex(rv["msgpack_hex"]), raw=False, strict_map_key=False)
            except msgpack.ExtraData:
                continue
            raise AssertionError(f"msgpack-python accepted reader reject vector {rv['name']}")

    # Encryption chain: the derived key must match the fingerprint already
    # published in test-vectors/encryption.json (ground-truth continuity).
    key = derive_encryption_key(bytes.fromhex(ENC_MASTER_KEY_HEX), ENC_TENANT_ID)
    assert key_fingerprint(key) == ENC_KEY_FINGERPRINT_HEX, (
        "HKDF chain no longer matches the ground truth pinned in encryption.json"
    )
    ev = built["encryption_vectors"][0]
    assert ev["aad_hex"] == built["aad_vectors"][0]["aad_hex"]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
    except ImportError:
        print("note: `cryptography` not installed — AES-GCM seal verified only by interop-crosscheck.mjs (WebCrypto)")
    else:
        ct = bytes.fromhex(ev["ciphertext_hex"])
        pt = AESGCM(key).decrypt(ct[:12], ct[12:], bytes.fromhex(ev["aad_hex"]))
        assert pt.hex() == ev["plaintext_hex"], "encryption vector does not decrypt to the pinned plaintext"
        resealed = ct[:12] + AESGCM(key).encrypt(ct[:12], pt, bytes.fromhex(ev["aad_hex"]))
        assert resealed.hex() == ev["ciphertext_hex"], "encryption vector seal mismatch"


def main() -> int:
    vectors_path = Path(__file__).resolve().parent.parent / "test-vectors" / "interop-mode.json"
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if cmd not in ("generate", "verify"):
        print(f"unknown command {cmd!r} — use 'generate' or 'verify'")
        return 2
    built = _build()
    _self_check(built)

    if cmd == "generate":
        vectors_path.write_text(json.dumps(built, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        print(
            f"wrote {vectors_path} ({len(built['key_vectors'])} key, {len(built['value_vectors'])} value, "
            f"{len(built['reader_accept_vectors'])} reader accept, {len(built['reader_reject_vectors'])} reader reject, "
            f"{len(built['error_vectors'])} error, {len(built['aad_vectors'])} AAD, "
            f"{len(built['encryption_vectors'])} encryption vectors)"
        )
        return 0

    on_disk = json.loads(vectors_path.read_text(encoding="utf-8"))
    if on_disk != built:
        print("MISMATCH: test-vectors/interop-mode.json does not match the reference implementation")
        return 1
    print(
        f"OK: {len(built['key_vectors'])} key, {len(built['value_vectors'])} value, "
            f"{len(built['reader_accept_vectors'])} reader accept, {len(built['reader_reject_vectors'])} reader reject, "
        f"{len(built['error_vectors'])} error, {len(built['aad_vectors'])} AAD, "
        f"{len(built['encryption_vectors'])} encryption vectors all verified"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
