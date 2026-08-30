#!/usr/bin/env python3
"""Reference implementation of CacheKit interop/v2 (spec/interop-v2.md).

Stdlib-only (two optional extras, see below). Executable companion to the
compressed-values profile spec:
  - the v2 value container (0xC1 0x02 + msgpack [method, original_size, payload:bin])
  - a pure-Python LZ4 *block* codec (compressor + strict decompressor), so
    vector generation has no third-party dependency
  - the normative reader algorithm, including every Security-Limits bound
  - v2 AAD construction (compressed = "True", the frozen token)
  - test-vector generator + self-verifier for ../test-vectors/interop-v2.json

The interop/v1 surface (canonical MessagePack encoder, HKDF chain, AAD builder,
published v1 vectors) is imported from tools/interop-reference.py — v1 is the
single source of truth for everything this profile inherits, and importing it
(instead of copying it) is the standing proof that v1 is untouched.

Usage:
    python3 tools/interop-v2-reference.py generate   # rewrite test-vectors/interop-v2.json
    python3 tools/interop-v2-reference.py verify     # re-derive and compare against the JSON

Optional-dependency checks deepen `verify` when importable (both run in CI):
  - `lz4`: bidirectional conformance with the de-facto C implementation —
    our compressed bytes decompress under lz4.block, and lz4.block's output
    (store_size=False) decompresses under our decoder.
  - `cryptography`: re-verifies the AES-256-GCM seal of the encryption vector
    and both cross-mode AAD rejections (tools/interop-v2-crosscheck.mjs ALWAYS
    verifies these via Node's built-in WebCrypto regardless).

Cross-check with an independent implementation: tools/interop-v2-crosscheck.mjs
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from types import ModuleType

_HERE = Path(__file__).resolve().parent


def _load_v1() -> ModuleType:
    """Import tools/interop-reference.py (hyphenated filename) as a module."""
    spec = importlib.util.spec_from_file_location("interop_reference", _HERE / "interop-reference.py")
    if spec is None or spec.loader is None:
        msg = "cannot load tools/interop-reference.py"
        raise ImportError(msg)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


v1 = _load_v1()

# Security Limits (spec/interop-v2.md), reusing the wire-format.md constants.
MAX_UNCOMPRESSED = 512 * 1024 * 1024
MAX_COMPRESSED = 512 * 1024 * 1024
MAX_RATIO = 1000

MAGIC = 0xC1
CONTAINER_VERSION = 0x02
METHOD_NONE = 0
METHOD_LZ4_BLOCK = 1


class V2Error(ValueError):
    """Raised for any interop/v2 container the reader algorithm must reject."""


def _bad_marker(clause: str, marker: int) -> V2Error:
    """Reader rejection for a wrong MessagePack marker (diagnostic text, not normative)."""
    return V2Error(f"{clause}, got marker 0x{marker:02x}")


class SelfCheckError(Exception):
    """A vector invariant failed. Unlike `assert`, never disabled by `python -O`."""


def _require(cond: object, msg: str) -> None:
    """Self-check guard: `assert` semantics that survive optimized mode."""
    if not cond:
        raise SelfCheckError(msg)


# ---------------------------------------------------------------------------
# Pure-Python LZ4 *block* codec (https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)
#
# The compressor is a simple greedy hash-table matcher. Its output is valid
# LZ4 (verified against lz4.block when importable) but deliberately NOT
# canonical — the spec pins read-side conformance only; compressed bytes are
# writer-dependent. The decompressor is strict: invalid offsets, truncation,
# and any output-size disagreement with original_size are hard errors.
# ---------------------------------------------------------------------------

# LZ4 end-of-block restrictions: the last 5 bytes are always literals, and the
# last match must start at least 12 bytes before the end of the block.
_MFLIMIT = 12
_LAST_LITERALS = 5
_MIN_MATCH = 4
_MAX_OFFSET = 0xFFFF


def _emit_literal_run(out: bytearray, literals: bytes) -> None:
    n = len(literals)
    token_lit = 15 if n >= 15 else n
    out.append(token_lit << 4)
    if n >= 15:
        rem = n - 15
        while rem >= 255:
            out.append(255)
            rem -= 255
        out.append(rem)
    out += literals


def _emit_sequence(out: bytearray, literals: bytes, offset: int, match_len: int) -> None:
    n = len(literals)
    ml = match_len - _MIN_MATCH
    token = (15 if n >= 15 else n) << 4 | (15 if ml >= 15 else ml)
    out.append(token)
    if n >= 15:
        rem = n - 15
        while rem >= 255:
            out.append(255)
            rem -= 255
        out.append(rem)
    out += literals
    out += offset.to_bytes(2, "little")
    if ml >= 15:
        rem = ml - 15
        while rem >= 255:
            out.append(255)
            rem -= 255
        out.append(rem)


def lz4_block_compress(data: bytes) -> bytes:
    """Greedy LZ4 block compressor. Valid output, not canonical output."""
    n = len(data)
    out = bytearray()
    if n < _MFLIMIT + 1:  # too short for any match: literals-only block
        _emit_literal_run(out, data)
        return bytes(out)
    table: dict[bytes, int] = {}
    i = 0
    anchor = 0
    match_start_limit = n - _MFLIMIT  # matches may not start after this
    match_end_limit = n - _LAST_LITERALS  # matches may not extend past this
    while i <= match_start_limit:
        seq = data[i : i + _MIN_MATCH]
        j = table.get(seq)
        table[seq] = i
        if j is not None and i - j <= _MAX_OFFSET:
            length = _MIN_MATCH
            while i + length < match_end_limit and data[j + length] == data[i + length]:
                length += 1
            _emit_sequence(out, data[anchor:i], i - j, length)
            i += length
            anchor = i
        else:
            i += 1
    _emit_literal_run(out, data[anchor:])
    return bytes(out)


def lz4_block_decompress(block: bytes, original_size: int) -> bytes:
    """Strict LZ4 block decoder; output MUST be exactly original_size bytes."""
    out = bytearray()
    i = 0
    n = len(block)
    if n == 0:
        raise V2Error("empty LZ4 block")
    while True:
        if i >= n:
            raise V2Error("truncated LZ4 block: missing token")
        token = block[i]
        i += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                if i >= n:
                    raise V2Error("truncated LZ4 block: literal-length extension")
                b = block[i]
                i += 1
                lit_len += b
                if b != 255:
                    break
        if i + lit_len > n:
            raise V2Error("truncated LZ4 block: literals overrun input")
        out += block[i : i + lit_len]
        i += lit_len
        if len(out) > original_size:
            raise V2Error("LZ4 output exceeds original_size")
        if i == n:
            break  # clean end: last sequence is literals-only
        if i + 2 > n:
            raise V2Error("truncated LZ4 block: missing match offset")
        offset = block[i] | (block[i + 1] << 8)
        i += 2
        if offset == 0:
            raise V2Error("invalid LZ4 match offset 0")
        if offset > len(out):
            raise V2Error("LZ4 match offset beyond output start")
        match_len = (token & 0x0F) + _MIN_MATCH
        if (token & 0x0F) == 15:
            while True:
                if i >= n:
                    raise V2Error("truncated LZ4 block: match-length extension")
                b = block[i]
                i += 1
                match_len += b
                if b != 255:
                    break
        if len(out) + match_len > original_size:
            raise V2Error("LZ4 output exceeds original_size")
        for _ in range(match_len):  # byte-wise: overlapping matches are legal
            out.append(out[-offset])
    if len(out) != original_size:
        raise V2Error(f"LZ4 output length {len(out)} != original_size {original_size}")
    return bytes(out)


# ---------------------------------------------------------------------------
# The v2 value container
# ---------------------------------------------------------------------------

def encode_container(method: int, original_size: int, payload: bytes) -> bytes:
    """Canonical container bytes: 0xC1 0x02 + canonical msgpack [method, size, bin]."""
    body = v1.encode_canonical([method, original_size, payload], collapse_floats=False)
    return bytes([MAGIC, CONTAINER_VERSION]) + body


class _Reader:
    """Minimal strict MessagePack reader for the container body only.

    Accepts any well-formed header width (per spec) but only the types the
    body grammar allows: array, non-negative int, bin. Validates every
    declared length against the remaining input before consuming it.
    """

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise V2Error("container body truncated")
        chunk = self.buf[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def read_array_header(self) -> int:
        marker = self._take(1)[0]
        if 0x90 <= marker <= 0x9F:
            return marker & 0x0F
        if marker == 0xDC:
            return int.from_bytes(self._take(2), "big")
        if marker == 0xDD:
            return int.from_bytes(self._take(4), "big")
        raise _bad_marker("container body must be a msgpack array", marker)

    def read_uint(self) -> int:
        # Unsigned-family markers ONLY (spec: marker-level enforcement). The
        # signed family (negative fixint, 0xd0-0xd3) is rejected even when the
        # carried value is non-negative — which makes a negative original_size
        # structurally unrepresentable.
        marker = self._take(1)[0]
        if marker <= 0x7F:
            return marker
        if marker == 0xCC:
            return self._take(1)[0]
        if marker == 0xCD:
            return int.from_bytes(self._take(2), "big")
        if marker == 0xCE:
            return int.from_bytes(self._take(4), "big")
        if marker == 0xCF:
            return int.from_bytes(self._take(8), "big")
        raise _bad_marker("expected an unsigned-family msgpack int marker", marker)

    def read_bin(self) -> bytes:
        marker = self._take(1)[0]
        if marker == 0xC4:
            n = self._take(1)[0]
        elif marker == 0xC5:
            n = int.from_bytes(self._take(2), "big")
        elif marker == 0xC6:
            n = int.from_bytes(self._take(4), "big")
        else:
            # The explicit non-inheritance of the array-of-ints leniency (and
            # rejection of str-family payloads) lands here.
            raise _bad_marker("payload must be msgpack bin (0xc4/0xc5/0xc6)", marker)
        if self.pos + n > len(self.buf):  # header-vs-remaining-input rule
            raise V2Error("bin length header exceeds remaining input")
        return self._take(n)

    def expect_exhausted(self) -> None:
        if self.pos != len(self.buf):
            raise V2Error(f"{len(self.buf) - self.pos} trailing byte(s) after container body")


def decode_container(data: bytes) -> bytes:
    """Normative reader algorithm steps 2-5: container bytes -> plain value bytes."""
    if len(data) < 2:
        msg = "truncated container (magic + version bytes required)"
        raise V2Error(msg)
    if data[0] != MAGIC:
        raise V2Error("bad container magic (0xC1 expected) — possible interop/v1 value or mode misconfiguration")
    if data[1] != CONTAINER_VERSION:
        raise V2Error(f"unsupported container version 0x{data[1]:02x}")
    r = _Reader(data[2:])
    if r.read_array_header() != 3:
        raise V2Error("container body must be a 3-element array")
    method = r.read_uint()
    original_size = r.read_uint()
    payload = r.read_bin()
    r.expect_exhausted()

    if method not in (METHOD_NONE, METHOD_LZ4_BLOCK):
        raise V2Error(f"unknown compression method {method}")
    # Security Limits — all BEFORE any decompression, integer arithmetic only.
    if original_size > MAX_UNCOMPRESSED:
        raise V2Error(f"original_size {original_size} exceeds max uncompressed size")
    if len(payload) > MAX_COMPRESSED:
        raise V2Error("payload exceeds max compressed size")
    if method == METHOD_LZ4_BLOCK:
        if len(payload) == 0:
            raise V2Error("zero-length compressed payload")
        if original_size > MAX_RATIO * len(payload):
            raise V2Error("compression ratio exceeds 1000:1 — decompression bomb")
        return lz4_block_decompress(payload, original_size)
    if original_size != len(payload):
        raise V2Error(f"method 0 original_size {original_size} != payload length {len(payload)}")
    return payload


# ---------------------------------------------------------------------------
# Encryption vector constants. Master key + tenant match interop/v1 and
# test-vectors/encryption.json, so the derived key (fingerprint 96179a9b...)
# is the published ground truth. The ciphertext was produced with AES-256-GCM
# (cryptography/OpenSSL) over the lz4_roundtrip_compressible CONTAINER bytes
# with the v2 AAD (compressed="True") and the fixed nonce below; it is
# re-verified by the optional `cryptography` check here and ALWAYS by
# WebCrypto in interop-v2-crosscheck.mjs.
# ---------------------------------------------------------------------------

ENC_NONCE_HEX = "101112131415161718191a1b"
ENC_CIPHERTEXT_HEX = (
    "101112131415161718191a1b"
    "043e651799eeb533c4ddf646124b57eabe59f9292ed9f2cc1412ce52f677fccc93f82f01894f61"
    "9b13576eb790ea10a714a3afd85019a283a5240a602a170c9485575fe350ba5c414d1374f33216"
    "bd6b38eaf1f55503767f71229480e5"
)


# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------

# A value with real redundancy so method 1 actually compresses (and the
# reference compressor emits real match sequences, not a literals-only block).
COMPRESSIBLE_VALUE = {
    "events": ["GET /api/users/42 200 OK"] * 8,
    "source": "interop-v2-reference",
}

CONTAINER_VECTOR_DEFS: list[dict] = [
    {
        "name": "method0_issue_example",
        "description": (
            "method 0 (no compression) wrap of the v1 issue_example_object value — "
            "original_size MUST equal the payload length"
        ),
        "value": {"name": "alice", "age": 30},
        "method": METHOD_NONE,
    },
    {
        "name": "lz4_roundtrip_compressible",
        "description": (
            "method 1 compressed round-trip of a redundant value. The payload is the "
            "REFERENCE compressor's output: readers MUST decompress it to the pinned "
            "value bytes; writers are NOT required to reproduce these compressed bytes "
            "(compressed bytes are non-canonical, read-side conformance only)"
        ),
        "value": COMPRESSIBLE_VALUE,
        "method": METHOD_LZ4_BLOCK,
    },
    {
        "name": "lz4_wraps_v1_value_vector",
        "description": (
            "method 1 container over the SAME plain bytes as v1's issue_example_object "
            "value vector — the inner value profile is inherited from v1 unchanged. "
            "Incompressible at this size: the LZ4 payload is a literals-only block "
            "LARGER than the value (writers SHOULD have used method 0; readers MUST "
            "still accept it)"
        ),
        "value": {"name": "alice", "age": 30},
        "method": METHOD_LZ4_BLOCK,
    },
]


def _hex_container(method: int, original_size: int, payload: bytes) -> str:
    return encode_container(method, original_size, payload).hex()


def _build_reject_vectors(containers: dict[str, dict]) -> list[dict]:
    """Structural must-reject cases; every container_hex MUST raise in decode."""
    method0 = containers["method0_issue_example"]
    value_bytes = bytes.fromhex(method0["value_msgpack_hex"])
    lz4_payload = bytes.fromhex(containers["lz4_roundtrip_compressible"]["payload_hex"])
    lz4_size = containers["lz4_roundtrip_compressible"]["original_size"]

    return [
        {
            "name": "reject_bad_magic_v1_value",
            "description": "A bare interop/v1 value fed to a v2 reader: first byte is a msgpack marker, not 0xC1",
            "container_hex": value_bytes.hex(),
            "error": "bad magic; reader SHOULD diagnose 'possible interop/v1 value'",
        },
        {
            "name": "reject_bad_container_version",
            "description": "Right magic, wrong version byte (0x03)",
            "container_hex": (bytes([MAGIC, 0x03]) + v1.encode_canonical([0, len(value_bytes), value_bytes], collapse_floats=False)).hex(),
            "error": "unsupported container version",
        },
        {
            "name": "reject_unknown_method",
            "description": "method 2 is not in the registry",
            "container_hex": _hex_container(2, len(value_bytes), value_bytes),
            "error": "unknown compression method",
        },
        {
            "name": "reject_payload_array_of_ints",
            "description": (
                "Payload encoded as a msgpack array of integers instead of bin — the legacy "
                "ByteStorage leniency is explicitly NOT inherited by interop/v2"
            ),
            "container_hex": (bytes([MAGIC, CONTAINER_VERSION]) + v1.encode_canonical([0, 3, [1, 2, 3]], collapse_floats=False)).hex(),
            "error": "payload must be msgpack bin",
        },
        {
            "name": "reject_method_signed_marker",
            "description": (
                "method encoded with a signed-family marker (int8 0xd0 carrying value 0) — "
                "marker-level enforcement rejects the signed family even for non-negative values"
            ),
            "container_hex": (bytes([MAGIC, CONTAINER_VERSION, 0x93, 0xD0, 0x00, len(value_bytes), 0xC4, len(value_bytes)]) + value_bytes).hex(),
            "error": "signed-family int marker for method",
        },
        {
            "name": "reject_negative_original_size",
            "description": (
                "original_size encoded as negative fixint -1 (0xff) — negative sizes are "
                "structurally unrepresentable once signed-family markers are rejected; a "
                "value-level reader that accepts -1 here bypasses every upper-bound check"
            ),
            "container_hex": (bytes([MAGIC, CONTAINER_VERSION, 0x93, 0x01, 0xFF, 0xC4, 0x04]) + bytes.fromhex("10410000")).hex(),
            "error": "signed-family int marker for original_size",
        },
        {
            "name": "reject_forged_bin32_length",
            "description": (
                "bin32 payload header declaring 4 GiB (0xffffffff) with no data following — "
                "readers MUST validate the length header against remaining input BEFORE allocating"
            ),
            "container_hex": bytes([MAGIC, CONTAINER_VERSION, 0x93, 0x00, 0x05, 0xC6, 0xFF, 0xFF, 0xFF, 0xFF]).hex(),
            "error": "bin length header exceeds remaining input",
        },
        {
            "name": "reject_payload_str",
            "description": "Payload encoded as the msgpack str family instead of bin",
            "container_hex": (bytes([MAGIC, CONTAINER_VERSION]) + v1.encode_canonical([0, 3, "abc"], collapse_floats=False)).hex(),
            "error": "payload must be msgpack bin",
        },
        {
            "name": "reject_method0_size_mismatch",
            "description": "method 0 with original_size != payload length",
            "container_hex": _hex_container(METHOD_NONE, len(value_bytes) + 1, value_bytes),
            "error": "method 0 original_size mismatch",
        },
        {
            "name": "reject_trailing_bytes",
            "description": "Valid container followed by one extra byte",
            "container_hex": _hex_container(METHOD_NONE, len(value_bytes), value_bytes) + "00",
            "error": "trailing bytes after container body",
        },
        {
            "name": "reject_declared_size_bomb",
            "description": "original_size declares 1 TiB — exceeds the 512 MiB cap (checked BEFORE decompression)",
            "container_hex": _hex_container(METHOD_LZ4_BLOCK, 1 << 40, bytes.fromhex("10410000")),
            "error": "original_size exceeds max uncompressed size",
        },
        {
            "name": "reject_ratio_bomb",
            "description": "10-byte payload declaring 10001 output bytes — exceeds the 1000:1 ratio (checked BEFORE decompression)",
            "container_hex": _hex_container(METHOD_LZ4_BLOCK, 10_001, bytes(10)),
            "error": "compression ratio exceeds 1000:1",
        },
        {
            "name": "reject_zero_length_compressed",
            "description": "method 1 with an empty payload",
            "container_hex": _hex_container(METHOD_LZ4_BLOCK, 1, b""),
            "error": "zero-length compressed payload",
        },
        {
            "name": "reject_lz4_zero_offset",
            "description": "LZ4 sequence with match offset 0 (invalid in the block format)",
            "container_hex": _hex_container(METHOD_LZ4_BLOCK, 5, bytes.fromhex("10410000")),
            "error": "invalid LZ4 match offset 0",
        },
        {
            "name": "reject_lz4_truncated",
            "description": "The lz4_roundtrip_compressible payload with its last 3 bytes removed",
            "container_hex": _hex_container(METHOD_LZ4_BLOCK, lz4_size, lz4_payload[:-3]),
            "error": "truncated LZ4 block",
        },
        {
            "name": "reject_lz4_length_mismatch",
            "description": "Valid LZ4 block whose output is one byte short of original_size",
            "container_hex": _hex_container(METHOD_LZ4_BLOCK, lz4_size + 1, lz4_payload),
            "error": "LZ4 output length != original_size (also fine to fail as overrun, depending on decoder structure)",
        },
    ]


def _build() -> dict:
    tenant = v1.ENC_TENANT_ID
    master_key_hex = v1.ENC_MASTER_KEY_HEX

    # Reuse the v1 single_int key so the v1/v2 AAD pair is side-by-side comparable.
    cache_key = v1.interop_key("users", "get_user", [42])
    aad_v2 = v1.aad_v3(tenant, cache_key, compressed=True)
    aad_v1 = v1.aad_v3(tenant, cache_key, compressed=False)

    container_vectors = []
    by_name: dict[str, dict] = {}
    for d in CONTAINER_VECTOR_DEFS:
        value = v1.from_tagged(d["value"])
        value_bytes = v1.encode_canonical(value, collapse_floats=False)
        payload = value_bytes if d["method"] == METHOD_NONE else lz4_block_compress(value_bytes)
        entry = {
            "name": d["name"],
            "description": d["description"],
            "value": d["value"],
            "value_msgpack_hex": value_bytes.hex(),
            "method": d["method"],
            "original_size": len(value_bytes),
            "payload_hex": payload.hex(),
            "container_hex": _hex_container(d["method"], len(value_bytes), payload).lower(),
        }
        container_vectors.append(entry)
        by_name[d["name"]] = entry

    # Hand-built NON-canonical container: array16 header, uint8/uint32 ints,
    # bin16 payload. Pins the reader MUST for non-canonical unsigned-family
    # widths (writers MUST NOT emit this; readers MUST accept it).
    nc_value = by_name["method0_issue_example"]
    nc_bytes = bytes.fromhex(nc_value["value_msgpack_hex"])
    nc_container = (
        bytes([MAGIC, CONTAINER_VERSION])
        + b"\xdc\x00\x03"  # array16(3)
        + b"\xcc\x00"  # method 0 as uint8
        + b"\xce" + len(nc_bytes).to_bytes(4, "big")  # original_size as uint32
        + b"\xc5" + len(nc_bytes).to_bytes(2, "big")  # payload as bin16
        + nc_bytes
    )
    nc_entry = {
        "name": "method0_noncanonical_widths",
        "description": (
            "Same value as method0_issue_example, but with deliberately NON-canonical "
            "header widths (array16, uint8 method, uint32 original_size, bin16 payload). "
            "Readers MUST accept any unsigned-family width; writers MUST NOT emit this."
        ),
        "value": nc_value["value"],
        "value_msgpack_hex": nc_value["value_msgpack_hex"],
        "method": METHOD_NONE,
        "original_size": len(nc_bytes),
        "payload_hex": nc_bytes.hex(),
        "container_hex": nc_container.hex(),
    }
    container_vectors.append(nc_entry)
    by_name[nc_entry["name"]] = nc_entry

    enc_container_hex = by_name["lz4_roundtrip_compressible"]["container_hex"]

    return {
        "version": "1.0.0",
        "spec": "spec/interop-v2.md",
        "generator": "tools/interop-v2-reference.py (CPython stdlib, incl. pure-Python LZ4 block codec)",
        "cross_checked_by": "tools/interop-v2-crosscheck.mjs (independent container parser + LZ4 block decoder + WebCrypto HKDF/AES-GCM; zero dependencies)",
        "container_format": "0xC1 0x02 + canonical msgpack [method:int, original_size:int, payload:bin]",
        "security_limits": {
            "max_uncompressed_size": MAX_UNCOMPRESSED,
            "max_compressed_size": MAX_COMPRESSED,
            "max_compression_ratio": MAX_RATIO,
            "note": "All enforced BEFORE decompression, integer arithmetic only — spec/interop-v2.md#security-limits-decompression-bounds",
        },
        "compressed_bytes_note": (
            "method-1 payload bytes are NOT canonical: conformant LZ4 encoders legally differ. "
            "Vectors pin the reference compressor's output for READ-side conformance; writers "
            "may produce different valid LZ4 for the same value."
        ),
        "error_vectors_note": (
            "reject_* vectors MUST be rejected with an error; the 'error' text is a maintainer "
            "note, not a normative message."
        ),
        "container_vectors": container_vectors,
        "aad_vectors": [
            {
                "name": "interop_v2_aad",
                "description": (
                    "AAD v0x03 over the same tenant + interop key as v1's interop_key_aad; the two "
                    "AADs differ ONLY in the final component (frozen tokens 'True' vs 'False') — "
                    "this is the cryptographic mode separation"
                ),
                "tenant_id": tenant,
                "cache_key": cache_key,
                "format": "msgpack",
                "compressed": True,
                "aad_hex": aad_v2.hex(),
                "v1_aad_hex_for_comparison": aad_v1.hex(),
            }
        ],
        "encryption_vectors": [
            {
                "name": "interop_v2_compressed_encryption_roundtrip",
                "description": (
                    "Full v2 round-trip: HKDF-SHA256 per spec/encryption.md (same master key + "
                    "tenant as interop/v1 and encryption.json, hence the same derived key), "
                    "AES-256-GCM over the ENTIRE v2 container bytes (lz4_roundtrip_compressible) "
                    "with the v2 AAD (compressed='True') and a fixed nonce."
                ),
                "master_key_hex": master_key_hex,
                "tenant_id": tenant,
                "derived_key_fingerprint_hex": v1.ENC_KEY_FINGERPRINT_HEX,
                "cache_key": cache_key,
                "format": "msgpack",
                "compressed": True,
                "aad_hex": aad_v2.hex(),
                "plaintext_hex": enc_container_hex,
                "nonce_hex": ENC_NONCE_HEX,
                "ciphertext_hex": ENC_CIPHERTEXT_HEX,
                "ciphertext_layout": "nonce(12) || ciphertext || auth_tag(16)",
            }
        ],
        "reject_vectors": _build_reject_vectors(by_name),
        "crypto_reject_vectors": [
            {
                "name": "reject_v2_ciphertext_with_v1_aad",
                "description": "The v2 ciphertext MUST fail AES-GCM authentication under the v1 AAD (compressed='False')",
                "master_key_hex": master_key_hex,
                "tenant_id": tenant,
                "ciphertext_hex": ENC_CIPHERTEXT_HEX,
                "aad_hex": aad_v1.hex(),
                "error": "authentication failure — cross-mode read, terminal per the no-retry rule",
            },
            {
                "name": "reject_v1_ciphertext_with_v2_aad",
                "description": "interop/v1's published interop_encryption_roundtrip ciphertext MUST fail under the v2 AAD (compressed='True')",
                "master_key_hex": master_key_hex,
                "tenant_id": tenant,
                "ciphertext_hex": v1.ENC_CIPHERTEXT_HEX,
                "aad_hex": aad_v2.hex(),
                "error": "authentication failure — cross-mode read, terminal per the no-retry rule",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Self-checks
# ---------------------------------------------------------------------------

def _deterministic_junk(n: int) -> bytes:
    """Deterministic pseudo-random bytes (no RNG state, no seed drift)."""
    import hashlib

    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def _self_check(built: dict) -> None:
    # LZ4 codec round-trips: repetitive, incompressible, and boundary sizes.
    samples = [
        b"a",
        b"abcd" * 4,
        bytes(range(13)),
        b"the quick brown fox jumps over the lazy dog. " * 40,
        _deterministic_junk(1),
        _deterministic_junk(12),
        _deterministic_junk(13),
        _deterministic_junk(64 * 1024 + 17),
        b"\x00" * 100_000,
    ]
    for s in samples:
        _require(lz4_block_decompress(lz4_block_compress(s), len(s)) == s, f"LZ4 roundtrip failed for {len(s)}-byte sample")

    # Container round-trips + pinned bytes.
    for cv in built["container_vectors"]:
        got = decode_container(bytes.fromhex(cv["container_hex"]))
        _require(got.hex() == cv["value_msgpack_hex"], f"container {cv['name']} does not decode to its value bytes")

    by_name = {c["name"]: c for c in built["container_vectors"]}
    # The inherited-value-profile claim: identical inner bytes across the two wraps,
    # AND byte-identical to the PUBLISHED v1 value vector in interop-mode.json —
    # cross-file, so drift in either file breaks generation/verify loudly.
    _require(
        by_name["method0_issue_example"]["value_msgpack_hex"] == by_name["lz4_wraps_v1_value_vector"]["value_msgpack_hex"],
        "the two method0/lz4 wraps of the v1 value no longer share inner bytes",
    )
    v1_path = _HERE.parent / "test-vectors" / "interop-mode.json"
    try:
        v1_doc = json.loads(v1_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        msg = f"cannot read the published v1 vectors at {v1_path}: {e}"
        raise SelfCheckError(msg) from e
    v1_example = next(v for v in v1_doc["value_vectors"] if v["name"] == "issue_example_object")
    _require(
        by_name["method0_issue_example"]["value_msgpack_hex"] == v1_example["canonical_msgpack_hex"],
        "inner value bytes no longer match the published v1 issue_example_object vector",
    )
    v1_enc = v1_doc["encryption_vectors"][0]
    _require(
        built["crypto_reject_vectors"][1]["ciphertext_hex"] == v1_enc["ciphertext_hex"],
        "reject_v1_ciphertext_with_v2_aad no longer pins the published v1 ciphertext",
    )
    # The compressible vector must actually compress (real match sequences).
    lz4_cv = by_name["lz4_roundtrip_compressible"]
    _require(
        len(bytes.fromhex(lz4_cv["payload_hex"])) < lz4_cv["original_size"],
        "the 'compressible' vector did not compress — vector loses its point",
    )

    # Every structural reject vector must raise.
    for rv in built["reject_vectors"]:
        try:
            decode_container(bytes.fromhex(rv["container_hex"]))
        except V2Error:
            pass
        else:
            msg = f"reject vector {rv['name']} did not raise"
            raise SelfCheckError(msg)

    # AAD pair: v2 differs from v1 exactly in the final component.
    aad = built["aad_vectors"][0]
    v2b, v1b = bytes.fromhex(aad["aad_hex"]), bytes.fromhex(aad["v1_aad_hex_for_comparison"])
    _require(v2b[: -len(b"\x00\x00\x00\x04True")] == v1b[: -len(b"\x00\x00\x00\x05False")], "AAD prefixes diverge")
    _require(v2b.endswith(b"\x00\x00\x00\x04True") and v1b.endswith(b"\x00\x00\x00\x05False"), "frozen token suffixes wrong")

    # HKDF ground-truth continuity (same chain as v1 / encryption.json).
    key = v1.derive_encryption_key(bytes.fromhex(v1.ENC_MASTER_KEY_HEX), v1.ENC_TENANT_ID)
    _require(v1.key_fingerprint(key) == v1.ENC_KEY_FINGERPRINT_HEX, "derived-key fingerprint diverges from the published chain")

    # Optional: bidirectional conformance with the de-facto C implementation.
    try:
        import lz4.block  # noqa: PLC0415
    except ImportError:
        logging.warning("note: `lz4` not installed — C-implementation conformance check skipped")
    else:
        for s in samples:
            ours = lz4_block_compress(s)
            _require(lz4.block.decompress(ours, uncompressed_size=len(s)) == s, "lz4.block rejects our compressor output")
            theirs = lz4.block.compress(s, store_size=False)
            _require(lz4_block_decompress(theirs, len(s)) == s, "our decoder rejects lz4.block output")
        pinned = bytes.fromhex(lz4_cv["payload_hex"])
        _require(
            lz4.block.decompress(pinned, uncompressed_size=lz4_cv["original_size"]).hex() == lz4_cv["value_msgpack_hex"],
            "lz4.block does not decompress the pinned payload to the pinned value bytes",
        )

    # Optional: AES-GCM seal + both cross-mode AAD rejections.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
        from cryptography.exceptions import InvalidTag  # noqa: PLC0415
    except ImportError:
        logging.warning("note: `cryptography` not installed — AES-GCM checks run only in interop-v2-crosscheck.mjs (WebCrypto)")
    else:
        ev = built["encryption_vectors"][0]
        ct = bytes.fromhex(ev["ciphertext_hex"])
        pt = AESGCM(key).decrypt(ct[:12], ct[12:], bytes.fromhex(ev["aad_hex"]))
        _require(pt.hex() == ev["plaintext_hex"], "v2 encryption vector does not decrypt to the pinned container")
        resealed = ct[:12] + AESGCM(key).encrypt(ct[:12], pt, bytes.fromhex(ev["aad_hex"]))
        _require(resealed.hex() == ev["ciphertext_hex"], "v2 encryption vector seal mismatch")
        for rv in built["crypto_reject_vectors"]:
            rct = bytes.fromhex(rv["ciphertext_hex"])
            try:
                AESGCM(key).decrypt(rct[:12], rct[12:], bytes.fromhex(rv["aad_hex"]))
            except InvalidTag:
                pass
            else:
                msg = f"{rv['name']}: cross-mode decrypt unexpectedly succeeded"
                raise SelfCheckError(msg)


def main() -> int:
    vectors_path = _HERE.parent / "test-vectors" / "interop-v2.json"
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if cmd not in ("generate", "verify"):
        logging.error("unknown command %r — use 'generate' or 'verify'", cmd)
        return 2
    if cmd == "generate":
        # Generation (unlike verify) hard-requires `cryptography`: the pinned
        # ciphertext constant is coupled to the compressor's exact container
        # bytes, and without an AES-GCM reseal check a compressor change would
        # silently write vectors whose ciphertext no longer decrypts.
        try:
            import cryptography  # noqa: F401, PLC0415
        except ImportError:
            logging.error("generate requires the `cryptography` package (verify stays stdlib-only): pip install cryptography")
            return 2
    built = _build()
    _self_check(built)

    counts = (
        f"{len(built['container_vectors'])} container, {len(built['aad_vectors'])} AAD, "
        f"{len(built['encryption_vectors'])} encryption, {len(built['reject_vectors'])} reject, "
        f"{len(built['crypto_reject_vectors'])} crypto-reject vectors"
    )
    if cmd == "generate":
        vectors_path.write_text(json.dumps(built, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        logging.info("wrote %s (%s)", vectors_path, counts)
        return 0

    on_disk = json.loads(vectors_path.read_text(encoding="utf-8"))
    if on_disk != built:
        logging.error("MISMATCH: test-vectors/interop-v2.json does not match the reference implementation")
        return 1
    logging.info("OK: %s all verified", counts)
    return 0


if __name__ == "__main__":
    # stdout, matching the pre-logging behaviour and the twin JS cross-check.
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    sys.exit(main())
