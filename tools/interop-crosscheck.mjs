#!/usr/bin/env node
// Independent cross-check of test-vectors/interop-mode.json (spec/interop-mode.md).
//
// This is a from-scratch canonical-MessagePack + normalization implementation in
// JavaScript — sharing no code with tools/interop-reference.py — so an encoding
// bug in either implementation shows up as a byte mismatch here. Hashing uses
// @noble/hashes, the same blake2b dependency cachekit-ts ships with.
//
// Run:
//   npm install @noble/hashes          # the only dependency
//   node tools/interop-crosscheck.mjs [path/to/interop-mode.json]

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

let blake2b;
try {
  ({ blake2b } = await import("@noble/hashes/blake2.js")); // noble v2 export path
} catch {
  ({ blake2b } = await import("@noble/hashes/blake2b")); // noble v1 export path
}

const UINT64_MAX = 18446744073709551615n;
const INT64_MIN = -9223372036854775808n;
// Exact float64 bounds for the integral-collapse range check (powers of two).
const F64_UPPER_EXCL = 18446744073709551616.0; // 2^64
const F64_LOWER_INCL = -9223372036854775808.0; // -(2^63)

// --- typed wrappers for tagged-JSON inputs (JS has one Number type) ---------
class Float {
  constructor(v) {
    this.v = v;
  }
}
class TaggedSet {
  constructor(elements) {
    this.elements = elements;
  }
}

function fromTagged(v) {
  if (Array.isArray(v)) return v.map(fromTagged);
  if (v !== null && typeof v === "object") {
    const keys = Object.keys(v);
    if (keys.length === 1 && keys[0].startsWith("$")) {
      const val = v[keys[0]];
      switch (keys[0]) {
        case "$set":
          return new TaggedSet(val.map(fromTagged));
        case "$bytes":
          return Buffer.from(val, "hex");
        case "$datetime":
          return isoToUnixFloat64(val);
        case "$uuid":
          return val.toLowerCase();
        case "$float":
          return new Float(Number(val));
        case "$int":
          return BigInt(val);
        default:
          throw new Error(`unknown tag ${keys[0]}`);
      }
    }
    const out = {};
    for (const k of keys) out[k] = fromTagged(v[k]);
    return out;
  }
  return v;
}

// ISO 8601 (with mandatory offset) -> integer micros since epoch -> ONE
// float64 division by 10^6, exactly as the spec defines. JS Date only has
// millisecond precision, so parse the fractional seconds by hand.
function isoToUnixFloat64(iso) {
  const m = iso.match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/,
  );
  if (!m) throw new Error(`naive or malformed datetime: ${iso}`);
  const [, Y, Mo, D, H, Mi, S, frac, off] = m;
  let ms = Date.UTC(+Y, +Mo - 1, +D, +H, +Mi, +S);
  if (off !== "Z") {
    const sign = off[0] === "-" ? -1 : 1;
    ms -= sign * (Number(off.slice(1, 3)) * 60 + Number(off.slice(4, 6))) * 60_000;
  }
  const micros = BigInt(ms) * 1000n + BigInt((frac ?? "").padEnd(6, "0") || "0");
  return new Float(Number(micros) / 1_000_000.0);
}

// --- canonical MessagePack encoder (independent implementation) -------------
function encodeInt(n /* BigInt */, chunks) {
  if (n < INT64_MIN || n > UINT64_MAX) throw new Error(`int out of range: ${n}`);
  const b = Buffer.alloc(9);
  if (n >= 0n && n <= 0x7fn) chunks.push(Buffer.from([Number(n)]));
  else if (n >= -32n && n < 0n) chunks.push(Buffer.from([Number(n) & 0xff]));
  else if (n > 0n) {
    if (n <= 0xffn) chunks.push(Buffer.from([0xcc, Number(n)]));
    else if (n <= 0xffffn) {
      b[0] = 0xcd;
      b.writeUInt16BE(Number(n), 1);
      chunks.push(Buffer.from(b.subarray(0, 3)));
    } else if (n <= 0xffffffffn) {
      b[0] = 0xce;
      b.writeUInt32BE(Number(n), 1);
      chunks.push(Buffer.from(b.subarray(0, 5)));
    } else {
      b[0] = 0xcf;
      b.writeBigUInt64BE(n, 1);
      chunks.push(Buffer.from(b.subarray(0, 9)));
    }
  } else {
    if (n >= -128n) {
      b[0] = 0xd0;
      b.writeInt8(Number(n), 1);
      chunks.push(Buffer.from(b.subarray(0, 2)));
    } else if (n >= -32768n) {
      b[0] = 0xd1;
      b.writeInt16BE(Number(n), 1);
      chunks.push(Buffer.from(b.subarray(0, 3)));
    } else if (n >= -2147483648n) {
      b[0] = 0xd2;
      b.writeInt32BE(Number(n), 1);
      chunks.push(Buffer.from(b.subarray(0, 5)));
    } else {
      b[0] = 0xd3;
      b.writeBigInt64BE(n, 1);
      chunks.push(Buffer.from(b.subarray(0, 9)));
    }
  }
}

function encodeStr(s, chunks) {
  const b = Buffer.from(s, "utf8");
  if (b.length <= 31) chunks.push(Buffer.from([0xa0 | b.length]));
  else if (b.length <= 0xff) chunks.push(Buffer.from([0xd9, b.length]));
  else if (b.length <= 0xffff) {
    const h = Buffer.alloc(3);
    h[0] = 0xda;
    h.writeUInt16BE(b.length, 1);
    chunks.push(h);
  } else {
    const h = Buffer.alloc(5);
    h[0] = 0xdb;
    h.writeUInt32BE(b.length, 1);
    chunks.push(h);
  }
  chunks.push(b);
}

function encodeFloat64(f, chunks) {
  if (Number.isNaN(f) || !Number.isFinite(f)) throw new Error("NaN/Infinity rejected");
  const b = Buffer.alloc(9);
  b[0] = 0xcb;
  b.writeDoubleBE(f, 1);
  chunks.push(b);
}

function encodeCanonical(v, chunks, { collapseFloats }) {
  if (v === null) chunks.push(Buffer.from([0xc0]));
  else if (typeof v === "boolean") chunks.push(Buffer.from([v ? 0xc3 : 0xc2]));
  else if (typeof v === "bigint") encodeInt(v, chunks);
  else if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("bare non-integer Number — use $float");
    encodeInt(BigInt(v), chunks);
  } else if (v instanceof Float) {
    const f = v.v;
    if (Number.isNaN(f) || !Number.isFinite(f)) throw new Error("NaN/Infinity rejected");
    // Number canonicalization (args profile): integral f64 in range -> int.
    // Covers -0.0: Number.isInteger(-0) is true and BigInt(-0) === 0n.
    if (collapseFloats && Number.isInteger(f) && f >= F64_LOWER_INCL && f < F64_UPPER_EXCL) {
      encodeInt(BigInt(f), chunks);
    } else {
      encodeFloat64(f, chunks);
    }
  } else if (typeof v === "string") encodeStr(v, chunks);
  else if (Buffer.isBuffer(v)) {
    if (v.length <= 0xff) chunks.push(Buffer.from([0xc4, v.length]));
    else throw new Error("bin16/32 not needed by vectors");
    chunks.push(v);
  } else if (v instanceof TaggedSet) {
    const encoded = v.elements.map((e) => encodeToBuffer(e, { collapseFloats }));
    encoded.sort(Buffer.compare);
    const dedup = encoded.filter((b, i) => i === 0 || !b.equals(encoded[i - 1]));
    pushArrayHeader(dedup.length, chunks);
    for (const b of dedup) chunks.push(b);
  } else if (Array.isArray(v)) {
    pushArrayHeader(v.length, chunks);
    for (const item of v) encodeCanonical(item, chunks, { collapseFloats });
  } else if (typeof v === "object") {
    // Sort keys by UTF-8 byte order (== Unicode code point order). JS default
    // string sort compares UTF-16 code units and gets supplementary-plane
    // characters WRONG — compare encoded bytes instead.
    const keys = Object.keys(v).sort((a, b) =>
      Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")),
    );
    if (keys.length <= 15) chunks.push(Buffer.from([0x80 | keys.length]));
    else throw new Error("map16/32 not needed by vectors");
    for (const k of keys) {
      encodeStr(k, chunks);
      encodeCanonical(v[k], chunks, { collapseFloats });
    }
  } else throw new Error(`unsupported: ${typeof v}`);
}

function pushArrayHeader(n, chunks) {
  if (n <= 15) chunks.push(Buffer.from([0x90 | n]));
  else throw new Error("array16/32 not needed by vectors");
}

function encodeToBuffer(v, opts) {
  const chunks = [];
  encodeCanonical(v, chunks, opts);
  return Buffer.concat(chunks);
}

function aadV3(tenantId, cacheKey, format, compressed) {
  const chunks = [Buffer.from([0x03])];
  for (const comp of [tenantId, cacheKey, format, compressed ? "True" : "False"]) {
    const b = Buffer.from(comp, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    chunks.push(len, b);
  }
  return Buffer.concat(chunks);
}

// --- run ---------------------------------------------------------------------
const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = process.argv[2] ?? join(here, "..", "test-vectors", "interop-mode.json");
const doc = JSON.parse(readFileSync(vectorsPath, "utf8"));

let failures = 0;
const check = (name, kind, expected, actual) => {
  if (expected !== actual) {
    failures++;
    console.error(`FAIL ${name} (${kind})\n  expected ${expected}\n  actual   ${actual}`);
  }
};

for (const v of doc.key_vectors) {
  const args = fromTagged(v.args);
  const bytes = encodeToBuffer(args, { collapseFloats: true });
  check(v.name, "canonical_args_hex", v.canonical_args_hex, bytes.toString("hex"));
  const hash = Buffer.from(blake2b(bytes, { dkLen: 32 })).toString("hex");
  check(v.name, "args_hash", v.args_hash, hash);
  check(v.name, "expected_key", v.expected_key, `${v.namespace}:${v.operation}:${hash}`);
}

for (const v of doc.value_vectors) {
  const value = fromTagged(v.value);
  const bytes = encodeToBuffer(value, { collapseFloats: false });
  check(v.name, "canonical_msgpack_hex", v.canonical_msgpack_hex, bytes.toString("hex"));
}

for (const v of doc.aad_vectors) {
  const aad = aadV3(v.tenant_id, v.cache_key, v.format, v.compressed);
  check(v.name, "aad_hex", v.aad_hex, aad.toString("hex"));
}

for (const v of doc.error_vectors) {
  try {
    if (v.namespace !== undefined) {
      const re = new RegExp(doc.segment_pattern, "u");
      if (!re.test(v.namespace) || !re.test(v.operation)) throw new Error("segment rejected");
    }
    encodeToBuffer(fromTagged(v.args), { collapseFloats: true });
    failures++;
    console.error(`FAIL ${v.name}: expected rejection (${v.error}), but encoding succeeded`);
  } catch {
    /* expected */
  }
}

if (failures > 0) {
  console.error(`\n${failures} mismatch(es) — reference and cross-check DISAGREE`);
  process.exit(1);
}
console.log(
  `OK: ${doc.key_vectors.length} key, ${doc.value_vectors.length} value, ` +
    `${doc.aad_vectors.length} AAD, ${doc.error_vectors.length} error vectors verified independently`,
);
