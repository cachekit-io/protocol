#!/usr/bin/env node
// Independent cross-check of test-vectors/interop-mode.json (spec/interop-mode.md).
//
// This is a from-scratch canonical-MessagePack + normalization implementation in
// JavaScript — sharing no code with tools/interop-reference.py — so an encoding
// bug in either implementation shows up as a byte mismatch here. Hashing uses
// @noble/hashes, the same blake2b dependency cachekit-ts ships with. The
// encryption vector is verified cryptographically (HKDF-SHA256 derivation +
// AES-256-GCM decrypt with AAD) via Node's built-in WebCrypto.
//
// Run:
//   npm install @noble/hashes          # the only dependency
//   node tools/interop-crosscheck.mjs [path/to/interop-mode.json]

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";

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
  // Strings must be well-formed Unicode scalar sequences. Buffer.from would
  // silently map a lone surrogate to U+FFFD — a silent key collision — while
  // Python raises. The spec requires an error on both sides.
  if (!s.isWellFormed()) throw new Error("lone surrogate: strings must be well-formed Unicode");
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
  // NaN/Infinity are rejected by the sole caller (the Float branch) before
  // this point — no duplicate guard here.
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
    // isSafeInteger, not isInteger: a bare Number beyond 2^53 has already
    // lost precision — the spec requires an error, never silent rounding.
    if (!Number.isSafeInteger(v)) throw new Error("bare Number must be a safe integer — use $float / $int");
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
    else if (v.length <= 0xffff) {
      const h = Buffer.alloc(3);
      h[0] = 0xc5;
      h.writeUInt16BE(v.length, 1);
      chunks.push(h);
    } else {
      const h = Buffer.alloc(5);
      h[0] = 0xc6;
      h.writeUInt32BE(v.length, 1);
      chunks.push(h);
    }
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
  } else if (typeof v === "object" && [Object.prototype, null].includes(Object.getPrototypeOf(v))) {
    // A plain object is a map. Anything else (a Map, a Date, a class instance) is
    // outside the data model and falls through to the error below, never to an
    // empty map. Sort keys by UTF-8 byte order (== Unicode code point order). JS default
    // string sort compares UTF-16 code units and gets supplementary-plane
    // characters WRONG — compare encoded bytes instead.
    const keys = Object.keys(v).sort((a, b) =>
      Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")),
    );
    if (keys.length <= 15) chunks.push(Buffer.from([0x80 | keys.length]));
    else if (keys.length <= 0xffff) {
      const h = Buffer.alloc(3);
      h[0] = 0xde;
      h.writeUInt16BE(keys.length, 1);
      chunks.push(h);
    } else {
      const h = Buffer.alloc(5);
      h[0] = 0xdf;
      h.writeUInt32BE(keys.length, 1);
      chunks.push(h);
    }
    for (const k of keys) {
      encodeStr(k, chunks);
      encodeCanonical(v[k], chunks, { collapseFloats });
    }
  } else throw new Error(`unsupported: ${typeof v}`);
}

function pushArrayHeader(n, chunks) {
  if (n <= 15) chunks.push(Buffer.from([0x90 | n]));
  else if (n <= 0xffff) {
    const h = Buffer.alloc(3);
    h[0] = 0xdc;
    h.writeUInt16BE(n, 1);
    chunks.push(h);
  } else {
    const h = Buffer.alloc(5);
    h[0] = 0xdd;
    h.writeUInt32BE(n, 1);
    chunks.push(h);
  }
}

function encodeToBuffer(v, opts) {
  const chunks = [];
  encodeCanonical(v, chunks, opts);
  return Buffer.concat(chunks);
}

// --- value reader (independent implementation) -------------------------------
// Accepts ANY well-formed document, canonical or not, and rejects trailing bytes.
// Integers decode to BigInt and floats to Float, so the encoder above re-encodes
// what was read. A map with a non-string or repeated key and an ext type decode
// to these stand-ins, which the encoder rejects by type.
class DecodedMap {
  constructor(pairs) {
    this.pairs = pairs;
  }
}
class DecodedExt {
  constructor(type, data) {
    this.type = type;
    this.data = data;
  }
}

function decodeValue(buf) {
  let pos = 0;
  const take = (n) => {
    if (pos + n > buf.length) throw new Error("truncated document");
    pos += n;
    return buf.subarray(pos - n, pos);
  };
  const uint = (n) => (n === 8 ? take(8).readBigUInt64BE() : BigInt(take(n).readUIntBE(0, n)));
  const str = (n) => new TextDecoder("utf-8", { fatal: true }).decode(take(n));
  const ext = (n) => {
    const type = take(1).readInt8();
    return new DecodedExt(type, Buffer.from(take(n)));
  };
  const array = (n) => Array.from({ length: n }, () => item());
  const map = (n) => {
    const pairs = Array.from({ length: n }, () => [item(), item()]);
    const keys = pairs.map(([k]) => k);
    if (!keys.every((k) => typeof k === "string") || new Set(keys).size !== keys.length) {
      return new DecodedMap(pairs);
    }
    const out = {};
    for (const [k, v] of pairs) Object.defineProperty(out, k, { value: v, enumerable: true, writable: true });
    return out;
  };
  function item() {
    const t = take(1)[0];
    if (t <= 0x7f) return BigInt(t);
    if (t >= 0xe0) return BigInt(t - 0x100);
    if (t <= 0x8f) return map(t & 0x0f);
    if (t <= 0x9f) return array(t & 0x0f);
    if (t <= 0xbf) return str(t & 0x1f);
    switch (t) {
      case 0xc0:
        return null;
      case 0xc2:
        return false;
      case 0xc3:
        return true;
      case 0xc4:
      case 0xc5:
      case 0xc6:
        return Buffer.from(take(Number(uint(1 << (t - 0xc4)))));
      case 0xc7:
      case 0xc8:
      case 0xc9:
        return ext(Number(uint(1 << (t - 0xc7))));
      case 0xca:
        return new Float(take(4).readFloatBE());
      case 0xcb:
        return new Float(take(8).readDoubleBE());
      case 0xcc:
      case 0xcd:
      case 0xce:
      case 0xcf:
        return uint(1 << (t - 0xcc));
      case 0xd0:
        return BigInt(take(1).readInt8());
      case 0xd1:
        return BigInt(take(2).readInt16BE());
      case 0xd2:
        return BigInt(take(4).readInt32BE());
      case 0xd3:
        return take(8).readBigInt64BE();
      case 0xd4:
      case 0xd5:
      case 0xd6:
      case 0xd7:
      case 0xd8:
        return ext(1 << (t - 0xd4));
      case 0xd9:
      case 0xda:
      case 0xdb:
        return str(Number(uint(1 << (t - 0xd9))));
      case 0xdc:
      case 0xdd:
        return array(Number(uint(2 << (t - 0xdc))));
      case 0xde:
      case 0xdf:
        return map(Number(uint(2 << (t - 0xde))));
      default:
        throw new Error(`type byte 0x${t.toString(16)} is never used`);
    }
  }
  const value = item();
  if (pos !== buf.length) throw new Error(`${buf.length - pos} trailing byte(s) after one complete document`);
  return value;
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

// Segment grammar: the fixture's pattern governs both segments; the reserved
// namespaces and the `..` ban are hard-coded from the spec, not read from the
// fixture, so both rules are checked by a second implementation rather than
// echoed back.
const segmentRe = new RegExp(doc.segment_pattern, "u");
const RESERVED_NAMESPACES = new Set(["ns", "nsapi"]);
const segmentValid = (segment) => segmentRe.test(segment) && !segment.includes("..");
const segmentsValid = (namespace, operation) =>
  segmentValid(namespace) && segmentValid(operation) && !RESERVED_NAMESPACES.has(namespace);

let failures = 0;
const check = (name, kind, expected, actual) => {
  if (expected !== actual) {
    failures++;
    console.error(`FAIL ${name} (${kind})\n  expected ${expected}\n  actual   ${actual}`);
  }
};

for (const v of doc.key_vectors) {
  check(v.name, "segments valid", true, segmentsValid(v.namespace, v.operation));
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

// Reader vectors: this reader must accept every accept vector, re-encode it to the
// same canonical bytes as its tagged `value` (or fail to encode it at all when it has
// none), and find it non-canonical; it must reject every reject vector.
const encodeOrNull = (value) => {
  try {
    return encodeToBuffer(value, { collapseFloats: false });
  } catch {
    return null;
  }
};
for (const v of doc.reader_accept_vectors) {
  const raw = Buffer.from(v.msgpack_hex, "hex");
  let canonical;
  try {
    canonical = encodeOrNull(decodeValue(raw));
  } catch (err) {
    failures++;
    console.error(`FAIL ${v.name}: reader rejected a well-formed document (${err.message})`);
    continue;
  }
  const expected = v.value === undefined ? null : encodeToBuffer(fromTagged(v.value), { collapseFloats: false });
  check(v.name, "decoded value (canonical hex)", expected?.toString("hex"), canonical?.toString("hex"));
  check(v.name, "not canonical", false, canonical !== null && canonical.equals(raw));
}
for (const v of doc.reader_reject_vectors) {
  try {
    decodeValue(Buffer.from(v.msgpack_hex, "hex"));
    failures++;
    console.error(`FAIL ${v.name}: expected rejection (${v.error}), but the reader decoded it`);
  } catch {
    /* expected */
  }
}

for (const v of doc.aad_vectors) {
  const aad = aadV3(v.tenant_id, v.cache_key, v.format, v.compressed);
  check(v.name, "aad_hex", v.aad_hex, aad.toString("hex"));
}

// Encryption vectors: independently derive the key with WebCrypto HKDF-SHA256
// (salt construction per spec/encryption.md), check the fingerprint pinned in
// test-vectors/encryption.json, then AES-256-GCM decrypt with the AAD and
// compare the recovered plaintext against the pinned plain-msgpack bytes.
function constructSalt(domain, tenantSalt) {
  const d = Buffer.from(domain, "utf8");
  const t = Buffer.from(tenantSalt, "utf8");
  const tLen = Buffer.alloc(2);
  tLen.writeUInt16BE(t.length);
  return Buffer.concat([Buffer.from("cachekit_v1_", "utf8"), Buffer.from([d.length]), d, tLen, t]);
}

for (const v of doc.encryption_vectors ?? []) {
  try {
    const masterKey = await webcrypto.subtle.importKey(
      "raw",
      Buffer.from(v.master_key_hex, "hex"),
      "HKDF",
      false,
      ["deriveBits"],
    );
    const derivedBits = await webcrypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: constructSalt("encryption", v.tenant_id),
        info: Buffer.from("encryption", "utf8"),
      },
      masterKey,
      256,
    );
    const derived = Buffer.from(derivedBits);
    const fpInput = Buffer.concat([Buffer.from("key_fingerprint_v1", "utf8"), derived]);
    const fp = Buffer.from(await webcrypto.subtle.digest("SHA-256", fpInput)).subarray(0, 16);
    check(v.name, "derived_key_fingerprint_hex", v.derived_key_fingerprint_hex, fp.toString("hex"));

    const gcmKey = await webcrypto.subtle.importKey("raw", derived, "AES-GCM", false, ["decrypt"]);
    const ct = Buffer.from(v.ciphertext_hex, "hex");
    const plaintext = Buffer.from(
      await webcrypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ct.subarray(0, 12),
          additionalData: Buffer.from(v.aad_hex, "hex"),
          tagLength: 128,
        },
        gcmKey,
        ct.subarray(12),
      ),
    );
    check(v.name, "plaintext_hex (AES-GCM decrypt)", v.plaintext_hex, plaintext.toString("hex"));
    check(v.name, "nonce_hex", v.nonce_hex, ct.subarray(0, 12).toString("hex"));
  } catch (err) {
    failures++;
    console.error(`FAIL ${v.name} (encryption): ${err.message ?? err}`);
  }
}

for (const v of doc.error_vectors) {
  try {
    if (v.namespace !== undefined && !segmentsValid(v.namespace, v.operation)) {
      throw new Error("segment rejected");
    }
    encodeToBuffer(fromTagged(v.args), { collapseFloats: true });
    failures++;
    console.error(`FAIL ${v.name}: expected rejection (${v.error}), but encoding succeeded`);
  } catch {
    /* expected */
  }
}

// Self-tests for inputs portable JSON cannot carry. Named functions, so
// conformance/requirements.json can cite them.
function expectRejected(test, label, args) {
  try {
    encodeToBuffer(args, { collapseFloats: true });
  } catch {
    return; // expected
  }
  failures++;
  console.error(`FAIL ${test} (${label}): expected rejection, encoding succeeded`);
}

// A lone surrogate (serde_json rejects one; Rust String is immune by
// construction) is rejected wherever it sits, as in the Python reference.
function loneSurrogateSelftest() {
  const hi = String.fromCharCode(0xd800);
  const lo = String.fromCharCode(0xdc00);
  for (const [label, args] of [
    ["lone high surrogate", [hi]],
    ["lone low surrogate", [lo]],
    ["lone surrogate in a map key", [{ [hi]: 1n }]],
    ["lone low surrogate in a map key", [{ [lo]: 1n }]],
    ["lone surrogate in a nested value", [{ k: ["ok", lo] }]],
    ["lone surrogate in a set", [new TaggedSet([hi])]],
  ]) {
    expectRejected("loneSurrogateSelftest", label, args);
  }
  check("loneSurrogateSelftest", "valid pair", "91a4f0908080", encodeToBuffer([hi + lo], { collapseFloats: true }).toString("hex"));
}

// A value outside the data model is rejected wherever it sits, never encoded
// as an empty map: in JavaScript a non-string map key needs a Map.
function outOfModelSelftest() {
  class Point {}
  for (const [label, args] of [
    ["Map with a number key", [new Map([[1, "a"]])]],
    ["Date", [new Date(0)]],
    ["class instance", [new Point()]],
    ["undefined", [undefined]],
    ["Map in a list", [[1n, new Map([[1, "a"]])]]],
    ["class instance in a map value", [{ k: new Point() }]],
    ["class instance in a set", [new TaggedSet([new Point()])]],
  ]) {
    expectRejected("outOfModelSelftest", label, args);
  }
}

// A bare Number that is not a safe integer has already lost precision, so it is
// rejected, never rounded; the largest safe integer still encodes like its BigInt.
function unsafeNumberSelftest() {
  for (const [label, args] of [
    ["2^53", [2 ** 53]],
    ["-(2^53)", [-(2 ** 53)]],
    ["2^53 + 2", [2 ** 53 + 2]],
    ["2^64", [2 ** 64]],
    ["2^53 + 2 in a list", [[2 ** 53 + 2]]],
    ["2^53 + 2 in a map value", [{ id: 2 ** 53 + 2 }]],
  ]) {
    expectRejected("unsafeNumberSelftest", label, args);
  }
  const safe = Number.MAX_SAFE_INTEGER;
  check(
    "unsafeNumberSelftest",
    "MAX_SAFE_INTEGER",
    encodeToBuffer([BigInt(safe)], { collapseFloats: true }).toString("hex"),
    encodeToBuffer([safe], { collapseFloats: true }).toString("hex"),
  );
}

loneSurrogateSelftest();
outOfModelSelftest();
unsafeNumberSelftest();

if (failures > 0) {
  console.error(`\n${failures} mismatch(es) — reference and cross-check DISAGREE`);
  process.exit(1);
}
console.log(
  `OK: ${doc.key_vectors.length} key, ${doc.value_vectors.length} value, ` +
    `${doc.reader_accept_vectors.length} reader accept, ${doc.reader_reject_vectors.length} reader reject, ` +
    `${doc.aad_vectors.length} AAD, ${(doc.encryption_vectors ?? []).length} encryption, ` +
    `${doc.error_vectors.length} error vectors verified independently`,
);
