#!/usr/bin/env node
// Independent cross-check of test-vectors/python-frame.json (spec/wire-format.md,
// "SDK Storage Containers"). Zero dependencies.
//
// This is a from-scratch, non-Python reader of Python-written cache entries. For
// the default-path vector it performs the FULL round-trip a hypothetical reader
// of the documented container would: CK v3 frame parse -> ByteStorage envelope
// decode (positional msgpack array) -> LZ4 block decompress -> inner MessagePack
// decode -> deep-compare against the original value. It also pins the normative
// behavior for interop readers: a CK frame is NOT one well-formed MessagePack
// document, so a strict single-document decoder rejects it.
//
// Run:  node tools/frame-crosscheck.mjs [path/to/python-frame.json]

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const vectorPath =
  process.argv[2] ??
  join(dirname(fileURLToPath(import.meta.url)), "..", "test-vectors", "python-frame.json");

const hexToBytes = (hex) => {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("invalid hexadecimal byte string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
// Envelope byte fields are msgpack arrays of integers — reject anything a
// Uint8Array would silently coerce (fractional, negative, >255, non-numeric).
const intArrayToBytes = (arr, what) => {
  if (!Array.isArray(arr) || arr.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) {
    throw new Error(`${what} is not an array of integers in 0..255`);
  }
  return Uint8Array.from(arr);
};
const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// ---------------------------------------------------------------- CK v3 frame

const FRAME_PREFIX_LEN = 7; // magic(2) + version(1) + header_len(4)

function parseFrame(frame) {
  if (frame[0] !== 0x43 || frame[1] !== 0x4b) throw new Error("not a CK frame");
  if (frame.length < FRAME_PREFIX_LEN) throw new Error("truncated frame");
  if (frame[2] !== 3) throw new Error(`unsupported frame version ${frame[2]}`);
  const hdrLen = ((frame[3] << 24) | (frame[4] << 16) | (frame[5] << 8) | frame[6]) >>> 0;
  const headerEnd = FRAME_PREFIX_LEN + hdrLen;
  if (headerEnd > frame.length) throw new Error("header length exceeds frame");
  const header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame.subarray(FRAME_PREFIX_LEN, headerEnd)));
  return { header, payload: frame.subarray(headerEnd) };
}

// ------------------------------------------------- minimal MessagePack decode
// Covers common MessagePack types. `bin` (0xc4/0xc5/0xc6) is DELIBERATELY
// unsupported: the corrected spec pins ByteStorage byte fields as arrays of
// integers, and accepting bin here would silently mask a drift back to
// bin-encoded fields. decodeOne returns [value, nextOffset]; decodeDocument
// additionally enforces single-document strictness (no trailing bytes) — the
// property that makes CK frames fail loudly in interop readers.

function decodeOne(b, at) {
  const t = b[at];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (t <= 0x7f) return [t, at + 1]; // positive fixint
  if (t >= 0xe0) return [t - 0x100, at + 1]; // negative fixint
  if (t >= 0x80 && t <= 0x8f) return decodeMap(b, at + 1, t & 0x0f);
  if (t >= 0x90 && t <= 0x9f) return decodeArray(b, at + 1, t & 0x0f);
  if (t >= 0xa0 && t <= 0xbf) return decodeStr(b, at + 1, t & 0x1f);
  switch (t) {
    case 0xc0: return [null, at + 1];
    case 0xc2: return [false, at + 1];
    case 0xc3: return [true, at + 1];
    case 0xcb: return [dv.getFloat64(at + 1), at + 9];
    case 0xcc: return [b[at + 1], at + 2];
    case 0xcd: return [dv.getUint16(at + 1), at + 3];
    case 0xce: return [dv.getUint32(at + 1), at + 5];
    case 0xd0: return [dv.getInt8(at + 1), at + 2];
    case 0xd1: return [dv.getInt16(at + 1), at + 3];
    case 0xd2: return [dv.getInt32(at + 1), at + 5];
    case 0xd9: return decodeStr(b, at + 2, b[at + 1]);
    case 0xda: return decodeStr(b, at + 3, dv.getUint16(at + 1));
    case 0xdc: return decodeArray(b, at + 3, dv.getUint16(at + 1));
    case 0xdd: return decodeArray(b, at + 5, dv.getUint32(at + 1));
    case 0xde: return decodeMap(b, at + 3, dv.getUint16(at + 1));
    default: throw new Error(`msgpack type 0x${t.toString(16)} not supported by this cross-check`);
  }
}
function decodeStr(b, at, len) {
  if (at + len > b.length) throw new Error("msgpack str overruns buffer");
  return [new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(at, at + len)), at + len];
}
function decodeArray(b, at, count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    const [v, next] = decodeOne(b, at);
    out.push(v);
    at = next;
  }
  return [out, at];
}
function decodeMap(b, at, count) {
  const out = {};
  for (let i = 0; i < count; i++) {
    const [k, kNext] = decodeOne(b, at);
    const [v, vNext] = decodeOne(b, kNext);
    out[k] = v;
    at = vNext;
  }
  return [out, at];
}
function decodeDocument(b) {
  const [value, consumed] = decodeOne(b, 0);
  if (consumed !== b.length) throw new Error(`trailing bytes after MessagePack document (${b.length - consumed})`);
  return value;
}

// ------------------------------------------------------- LZ4 block decompress

function lz4BlockDecompress(src, expectedSize) {
  const out = new Uint8Array(expectedSize);
  let sp = 0;
  let op = 0;
  while (sp < src.length) {
    const token = src[sp++];
    let litLen = token >> 4;
    if (litLen === 15) {
      let b;
      do {
        b = src[sp++];
        litLen += b;
      } while (b === 255);
    }
    if (op + litLen > out.length || sp + litLen > src.length) throw new Error("LZ4 literal overrun");
    out.set(src.subarray(sp, sp + litLen), op);
    sp += litLen;
    op += litLen;
    if (sp >= src.length) break; // final block ends with literals
    const offset = src[sp] | (src[sp + 1] << 8);
    sp += 2;
    if (offset === 0 || offset > op) throw new Error("LZ4 invalid match offset");
    let matchLen = token & 0x0f;
    if (matchLen === 15) {
      let b;
      do {
        b = src[sp++];
        matchLen += b;
      } while (b === 255);
    }
    matchLen += 4;
    if (op + matchLen > out.length) throw new Error("LZ4 match overrun");
    for (let i = 0; i < matchLen; i++, op++) out[op] = out[op - offset];
  }
  if (op !== expectedSize) throw new Error(`LZ4 output ${op} != expected ${expectedSize}`);
  return out;
}

// ----------------------------------------------------------------- assertions

let failures = 0;
const ok = (name, detail = "") => console.log(`ok   ${name}${detail ? ` (${detail})` : ""}`);
const fail = (name, msg) => {
  console.log(`FAIL ${name}: ${msg}`);
  failures++;
};
const deepEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const doc = JSON.parse(readFileSync(vectorPath, "utf-8"));

for (const vec of doc.frame_vectors) {
  const frame = hexToBytes(vec.frame_hex);
  let parsed;
  try {
    parsed = parseFrame(frame);
  } catch (e) {
    fail(vec.name, `frame parse: ${e.message}`);
    continue;
  }
  if (!deepEqual(parsed.header, vec.expected_header)) {
    fail(vec.name, "header mismatch");
    continue;
  }
  if (vec.expected_payload_hex && bytesToHex(parsed.payload) !== vec.expected_payload_hex) {
    fail(vec.name, "payload mismatch");
    continue;
  }

  if (vec.payload_envelope) {
    // Full round-trip: ByteStorage envelope -> LZ4 -> inner msgpack -> value.
    const env = vec.payload_envelope;
    try {
      const envelope = decodeDocument(parsed.payload);
      if (!Array.isArray(envelope) || envelope.length !== 4) throw new Error("envelope is not a 4-element msgpack array");
      const [compressedData, checksum, originalSize, format] = envelope;
      const compressedBytes = intArrayToBytes(compressedData, "compressed_data");
      if (bytesToHex(compressedBytes) !== env.compressed_data_hex) throw new Error("compressed_data mismatch");
      const checksumBytes = intArrayToBytes(checksum, "checksum");
      if (checksumBytes.length !== 8) throw new Error(`checksum is ${checksumBytes.length} bytes (envelope requires exactly 8)`);
      if (bytesToHex(checksumBytes) !== env.checksum_hex) throw new Error("checksum field mismatch");
      if (originalSize !== env.original_size) throw new Error("original_size mismatch");
      if (format !== env.format) throw new Error("format mismatch");
      const inner = lz4BlockDecompress(compressedBytes, originalSize);
      if (bytesToHex(inner) !== env.inner_msgpack_hex) throw new Error("decompressed payload mismatch");
      const value = decodeDocument(inner);
      if (!deepEqual(value, vec.value_json)) throw new Error("decoded value != value_json");
      ok(vec.name, "full round-trip: frame -> envelope -> LZ4 -> msgpack -> value");
    } catch (e) {
      fail(vec.name, e.message);
    }
    continue;
  }

  if (vec.arrow_detection) {
    const det = vec.arrow_detection;
    const magic = new TextEncoder().encode(det.ipc_magic);
    const at = parsed.payload.subarray(det.ipc_magic_offset, det.ipc_magic_offset + magic.length);
    if (det.checksum_len !== 8) {
      fail(vec.name, `arrow checksum_len is ${det.checksum_len} (envelope requires exactly 8)`);
    } else if (bytesToHex(parsed.payload.subarray(0, det.checksum_len)) !== det.checksum_hex) {
      fail(vec.name, "checksum prefix mismatch");
    } else if (bytesToHex(at) !== bytesToHex(magic)) {
      fail(vec.name, "ARROW1 magic not at documented offset");
    } else {
      ok(vec.name, "frame parse + Arrow envelope detection");
    }
    continue;
  }

  ok(vec.name);
}

for (const vec of doc.error_vectors) {
  const frame = hexToBytes(vec.frame_hex);
  if (vec.name === "ck_frame_fed_to_interop_reader") {
    // Normative: strict single-document msgpack decode MUST reject a CK frame.
    try {
      decodeDocument(frame);
      fail(vec.name, "strict msgpack decode accepted a CK frame");
    } catch {
      ok(vec.name, "strict single-document msgpack decode rejects");
    }
    continue;
  }
  try {
    parseFrame(frame);
    fail(vec.name, "expected rejection, parsed successfully");
  } catch {
    ok(vec.name, "rejected");
  }
}

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall python-frame vectors cross-checked (independent JS reader)");
