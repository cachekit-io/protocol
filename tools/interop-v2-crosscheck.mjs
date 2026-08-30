#!/usr/bin/env node
// Independent cross-check of test-vectors/interop-v2.json (spec/interop-v2.md).
//
// From-scratch JavaScript implementations — sharing no code with
// tools/interop-v2-reference.py — of the pieces this profile ADDS: the v2
// value container parser (strict types, bounds-before-decompress), an LZ4
// *block* decompressor, the v2 AAD (compressed = "True"), and the encrypted
// round-trip via Node's built-in WebCrypto (HKDF-SHA256 + AES-256-GCM),
// including both cross-mode AAD rejections. The inherited v1 surface
// (canonical value encoding, key generation) is exhaustively cross-checked by
// tools/interop-crosscheck.mjs already and is not re-verified here.
//
// Run (zero dependencies):
//   node tools/interop-v2-crosscheck.mjs [path/to/interop-v2.json]

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";

const MAX_UNCOMPRESSED = 512n * 1024n * 1024n;
const MAX_COMPRESSED = 512 * 1024 * 1024;
const MAX_RATIO = 1000n;

// --- LZ4 block decompressor (independent implementation) --------------------
function lz4BlockDecompress(block, originalSize) {
  const out = Buffer.alloc(originalSize);
  let o = 0;
  let i = 0;
  const n = block.length;
  if (n === 0) throw new Error("empty LZ4 block");
  for (;;) {
    if (i >= n) throw new Error("truncated LZ4 block: missing token");
    const token = block[i++];
    let litLen = token >> 4;
    if (litLen === 15) {
      let b;
      do {
        if (i >= n) throw new Error("truncated LZ4 block: literal-length extension");
        b = block[i++];
        litLen += b;
      } while (b === 255);
    }
    if (i + litLen > n) throw new Error("truncated LZ4 block: literals overrun input");
    if (o + litLen > originalSize) throw new Error("LZ4 output exceeds original_size");
    block.copy(out, o, i, i + litLen);
    o += litLen;
    i += litLen;
    if (i === n) break; // clean end: last sequence is literals-only
    if (i + 2 > n) throw new Error("truncated LZ4 block: missing match offset");
    const offset = block[i] | (block[i + 1] << 8);
    i += 2;
    if (offset === 0) throw new Error("invalid LZ4 match offset 0");
    if (offset > o) throw new Error("LZ4 match offset beyond output start");
    let matchLen = (token & 0x0f) + 4;
    if ((token & 0x0f) === 15) {
      let b;
      do {
        if (i >= n) throw new Error("truncated LZ4 block: match-length extension");
        b = block[i++];
        matchLen += b;
      } while (b === 255);
    }
    if (o + matchLen > originalSize) throw new Error("LZ4 output exceeds original_size");
    for (let k = 0; k < matchLen; k++) {
      out[o] = out[o - offset]; // byte-wise: overlapping matches are legal
      o++;
    }
  }
  if (o !== originalSize) throw new Error(`LZ4 output length ${o} != original_size ${originalSize}`);
  return out;
}

// --- v2 container parser (strict) --------------------------------------------
// Minimal msgpack reader for the body grammar only: array header, two
// non-negative ints (BigInt — original_size may exceed 2^53 in hostile
// input), one bin. Anything else is a hard error, including the legacy
// array-of-ints payload shape.
function parseContainer(data) {
  if (data.length < 2 || data[0] !== 0xc1) {
    throw new Error("bad container magic (0xC1 expected) — possible interop/v1 value");
  }
  if (data[1] !== 0x02) throw new Error(`unsupported container version 0x${data[1].toString(16)}`);
  const body = data.subarray(2);
  let pos = 0;
  const need = (k) => {
    if (pos + k > body.length) throw new Error("container body truncated");
  };

  const readArrayHeader = () => {
    need(1);
    const m = body[pos++];
    if (m >= 0x90 && m <= 0x9f) return m & 0x0f;
    if (m === 0xdc) {
      need(2);
      const v = body.readUInt16BE(pos);
      pos += 2;
      return v;
    }
    if (m === 0xdd) {
      need(4);
      const v = body.readUInt32BE(pos);
      pos += 4;
      return v;
    }
    throw new Error(`container body must be a msgpack array, got marker 0x${m.toString(16)}`);
  };
  const readUint = () => {
    need(1);
    const m = body[pos++];
    if (m <= 0x7f) return BigInt(m);
    if (m === 0xcc) {
      need(1);
      return BigInt(body[pos++]);
    }
    if (m === 0xcd) {
      need(2);
      const v = BigInt(body.readUInt16BE(pos));
      pos += 2;
      return v;
    }
    if (m === 0xce) {
      need(4);
      const v = BigInt(body.readUInt32BE(pos));
      pos += 4;
      return v;
    }
    if (m === 0xcf) {
      need(8);
      const v = body.readBigUInt64BE(pos);
      pos += 8;
      return v;
    }
    throw new Error(`expected non-negative msgpack int, got marker 0x${m.toString(16)}`);
  };
  const readBin = () => {
    need(1);
    const m = body[pos++];
    let len;
    if (m === 0xc4) {
      need(1);
      len = body[pos++];
    } else if (m === 0xc5) {
      need(2);
      len = body.readUInt16BE(pos);
      pos += 2;
    } else if (m === 0xc6) {
      need(4);
      len = body.readUInt32BE(pos);
      pos += 4;
    } else {
      throw new Error(`payload must be msgpack bin (0xc4/0xc5/0xc6), got marker 0x${m.toString(16)}`);
    }
    // header-vs-remaining-input rule: validate BEFORE consuming/allocating
    if (pos + len > body.length) throw new Error("bin length header exceeds remaining input");
    const p = body.subarray(pos, pos + len);
    pos += len;
    return p;
  };

  if (readArrayHeader() !== 3) throw new Error("container body must be a 3-element array");
  const method = readUint();
  const originalSize = readUint();
  const payload = readBin();
  if (pos !== body.length) throw new Error("trailing bytes after container body");
  return { method, originalSize, payload };
}

// Normative reader algorithm steps 2-5: container bytes -> plain value bytes.
function decodeContainer(data) {
  const { method, originalSize, payload } = parseContainer(data);
  if (method !== 0n && method !== 1n) throw new Error(`unknown compression method ${method}`);
  // Security Limits — all BEFORE decompression, integer arithmetic (BigInt).
  if (originalSize > MAX_UNCOMPRESSED) throw new Error("original_size exceeds max uncompressed size");
  if (payload.length > MAX_COMPRESSED) throw new Error("payload exceeds max compressed size");
  if (method === 1n) {
    if (payload.length === 0) throw new Error("zero-length compressed payload");
    if (originalSize > MAX_RATIO * BigInt(payload.length)) {
      throw new Error("compression ratio exceeds 1000:1 — decompression bomb");
    }
    return lz4BlockDecompress(payload, Number(originalSize));
  }
  if (originalSize !== BigInt(payload.length)) {
    throw new Error(`method 0 original_size ${originalSize} != payload length ${payload.length}`);
  }
  return payload;
}

// --- AAD v0x03 + HKDF-SHA256 (per spec/encryption.md) ------------------------
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

function constructSalt(domain, tenantSalt) {
  const d = Buffer.from(domain, "utf8");
  const t = Buffer.from(tenantSalt, "utf8");
  const tLen = Buffer.alloc(2);
  tLen.writeUInt16BE(t.length);
  return Buffer.concat([Buffer.from("cachekit_v1_", "utf8"), Buffer.from([d.length]), d, tLen, t]);
}

async function deriveEncryptionKey(masterKeyHex, tenantId) {
  const masterKey = await webcrypto.subtle.importKey(
    "raw",
    Buffer.from(masterKeyHex, "hex"),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await webcrypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: constructSalt("encryption", tenantId),
      info: Buffer.from("encryption", "utf8"),
    },
    masterKey,
    256,
  );
  return Buffer.from(bits);
}

// --- run ---------------------------------------------------------------------
const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = process.argv[2] ?? join(here, "..", "test-vectors", "interop-v2.json");
const doc = JSON.parse(readFileSync(vectorsPath, "utf8"));

let failures = 0;
const check = (name, kind, expected, actual) => {
  if (expected !== actual) {
    failures++;
    console.error(`FAIL ${name} (${kind})\n  expected ${expected}\n  actual   ${actual}`);
  }
};

for (const v of doc.container_vectors) {
  try {
    const value = decodeContainer(Buffer.from(v.container_hex, "hex"));
    check(v.name, "decoded value bytes", v.value_msgpack_hex, value.toString("hex"));
    // Structural pins: method / original_size / payload fields agree with the parse.
    const parsed = parseContainer(Buffer.from(v.container_hex, "hex"));
    check(v.name, "method", BigInt(v.method), parsed.method);
    check(v.name, "original_size", BigInt(v.original_size), parsed.originalSize);
    check(v.name, "payload_hex", v.payload_hex, parsed.payload.toString("hex"));
  } catch (err) {
    failures++;
    console.error(`FAIL ${v.name} (container): ${err.message ?? err}`);
  }
}

for (const v of doc.aad_vectors) {
  const aad = aadV3(v.tenant_id, v.cache_key, v.format, v.compressed);
  check(v.name, "aad_hex", v.aad_hex, aad.toString("hex"));
  const aadV1 = aadV3(v.tenant_id, v.cache_key, v.format, false);
  check(v.name, "v1_aad_hex_for_comparison", v.v1_aad_hex_for_comparison, aadV1.toString("hex"));
}

for (const v of doc.encryption_vectors ?? []) {
  try {
    const derived = await deriveEncryptionKey(v.master_key_hex, v.tenant_id);
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
    // End-to-end: the decrypted container must decode to the pinned value bytes
    // of the container vector it wraps.
    const inner = decodeContainer(plaintext);
    const src = doc.container_vectors.find((c) => c.container_hex === v.plaintext_hex);
    if (src) check(v.name, "decrypted container decodes", src.value_msgpack_hex, inner.toString("hex"));
  } catch (err) {
    failures++;
    console.error(`FAIL ${v.name} (encryption): ${err.message ?? err}`);
  }
}

for (const v of doc.reject_vectors) {
  try {
    decodeContainer(Buffer.from(v.container_hex, "hex"));
    failures++;
    console.error(`FAIL ${v.name}: expected rejection (${v.error}), but decoding succeeded`);
  } catch {
    /* expected */
  }
}

// Cross-mode AAD rejections: AES-GCM authentication MUST fail both ways.
for (const v of doc.crypto_reject_vectors ?? []) {
  const derived = await deriveEncryptionKey(v.master_key_hex, v.tenant_id);
  const gcmKey = await webcrypto.subtle.importKey("raw", derived, "AES-GCM", false, ["decrypt"]);
  const ct = Buffer.from(v.ciphertext_hex, "hex");
  try {
    await webcrypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ct.subarray(0, 12),
        additionalData: Buffer.from(v.aad_hex, "hex"),
        tagLength: 128,
      },
      gcmKey,
      ct.subarray(12),
    );
    failures++;
    console.error(`FAIL ${v.name}: cross-mode decrypt unexpectedly succeeded (${v.error})`);
  } catch {
    /* expected: authentication failure */
  }
}

if (failures > 0) {
  console.error(`\n${failures} mismatch(es) — reference and cross-check DISAGREE`);
  process.exit(1);
}
console.log(
  `OK: ${doc.container_vectors.length} container, ${doc.aad_vectors.length} AAD, ` +
    `${(doc.encryption_vectors ?? []).length} encryption, ${doc.reject_vectors.length} reject, ` +
    `${(doc.crypto_reject_vectors ?? []).length} crypto-reject vectors verified independently`,
);
