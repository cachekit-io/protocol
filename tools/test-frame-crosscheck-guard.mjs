#!/usr/bin/env node
// Mutation tests for guards in frame-crosscheck.mjs: the lz4BlockDecompress
// validate-before-allocate guard, the value check on a frame whose payload is
// plain MessagePack (no envelope), the serializer-name check on frame vectors,
// and the hold of each error vector to the frame parser or to the
// serializer-name check, as its rejected_by says.
// Zero dependencies. Run: node tools/test-frame-crosscheck-guard.mjs
//
// Evidence convention (LAB-903 / test_check_version_floors.py): a baseline
// case pins exit 0 on unmutated input, every mutation is checked for
// no-op-ness, and a guard-stripped run proves the guard load-bearing.
//
// One deliberate refinement over "stripping the guard makes the case exit 0":
// it cannot, and pretending otherwise would test nothing. The driver's
// post-allocation `op !== expectedSize` check means an absurd original_size
// exits non-zero even WITHOUT the guard — just after the oversized allocation
// has already happened, which is exactly the pre-LAB-1202 vulnerability. Exit
// codes therefore cannot discriminate guarded from unguarded; failure MESSAGES
// can, and do so precisely: the guarded run must fail with the pre-allocation
// ceiling refusal, and the stripped run must fail with the post-allocation
// size mismatch (proof the 64 MiB allocation succeeded before any validation).

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const TOOL = join(HERE, "frame-crosscheck.mjs");
const FIXTURE = join(HERE, "..", "test-vectors", "python-frame.json");

// Must match the guard's message in frame-crosscheck.mjs and the driver's
// post-allocation mismatch message respectively.
const GUARD_MSG = "exceeds max expansion ceiling";
// The plain-MessagePack value check and the vector that reaches it: integrity
// checking off, so its payload is the value's MessagePack with no envelope.
const PLAIN_VECTOR = "integrity_checking_off_write";
const VALUE_MSG = "decoded value != value_json";
const PLAIN_CHECK = 'if (!deepEqual(decodeDocument(parsed.payload), vec.value_json)) throw new Error("decoded value != value_json");';
const POST_ALLOC_MSG = "LZ4 output 2 != expected 67108864";

const ABSURD_SIZE = 64 * 1024 * 1024; // 64 MiB declared from 3 compressed bytes; ceiling is 3*255 = 765

// A minimal CK v3 frame whose ByteStorage envelope declares ABSURD_SIZE as
// original_size. compressed_data is 3 bytes: token 0x20 (2 literals, no
// match) + "AB" — a valid LZ4 block that decompresses to exactly 2 bytes, so
// an unguarded decompressor allocates ABSURD_SIZE, succeeds, and only then
// trips the output-size mismatch.
function buildAbsurdVector() {
  const compressed = [0x20, 0x41, 0x42];
  const size32 = [(ABSURD_SIZE >>> 24) & 0xff, (ABSURD_SIZE >>> 16) & 0xff, (ABSURD_SIZE >>> 8) & 0xff, ABSURD_SIZE & 0xff];
  const format = [..."msgpack"].map((c) => c.charCodeAt(0));
  const envelope = [
    0x94, // fixarray(4)
    0xc4, compressed.length, ...compressed, // bin8 compressed_data
    0x98, 1, 2, 3, 4, 5, 6, 7, 8, // checksum: fixarray of 8 ints (int-array, per protocol 1.1)
    0xce, ...size32, // uint32 original_size = ABSURD_SIZE
    0xa7, ...format, // fixstr "msgpack"
  ];
  // A header that records a serializer name, so the frame reaches the envelope: the cross-check refuses a nameless one.
  const header = [...'{"s":"default"}'].map((c) => c.charCodeAt(0));
  const frame = [0x43, 0x4b, 3, 0, 0, 0, header.length, ...header, ...envelope];
  return {
    name: "mutation_absurd_original_size",
    frame_hex: frame.map((b) => b.toString(16).padStart(2, "0")).join(""),
    expected_header: { s: "default" },
    payload_envelope: {
      envelope_encoding: "bin",
      compressed_data_hex: "204142",
      checksum_hex: "0102030405060708",
      original_size: ABSURD_SIZE,
      format: "msgpack",
      inner_msgpack_hex: "never-reached: the ceiling guard must fire before decompression output exists",
    },
    value_json: null,
  };
}

// Rewrite a vector's CK frame header with `change`, keeping HDR_LEN and expected_header in step.
function reheader(vec, change) {
  const bytes = Buffer.from(vec.frame_hex, "hex");
  const hdrLen = bytes.readUInt32BE(3);
  const header = change(JSON.parse(bytes.subarray(7, 7 + hdrLen).toString("utf-8")));
  const raw = Buffer.from(JSON.stringify(header), "utf-8");
  const prefix = Buffer.from(bytes.subarray(0, 7));
  prefix.writeUInt32BE(raw.length, 3);
  vec.frame_hex = Buffer.concat([prefix, raw, bytes.subarray(7 + hdrLen)]).toString("hex");
  vec.expected_header = header;
}

const run = (toolPath, fixturePath) => {
  const r = spawnSync(process.execPath, [toolPath, fixturePath], { encoding: "utf-8" });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};

const failures = [];
const check = (name, cond, detail) => {
  console.log(`  [${cond ? "ok" : "FAIL"}] ${name}`);
  if (!cond) failures.push(`${name}: ${detail}`);
};

const tmp = mkdtempSync(join(tmpdir(), "lab1202-"));
try {
  // Case 1 — baseline: unmutated fixture, real tool, exit 0. Pins that any
  // failure below is caused by the mutation, not ambient breakage.
  const base = run(TOOL, FIXTURE);
  check("baseline: committed vectors exit 0 under the guarded tool", base.code === 0, `exit ${base.code}\n${base.out}`);

  // Case 2 — absurd original_size vector appended to the fixture (mutation
  // no-op-proof by construction: one more vector than the committed file).
  const doc = JSON.parse(readFileSync(FIXTURE, "utf-8"));
  doc.frame_vectors.push(buildAbsurdVector());
  const mutatedFixture = join(tmp, "python-frame-absurd.json");
  writeFileSync(mutatedFixture, JSON.stringify(doc));
  const guarded = run(TOOL, mutatedFixture);
  check("guarded tool: absurd original_size exits non-zero", guarded.code !== 0, `exit ${guarded.code}\n${guarded.out}`);
  check(
    "guarded tool: rejection is the PRE-allocation ceiling refusal",
    guarded.out.includes(GUARD_MSG),
    `guard message "${GUARD_MSG}" absent:\n${guarded.out}`
  );

  // Case 3 — strip the guard from the tool source and re-run the same case.
  const source = readFileSync(TOOL, "utf-8");
  const stripped = source.replace(
    /function lz4BlockDecompress\(src, expectedSize\) \{[\s\S]*?const out = new Uint8Array\(expectedSize\);/,
    "function lz4BlockDecompress(src, expectedSize) {\n  const out = new Uint8Array(expectedSize);"
  );
  check(
    "guard-strip mutation is not a no-op",
    stripped !== source && !stripped.includes(GUARD_MSG),
    "the strip regex no longer matches the guard; the anchor text moved, fix this test"
  );
  const strippedTool = join(tmp, "frame-crosscheck-stripped.mjs");
  writeFileSync(strippedTool, stripped);
  const unguarded = run(strippedTool, mutatedFixture);
  check(
    "stripped tool: ceiling refusal is gone (the guard, not a later check, rejects pre-allocation)",
    !unguarded.out.includes(GUARD_MSG),
    `guard message still present after strip:\n${unguarded.out}`
  );
  check(
    "stripped tool: failure is the POST-allocation size mismatch — the 64 MiB allocation succeeded first",
    unguarded.code !== 0 && unguarded.out.includes(POST_ALLOC_MSG),
    `expected exit != 0 with "${POST_ALLOC_MSG}", got exit ${unguarded.code}:\n${unguarded.out}`
  );

  // Case 4 — a plain-MessagePack vector whose value_json is not the value its
  // payload holds. Only the plain branch's value check can refuse it: the frame
  // and payload are untouched. Stripping that check must turn the run green.
  const plainDoc = JSON.parse(readFileSync(FIXTURE, "utf-8"));
  const plain = plainDoc.frame_vectors.find((v) => v.name === PLAIN_VECTOR);
  const before = JSON.stringify(plain.value_json);
  plain.value_json = { ...plain.value_json, user_id: plain.value_json.user_id + 1 };
  check("value mutation is not a no-op", JSON.stringify(plain.value_json) !== before, `value_json unchanged: ${before}`);
  const plainFixture = join(tmp, "python-frame-wrong-value.json");
  writeFileSync(plainFixture, JSON.stringify(plainDoc));
  const valued = run(TOOL, plainFixture);
  check(
    "guarded tool: a wrong value_json on a plain-MessagePack vector exits non-zero, by the value check",
    valued.code !== 0 && valued.out.includes(PLAIN_VECTOR) && valued.out.includes(VALUE_MSG),
    `expected exit != 0 naming ${PLAIN_VECTOR} with "${VALUE_MSG}", got exit ${valued.code}:\n${valued.out}`
  );
  const unchecked = source.replace(PLAIN_CHECK, "decodeDocument(parsed.payload);");
  check("value-check strip is not a no-op", unchecked !== source, "the plain branch's value check moved; fix this test's anchor");
  const uncheckedTool = join(tmp, "frame-crosscheck-unchecked.mjs");
  writeFileSync(uncheckedTool, unchecked);
  const loose = run(uncheckedTool, plainFixture);
  check(
    "stripped tool: the same fixture passes once the value check is gone (no other check refuses it)",
    loose.code === 0,
    `expected exit 0, got exit ${loose.code}:\n${loose.out}`
  );

  // Cases 5-8 — one fixture mutation each, which the tool must refuse with the
  // named guard's message: a frame vector that records no serializer name; a
  // serializer_name error vector the frame parser already rejects; a parseable
  // error vector whose rejected_by names a parser check; a serializer_name error
  // vector that parses and records a name.
  for (const [label, mutate, vector, message] of [
    [
      "a frame vector that records no serializer name",
      (d) => reheader(d.frame_vectors.find((v) => v.name === "raw_payload_frame"), ({ s, ...rest }) => rest),
      "raw_payload_frame",
      "frame header records no serializer name",
    ],
    [
      "a serializer_name error vector the frame parser rejects first",
      (d) => (d.error_vectors.find((v) => v.name === "bare_envelope_fed_to_frame_reader").rejected_by = "serializer_name"),
      "bare_envelope_fed_to_frame_reader",
      "rejected by the frame parser, not the serializer-name check",
    ],
    [
      "a parseable error vector held to a parser check",
      (d) => (d.error_vectors.find((v) => v.name === "serializer_name_missing").rejected_by = "magic"),
      "serializer_name_missing",
      "expected rejection by the magic check, parsed successfully",
    ],
    [
      "a serializer_name error vector that records a name",
      (d) => reheader(d.error_vectors.find((v) => v.name === "serializer_name_missing"), (h) => ({ ...h, s: "default" })),
      "serializer_name_missing",
      "expected rejection by the serializer-name check, parsed successfully",
    ],
  ]) {
    const mutated = JSON.parse(readFileSync(FIXTURE, "utf-8"));
    mutate(mutated);
    const path = join(tmp, "python-frame-mutated.json");
    writeFileSync(path, JSON.stringify(mutated));
    const r = run(TOOL, path);
    const line = r.out.split("\n").find((l) => l.includes(vector) && l.includes(message));
    check(`guarded tool: ${label} exits non-zero, by that guard`, r.code !== 0 && line !== undefined, `exit ${r.code}:\n${r.out}`);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (failures.length) {
  console.error(`\n${failures.length} case(s) failed:`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log("\nall frame-crosscheck guard mutation cases passed");
