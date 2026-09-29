#!/usr/bin/env node
// Mutation tests for the ratio-width coverage guard in interop-v2-crosscheck.mjs.
// Zero dependencies. Run: node tools/test-interop-v2-crosscheck-guard.mjs
//
// The cross-check must refuse a fixture in which no constructed vector fails a
// reader that computes the ratio product in 32 bits. Otherwise it passes a
// 32-bit reader's suite. Same evidence convention as
// test-frame-crosscheck-guard.mjs: a baseline pins exit 0, each poisoned copy
// must exit non-zero with the guard's own message, and every mutation is
// checked for no-op-ness.

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const TOOL = join(HERE, "interop-v2-crosscheck.mjs");
const FIXTURE = join(HERE, "..", "test-vectors", "interop-v2.json");
const GUARD_MSG = "no vector fails a reader computing the ratio product in 32 bits";

const doc = JSON.parse(readFileSync(FIXTURE, "utf8"));
const vector = doc.constructed_container_vectors[0];
const n = vector.payload_len;

// method 0, same size: a stored bin32 of zeros. Valid, and it never reaches the
// ratio bound, so a 32-bit reader passes it.
const valueHead = `c6${(n - 5).toString(16).padStart(8, "0")}`;
const stored = {
  ...vector,
  method: 0,
  original_size: n,
  container_len: n + 14, // 2 magic+version, 1 fixarray, 1 method, 5 uint32, 5 bin32 header
  // c1 02 | 93 | method 0 | uint32 original_size | bin32 payload length | value
  container_construction: [
    { hex: `c1029300ce${n.toString(16).padStart(8, "0")}c6${n.toString(16).padStart(8, "0")}${valueHead}`, count: 1 },
    { hex: "00", count: n - 5 },
  ],
  value_construction: [
    { hex: valueHead, count: 1 },
    { hex: "00", count: n - 5 },
  ],
};

const CASES = [
  ["group dropped", (d) => { delete d.constructed_container_vectors; }],
  ["group empty", (d) => { d.constructed_container_vectors = []; }],
  ["method-0 container at the threshold", (d) => { d.constructed_container_vectors = [stored]; }],
];

const dir = mkdtempSync(join(tmpdir(), "iv2-guard-"));
const run = (path) => {
  const r = spawnSync(process.execPath, [TOOL, path], { encoding: "utf-8" });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};
const failures = [];
const check = (name, cond, detail) => {
  console.log(`  [${cond ? "ok" : "FAIL"}] ${name}`);
  if (!cond) failures.push(`${name}: ${detail}`);
};

try {
  const base = run(FIXTURE);
  check("baseline exits 0", base.code === 0, base.out);
  for (const [name, mutate] of CASES) {
    const d = structuredClone(doc);
    mutate(d);
    check(`${name}: mutation is not a no-op`, JSON.stringify(d) !== JSON.stringify(doc), "fixture unchanged");
    const path = join(dir, "fixture.json");
    writeFileSync(path, JSON.stringify(d));
    const r = run(path);
    check(`${name}: guard fires`, r.code !== 0 && r.out.includes(GUARD_MSG), `exit ${r.code}: ${r.out}`);
    // The poisoned copy must fail ONLY on coverage, or the guard is not what caught it.
    check(`${name}: nothing else fails`, (r.out.match(/^FAIL /gm) ?? []).length === 1, r.out);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

if (failures.length) {
  console.error(`\n${failures.length} guard check(s) failed:\n${failures.join("\n")}`);
  process.exit(1);
}
console.log("all interop-v2 cross-check coverage-guard cases passed");
