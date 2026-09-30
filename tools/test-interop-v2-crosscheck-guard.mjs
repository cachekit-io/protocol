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
//
// It must also refuse, before allocating, a construction whose declared length
// is above the spec's limit for its field, even when the segment counts agree
// with that length.

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

// method 1, same size, literals-only: it decodes to slightly less than its
// payload, so a reader that accepts original_size <= payload_len before the
// 32-bit product passes it.
const [ext, last] = [Math.floor((n - 17) / 256), (n - 17) % 256];
const litOriginal = 15 + 255 * ext + last;
const hex32 = (x) => x.toString(16).padStart(8, "0");
const litHead = `c6${hex32(litOriginal - 5)}`;
const literalsOnly = {
  ...vector,
  original_size: litOriginal,
  container_len: n + 14,
  container_construction: [
    { hex: `c1029301ce${hex32(litOriginal)}c6${hex32(n)}f0`, count: 1 },
    { hex: "ff", count: ext },
    { hex: `${last.toString(16).padStart(2, "0")}${litHead}`, count: 1 },
    { hex: "00", count: litOriginal - 5 },
  ],
  value_construction: [
    { hex: litHead, count: 1 },
    { hex: "00", count: litOriginal - 5 },
  ],
};

// The cross-check's field limits: MAX_COMPRESSED plus the widest container
// header its parser accepts, and MAX_UNCOMPRESSED.
const LIMITS = { container_construction: 512 * 1024 * 1024 + 30, value_construction: 512 * 1024 * 1024 };
// One byte over each limit pins the boundary and the constant: a cap that is
// raised, off by one, or applied to the wrong field lets these through. At 2^50
// B, above the user address space of common 64-bit hosts, a cross-check that
// lost its cap fails in the allocator at once instead of filling gigabytes.
const HUGE = 2 ** 50;
const oversize = (field, len) => (v) => {
  if (field === "container_construction") v.container_len = len;
  else v.original_size = len;
  v[field] = [{ hex: "00", count: len }];
};
// A declared length AT the limit must get past the cap. Its segments come up
// one byte short, so the length check refuses it before anything is allocated;
// a cap that also refuses the limit itself (>= for >) fails here instead.
const AT_LIMIT_CASES = Object.keys(LIMITS);

const OVERSIZE_CASES = [
  ["container one byte over its limit", "container_construction", LIMITS.container_construction + 1],
  ["value one byte over its limit", "value_construction", LIMITS.value_construction + 1],
  ["container declared at 1 PiB", "container_construction", HUGE],
  ["value declared at 1 PiB", "value_construction", HUGE],
];

const CASES = [
  ["group dropped", (d) => { delete d.constructed_container_vectors; }],
  ["group empty", (d) => { d.constructed_container_vectors = []; }],
  ["method-0 container at the threshold", (d) => { d.constructed_container_vectors = [stored]; }],
  ["literals-only block at the threshold", (d) => { d.constructed_container_vectors = [literalsOnly]; }],
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
  for (const [name, field, len] of OVERSIZE_CASES) {
    const d = structuredClone(doc);
    oversize(field, len)(d.constructed_container_vectors[0]);
    const path = join(dir, "fixture.json");
    writeFileSync(path, JSON.stringify(d));
    const r = run(path);
    const msg = `${vector.name}.${field} declares ${len} B, above the ${LIMITS[field]} B limit`;
    check(`${name}: refused before allocating`, r.code !== 0 && r.out.includes(msg), `exit ${r.code}: ${r.out}`);
  }
  for (const field of AT_LIMIT_CASES) {
    const d = structuredClone(doc);
    const v = d.constructed_container_vectors[0];
    oversize(field, LIMITS[field])(v);
    v[field][0].count -= 1;
    const path = join(dir, "fixture.json");
    writeFileSync(path, JSON.stringify(d));
    const r = run(path);
    const msg = `${vector.name}.${field} builds ${LIMITS[field] - 1} B, expected ${LIMITS[field]} B`;
    check(`${field} declared at its limit: passes the cap`, r.code !== 0 && r.out.includes(msg), `exit ${r.code}: ${r.out}`);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

if (failures.length) {
  console.error(`\n${failures.length} guard check(s) failed:\n${failures.join("\n")}`);
  process.exit(1);
}
console.log("all interop-v2 cross-check coverage-guard cases passed");
