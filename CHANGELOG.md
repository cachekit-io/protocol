# Changelog

All notable changes to the CacheKit Protocol Specification.

## [Unreleased]

### SaaS API

- **`X-CacheKit-Fresh-For` remaining-freshness response header (LAB-557).**
  `GET /v1/cache/{key}` `200 OK` responses now carry the entry's remaining
  freshness in whole seconds (server-clock delta; `0` on stale-window
  responses; emitted on every `GET` `200 OK` — TTL is mandatory, so a
  "no expiry" entry cannot exist; omitted only by pre-signal servers), so
  SDK local caches (L1) can bound backfill to `min(local_ttl, fresh_for)`
  instead of restarting the freshness clock at time-of-read — an entry read
  near the end of its server-side window could previously be served fresh from
  L1 for up to another full TTL, past `fresh_until` (and, with a stale-grace
  window, past `evict_at`). The header value is a hard local service bound:
  once elapsed, the local copy MUST NOT be served in any form (a `0` value
  prohibits backfill entirely) — client-side stale service of server-backed
  entries is prohibited regardless of header presence, since the client has
  no remaining-eviction signal; the server owns the stale window through
  `evict_at`. Additive and backward compatible: absent header =
  legacy behavior on both sides. Not emitted on `HEAD`. Spec:
  [saas-api.md → Remaining Freshness](spec/saas-api.md#remaining-freshness).
  Origin: CodeRabbit outside-diff finding on
  [cachekit-py#233](https://github.com/cachekit-io/cachekit-py/pull/233).
- **Second panel round on the same header (LAB-2531).** The deployment-specific
  "≤5 seconds" edge-coherence figure is dropped from the normative text — the
  deployed tiers compose to roughly double it, and the spec now states the
  general truth instead: coherence windows **compound** across composed tiers
  that re-stamp rather than decay. New in the same round: servers MUST emit
  `Cache-Control: no-store` on every response (the cache key carries no tenant,
  so byte-identical URLs across tenants make heuristic HTTP caching
  (RFC 9111 §4.2.2) a cross-tenant read; CacheKit-operated tiers MUST partition
  internal caches by tenant); `fresh` + `Fresh-For: 0` documented as legal
  (final sub-second floors to `0` — serve, don't backfill); the dead
  "no expiry" emission branch removed (it failed open into pre-signal legacy
  behavior); local deadlines SHOULD use a suspend-counting clock. The
  revocation-propagation bound names the serving path's compounded coherence
  windows as a summed term alongside the local bound, transit, and clock error
  — a re-stamping tier can hand out a pre-`DELETE` copy that was never in
  flight (CodeRabbit finding on protocol#51).

### Wire format — compressed-byte reproducibility scoped per-vector (LAB-1751)

- LZ4 compressed bytes are **not canonical** across conforming block encoders.
  [`spec/wire-format.md`](spec/wire-format.md) now states this explicitly
  (new "Compressed-byte reproducibility" section, mirroring interop v2's
  doctrine): `compressed_data` conformance is read-side only, a **non-canonical**
  writer is never judged non-conforming for differing from the pinned bytes
  (byte-comparison as a declared-divergence tripwire remains allowed), and
  only the canonical writer (`lz4_flex` via `cachekit-core`) has enforced
  byte-reproducibility. The `large_compressible` / `large_compressible_bin`
  pair is marked **known encode-divergent, decode-verified only** under the
  spec's own reference liblz4 mapping — `lz4.block.compress(store_size=False)`
  emits a 14 B block where the fixture pins `lz4_flex`'s 15 B. Found by
  execution during the LAB-868 panel review; resolves the trust bug of a
  fixture implying a reproducibility property the reference toolchain cannot
  produce. Regeneration was rejected: every envelope-using SDK compresses
  through `cachekit-core`'s `lz4_flex` (`cachekit-rs` writes plain MessagePack
  with no envelope — spec 'SDK Storage Containers (auto mode)'), whose CI asserts re-encode byte-identity, so
  re-pinning to liblz4 output would break the canonical writer and merely swap
  which compressor diverges.
- [`tools/wire-format-reference.py`](tools/wire-format-reference.py) `verify`
  gains an optional `lz4` leg (the dependency was already installed in CI's
  optional-deps step): liblz4 MUST decompress every pinned `compressed_data`
  to the pinned input; encoder agreement is asserted only as a drift
  tripwire against `LZ4_ENCODE_DIVERGENT`, never as a per-vector conformance rule. The CI invocation now passes `--require-extras`
  (precedent: `encryption-verify.py --require-seal`) so a dependency drift
  cannot silently turn the deeper checks off. Fixture bytes untouched
  (version stays 1.1.1) — no downstream SDK re-vendors required.
- Expert-panel hardening of the same verifier (crypto/protocol gate; every item
  below was reproduced by poisoning the fixture and re-run after the fix):
  - `original_size` is now checked against `len(input_hex)`, not just the
    co-located `input_size` field. Both declared sizes live *in* the file under
    test, so a regeneration bug that inflates them drifts them together and the
    old check still passed — a vector declaring 100 MB for 16 bytes of input
    verified green, and liblz4 did not catch it because
    `decompress(uncompressed_size=…)` sizes the output buffer rather than
    asserting the length. Runs on both CI legs (stdlib and optional-deps).
  - **Both** commands refuse to run under `-O`/`PYTHONOPTIMIZE`: every conformance
    check is an `assert`, so an optimised `verify` reported "all 7 vector pairs
    verified" against a poisoned fixture, and an optimised `generate` rewrote the
    fixture with its input checks stripped. The guard is at module scope, not in
    `main()`, because a CLI-only guard is bypassed by importing the module and
    calling `verify()` directly — which the regression harness's `importlib`
    probe does, and which is how the sibling tools load each other's codecs.
  - `generate` is now **append-only**: it refuses to write when the rebuild would
    drop a committed vector. It previously rebuilt `vectors` from the legacy set
    alone, so a bin vector with no legacy base was erased silently — and because
    `verify`'s orphan FAIL names `generate` as the remedy, the documented repair
    step completed the data loss. Reproduced end to end: dropping legacy
    `width_boundary_bin16` (the fleet's only bin16 coverage) left `generate`
    reporting success on a fixture two vectors smaller, with CI green.
  - `--require-extras` is rejected outside `verify` (exit 2). It was accepted and
    silently ignored on `generate`, the fixture-writing path — the same
    accepted-and-dropped fail-open the unrecognised-argument check closes.
  - Unrecognised arguments now exit 2 instead of being dropped, closing a
    fail-open in the new flag itself: `verify --require-extra` (one character
    short) exited 0 with the extras legs silently off.
  - The set of vectors liblz4 fails to reproduce on encode is pinned in
    `LZ4_ENCODE_DIVERGENT` and asserted, so a toolchain bump that changes it
    fails CI instead of quietly making the new spec section's prose wrong.
- Second expert-panel round on the remediated verifier (crypto/protocol gate
  keys off current HEAD, not "a panel ran once"). Three whole-file fail-opens,
  all reproduced by execution and all previously exit-0:
  - **The base-vector set is now pinned in code** (`EXPECTED_BASE_VECTORS`).
    Every other check iterates the fixture's own vector list and so is
    structurally blind to a vector that is simply *absent*. Dropping a legacy
    base **and** its `_bin` twin together — the realistic bad-merge shape, which
    the orphan-twin refusal does not cover — netted to zero in `generate`'s
    append-only diff: `verify` reported "all 6 vector pairs verified" and
    `generate` wrote the 12-vector fixture, both exit 0. It also silently
    disarmed `LZ4_ENCODE_DIVERGENT`, since the divergent vector was no longer
    iterated. Same lesson as `original_size`/`input_size` one level up: a name
    list derived from the artifact under test pins nothing.
  - **The fixture's declared `limits` block is now compared against the spec's
    Security Limits table.** SDKs read their bounds from that block and nothing
    pinned it either way, so a fixture rewriting `max_uncompressed_size` to `1`
    verified green while handing every downstream reader a wrong bound.
  - **A declared-divergent vector's `compressed_data` is now byte-pinned.**
    `assert diverges == (name in LZ4_ENCODE_DIVERGENT)` is a one-bit check that
    any other valid LZ4 block satisfies, so re-pinning `large_compressible` to
    an unrelated (valid, correctly-decompressing) block passed both CI legs. The
    byte-pin sits outside the optional-deps gate, so the one vector this section
    exists to document is enforced on the stdlib leg too — it has no
    canonical-writer check anywhere else in the fleet.
  - `tools/test_wire_format_reference.py` gains mutation cases for all three,
    each verified non-vacuous by deleting the guard and confirming the case
    fails. Its own invocations that can reach `generate` now run against a
    scratch mirror rather than the repo's sha256-pinned fixture — with the
    guard regressed, the suite (CI's first step) rewrote the vendored artifact.
    Exit-code-only assertions gained guard-marker checks, because python itself
    exits 2 on a bad script path and 1 on a traceback, which made an
    exit-code-only case pass vacuously.
  - Fixture-shape rejections now name the offending vector instead of exiting
    via a bare traceback.
- [`spec/wire-format.md`](spec/wire-format.md) corrections from the same panel:
  the "MUST NOT byte-compare a writer's compressor output" rule is scoped to
  **non-canonical** writers — unscoped, it forbade the `cachekit-core` re-encode
  assertions that the very next paragraph relies on as the enforcement
  mechanism, i.e. the fleet's only `lz4_flex` drift detector. The claim that
  cachekit-core enforces canonical-writer reproducibility is now scoped to the
  vectors that repo actually vendors: core pins `version == "1.1.0"`, so
  `width_boundary_bin16` (added at 1.1.1) has no **canonical-writer
  (`lz4_flex`) compressed-byte** check anywhere in the fleet, and its pinned
  xxh3-64 checksum is recomputed nowhere. The earlier phrasing — "no
  encode-side check anywhere" — was too broad and is corrected: this repo's
  verifier does assert that vector's legacy and bin re-encode byte-identity on
  every run, and liblz4 reproduces its compressed bytes on the optional leg. The
  spec also now names what re-vendoring 1.1.1 into cachekit-core actually
  requires: bump `FIXTURE_SHA256`, bump the version pin, **and** relax
  `assert_eq!(twin_bytes[1], 0xc4)` to accept `0xc5` — that assertion demands
  every twin be bin8, and `width_boundary_bin16_bin` is bin16, so a drop-in
  re-vendor fails it. A remedy that fails on contact leaves the gap open longer.

### Interop v2 — compressed-values profile (DRAFT)

- New [`spec/interop-v2.md`](spec/interop-v2.md) (LAB-1135, protocol#52):
  opt-in successor mode restoring the 2025-11-14 RFC's descoped
  compressed+encrypted cross-SDK values. Values wrap in a `0xC1 0x02` +
  msgpack `[method, original_size, payload:bin]` container (LZ4 block or
  uncompressed), carried **inside** AES-256-GCM with a constant
  four-component AAD reusing the frozen `"True"` token — deterministic
  pre-AAD mode discrimination by configuration, no sniff-and-retry, and
  cryptographic v1/v2 separation (cross-mode reads fail authentication).
  Ships with a stdlib-only reference generator
  ([`tools/interop-v2-reference.py`](tools/interop-v2-reference.py),
  including a pure-Python LZ4 block codec), a zero-dependency independent
  JS cross-check ([`tools/interop-v2-crosscheck.mjs`](tools/interop-v2-crosscheck.mjs)),
  and [`test-vectors/interop-v2.json`](test-vectors/interop-v2.json)
  (compressed, uncompressed, and non-canonical-widths round-trips,
  compressed+encrypted round-trip, 16 structural + 2 cryptographic
  must-reject vectors). Security limits
  reuse the wire-format constants (512 MiB / 1000:1, enforced before
  decompression); the CRIME/BREACH verdict is recorded in-spec (in threat
  model, accepted with normative mitigations); the legacy array-of-ints
  payload leniency is explicitly **not** inherited. Interop/v1 is
  byte-for-byte untouched — its vectors and tools run unchanged beside the
  new ones in CI. Status DRAFT until the vectors run in cachekit-py/ts/rs CI.

### SDK Feature Matrix

- Consolidated ten conflicting open matrix PRs into one code-verified end-state
  (LAB-1400), regenerated from current SDK code rather than from the stale PR
  diffs. Cells that **reversed** — check these if you built on them: key
  rotation (py/rs ✅ → ❌ fleet-wide; `rotate_key()` is a `NotImplemented`
  stub, and cachekit-py's importable PyO3 `KeyRotationState` succeeds while
  rotating nothing), Rust `::secure` preset and Rust sync support (both ✅ →
  never existed), Builder API (py/ts ✅ → ❌), hardware-acceleration detection
  (rs ✅ → not re-exported; ts N/A → ❌), TypeScript Arrow (🔜 → ❌), and
  Python's encrypted read path (documented fail-closed → **fail-open by
  default**), and `cache.secure.wrap()` in TypeScript (implied encryption → no
  guarantee at all; LAB-513, CWE-311). New rows: Retry, Graceful degradation,
  Cross-instance L1 invalidation (LAB-520), client-L1 stale-while-revalidate
  (LAB-728), Orjson serializer, tamper/wrong-key failure mode, `secure`-API
  enforcement, plus an Observability section (LAB-275). Supersedes protocol#25,
  #28, #29, #31, #32, #33, #35, #37, #40, #43 — per-PR fold verdicts below.

- **Every version-keyed claim re-verified against published artifacts**, after an
  expert-panel review found the first pass had introduced two new false cells of
  the very class it was fixing. `cachekit-rs` 0.6.0 published 74 minutes before
  that pass's final commit, so six Rust reliability cells shipped marked 🚧
  unreleased when the tier was in fact released and **on by default**; and
  "cachekit-ts ships the protocol-1.1 `bin` flip as of 0.1.5" was false —
  published `@cachekit-io/cachekit@0.1.5` carries dependency pins byte-identical
  to 0.1.4's, on `cachekit-core-ts@0.1.2` (native addons embed core **0.2.0**)
  and `cachekit-core-wasm@0.1.1` (core **0.3.0**), so TypeScript emits legacy on
  both paths. The matrix now carries a per-artifact rollout table with the
  embedded-core evidence, and the method is recorded in
  [decisions/matrix-version-verification.md](decisions/matrix-version-verification.md):
  registry metadata establishes which artifact is current, and where an embedded
  dependency decides the claim the `.crate`/`.tgz` is opened. Versions in the SDK
  Overview are now floors (`X+`), enforced by
  [`tools/check-version-floors.py`](tools/check-version-floors.py) in `verify.yml`
  — four failures of this one mechanical class in six weeks.

- Footnote namespace repaired: markers `¹`–`⁴` were each defined **twice** with
  unrelated content (Cache Backends and Protocol Compliance), so half the
  evidence pointers in the file resolved to the wrong note — including the
  "version cells are floors" note. The Protocol Compliance block is now `¹⁴`–`¹⁷`
  and every marker is defined exactly once.

#### Per-PR fold verdicts (LAB-1400)

| PR | Ticket | Verdict |
| :--- | :--- | :--- |
| [#25](https://github.com/cachekit-io/protocol/pull/25) | LAB-423 | Incorporated — `spec/wire-format.md` lacked the CI-enforcement note; both enforcement points now named |
| [#28](https://github.com/cachekit-io/protocol/pull/28) | LAB-274 | Incorporated incl. the intent-preset semantics table; rejected its stale "rs has no circuit breaker" line |
| [#29](https://github.com/cachekit-io/protocol/pull/29) | LAB-275 | Partly incorporated (key rotation, hardware accel, Observability, serializer rows, MSRV 1.85); versions / ts-Workers / rs-stampede / interop claims rejected as stale |
| [#31](https://github.com/cachekit-io/protocol/pull/31) | LAB-520 | Incorporated as-is |
| [#32](https://github.com/cachekit-io/protocol/pull/32) | LAB-426 | Incorporated — rs Workers locking + TTL was still missing from `main` |
| [#33](https://github.com/cachekit-io/protocol/pull/33) | LAB-427 | Already on `main`; would have reintroduced a stale rs-Redis-lock ❌ |
| [#35](https://github.com/cachekit-io/protocol/pull/35) | LAB-518 | Incorporated; rejected its "backpressure stays ❌" line (LAB-729) |
| [#37](https://github.com/cachekit-io/protocol/pull/37) | LAB-430 | Already on `main`; same stale-cell problem as #33 |
| [#40](https://github.com/cachekit-io/protocol/pull/40) | LAB-751 | Incorporated — `main` still claimed "SWR forced off" on Workers |
| [#43](https://github.com/cachekit-io/protocol/pull/43) | LAB-728 | Incorporated; extended the py cell, which understated its gate (needs an explicit `ttl=`) |
| [#17](https://github.com/cachekit-io/protocol/pull/17) | — | Out of scope, left open |

### Specs

- StorageEnvelope `compressed_data` canonical encoding flipped from MessagePack
  array-of-ints to `bin` (LAB-783 /
  [cachekit-core#54](https://github.com/cachekit-io/cachekit-core/issues/54)):
  protocol 1.1+ writers MUST emit `bin`; readers MUST accept both encodings
  permanently. **Not a breaking change** — dual-read is mutual in both directions
  under rmp-serde, toolchain-verified; no version field or discriminator.
  `checksum` stays array-of-ints; `format` untouched. Tiny envelopes may grow
  ≤ +1 B; incompressible payloads shrink ~35%. Rationale, evidence, and rollout
  order in [decisions/envelope-bin-encoding.md](decisions/envelope-bin-encoding.md).

- Key rotation specified (not yet implemented, LAB-516): client-side keyring —
  one forward-only current key plus ≤3 decrypt-only master keys; fingerprint-based
  key selection where per-entry identity exists (cachekit-py frames), sequential
  same-AAD attempts elsewhere; no wire change. Retires the never-written 32-byte
  `RotationAwareHeader` from the spec. Rationale, rejected options, and operator
  runbooks in [decisions/key-rotation.md](decisions/key-rotation.md).

- Interop mode promoted from draft to specified (interop/v1): flat canonical argument
  array (named→positional binding), number canonicalization (integral float64 → int,
  the only rule implementable in JS), code-point map-key ordering, encoded-byte set
  ordering (with post-normalization dedupe), bit-deterministic datetime rule (floor
  toward −∞, pre-epoch supported), full-string segment validation, canonical
  (shortest-form) MessagePack encoding, plain-MessagePack value format, unchanged
  AAD v0x03. Design rationale recorded in the spec's Design Decisions section.
  ([#1](https://github.com/cachekit-io/protocol/issues/1))

### Test Vectors

- 7 legacy/`bin` vector pairs in `test-vectors/wire-format.json` (append-only;
  legacy vectors are retained forever as legacy-read proof; fixture
  1.0.0 → 1.1.1). The original six `bin` twins were generated by the stdlib-only
  `tools/wire-format-reference.py` and byte-verified against rmp-serde output;
  `verify` now runs in CI (stdlib pass + `msgpack` third-encoder conformance) —
  the wire-format fixture's first protocol-side CI verification.

- 33 interop key vectors (including every `*16`-tier MessagePack width boundary),
  4 value vectors, 1 AAD vector, 1 full HKDF→AES-256-GCM encryption round-trip
  vector, and 9 must-reject error vectors (`test-vectors/interop-mode.json`).
  Generated by a stdlib-only Python reference implementation
  (`tools/interop-reference.py`), byte-verified by an independent JavaScript encoder
  using `@noble/hashes` (`tools/interop-crosscheck.mjs`), and decrypt-verified via
  Node WebCrypto; both checks run in CI (`.github/workflows/verify.yml`).

## [1.0.0] - 2026-03-28

Initial protocol specification.

### Specs

- Cache key format (Blake2b-256, MessagePack argument normalization)
- Wire format (ByteStorage envelope: LZ4 + xxHash3-64)
- Encryption (AES-256-GCM, HKDF-SHA256, AAD v0x03, deterministic nonce)
- SaaS REST API (endpoints, headers, error codes)
- SDK feature matrix (Python, Rust, TypeScript, PHP)

### Test Vectors

- 10 canonical cache key vectors from Python reference implementation

### Draft

- Interop mode for cross-SDK cache sharing

### Notes

- 7 discrepancies between original RFC and implementation resolved in favor of implementation
