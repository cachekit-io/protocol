# Changelog

All notable changes to the CacheKit Protocol Specification.

## [Unreleased]

### SaaS API

- **`X-CacheKit-Fresh-For` remaining-freshness response header (LAB-557).**
  `GET /v1/cache/{key}` `200 OK` responses now carry the entry's remaining
  freshness in whole seconds (server-clock delta; `0` on stale-window
  responses; omitted for entries with no expiry and by pre-signal servers), so
  SDK local caches (L1) can bound backfill to `min(local_ttl, fresh_for)`
  instead of restarting the freshness clock at time-of-read — an entry read
  near the end of its server-side window could previously be served fresh from
  L1 for up to another full TTL, past `fresh_until` (and, with a stale-grace
  window, past `evict_at`). Additive and backward compatible: absent header =
  legacy behavior on both sides. Not emitted on `HEAD`. Spec:
  [saas-api.md → Remaining Freshness](spec/saas-api.md#remaining-freshness).
  Origin: CodeRabbit outside-diff finding on
  [cachekit-py#233](https://github.com/cachekit-io/cachekit-py/pull/233).

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
