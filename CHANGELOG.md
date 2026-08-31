# Changelog

All notable changes to the CacheKit Protocol Specification.

## [Unreleased]

### Wire format — compressed-byte reproducibility scoped per-vector (LAB-1751)

- LZ4 compressed bytes are **not canonical** across conforming block encoders.
  [`spec/wire-format.md`](spec/wire-format.md) now states this explicitly
  (new "Compressed-byte reproducibility" section, mirroring interop v2's
  doctrine): `compressed_data` conformance is read-side only, writers are
  never validated by byte-comparing compressor output against fixtures, and
  only the canonical writer (`lz4_flex` via `cachekit-core`) has enforced
  byte-reproducibility. The `large_compressible` / `large_compressible_bin`
  pair is marked **known encode-divergent, decode-verified only** under the
  spec's own reference liblz4 mapping — `lz4.block.compress(store_size=False)`
  emits a 14 B block where the fixture pins `lz4_flex`'s 15 B. Found by
  execution during the LAB-868 panel review; resolves the trust bug of a
  fixture implying a reproducibility property the reference toolchain cannot
  produce. Regeneration was rejected: every envelope-using SDK compresses
  through `cachekit-core`'s `lz4_flex` (`cachekit-rs` writes plain MessagePack
  with no envelope — spec 'Per-SDK'), whose CI asserts re-encode byte-identity, so
  re-pinning to liblz4 output would break the canonical writer and merely swap
  which compressor diverges.
- [`tools/wire-format-reference.py`](tools/wire-format-reference.py) `verify`
  gains an optional `lz4` leg (the dependency was already installed in CI's
  optional-deps step): liblz4 MUST decompress every pinned `compressed_data`
  to the pinned input; encoder agreement with the pin is reported per vector
  but never asserted. The CI invocation now passes `--require-extras`
  (precedent: `encryption-verify.py --require-seal`) so a dependency drift
  cannot silently turn the deeper checks off. Fixture bytes untouched
  (version stays 1.1.1) — no downstream SDK re-vendors required.

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
