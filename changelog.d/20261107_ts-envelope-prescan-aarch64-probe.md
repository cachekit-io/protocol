### SDK feature matrix — TypeScript envelope pre-scan and aarch64 AES probe released in npm 0.2.2

- [`sdk-feature-matrix.md`](sdk-feature-matrix.md): `@cachekit-io/cachekit` 0.2.2 is the first release that
  pins `cachekit-core-ts` 0.2.1 and `cachekit-core-wasm` 0.2.1, and all five platform `.node` binaries and the
  `.wasm` of those bindings embed `cachekit-core` 0.7.2 (`strings`, 2026-11-07). npm 0.2.1 pins the 0.2.0
  bindings, which embed core 0.6.0.
- **Wire format (ByteStorage)**, TypeScript: the envelope pre-scan exception is closed since 0.2.2, and the
  "🚧 unreleased — compliant on `main`" clause is gone. The cell stays ⚠️ because the allocation bound for the
  size-cap and ratio vectors is still unasserted in cachekit-ts.
- **Test vectors in CI**, TypeScript: every `decode-bounds.json` vector runs through both `unpack` bindings
  since 0.2.2 ([cachekit-ts#245](https://github.com/cachekit-io/cachekit-ts/pull/245)), no longer 🚧.
- **Hardware acceleration detection**, TypeScript, and note ⁶: 0.2.2+ probes the Armv8 Crypto Extension on
  aarch64; 0.2.1 reports `true` on every aarch64 build.
