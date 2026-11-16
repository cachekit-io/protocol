### SDK feature matrix and conformance — cachekit-core's one-pass envelope read, and the envelope pre-scan gap text

- [`sdk-feature-matrix.md`](sdk-feature-matrix.md), **Wire format (ByteStorage)**, Rust: on `main`, unreleased
  (the crates.io 0.7.4 `.crate` lacks it), `cachekit-core` reads an envelope in the shape `store` writes in one
  bounded pass ([cachekit-core#150](https://github.com/cachekit-io/cachekit-core/pull/150)). That pass holds the
  same decode bounds and accepts only what the pre-scan plus typed decode accept, into the same fields; every other
  input, every reject included, still takes the pre-scan and typed decode and gets the same error.
- [`conformance/requirements.json`](conformance/requirements.json) and the regenerated
  [`conformance/coverage.md`](conformance/coverage.md): the [WIRE-8](spec/wire-format.md#wire-8) and
  [WIRE-9](spec/wire-format.md#wire-9) gap texts no longer say that no released `cachekit-core` pre-scans the
  envelope. That has been false since crates.io 0.7.0
  ([cachekit-core#80](https://github.com/cachekit-io/cachekit-core/pull/80)), whose envelope read refuses an envelope
  that breaks either bound with its pre-scan's own error.
