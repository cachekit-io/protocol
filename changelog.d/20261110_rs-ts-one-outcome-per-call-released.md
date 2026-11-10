### SDK feature matrix — one outcome per wrapped call released in cachekit-rs 0.13.1 and npm 0.2.2

- [`sdk-feature-matrix.md`](sdk-feature-matrix.md), **SaaS session telemetry headers**: the Rust and TypeScript
  cells drop their ⚠️ notes. `cachekit-rs` 0.13.1, with `cachekit-macros` 0.13.1, is the first release where a
  `#[cachekit]` call counts one outcome ([API-76](spec/saas-api.md#api-76),
  [cachekit-rs#196](https://github.com/cachekit-io/cachekit-rs/pull/196)); `@cachekit-io/cachekit` 0.2.2 is the
  first where a `wrap()` call does ([cachekit-ts#265](https://github.com/cachekit-io/cachekit-ts/pull/265)). Both
  verified in the published `.crate` and `.tgz`; 0.13.0 and 0.2.1 count the reads inside the call instead.
