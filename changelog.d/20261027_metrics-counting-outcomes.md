### SaaS API — what one hit and one miss mean in the metrics headers

- [`spec/saas-api.md` § Counting outcomes](spec/saas-api.md#counting-outcomes) (new, under
  Optional Metrics Headers) defines the `X-CacheKit-L1-Hits` / `L2-Hits` / `Misses`
  counters: a plain read counts one outcome by the layer that served it, or one miss
  ([API-75](spec/saas-api.md#api-75)); a wrapped call counts one outcome however many
  reads it makes: one miss when it runs the function, counted before its write-after-miss,
  otherwise one hit by the serving layer, and one L1 hit for a caller that joined another
  in-process call ([API-76](spec/saas-api.md#api-76)); the reads inside a wrapped call
  (first read, single-flight re-polls, lock re-checks) count nothing
  ([API-77](spec/saas-api.md#api-77)). cachekit-py's decorators already count this way.
- [`sdk-feature-matrix.md` § Observability](sdk-feature-matrix.md#observability): the
  telemetry-headers row records the released Rust (through 0.13.0) and TypeScript (through
  npm 0.2.1) over-counts, with their fixes
  ([cachekit-rs#196](https://github.com/cachekit-io/cachekit-rs/pull/196),
  [cachekit-ts#265](https://github.com/cachekit-io/cachekit-ts/pull/265)).
