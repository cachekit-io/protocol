### Conformance — cachekit-py and cachekit-ts vendor the current `wire-format.json` (LAB-10355)

- `conformance/sdks.json` reads cachekit-py at
  [`ff04061`](https://github.com/cachekit-io/cachekit-py/commit/ff040612445d9d14673b34108befb8415e21add6) and
  cachekit-ts at
  [`37a543d`](https://github.com/cachekit-io/cachekit-ts/commit/37a543d068e4b17ccae8e4244a8385991c68f1a2), the merge
  commits that re-vendor `wire-format.json` 1.4.0 after its generator note changed. Every copy in both SDKs was
  re-hashed at those commits, and only `wire-format.json` changed. `conformance/coverage.md` is regenerated, and
  neither SDK's `wire-format.json` copy reads "not the current revision" any more. No coverage status changes.
