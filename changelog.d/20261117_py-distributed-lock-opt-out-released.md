### SDK feature matrix — Python distributed-lock opt-out released in cachekit 0.26.0

- [`sdk-feature-matrix.md`](sdk-feature-matrix.md), **Distributed locking**: the Python cell records the
  per-function opt-out `distributed_lock=False`, released in `cachekit` 0.26.0
  ([cachekit-py#667](https://github.com/cachekit-io/cachekit-py/pull/667)). The lock stays on by default for an async
  `@cache` miss; opting out drops cross-process stampede protection and keeps in-process single-flight and the SWR
  revalidation lease. Verified in the published 0.26.0 wheel: `DecoratorConfig.distributed_lock`, default `True`.
- [`sdk-feature-matrix.md`](sdk-feature-matrix.md), **Cache stampede prevention**, Python cell: sync misses with a
  backend share one call within a process from `cachekit` 0.25.0+
  ([cachekit-py#655](https://github.com/cachekit-io/cachekit-py/pull/655)); the cell said they did not coalesce. It
  still takes no distributed lock. The async path's sharing is restated: only callers on the event loop running the
  key's call share it. Checked on the 0.24.1, 0.25.0 and 0.26.0 wheels with a 20-thread File-backend herd.
