### SDK feature matrix — Python distributed-lock opt-out released in cachekit 0.26.0

- [`sdk-feature-matrix.md`](sdk-feature-matrix.md), **Distributed locking**: the Python cell records the
  per-function opt-out `distributed_lock=False`, released in `cachekit` 0.26.0
  ([cachekit-py#667](https://github.com/cachekit-io/cachekit-py/pull/667)). The lock stays on by default for an async
  `@cache` miss; opting out drops cross-process stampede protection and keeps in-process single-flight and the SWR
  revalidation lease. Verified in the published 0.26.0 wheel: `DecoratorConfig.distributed_lock`, default `True`.
