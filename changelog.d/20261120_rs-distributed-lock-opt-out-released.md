### SDK feature matrix — Rust distributed-lock opt-out released in cachekit-rs 0.14.0

- [`sdk-feature-matrix.md`](sdk-feature-matrix.md), **Cache stampede prevention**: the Rust cell records the
  per-function opt-out `#[cachekit(distributed_lock = false)]`, released in `cachekit-rs` 0.14.0
  ([cachekit-rs#201](https://github.com/cachekit-io/cachekit-rs/pull/201)). The fill lock stays on by default; opting
  out sends no lock or unlock request on a cold miss, keeps the in-process gate, and lets processes that miss one key
  together each run the function. The SWR background refresh keeps its lock. Verified in the published 0.14.0
  `cachekit-macros` crate: `MacroArgs.distributed_lock`, default `true`.
