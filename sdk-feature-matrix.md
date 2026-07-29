**[Protocol](README.md)** > **SDK Feature Matrix**

<div align="center">

# SDK Feature Matrix

**Feature parity and compliance status across all CacheKit SDK implementations.**

*Last updated: 2026-07-28 — LAB-998: interop/v1 ship-status corrected — the row no longer reads `unreleased`; all three SDKs have published it (PyPI 0.14.0+, crates.io 0.4.0+, npm 0.1.3+), stated as floors per footnote ⁴, aligned with docs.cachekit.io (LAB-996). LAB-729: rs backpressure flipped ❌ → ✅ (semaphore + bounded queue in the rs reliability stack; decision footnote records why the LAB-519 ts rationale doesn't transfer to tokio). LAB-430 shipped TypeScript Node-only Memcached and File backends; the protocol-owned File format and vectors now define fail-closed flag negotiation. LAB-446: Python File backend gains full TTL inspection/refresh; Memcached gains `refresh_ttl` (touch) only (see [TTL management note](#reliability-features)). LAB-595 shipped: ts Cloudflare Workers flipped ❌ → ✅ via the `@cachekit-io/cachekit/workers` entrypoint on a wasm32 cachekit-core build (~55 KB gz measured); footnote ¹ records the phase-1 surface and semantics deltas. LAB-519: ts cold-miss single-flight (in-process, always on) + LockableBackend wired into `wrap()`'s miss path (opt-in); ts backpressure decision recorded; ts Redis lock/TTL capability cells refreshed for LAB-427. LAB-272 code-verified protocol-adherence audit (2026-07-22): interop/v1 merged in Python ([cachekit-py#220](https://github.com/cachekit-io/cachekit-py/pull/220)), TypeScript ([cachekit-ts#71](https://github.com/cachekit-io/cachekit-ts/pull/71)), and Rust ([cachekit-rs#33](https://github.com/cachekit-io/cachekit-rs/pull/33)); test-vector CI coverage corrected*

</div>

---

## Table of Contents

- [SDK Overview](#sdk-overview)
- [Core Features](#core-features)
- [Encryption](#encryption)
- [Cache Backends](#cache-backends)
- [Backend Abstraction](#backend-abstraction)
- [Reliability Features](#reliability-features)
- [Developer Experience](#developer-experience)
- [Protocol Compliance](#protocol-compliance)
- [Architecture Notes](#architecture-notes)

---

## SDK Overview

| SDK | Package | Version | Language | Status |
| :--- | :--- | :---: | :--- | :---: |
| cachekit-py | `cachekit` (PyPI) | 0.12.0 | Python 3.10+ | ✅ Production |
| cachekit-rs | `cachekit-rs` (crates.io) | 0.3.0 | Rust 1.82+ | ✅ Production |
| cachekit-core | `cachekit-core` (crates.io) | 0.3.0 | Rust (shared core) | ✅ Production |
| cachekit-ts | `@cachekit-io/cachekit` (npm) | 0.1.2 | TypeScript | ✅ Production |
| cachekit-php | — | — | PHP 8.1+ | 🔜 Development |

---

## Core Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| StandardSerializer (MessagePack) | ✅ | ✅ via rmp-serde | ✅ | 🔜 Planned |
| AutoSerializer (Python-specific) | ✅ | N/A | N/A | N/A |
| ArrowSerializer (columnar) | ✅ | N/A | 🔜 Planned | ❌ |
| ByteStorage (LZ4 + xxHash3-64) | ✅ via Rust FFI | ✅ canonical (cachekit-core) | ✅ via NAPI (Rust) | 🔜 Planned |
| Blake2b-256 key generation | ✅ | N/A | ✅ via @noble/hashes | 🔜 Planned |

---

## Encryption

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| AES-256-GCM | ✅ via Rust FFI | ✅ ring (native) / aes-gcm (wasm32) | ✅ via NAPI (Rust) | 🔜 Planned |
| HKDF-SHA256 key derivation | ✅ via Rust FFI | ✅ | ✅ via NAPI (Rust) | 🔜 Planned |
| Per-tenant key isolation | ✅ | ✅ | ✅ via TenantKeys NAPI | 🔜 Planned |
| AAD v0x03 (cache_key binding) | ✅ | ✅ | ✅ | ❌ |
| Key rotation | ✅ | ✅ | ❌ | ❌ |
| Hardware acceleration detection | ✅ | ✅ | N/A | N/A |
| Counter-based nonces | ✅ via Rust | ✅ | ✅ via NAPI (Rust) | ❌ use random |

> [!IMPORTANT]
> AAD v0x03 is required for protocol compliance. SDKs without it cannot safely interoperate with encrypted payloads from compliant SDKs — the auth tag will fail verification. Python, Rust, and TypeScript construction was code-verified byte-identical on 2026-07-21 (LAB-272); the normative byte layout and the frozen `True`/`False` compressed tokens (protocol#12) are defined in [spec/encryption.md](spec/encryption.md#additional-authenticated-data-aad). Python's auto serializers append the optional `original_type` fifth component; Rust, TypeScript, and interop mode always emit exactly four. Python's read path fails closed when encryption is enabled but a stored entry claims plaintext ([cachekit-py#215](https://github.com/cachekit-io/cachekit-py/pull/215)).

---

## Cache Backends

| Backend | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Redis (direct) | ✅ `backends/redis` (redis-py, required dep) | ✅ `redis` feature (fred) | ✅ `backends/redis.ts` (ioredis) | ❌ |
| Memcached | ✅ `backends/memcached` (`memcached` extra) | ✅ `memcached` feature (rust-memcache)³ | ✅ `backends/memcached.ts` (optional `memjs` peer; Node-only)⁴ | ❌ |
| File (local) | ✅ `backends/file` (stdlib + mmap) | ✅ `file` feature (byte-compatible with py)³ | ✅ `backends/file.ts` (Node-only; [format](spec/file-backend-format.md))⁴ | ❌ |
| CacheKit SaaS (HTTP) | ✅ `backends/cachekitio` (httpx) | ✅ `cachekitio` feature (reqwest, default) | ✅ `backends/cachekitio.ts` (fetch) | 🔜 Planned |
| Cloudflare Workers | N/A | ✅ `workers` feature (`worker::Fetch`) | ✅ `@cachekit-io/cachekit/workers` (wasm32 core)¹ | N/A |
| DynamoDB | ❌² | ❌ | ❌ | ❌ |

> ¹ Shipped in LAB-595 (2026-07-24), following spike LAB-431's GO verdict: the `@cachekit-io/cachekit/workers` subpath (also the `workerd` condition on the root export) runs crypto and the ByteStorage envelope on a **wasm32 build of cachekit-core** (`@cachekit-io/cachekit-core-wasm`, 137 KB raw / ~55 KB gzipped + ~10 KB JS glue, wasm-bindgen `--target web` + wasm-opt `-Oz`) — counter nonces and the envelope carry over unchanged and the crypto stays single-touchpoint in the Rust core; byte-verified against the Python-ground-truth `test-vectors/encryption.json` and `wire-format.json` suites inside real workerd. Phase-1 surface: CachekitIO backend (pure `fetch`) or a custom `Backend` instance; Redis-URL intents, Redis Pub/Sub invalidation, and Prometheus metrics stay Node-only and are excluded from the edge bundle (CI-guarded: no `node:*`, no NAPI, no ioredis/prom-client — no `nodejs_compat` flag needed); SWR background refresh is forced off (fire-and-forget refreshes aren't tied to `ctx.waitUntil` yet and workerd cancels them at response return). Semantics delta: keys live in wasm linear memory (a host-readable ArrayBuffer), weaker isolation than NAPI's Rust heap but ~JS-heap-equivalent on Workers where the host is your own isolate; zeroized deterministically on `dispose()`. WebCrypto (AES-256-GCM + HKDF-SHA256, random-nonce fallback per [encryption.md → Nonce Generation](spec/encryption.md#nonce-generation)) remains the documented fallback if the wasm path ever hits a wall.
>
> ² DynamoDB has never shipped in any SDK. The previous Python ✅ traced to the [custom-backend tutorial](https://github.com/cachekit-io/cachekit-py/blob/main/docs/backends/custom.md), which shows how a *user* can implement the backend protocol against DynamoDB — that is an extension point, not shipped support (LAB-273).

>
> ³ Added 2026-07-24 (LAB-429). Both are cargo features on cachekit-rs (`--features memcached` / `--features file`), native targets only (compile-error guarded against `workers`). The rs File backend shares py's on-disk format — Blake2b-128 hashed filenames, the 14-byte `CK` header, atomic write-then-rename, lazy expiry — verified by running the actual py `FileBackend` against an rs-written directory and vice versa. Not yet ported from py: LRU eviction/size caps and the mmap buffer read. rs Memcached is single-server (py's `HashClient` shards across servers); CI exercises it against a live memcached 1.6 container.

> ⁴ Added 2026-07-25 (LAB-430). TypeScript exposes these Node-only backends only through subpath exports, keeping `memjs` optional and `node:fs` out of browser and edge bundles. File implements full `TTLBackend`; Memcached deliberately offers refresh-only `touch`, not `TTLBackend`, because it cannot inspect remaining TTL. File names and headers follow [spec/file-backend-format.md](spec/file-backend-format.md); unknown reserved or flag values are misses preserved for a newer reader.

**Backend selection / env auto-detection:** Python is the only SDK that auto-detects *which* backend to use from the environment — a single unambiguous selector (`CACHEKIT_API_KEY` → SaaS, `CACHEKIT_REDIS_URL` → Redis, `CACHEKIT_MEMCACHED_SERVERS` → Memcached, `CACHEKIT_FILE_CACHE_DIR` → File; fallback `REDIS_URL` / localhost Redis; setting more than one selector raises `ConfigurationError`). Rust `CacheKit::from_env()` reads SaaS credentials only (`CACHEKIT_API_KEY` / `CACHEKIT_API_URL` / `CACHEKIT_MASTER_KEY` / `CACHEKIT_DEFAULT_TTL`) and always builds the CachekitIO backend — Redis/Memcached/File are wired explicitly via `.backend()`. TypeScript has no backend auto-detection: each preset fixes the backend type and env vars (`CACHEKIT_API_KEY`, `CACHEKIT_MASTER_KEY`) serve only as credential fallbacks. Whether rs/ts should gain selector-style auto-detection is an open product question, not a recorded decision (LAB-273 finding).

---

## Backend Abstraction

The contract a storage backend must satisfy per SDK (bytes in / bytes out; serialization and encryption live above the backend). Audited against code 2026-07-20 (LAB-273).

### Required interface

| Aspect | Python (`BaseBackend`) | Rust (`Backend`) | TypeScript (`Backend`) |
| :--- | :--- | :--- | :--- |
| Form | PEP 544 structural protocol, `@runtime_checkable` | `#[async_trait]`, `Send + Sync` (auto `?Send` on wasm32 / `unsync` feature) | interface (structural) |
| Core ops | `get` / `set` / `delete` / `exists` | `get` / `set` / `delete` / `exists` | `get` / `set` / `delete` / `exists` |
| Health check | ✅ `health_check() -> (bool, details)` required | ✅ `health() -> HealthStatus` required | ❌ not in the interface (SaaS backend has an internal check) |
| Lifecycle | — | — | ✅ `close()` required |
| Interop key-prefix guard | — | — | ✅ optional `readonly keyPrefix` (interop mode fails closed on hidden prefixes) |

### Optional capabilities — and which shipped backends implement them

| Capability | Python | Rust | TypeScript |
| :--- | :--- | :--- | :--- |
| TTL inspect / refresh | `TTLInspectableBackend` — Redis ✅, SaaS ✅, File ✅, Memcached ⚠️ `refresh_ttl` only (LAB-446) | `TtlInspectable` — Redis ✅, SaaS ✅, File ✅, Memcached ⚠️ `refresh_ttl` only (LAB-429) | `TTLBackend` — Redis ✅, SaaS ✅ (`TTLCachekitIO`), File ✅; Memcached ⚠️ `refreshTTL` only (LAB-430) |
| Distributed locking | `LockableBackend` — Redis ✅ (`redis.lock.Lock`), SaaS ✅ | `LockableBackend` — SaaS ✅, Redis ✅ (`SET NX PX` + Lua compare-and-delete, `<key>:lock` namespace shared with py; LAB-426), Workers ❌ | `LockableBackend` — Redis ✅ (LAB-427), SaaS ✅ (`LockableCachekitIO`) |
| Per-operation timeout | `TimeoutConfigurableBackend` — Redis ✅ (SaaS ships a non-protocol `with_timeout` variant) | — no equivalent | — no equivalent |
| Zero-copy buffer read | `BufferReadableBackend` / `BufferHandle` — File ✅ (mmap; #171) | — no equivalent | — no equivalent |

> [!NOTE]
> **Lock API shape divergence:** Python's `acquire_lock` is an async context manager yielding `bool` — the lock token stays internal and release is automatic. Rust and TypeScript return the raw `lock_id` capability token from `acquire_lock`/`acquireLock` and require an explicit `release_lock(key, lock_id)` — a direct mirror of the SaaS lock endpoint. All three pass the **bare cache key** (backends own any `:lock` namespace derivation). Porting a lockable backend across SDKs must bridge this shape difference.
>
> **Coverage, not shape, is the parity gap:** all three SDKs use the same required-base + optional-capability pattern, and Python, Rust, and TypeScript all cover Redis locking plus TTL inspection. Rust's Workers backend lacks both despite speaking the same SaaS API (gap tickets under LAB-102).

---

## Reliability Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Circuit breaker | ✅ | ❌ | ✅ | ❌ |
| Backpressure | ✅ | ✅ Semaphore + bounded queue, decision recorded (LAB-729) | ⚠️ Refresh cap only — deliberate, decision recorded (LAB-519) | ❌ |
| Distributed locking | ✅ Redis + SaaS backends | ✅ Redis + SaaS (`LockableBackend`; LAB-426. Workers lacks an impl) | ✅ Redis + SaaS backends; wired into `wrap()` cold miss (opt-in `stampede.distributedLock`, LAB-519) | ❌ |
| L1/L2 dual-layer cache | ✅ | ✅ moka (native) / `l1` feature | ✅ | ❌ |
| Cache stampede prevention | ✅ | ❌ | ✅ Cold-miss single-flight + SWR version tokens (LAB-519) | ❌ |
| TTL management | ✅ Redis + SaaS + File; Memcached refresh-only (see note) | ✅ Redis + SaaS + File (`TtlInspectable`); Memcached refresh-only (LAB-429) | ✅ Redis + SaaS + File (`TTLBackend`); Memcached refresh-only (LAB-430) | ❌ |
| Stale-while-revalidate (server stale-grace) | 🚧 LAB-381 | ❌ | ❌ | ❌ |

> **Lock id transport (CWE-532):** the unlock call carries the lock capability token in the `X-CacheKit-Lock-Id` request header, never the `?lock_id=` query string (which leaks via access/proxy logs and OTel `http.url` spans). **Migration complete in all three SDKs** (verified 2026-07-20, LAB-273): Python (#131, closed), Rust (#24, closed), TypeScript ships the header (ts#63 remains open only for an unrelated NAPI-rebuild item). SaaS dual-reads both during the rollout window. See [spec/saas-api.md](spec/saas-api.md#delete-v1cachekeylock).
>
> **TypeScript backpressure decision (LAB-519):** general admission control beyond L1's `maxConcurrentRefreshes` was evaluated and declined. On Node's single-threaded event loop concurrent misses don't compete for threads, cold-miss single-flight collapses the per-key herd (the amplification vector metered-misses punishes), and distinct-key miss floods are bounded by backend timeouts plus the circuit breaker — a global miss semaphore would add queueing latency and a tuning knob without a failure mode it prevents. Revisit only with evidence of backend connection exhaustion. Full rationale on `StampedeConfig` in cachekit-ts.
>
> **Rust backpressure decision (LAB-729):** built — parity with Python's `reliability/load_control.py`, not net-new. The LAB-519 event-loop rationale does not transfer: Node's single event loop bounds nothing here either, but ts declined on herd-shape grounds specific to its stack, while in cachekit-rs a tokio runtime (multi-threaded or single-threaded `unsync` alike) will happily hold unbounded concurrent backend ops in flight — `fred`'s single multiplexed Redis connection buffers unbounded in-flight commands (caller memory), and the `reqwest` SaaS client grows per-host connections without cap (socket/FD exhaustion) — exactly the failure modes backpressure sheds. Shape: `tokio::sync::Semaphore` as the outermost layer of the `ReliableBackend` stack (`backpressure(breaker(retry(op)))`) — one permit per logical operation held across the whole retry sequence, so retry amplification is bounded and shed calls never skew breaker state. Over-limit calls wait in a bounded queue (max 1 000) up to 100 ms, then fail with the typed, non-retryable `BackendErrorKind::Backpressure` — never an unbounded silent queue. Defaults mirror Python (100 concurrent / 1 000 queued / 100 ms); on in `production`/`encrypted`/`io` presets, off in `minimal`. Divergence from Python: rejections are one typed non-retryable kind rather than Transient/Timeout — immediately retrying a shed call would re-amplify the overload being shed.

> [!NOTE]
> **TTL management is per-backend.** "TTL inspection/refresh" means the `TTLInspectableBackend`
> capability (`get_ttl` + `refresh_ttl`) that powers `refresh_ttl_on_get` threshold-based
> sliding expiration.
> - **Python (LAB-446):** supported on **Redis**, **CachekitIO**, and **File**. **Memcached**
>   implements `refresh_ttl` (via the `touch` command) but **not** `get_ttl` — the Memcached
>   protocol has no command to read a key's remaining TTL, and pymemcache's `HashClient`
>   exposes no meta protocol — so Memcached is **not** a full `TTLInspectableBackend` and
>   `refresh_ttl_on_get` does not apply to it (it warns once, then serves the hit).
> - **Rust (LAB-429):** File implements the full capability; Memcached implements the
>   refresh-only `touch` wrapper outside `TtlInspectable`, matching Python's split.
> - **TypeScript (LAB-430):** File implements the full `TTLBackend`; Memcached ships its `touch`-based `refreshTTL` method outside that capability, matching the Python and Rust split.

---

## Developer Experience

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Decorator API (`@cache`) | ✅ | ✅ `#[cachekit]` proc-macro | N/A (functional `wrap()` API) | ❌ attributes |
| Intent-based presets | ✅ `.minimal` `.production` `.secure` `.io` | ✅ `CacheKit::minimal` `::production` `::secure` `::io` | ✅ `createCache.minimal()` etc. | ❌ |
| Builder API | ✅ | ✅ `CacheKit::builder()` / `from_env()` | ✅ | ❌ |
| Async support | ✅ | ✅ | ✅ | ❌ |
| Sync support | ✅ | ✅ | ❌ | ✅ |
| WASM / CF Workers | N/A | ✅ `workers` feature (`?Send`, `Rc`) | ✅ `/workers` entrypoint (wasm32 core)¹ | N/A |
| pydantic-settings config | ✅ | N/A | N/A | N/A |
| Type hints / strict types | ✅ | ✅ | ✅ | ✅ PHP 8.1+ |

---

## Protocol Compliance

The protocol layers, each normative **where the SDK uses that layer** for its own
caching (auto mode). No storage layer is required of every SDK — the only contract
required of every SDK is [interop mode](spec/interop-mode.md) (plus AAD v0x03 if the
SDK ships encryption). "✅ Compliant" below means the SDK uses the layer and matches
its spec:

1. **Key Generation** — Blake2b-256 with MessagePack argument serialization ([spec/cache-key-format.md](spec/cache-key-format.md))
2. **Wire Format** — ByteStorage envelope with LZ4 block + xxHash3-64 ([spec/wire-format.md](spec/wire-format.md))
3. **Encryption** — AES-256-GCM with HKDF-SHA256 and AAD v0x03 ([spec/encryption.md](spec/encryption.md))
4. **SaaS API** — REST endpoints per [spec/saas-api.md](spec/saas-api.md)

**Cross-SDK interoperability** is a separate, narrower contract: [interop mode](spec/interop-mode.md) — language-neutral keys plus plain-MessagePack values with **no** envelope or container (protocol#11). Auto-mode storage containers are SDK-internal and are NOT required of, or readable by, other SDKs.

### Compliance Status

| Requirement | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Key generation (Blake2b) | ✅ Compliant | N/A auto mode¹ — interop/v1 keygen ✅ merged ([#33](https://github.com/cachekit-io/cachekit-rs/pull/33)); `#[cachekit]` mints interop keys ([#35](https://github.com/cachekit-io/cachekit-rs/pull/35)) | ✅ Compliant | ⚠️ Untested |
| Wire format (ByteStorage) | ✅ Compliant² | ✅ Canonical (`cachekit-core`) — unused for stored values² | ✅ Compliant | ⚠️ Untested |
| Storage container (auto mode)² | CK v3 frame (Python-internal) | Plain MessagePack (`rmp` named) — no envelope | Bare ByteStorage envelope (default) | — |
| Encryption (AES-256-GCM) | ✅ Compliant | ✅ Canonical (cachekit-core) | ✅ Compliant | ⚠️ Untested |
| AAD v0x03 | ✅ Compliant (5 components — every auto serializer appends `original_type`; interop mode is the sole 4-component path) | ✅ Compliant (4 components) | ✅ Compliant (4 components) | ❌ Not implemented |
| SaaS API | ✅ Compliant | ✅ Compliant (CachekitIO backend) | ✅ Compliant | ❌ Not implemented |
| Test vectors in CI³ | ✅ interop/v1 (full set, incl. AAD + encryption through the real stack) | ✅ interop/v1 (full set) since [#33](https://github.com/cachekit-io/cachekit-rs/pull/33) | ✅ interop/v1 (full set, incl. its key vectors) + inline Python-generated AAD-construction and encryption (decrypt-Python-ciphertext) vectors | ⚠️ Pending |
| Interop mode ([spec](spec/interop-mode.md), opt-in) | ✅ Released — PyPI 0.14.0+⁴ ([#220](https://github.com/cachekit-io/cachekit-py/pull/220)) | ✅ Released — crates.io 0.4.0+ ([#33](https://github.com/cachekit-io/cachekit-rs/pull/33)) | ✅ Released — npm 0.1.3+ ([#71](https://github.com/cachekit-io/cachekit-ts/pull/71)) | ❌ Not implemented |

> [!NOTE]
> ¹ "N/A" for Rust *auto-mode* key generation means `cachekit-rs` implements no auto-mode key format: `get`/`set` take caller-supplied keys. The `#[cachekit]` macro mints **interop/v1** keys via `interop_key` — required, compile-time-validated `interop = "operation"` and `namespace` attributes, byte-identical across SDKs ([cachekit-rs#35](https://github.com/cachekit-io/cachekit-rs/pull/35) / LAB-424; keygen itself merged in [#33](https://github.com/cachekit-io/cachekit-rs/pull/33)). The legacy RFC §3.1.5 keygen (`key::generate_cache_key`, `{namespace}:{blake2b256-hex}` — matched no protocol format, and WAS live in every `#[cachekit]` expansion despite the audit's "unused" premise, a proc-macro grep miss) is deleted outright in #35; upgrading is a full cache invalidation for `#[cachekit]` users. `cachekit-core` is a protocol primitive library with no keygen.
>
> ² Auto-mode **stored bytes** are SDK-internal and differ per SDK — see [wire-format.md → SDK Storage Containers](spec/wire-format.md#sdk-storage-containers-auto-mode). Python stores the ByteStorage envelope *inside* its CK v3 frame; `cachekit-rs` does not use the envelope for values at all (it uses `cachekit-core` only for encryption). Cross-SDK value compatibility is exclusively an [interop-mode](spec/interop-mode.md) property (protocol#11).
>
> ³ "Test vectors in CI" = vectors the SDK's own default CI executes. Beyond the SDKs, this repo's `verify.yml` CI-verifies `interop-mode.json`, `encryption.json`, `python-frame.json`, and — since LAB-423 — `wire-format.json` ([`tools/wire-format-reference.py`](tools/wire-format-reference.py)) against reference implementations. `cache-keys.json` (regenerated by cachekit-py v0.12.0, byte-identical to the v0.5.0 originals) is vendored and CI-verified in cachekit-py since [cachekit-py#229](https://github.com/cachekit-io/cachekit-py/pull/229) (LAB-425).
>
> ⁴ Version cells are **floors** (`X+`), not snapshots — they stay true as new versions publish; check the registry for the current release. Python's floor is the first *installable* one: interop merged under the `v0.13.0` tag, but neither `0.12.0` nor `0.13.0` was ever published to PyPI, so `0.14.0` is the earliest PyPI release containing interop mode. Do not "correct" this to 0.13.0 from the cachekit-py changelog alone.

---

## Architecture Notes

<details>
<summary><strong>Python SDK (cachekit-py)</strong></summary>

- Hybrid Python-Rust architecture: decorators and orchestration in Python, ByteStorage and encryption in Rust (via PyO3)
- The `cachekit-core` Rust crate is the canonical implementation for compression, checksums, and encryption
- 4 serializers: Standard (cross-language), Auto (Python-optimized), Orjson (JSON), Arrow (columnar)
- Backends: Redis, Memcached, File (local), CacheKit SaaS — backend auto-detected from the environment: a single unambiguous selector, with `REDIS_URL`/localhost fallback, and ambiguous (multiple) selectors raising `ConfigurationError` (see [Cache Backends](#cache-backends))
- Config via pydantic-settings; secrets via `SecretStr`

</details>

<details>
<summary><strong>Rust SDK (cachekit-rs)</strong></summary>

- Published on crates.io as `cachekit-rs` v0.3.0 + `cachekit-macros` v0.3.0
- Feature flags: `redis`, `cachekitio`, `encryption`, `l1`, `macros`, `workers`
- Backends: `RedisBackend` (fred), `CachekitIO` (reqwest), `WorkersCachekitIO` (CF Workers fetch)
- L1 cache via moka (native only, `l1` feature)
- `#[cachekit]` proc-macro for decorator-style caching
- `SecureCache` for zero-knowledge encrypted caching
- SSRF protection, credential redaction, `Zeroizing` key material
- WASM/Workers support: `?Send` + `Rc` paths via `cfg(target_arch = "wasm32")`
- Depends on `cachekit-core` v0.2.0 for ByteStorage and encryption primitives

</details>

<details>
<summary><strong>Rust Core (cachekit-core)</strong></summary>

- Published on crates.io as `cachekit-core` v0.3.0 (`cachekit-rs` still depends on the 0.2 line — Renovate bump tracked separately)
- Provides: `ByteStorage`, `ZeroKnowledgeEncryptor`, `derive_domain_key`, `derive_tenant_keys`
- Dependencies: `lz4_flex`, `xxhash-rust`, `ring` (native) / `aes-gcm` (wasm32), `hkdf`, `sha2`, `rmp-serde`
- Formally verified security properties via Kani
- Shared across Python (PyO3 FFI), Rust SDK, and TypeScript (NAPI) SDKs

</details>

<details>
<summary><strong>TypeScript SDK (cachekit-ts)</strong></summary>

- Monorepo: `@cachekit-io/cachekit` (SDK) + `@cachekit-io/cachekit-core-ts` (Rust NAPI bindings)
- Redis backend via ioredis, CacheKit SaaS backend via fetch API
- Node-only Memcached (`memjs` optional peer) and File backends via subpath exports; File format is byte-verified against the shared protocol vectors
- Encryption via Rust NAPI (AES-256-GCM, HKDF-SHA256, counter-based nonces)
- AAD v0x03 compliant with Python cross-SDK test vectors
- L1 LRU cache with background refresh, version tokens, namespace invalidation
- Cold-miss single-flight per process (always on); opt-in cross-process locking via `stampede.distributedLock` (LAB-519)
- Circuit breaker (rolling window), retry (exponential backoff + jitter), graceful degradation
- Distributed locking via Redis and CacheKit SaaS backends (`LockableBackend`)
- Intent-based API: `createCache.minimal()`, `.production()`, `.secure()`, `.io()`
- 567 tests, 94.79% statement coverage (measured on the LAB-519 branch, cachekit-ts#77)
- Dual output: ESM + CJS, Node 20+

</details>

<details>
<summary><strong>PHP SDK (cachekit-php)</strong></summary>

- Targets PHP 8.1+ with ext-msgpack and paragonie/sodium_compat
- LZ4 via forked php-ext-lz4 (`lz4_compress_raw()`)
- Blake2b via ext-sodium or dedicated Blake2b extension

</details>

---

<div align="center">

[Protocol](README.md) · [Cache Key Format](spec/cache-key-format.md) · [Wire Format](spec/wire-format.md) · [Encryption](spec/encryption.md) · [SaaS API](spec/saas-api.md)

</div>
