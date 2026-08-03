**[Protocol](README.md)** > **SDK Feature Matrix**

<div align="center">

# SDK Feature Matrix

**Feature parity and compliance status across all CacheKit SDK implementations.**

*Last updated: 2026-08-04 — **LAB-1400 consolidation.** Ten open matrix PRs (protocol#25/#28/#29/#31/#32/#33/#35/#37/#40/#43) were folded into this one end-state, regenerated from current SDK code rather than from the stale PR diffs; per-cell evidence and the accept/reject verdict for every folded PR are in the consolidation PR body. Corrections that were live falsehoods on `main`: **key rotation ships in no SDK** (`rotate_key()` is a `NotImplemented` stub — the matrix claimed py ✅ / rs ✅, contradicting this repo's own [decisions/key-rotation.md](decisions/key-rotation.md)); **`cachekit-rs` has no `::secure` preset** and is **async-only** (matrix claimed both); **Python has no builder API**; hardware-acceleration detection is surfaced by Python only; rs MSRV is 1.85 (not 1.82); ts requires Node 22+ (not 20+). New rows: Retry, Graceful degradation, Cross-instance L1 invalidation (LAB-520), client-L1 stale-while-revalidate (LAB-728), Orjson serializer, and an Observability section (LAB-275). Flipped on verified evidence: rs circuit breaker / retry / graceful degradation / cold-miss single-flight ✅ (LAB-518), rs Workers locking + TTL inspection ✅ (LAB-426), ts SWR on Workers ✅ via `withExecutionContext(ctx)` → `ctx.waitUntil` (LAB-751). Versions refreshed against the registries: py 0.17.1, core 0.4.0, rs 0.5.0 + macros 0.5.0, ts 0.1.5. Per-ticket provenance for entries older than this consolidation lives in [CHANGELOG.md](CHANGELOG.md) and `git log sdk-feature-matrix.md`.*

</div>

---

## Table of Contents

- [SDK Overview](#sdk-overview)
- [Core Features](#core-features)
- [Encryption](#encryption)
- [Cache Backends](#cache-backends)
- [Backend Abstraction](#backend-abstraction)
- [Reliability Features](#reliability-features)
- [Observability](#observability)
- [Developer Experience](#developer-experience)
- [Protocol Compliance](#protocol-compliance)
- [Architecture Notes](#architecture-notes)

---

## SDK Overview

| SDK | Package | Version | Language | Status |
| :--- | :--- | :---: | :--- | :---: |
| cachekit-py | `cachekit` (PyPI) | 0.17.1 | Python 3.10+ | ✅ Production |
| cachekit-rs | `cachekit-rs` (crates.io) | 0.5.0 | Rust 1.85+ | ✅ Production |
| cachekit-core | `cachekit-core` (crates.io) | 0.4.0 | Rust (shared core) | ✅ Production |
| cachekit-ts | `@cachekit-io/cachekit` (npm) | 0.1.5 | TypeScript (Node 22+) | ✅ Production |
| cachekit-php | — | — | PHP 8.1+ | 🔜 Development |

---

## Core Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| StandardSerializer (MessagePack) | ✅ | ✅ via rmp-serde | ✅ | 🔜 Planned |
| AutoSerializer (Python-specific) | ✅ | N/A | N/A | N/A |
| OrjsonSerializer (fast JSON) | ✅ `[json]` extra | N/A | N/A | N/A |
| ArrowSerializer (columnar) | ✅ `[data]` extra | N/A | ❌ (LAB-524)⁰ | ❌ |
| ByteStorage (LZ4 + xxHash3-64) | ✅ via Rust FFI | ✅ canonical (cachekit-core) | ✅ via NAPI (Rust) | 🔜 Planned |
| Blake2b-256 key generation | ✅ | ✅ interop mode only — N/A auto mode (see [Compliance Status](#compliance-status) note ¹) | ✅ via @noble/hashes | 🔜 Planned |

> ⁰ TypeScript Arrow was listed 🔜 Planned from 2026-06-06 with no code, stub, or tracking issue behind it; corrected to ❌ by the LAB-275 audit, with LAB-524 owning the implement-or-decline decision. Orjson and Arrow are Python-ecosystem serializers behind the `[json]` / `[data]` extras (`cachekit-py/pyproject.toml:73-81`); Rust and TypeScript serialize natively to MessagePack, so N/A there is by design.

---

## Encryption

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| AES-256-GCM | ✅ via Rust FFI | ✅ ring (native) / aes-gcm (wasm32) | ✅ via NAPI (Rust) | 🔜 Planned |
| HKDF-SHA256 key derivation | ✅ via Rust FFI | ✅ | ✅ via NAPI (Rust) | 🔜 Planned |
| Per-tenant key isolation | ✅ | ✅ | ✅ via TenantKeys NAPI | 🔜 Planned |
| AAD v0x03 (cache_key binding) | ✅ | ✅ | ✅ | ❌ |
| Key rotation | ❌ mismatch detection only⁵ | ❌⁵ | ❌ nonce-exhaustion detection only⁵ | ❌ |
| Hardware acceleration detection | ✅ surfaced (`hardware_acceleration_enabled()`) | ⚠️ core-internal, not re-exported⁶ | ❌ not exposed⁶ | N/A |
| Counter-based nonces | ✅ via Rust | ✅ | ✅ via NAPI (Rust) | ❌ use random |

> [!IMPORTANT]
> AAD v0x03 is required for protocol compliance. SDKs without it cannot safely interoperate with encrypted payloads from compliant SDKs — the auth tag will fail verification. Python, Rust, and TypeScript construction was code-verified byte-identical on 2026-07-21 (LAB-272); the normative byte layout and the frozen `True`/`False` compressed tokens (protocol#12) are defined in [spec/encryption.md](spec/encryption.md#additional-authenticated-data-aad). Python's auto serializers append the optional `original_type` fifth component; Rust, TypeScript, and interop mode always emit exactly four. Python's read path fails closed when encryption is enabled but a stored entry claims plaintext ([cachekit-py#215](https://github.com/cachekit-io/cachekit-py/pull/215)).

> [!WARNING]
> ⁵ **Key rotation ships in no SDK. Rotating a master key today invalidates every encrypted entry.** Corrected 2026-08-04 (LAB-1400) from a previous Python ✅ / Rust ✅ that no code supported — the same orphaned-API trust-bug class as LAB-388. Verified: `cachekit-core`'s `ZeroKnowledgeEncryptor::rotate_key()` returns `EncryptionError::NotImplemented` (`src/encryption/core.rs:492`); cachekit-py implements key-fingerprint **mismatch detection** only, which fails closed on an unexpected fingerprint but has no decrypt-with-previous-key path (`src/cachekit/serializers/encryption_wrapper.py:369-382`); cachekit-rs neither re-exports nor calls any rotation API; cachekit-ts only classifies the core's nonce-exhaustion error into `NonceExhaustedError`. `cachekit-core` exports `KeyRotationState` and `RotationAwareHeader` (`src/encryption/mod.rs:20`) but **no SDK consumes either** — there is no PyO3 or NAPI binding for them and no Rust-SDK call site, so the public surface overstates what is reachable. The **design** is specified and the retired header recorded in [decisions/key-rotation.md](decisions/key-rotation.md) (LAB-516); cells flip per SDK only as each implementation ships.
>
> ⁶ Runtime AES detection (`is_x86_feature_detected!("aes")`, `cachekit-core/src/encryption/core.rs:243`) lives in the shared core and is **surfaced only by Python** (`encryption_wrapper.py:583`). cachekit-rs never re-exports it — the SDK calls the non-metrics encrypt/decrypt entry points — and the TypeScript NAPI layer exposes nothing. The previous `N/A` for TypeScript was wrong: it runs the same Rust core, so the capability exists and is simply unexposed. Tracked as LAB-523.

---

## Cache Backends

| Backend | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Redis (direct) | ✅ `backends/redis` (redis-py, required dep) | ✅ `redis` feature (fred) | ✅ `backends/redis.ts` (ioredis) | ❌ |
| Memcached | ✅ `backends/memcached` (`memcached` extra) | ✅ `memcached` feature (rust-memcache)³ | ✅ `backends/memcached.ts` (optional `memjs` peer; Node-only)⁴ | ❌ |
| File (local) | ✅ `backends/file` (stdlib + mmap) | ✅ `file` feature (byte-compatible with py)³ | ✅ `backends/file.ts` (Node-only; [format](spec/file-backend-format.md))⁴ | ❌ |
| CacheKit SaaS (HTTP) | ✅ `backends/cachekitio` (httpx) | ✅ `cachekitio` feature (reqwest, default) | ✅ `backends/cachekitio.ts` (fetch) | 🔜 Planned |
| Cloudflare Workers | N/A | ✅ `workers` feature (`worker::Fetch`) | ✅ `@cachekit-io/cachekit/workers` (wasm32 core)¹ | N/A |
| Workers KV (Cloudflare) | N/A | ❌ | ✅ `workersKV` on the `/workers` entry (LAB-750)¹ | N/A |
| Cache API (Cloudflare) | N/A | ❌ | ✅ `workersCacheAPI` on the `/workers` entry (LAB-750)¹ | N/A |
| DynamoDB | ❌² | ❌ | ❌ | ❌ |

> ¹ Shipped in LAB-595 (2026-07-24), following spike LAB-431's GO verdict: the `@cachekit-io/cachekit/workers` subpath (also the `workerd` condition on the root export) runs crypto and the ByteStorage envelope on a **wasm32 build of cachekit-core** (`@cachekit-io/cachekit-core-wasm`, 137 KB raw / ~55 KB gzipped + ~10 KB JS glue, wasm-bindgen `--target web` + wasm-opt `-Oz`) — counter nonces and the envelope carry over unchanged and the crypto stays single-touchpoint in the Rust core; byte-verified against the Python-ground-truth `test-vectors/encryption.json` and `wire-format.json` suites inside real workerd. Backend surface (phase 2, LAB-750): CachekitIO (pure `fetch`), **Workers KV** (`workersKV({ kv })` over a `KVNamespace` binding; native `expirationTtl` — KV rejects values under its 60s minimum, so the SDK clamps shorter TTLs up to 60s before the `put`, and by an SDK rule (not KV's) `ttl <= 0` stores without expiry; eventually consistent ~60s), the **Cache API** (`workersCacheAPI()` over `caches.default`/named caches; per-data-center only, `Cache-Control: max-age` to the second, best-effort eviction, keys mapped to synthetic never-fetched URLs), or a custom `Backend` instance — all storage transports over the unchanged opaque ByteStorage payload (encryption above the backend; secure caches store ciphertext only). Backend instances are accepted by the `minimal`/`production`/`secure` intents (`{ backend }` in place of `{ url }`, both entrypoints); Redis-URL intents, Redis Pub/Sub invalidation, and Prometheus metrics stay Node-only and are excluded from the edge bundle (CI-guarded: no `node:*`, no NAPI, no ioredis/prom-client — no `nodejs_compat` flag needed); SWR background refresh requires binding the request's `ExecutionContext` — `cache.withExecutionContext(ctx)` returns a cheap per-request view whose refreshes ride `ctx.waitUntil`, because workerd cancels fire-and-forget work at response return; a read on a cache with no bound context fails safe to a plain (no-SWR) L1 get (LAB-751, `packages/cachekit/src/workers/index.ts:20-48`, `workers/runtime.ts:97-126`). Semantics delta: keys live in wasm linear memory (a host-readable ArrayBuffer), weaker isolation than NAPI's Rust heap but ~JS-heap-equivalent on Workers where the host is your own isolate; zeroized deterministically on `dispose()`. WebCrypto (AES-256-GCM + HKDF-SHA256, random-nonce fallback per [encryption.md → Nonce Generation](spec/encryption.md#nonce-generation)) remains the documented fallback if the wasm path ever hits a wall.
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
| TTL inspect / refresh | `TTLInspectableBackend` — Redis ✅, SaaS ✅, File ✅, Memcached ⚠️ `refresh_ttl` only (LAB-446) | `TtlInspectable` — Redis ✅, SaaS ✅, File ✅, Workers ✅ (`backend/workers.rs:322`; LAB-426), Memcached ⚠️ `refresh_ttl` only (LAB-429) | `TTLBackend` — Redis ✅, SaaS ✅ (`TTLCachekitIO`), File ✅; Memcached ⚠️ `refreshTTL` only (LAB-430) |
| Distributed locking | `LockableBackend` — Redis ✅ (`redis.lock.Lock`), SaaS ✅ | `LockableBackend` — SaaS ✅, Redis ✅ (`SET NX PX` + Lua compare-and-delete, `<key>:lock` namespace shared with py), Workers ✅ (`backend/workers.rs:262`) — all three LAB-426 | `LockableBackend` — Redis ✅ (LAB-427), SaaS ✅ (`LockableCachekitIO`) |
| Per-operation timeout | `TimeoutConfigurableBackend` — Redis ✅ (SaaS ships a non-protocol `with_timeout` variant) | — no equivalent | — no equivalent |
| Zero-copy buffer read | `BufferReadableBackend` / `BufferHandle` — File ✅ (mmap; #171) | — no equivalent | — no equivalent |

> [!NOTE]
> **Lock API shape divergence:** Python's `acquire_lock` is an async context manager yielding `bool` — the lock token stays internal and release is automatic. Rust and TypeScript return the raw `lock_id` capability token from `acquire_lock`/`acquireLock` and require an explicit `release_lock(key, lock_id)` — a direct mirror of the SaaS lock endpoint. All three pass the **bare cache key** (backends own any `:lock` namespace derivation). Porting a lockable backend across SDKs must bridge this shape difference.
>
> **Coverage, not shape, is the parity gap — and it has closed.** All three SDKs use the same required-base + optional-capability pattern, and all three now cover Redis locking plus TTL inspection. Rust's Workers backend gained both in LAB-426, so the "Workers speaks the SaaS API but implements neither capability" gap that the LAB-273 audit recorded no longer exists. What remains is narrower and deliberate: Memcached is refresh-only in every SDK (the protocol has no command to read a remaining TTL), and per-operation timeout / zero-copy buffer read are Python-only extensions with no cross-SDK contract.

---

## Reliability Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Circuit breaker | ✅ | ✅ `reliability` feature (default-on) — armed in `production`/`encrypted`/`io`, off in `minimal` (LAB-518) | ✅ | ❌ |
| Retry (backoff + jitter) | ⚠️ Redis-connection retry only — no generic backend-op retry⁷ | ✅ On the `is_retryable` classification, inside the breaker (`reliability.rs:216`, `:251`; LAB-518) | ✅ `reliability/retry.ts` | ❌ |
| Graceful degradation | ✅ Fail-open on backend unavailability; encrypted paths stay fail-closed | ✅ `#[cachekit]` runs the function uncached on outage-class failures (transient / timeout / circuit-open / shed); permanent and auth errors propagate, and `secure` fails closed on everything (`cachekit-macros/src/lib.rs:425-448`; LAB-518) | ✅ `reliability/degradation.ts` | ❌ |
| Backpressure | ✅ | ✅ Semaphore + bounded queue, decision recorded (LAB-729) | ⚠️ Refresh cap only — deliberate, decision recorded (LAB-519) | ❌ |
| Distributed locking | ✅ Redis + SaaS backends | ✅ Redis + SaaS + Workers (`LockableBackend`; LAB-426) | ✅ Redis + SaaS backends; wired into `wrap()` cold miss (opt-in `stampede.distributedLock`, LAB-519) | ❌ |
| L1/L2 dual-layer cache | ✅ | ✅ moka (native) / `l1` feature | ✅ | ❌ |
| Cache stampede prevention | ✅ Async decorators via backend lock; sync path none by design⁸ | ✅ Cold-miss single-flight wired into every `#[cachekit]` expansion — per-key in-process gate plus a distributed fill lock on lock-capable backends (`cachekit-macros/src/lib.rs:512`, `:544`; `flight.rs:278`; LAB-518) | ✅ Cold-miss single-flight + SWR version tokens (LAB-519) | ❌ |
| Cross-instance L1 invalidation (pub/sub) | ❌ built, never wired, then deleted⁹ | ❌ | ✅ Opt-in `invalidation` config over a Redis pub/sub channel (`invalidation/redis-channel.ts`) — the reference implementation⁹ | ❌ |
| TTL management | ✅ Redis + SaaS + File; Memcached refresh-only (see note) | ✅ Redis + SaaS + File + Workers (`TtlInspectable`); Memcached refresh-only (LAB-429/426) | ✅ Redis + SaaS + File (`TTLBackend`); Memcached refresh-only (LAB-430) | ❌ |
| Stale-while-revalidate (client L1) | ⚠️ L1-only mode (`backend=None`) only¹⁰ | ✅ Serve-stale + single-flight background refresh (LAB-728)¹⁰ | ✅ `getWithSwr` — version tokens + background refresh, `maxConcurrentRefreshes` cap; on Workers requires a bound `ExecutionContext` (see [Cache Backends](#cache-backends) note ¹) | ❌ |
| Stale-while-revalidate (server stale-grace) | 🚧 LAB-381 | ❌ | ❌ | ❌ |

> ⁷ **Python has no generic backend-operation retry** (LAB-522). What exists is Redis-client-level reconnect/timeout retry and lock-acquisition retry. The `max_retries` fields on `CachekitConfig` (`src/cachekit/config/settings.py:117`) and the CachekitIO backend config (`src/cachekit/backends/cachekitio/config.py:121`) have **zero consumers** — a config knob wired to nothing, which reads as a capability and is not one (the LAB-388 pattern; recorded here rather than left to be rediscovered). Rust and TypeScript both wrap backend ops in a real retry layer.
>
> ⁸ cachekit-py's sync decorator documents "use async decorators" for distributed locking (`decorators/wrapper.py`) — a recorded design decision, not drift.
>
> ⁹ Python shipped a complete but never-wired `invalidation/` package (channel, events, Redis pub/sub with reconnect) and **deleted** it rather than wiring it (LAB-520, [cachekit-py#237](https://github.com/cachekit-io/cachekit-py/pull/237); the package is absent from `src/cachekit/` as of 0.17.1). The reason is worth keeping: without server-side key tracking, broadcasting mass invalidations makes other pods evict L1 and immediately re-read the stale L2 entries the invalidating process could not delete — strictly worse than not invalidating. TypeScript's implementation is the reference if Python re-adds it, paired with a distributed key registry. **Invalidation events are not cross-SDK interoperable:** no protocol spec exists and ts's channel name and payload differ from what py's package used, so the ts channel is not a protocol surface.
>
> ¹⁰ **Client-L1 SWR is a distinct capability from the server stale-grace row above** (which is a SaaS response contract, LAB-381). Rust (LAB-728, [cachekit-rs#47](https://github.com/cachekit-io/cachekit-rs/pull/47)): a stale L1 hit is served immediately and triggers exactly one background re-execution, deduplicated through the same cold-miss `single_flight()` as a cold miss — builder options `swr_enabled` (default **on**) / `swr_threshold_ratio` (default 0.5, ±10% jitter drawn once per entry so a hot key does not stampede its own refresh), native only, live path `#[cachekit]` → `CacheKit::interop_get_swr` (`client.rs:433`) → `L1Cache::get_with_swr` (`l1/mod.rs:94`), non-blocking and exactly-once behaviour covered by `tests/swr_tests.rs`. Python: live only in L1-only mode, where `ObjectCache.get_with_swr` is wired into the decorator (`decorators/wrapper.py:1055-1057`, gated on `_l1_only_mode`); the byte-layer `L1Cache.get_with_swr` that backed modes would use has no caller outside benchmarks — this is exactly the dead code that made the previous backed-mode ✓ a trust bug (LAB-388), so the cell is scoped to what runs.
>
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

## Observability

"Wired" means the live cache path feeds it with zero user plumbing. Audited against code 2026-08-04 (LAB-1400, folding the LAB-275 audit and LAB-517's TypeScript metrics work).

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :--- | :--- | :--- | :--- |
| Metrics | ✅ Live `prometheus_client` counters / gauges / histograms on the default registry; no HTTP exposition helper | ⚠️ Not wired — `MetricsProvider` is a user-supplied `Arc<dyn Fn() -> Option<L1Stats>>` closure (`metrics.rs:16`); nothing populates it by default (LAB-521) | ✅ Live Prometheus metrics via the optional `prom-client` peer dep — `metrics: boolean \| MetricsConfig`, custom registry supported; warns once and degrades to a no-op when `prom-client` is absent (LAB-517) | ❌ |
| Structured logging | ✅ JSON ring-buffer logger with sensitive-data masking (`logging.py`) | ❌ No `log` / `tracing` integration — neither crate is a dependency (LAB-521) | ⚠️ Pluggable error-logger hook (`setLogger`, default `console.error`) — a logging seam, not a structured logger (LAB-517) | ❌ |
| Distributed tracing (OTel) | ❌ The span-shaped API is a no-op (`NoOpSpan`, `decorators/orchestrator.py:260-267`) | ❌ | ❌ | ❌ |
| SaaS telemetry headers (`X-CacheKit-L1-*`) | ✅ Auto | ⚠️ Reports `disabled` unless the user wires a `MetricsProvider` (LAB-521) | ✅ Auto-wired from the live L1/L2 hit/miss counters; an explicit user `metricsProvider` still wins | ❌ |

> **Distributed tracing is absent in every SDK** — a fleet-wide roadmap item, not a parity gap. Python's no-op span API is the one thing here that can be mistaken for support: it accepts spans and discards them, so instrumentation built against it silently produces nothing.

---

## Developer Experience

*Audited against code 2026-08-04 (LAB-1400, folding LAB-274): py `config/decorator.py` + `decorators/intent.py`, rs `intents.rs` + `client.rs` + `cachekit-macros/src/lib.rs`, ts `intents.ts` + `cache.ts`. This section records **semantics**, not just presence — two cells below were previously wrong in the presence-only framing.*

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Decorator API | ✅ `@cache` — wraps sync and async functions | ✅ `#[cachekit]` proc-macro — async fns returning `Result<T, CachekitError>` only | N/A (functional `wrap()` API) | ❌ attributes |
| Intent-based presets | ✅ `.minimal` `.production` `.secure` `.io` (+ Python-only `.dev` `.test` `.local`) | ⚠️ `::minimal` `::production` `::encrypted` `::io` — **there is no `::secure` preset**¹¹ | ✅ `createCache.minimal()` `.production()` `.secure()` `.io()` | ❌ |
| Builder API | ❌ No builder — `DecoratorConfig` presets + kwargs (frozen dataclass) + pydantic-settings, intentional¹² | ✅ `CacheKit::builder()` / `from_env()` | ❌ Options object on `createCache()` — no builder chain, no `from_env()`¹² | ❌ |
| Async support | ✅ | ✅ | ✅ | ❌ |
| Sync support | ✅ Same decorator wraps both | ❌ **Async-only** — every cache op is an `async fn` and the macro output only compiles on async fns¹¹ | ❌ | ✅ |
| WASM / CF Workers | N/A | ✅ `workers` feature (`?Send`, `Rc`) | ✅ `/workers` entrypoint (wasm32 core)¹ | N/A |
| pydantic-settings config | ✅ `CACHEKIT_` env prefix, `SecretStr` master key | N/A — `from_env()` + `Zeroizing` is the Rust idiom | N/A — per-intent env fallback only, intentional | N/A |
| Type hints / strict types | ✅ | ✅ | ✅ | ✅ PHP 8.1+ |

> ¹¹ Corrected 2026-08-04 (LAB-1400, from LAB-274): both cells were factually wrong. **`cachekit-rs` ships no `::secure` preset** — the encrypted preset is `CacheKit::encrypted(url, master_key)` (`intents.rs:158`), and `secure()` is a *post-build accessor* returning `Result<SecureCache, _>` that errors unless encryption was configured (`client.rs:658`). Writing `CacheKit::secure(...)` does not compile. **Rust is async-only**: `get`/`set`/`set_with_ttl` are all `async fn` (`client.rs:352`, `:531`, `:538`) and `#[cachekit]` expands only on async functions — the previous Sync ✅ would send a caller looking for a blocking API that has never existed.
>
> ¹² Neither Python nor TypeScript has a builder; both were previously ✅. Python configures through `DecoratorConfig` intent constructors plus kwargs on a frozen dataclass, with pydantic-settings underneath — there is no `Builder` class or `builder()` method anywhere in `src/cachekit/`. TypeScript takes an options object. Both are deliberate; the row now says so rather than implying a chained-builder surface that does not exist.

### Intent-preset semantics (parity, not presence)

The four shared preset names configure **different things per SDK**. Each cell is code-verified; a cross-SDK user hits these as surprises.

| Semantic | Python | Rust | TypeScript |
| :--- | :--- | :--- | :--- |
| Preset TTL defaults | **None — entries never expire** unless `ttl=` is passed | 300 / 600 / 600 / 3 600 s (`intents.rs:78`, `:118`, `:165`, `:214`) | 300 / 600 / 600 / 3 600 s |
| `minimal`: L1 | **on** (SWR / invalidation off) | **off** (`no_l1()`, `intents.rs:79`) | **on** (SWR / invalidation off) |
| `minimal`: integrity checksums | **off** (`integrity_checking=False`) | n/a — values carry no envelope | **on** (ByteStorage on by default) |
| `minimal`: reliability | circuit breaker / timeout off, backpressure on | **off** — the `reliability` layer is only attached by `production`/`encrypted`/`io` | circuit breaker neutered (∞ threshold), no retry, degradation off |
| Encrypted preset | `.secure(master_key=…)` — hex string, ≥64 hex chars; falls back to `CACHEKIT_MASTER_KEY` | `::encrypted(url, key: &[u8])` — **raw bytes, ≥32**; argument only, no env fallback | `.secure({ masterKey })` — hex; falls back to `CACHEKIT_MASTER_KEY` |
| Tenancy on the encrypted preset | `tenant_extractor` callable, `single_tenant_mode`, `fail_closed` tri-state | fixed `"default"` tenant (override via builder) | `tenantId` string |
| `io`: credentials | `CACHEKIT_API_KEY` env **only** | `api_key` argument **only** (env only via `from_env()`) | `apiKey` option **or** `CACHEKIT_API_KEY` |
| `CACHEKIT_MASTER_KEY` auto-enables encryption | **all presets** | only `CacheKit::from_env()` | only `createCache.secure()` |

> [!WARNING]
> Preset names promise more parity than they deliver. The sharpest traps: Python preset entries **live forever** where Rust and TypeScript expire in 300–3 600 s; the master key is a **hex string** in py/ts but **raw bytes** in rs, so passing the same value across SDKs is a type error at best and a wrong key at worst; and the same `CACHEKIT_MASTER_KEY` activates encryption everywhere in Python, only in `from_env()` in Rust, and only in `.secure()` in TypeScript. All three do reject a *missing* key on the encrypted preset — Python raises, Rust returns `Err`, and `createCache.secure()` throws `ConfigurationError` (`intents-core.ts:240`) — so the trap is key *format* and activation *scope*, not absence. The canonical preset contract is being specified under LAB-514 (epic LAB-105); whether TypeScript's `secure` namespace can be reached on an instance built without encryption is a separate open question tracked as LAB-513 and is deliberately **not** asserted here either way.

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
- 4 registry serializers: Standard (cross-language), Auto (Python-optimized), Orjson (JSON, `[json]` extra), Arrow (columnar, `[data]` extra) — plus the non-registry interop/v1 serializer for cross-SDK mode
- Live Prometheus metrics (`prometheus_client`, default registry) + structured JSON logging with sensitive-data masking
- Backends: Redis, Memcached, File (local), CacheKit SaaS — backend auto-detected from the environment: a single unambiguous selector, with `REDIS_URL`/localhost fallback, and ambiguous (multiple) selectors raising `ConfigurationError` (see [Cache Backends](#cache-backends))
- Config via pydantic-settings; secrets via `SecretStr`

</details>

<details>
<summary><strong>Rust SDK (cachekit-rs)</strong></summary>

- Published on crates.io as `cachekit-rs` v0.5.0 + `cachekit-macros` v0.5.0; MSRV 1.85
- Feature flags: `cachekitio`, `redis`, `memcached`, `file`, `encryption`, `l1`, `macros`, `workers`, `reliability`, `unsync` — default = `cachekitio` + `encryption` + `l1` + `reliability`
- Backends: `RedisBackend` (fred), `CachekitIO` (reqwest), `WorkersCachekitIO` (CF Workers fetch), `MemcachedBackend`, `FileBackend` (both native-only cargo features)
- L1 cache via moka (native only, `l1` feature), with serve-stale + single-flight background refresh (LAB-728)
- Reliability tier (`reliability` feature, native): retry with backoff + jitter on the `is_retryable` classification, circuit breaker, backpressure (semaphore + bounded queue), cold-miss single-flight with distributed fill locks, and macro-level graceful degradation (fail-open; `secure` fail-closed)
- `#[cachekit]` proc-macro for decorator-style caching (async fns only)
- `SecureCache` for zero-knowledge encrypted caching
- SSRF protection, credential redaction, `Zeroizing` key material
- WASM/Workers support: `?Send` + `Rc` paths via `cfg(target_arch = "wasm32")`
- Depends on `cachekit-core` for encryption primitives only (the envelope is unused for stored values — see [Compliance Status](#compliance-status) note ²); core-version rollout state is recorded in the cachekit-core note below

</details>

<details>
<summary><strong>Rust Core (cachekit-core)</strong></summary>

- Published on crates.io as `cachekit-core` v0.4.0 — the protocol 1.1 writer flip: `StorageEnvelope.compressed_data` now *emits* msgpack `bin` (`serde_bytes`); readers dual-decode both `bin` and the legacy array-of-ints ([spec/wire-format.md](spec/wire-format.md), [decisions/envelope-bin-encoding.md](decisions/envelope-bin-encoding.md)). Consumers: cachekit-py ≥ 0.17.0 ships it ([cachekit-py#249](https://github.com/cachekit-io/cachekit-py/pull/249)); released cachekit-rs 0.5.0 and cachekit-ts 0.1.4 still pin the 0.3 line — their 0.4.0 bumps ([cachekit-rs#53](https://github.com/cachekit-io/cachekit-rs/pull/53), [cachekit-ts#91](https://github.com/cachekit-io/cachekit-ts/pull/91)) are merged on main, unreleased
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
- Live Prometheus metrics via the optional `prom-client` peer dep; pluggable error-logger hook (`setLogger`)
- Dual output: ESM + CJS, **Node 22+** (`packages/cachekit/package.json` `engines.node: ">=22.0.0"`)

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
