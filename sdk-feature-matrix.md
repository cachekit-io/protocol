**[Protocol](README.md)** > **SDK Feature Matrix**

<div align="center">

# SDK Feature Matrix

**Feature parity and compliance status across all CacheKit SDK implementations.**

*Last updated: 2026-07-23 — LAB-518 rs reliability tier: circuit breaker, retry, graceful degradation, and stampede single-flight rows flipped to ✅ for Rust; rs distributed-locking/TTL cells refreshed for the already-landed LAB-426 Redis/Workers capability parity*

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
> AAD v0x03 is required for protocol compliance. SDKs without it cannot safely interoperate with encrypted payloads from compliant SDKs — the auth tag will fail verification. See [spec/encryption.md](spec/encryption.md#additional-authenticated-data-aad). Python, Rust, and TypeScript SDKs are compliant as of 2026-04-06.

---

## Cache Backends

| Backend | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Redis (direct) | ✅ `backends/redis` (redis-py, required dep) | ✅ `redis` feature (fred) | ✅ `backends/redis.ts` (ioredis) | ❌ |
| Memcached | ✅ `backends/memcached` (`memcached` extra) | ❌ | ❌ | ❌ |
| File (local) | ✅ `backends/file` (stdlib + mmap) | ❌ | ❌ | ❌ |
| CacheKit SaaS (HTTP) | ✅ `backends/cachekitio` (httpx) | ✅ `cachekitio` feature (reqwest, default) | ✅ `backends/cachekitio.ts` (fetch) | 🔜 Planned |
| Cloudflare Workers | N/A | ✅ `workers` feature (`worker::Fetch`) | ❌ Node 20+ only¹ | N/A |
| DynamoDB | ❌² | ❌ | ❌ | ❌ |

> ¹ The TS SDK cannot run on the Workers runtime today: crypto is a native NAPI module and the Redis backend is ioredis (TCP). Recorded as ❌ (a plausible target, unsupported) rather than N/A. Feasibility spike LAB-431 (2026-07-22, revised 2026-07-23) returned **GO** via a **wasm32 build of cachekit-core** — measured at ~64 KB gzipped (153 KB raw + JS glue, wasm-bindgen + wasm-opt) for the full crypto + ByteStorage surface, so counter nonces and the envelope carry over unchanged and the crypto stays single-touchpoint in the Rust core. The CachekitIO backend is already pure `fetch`, and a planned `workerd`-conditional entrypoint keeps ioredis/NAPI out of the edge bundle. WebCrypto (AES-256-GCM + HKDF-SHA256, random-nonce fallback per [encryption.md → Nonce Generation](spec/encryption.md#nonce-generation)) was evaluated as viable and stands as the documented fallback. Implementation tracked as LAB-595.
>
> ² DynamoDB has never shipped in any SDK. The previous Python ✅ traced to the [custom-backend tutorial](https://github.com/cachekit-io/cachekit-py/blob/main/docs/backends/custom.md), which shows how a *user* can implement the backend protocol against DynamoDB — that is an extension point, not shipped support (LAB-273).

**Backend selection / env auto-detection:** Python is the only SDK that auto-detects *which* backend to use from the environment — a single unambiguous selector (`CACHEKIT_API_KEY` → SaaS, `CACHEKIT_REDIS_URL` → Redis, `CACHEKIT_MEMCACHED_SERVERS` → Memcached, `CACHEKIT_FILE_CACHE_DIR` → File; fallback `REDIS_URL` / localhost Redis; setting more than one selector raises `ConfigurationError`). Rust `CacheKit::from_env()` reads SaaS credentials only (`CACHEKIT_API_KEY` / `CACHEKIT_API_URL` / `CACHEKIT_MASTER_KEY` / `CACHEKIT_DEFAULT_TTL`) and always builds the CachekitIO backend — Redis is wired explicitly via `.backend()`. TypeScript has no backend auto-detection: each preset fixes the backend type and env vars (`CACHEKIT_API_KEY`, `CACHEKIT_MASTER_KEY`) serve only as credential fallbacks. Whether rs/ts should gain selector-style auto-detection is an open product question, not a recorded decision (LAB-273 finding).

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
| TTL inspect / refresh | `TTLInspectableBackend` — Redis ✅, SaaS ✅, Memcached/File ❌ | `TtlInspectable` — Redis ✅, SaaS ✅, Workers ❌ | `TTLBackend` — SaaS ✅ (`TTLCachekitIO`), Redis ❌ |
| Distributed locking | `LockableBackend` — Redis ✅ (`redis.lock.Lock`), SaaS ✅ | `LockableBackend` — SaaS ✅, Redis ❌, Workers ❌ | `LockableBackend` — SaaS ✅ (`LockableCachekitIO`), Redis ❌ |
| Per-operation timeout | `TimeoutConfigurableBackend` — Redis ✅ (SaaS ships a non-protocol `with_timeout` variant) | — no equivalent | — no equivalent |
| Zero-copy buffer read | `BufferReadableBackend` / `BufferHandle` — File ✅ (mmap; #171) | — no equivalent | — no equivalent |

> [!NOTE]
> **Lock API shape divergence:** Python's `acquire_lock` is an async context manager yielding `bool` — the lock token stays internal and release is automatic. Rust and TypeScript return the raw `lock_id` capability token from `acquire_lock`/`acquireLock` and require an explicit `release_lock(key, lock_id)` — a direct mirror of the SaaS lock endpoint. All three pass the **bare cache key** (backends own any `:lock` namespace derivation). Porting a lockable backend across SDKs must bridge this shape difference.
>
> **Coverage, not shape, is the parity gap:** all three SDKs use the same required-base + optional-capability pattern, but optional-capability coverage varies by SDK: Python and Rust now cover both locking and TTL inspection on all their backends (Rust closed its Redis-locking and Workers gaps in LAB-426), while TypeScript's Redis backend implements neither (gap tickets under LAB-102).

---

## Reliability Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Circuit breaker | ✅ | ✅ `reliability` feature — on in `production`/`encrypted`/`io` presets, off in `minimal` (LAB-518) | ✅ | ❌ |
| Retry (exponential backoff + jitter) | ✅ | ✅ on transient/timeout classification (`is_retryable`), inside the breaker (LAB-518) | ✅ | ❌ |
| Graceful degradation | ✅ fail-open on `BackendError` | ✅ `#[cachekit]` runs the function uncached on outage-class failures (transient/timeout/circuit-open); permanent/auth errors propagate; `secure` fails closed on everything (LAB-518) | ✅ | ❌ |
| Backpressure | ✅ | ❌ | ⚠️ Concurrent refresh limits | ❌ |
| Distributed locking | ✅ Redis + SaaS backends | ✅ SaaS + Redis + Workers (`LockableBackend`, LAB-426) | ✅ SaaS backend only | ❌ |
| L1/L2 dual-layer cache | ✅ | ✅ moka (native) / `l1` feature | ✅ | ❌ |
| Cache stampede prevention | ✅ | ✅ cold-miss single-flight: per-key in-process lock + distributed fill lock on lock-capable backends (LAB-518) | ✅ Version tokens + background L1 refresh | ❌ |
| TTL management | ✅ Redis + SaaS | ✅ Redis + SaaS + Workers (`TtlInspectable`, LAB-426) | ✅ SaaS only (`TTLBackend`) | ❌ |
| Stale-while-revalidate (server stale-grace) | 🚧 LAB-381 | ❌ | ❌ | ❌ |

> **Lock id transport (CWE-532):** the unlock call carries the lock capability token in the `X-CacheKit-Lock-Id` request header, never the `?lock_id=` query string (which leaks via access/proxy logs and OTel `http.url` spans). **Migration complete in all three SDKs** (verified 2026-07-20, LAB-273): Python (#131, closed), Rust (#24, closed), TypeScript ships the header (ts#63 remains open only for an unrelated NAPI-rebuild item). SaaS dual-reads both during the rollout window. See [spec/saas-api.md](spec/saas-api.md#delete-v1cachekeylock).

---

## Developer Experience

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Decorator API (`@cache`) | ✅ | ✅ `#[cachekit]` proc-macro | N/A (functional `wrap()` API) | ❌ attributes |
| Intent-based presets | ✅ `.minimal` `.production` `.secure` `.io` | ✅ `CacheKit::minimal` `::production` `::secure` `::io` | ✅ `createCache.minimal()` etc. | ❌ |
| Builder API | ✅ | ✅ `CacheKit::builder()` / `from_env()` | ✅ | ❌ |
| Async support | ✅ | ✅ | ✅ | ❌ |
| Sync support | ✅ | ✅ | ❌ | ✅ |
| WASM / CF Workers | N/A | ✅ `workers` feature (`?Send`, `Rc`) | N/A | N/A |
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
| Key generation (Blake2b) | ✅ Compliant | N/A (SDK-level, not in core) | ✅ Compliant | ⚠️ Untested |
| Wire format (ByteStorage) | ✅ Compliant¹ | ✅ Canonical (`cachekit-core`) — unused for stored values¹ | ✅ Compliant | ⚠️ Untested |
| Storage container (auto mode)¹ | CK v3 frame (Python-internal) | Plain MessagePack (`rmp` named) — no envelope | Bare ByteStorage envelope (default) | — |
| Encryption (AES-256-GCM) | ✅ Compliant | ✅ Canonical (cachekit-core) | ✅ Compliant | ⚠️ Untested |
| AAD v0x03 | ✅ Compliant | ✅ Compliant | ✅ Compliant | ❌ Not implemented |
| SaaS API | ✅ Compliant | ✅ Compliant (CachekitIO backend) | ✅ Compliant | ❌ Not implemented |
| Test vectors | ⚠️ Pending | ⚠️ Pending | ✅ Python cross-SDK vectors | ⚠️ Pending |
| Interop mode ([spec](spec/interop-mode.md), opt-in) | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented |

> [!NOTE]
> "N/A" for Rust key generation means `cachekit-core` is a protocol primitive library. Key generation (Blake2b) is an SDK-level concern — `cachekit-rs` delegates cache key construction to the caller via the `key` parameter on `get`/`set`/`#[cachekit]`.

> [!NOTE]
> ¹ Auto-mode **stored bytes** are SDK-internal and differ per SDK — see [wire-format.md → SDK Storage Containers](spec/wire-format.md#sdk-storage-containers-auto-mode). Python stores the ByteStorage envelope *inside* its CK v3 frame; `cachekit-rs` does not use the envelope for values at all (it uses `cachekit-core` only for encryption). Cross-SDK value compatibility is exclusively an [interop-mode](spec/interop-mode.md) property (protocol#11).

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
- Feature flags: `redis`, `cachekitio`, `encryption`, `l1`, `macros`, `workers`, `reliability`
- Backends: `RedisBackend` (fred), `CachekitIO` (reqwest), `WorkersCachekitIO` (CF Workers fetch)
- L1 cache via moka (native only, `l1` feature)
- Reliability tier (`reliability` feature, native): retry with backoff + jitter on the `is_retryable` classification, circuit breaker (rolling window), macro-level graceful degradation (fail-open; `secure` fail-closed), cold-miss single-flight with distributed fill locks
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
- Encryption via Rust NAPI (AES-256-GCM, HKDF-SHA256, counter-based nonces)
- AAD v0x03 compliant with Python cross-SDK test vectors
- L1 LRU cache with background refresh, version tokens, namespace invalidation
- Circuit breaker (rolling window), retry (exponential backoff + jitter), graceful degradation
- Distributed locking via CacheKit SaaS backend
- Intent-based API: `createCache.minimal()`, `.production()`, `.secure()`, `.io()`
- 457 tests, 93.75% statement coverage
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
