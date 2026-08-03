**[Protocol](README.md)** > **SDK Feature Matrix**

<div align="center">

# SDK Feature Matrix

**Feature parity and compliance status across all CacheKit SDK implementations.**

*Last updated: 2026-07-21 — LAB-275 cross-SDK feature-gap synthesis: folds in the LAB-272 (protocol adherence) and LAB-273 (backend parity) audit corrections; serializer/reliability/encryption rows code-verified, Observability section added, key-rotation and hardware-acceleration cells corrected to reality, interop/v1 status refreshed (Rust [cachekit-rs#33](https://github.com/cachekit-io/cachekit-rs/pull/33) merged, Python released in v0.13.0)*

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
| cachekit-py | `cachekit` (PyPI) | 0.13.0 | Python 3.10+ | ✅ Production |
| cachekit-rs | `cachekit-rs` (crates.io) | 0.3.0 | Rust 1.85+ | ✅ Production |
| cachekit-core | `cachekit-core` (crates.io) | 0.3.0 | Rust (shared core) | ✅ Production |
| cachekit-ts | `@cachekit-io/cachekit` (npm) | 0.1.2 | TypeScript | ✅ Production |
| cachekit-php | — | — | PHP 8.1+ | 🔜 Development |

---

## Core Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| StandardSerializer (MessagePack) | ✅ | ✅ via rmp-serde | ✅ via @msgpack/msgpack | 🔜 Planned |
| AutoSerializer (Python-specific) | ✅ | N/A | N/A | N/A |
| OrjsonSerializer (fast JSON) | ✅ `[json]` extra | N/A | N/A | N/A |
| ArrowSerializer (columnar) | ✅ `[data]` extra | N/A | ❌ (LAB-524)¹ | ❌ |
| ByteStorage (LZ4 + xxHash3-64) | ✅ via Rust FFI | ✅ canonical (cachekit-core) | ✅ via NAPI (Rust) | 🔜 Planned |
| Blake2b-256 key generation | ✅ | ✅ interop mode ([#33](https://github.com/cachekit-io/cachekit-rs/pull/33)) / N/A auto mode | ✅ via @noble/hashes | 🔜 Planned |

> ¹ TS Arrow was listed 🔜 Planned since 2026-06-06 with zero code, stubs, or tracking behind it (LAB-275 audit). Corrected to ❌; LAB-524 owns the implement-or-decline decision. Orjson is a Python-ecosystem performance serializer (N/A elsewhere by design — Rust and TS serialize natively to MessagePack).

---

## Encryption

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| AES-256-GCM | ✅ via Rust FFI | ✅ ring (native) / aes-gcm (wasm32) | ✅ via NAPI (Rust) | 🔜 Planned |
| HKDF-SHA256 key derivation | ✅ via Rust FFI | ✅ | ✅ via NAPI (Rust) | 🔜 Planned |
| Per-tenant key isolation | ✅ | ✅ | ✅ via TenantKeys NAPI | 🔜 Planned |
| AAD v0x03 (cache_key binding) | ✅ | ✅ | ✅ | ❌ |
| Key rotation | ❌ detection only¹ | ❌¹ | ❌ nonce monitoring only¹ | ❌ |
| Hardware acceleration detection | ✅ surfaced (`hardware_acceleration_enabled`) | ⚠️ core-internal, not surfaced² | ❌² | N/A |
| Counter-based nonces | ✅ via Rust | ✅ | ✅ via NAPI (Rust) | ❌ use random |

> [!IMPORTANT]
> AAD v0x03 is required for protocol compliance. SDKs without it cannot safely interoperate with encrypted payloads from compliant SDKs — the auth tag will fail verification. Python, Rust, and TypeScript construction was code-verified byte-identical on 2026-07-21 (LAB-272); the normative byte layout and the frozen `True`/`False` compressed tokens (protocol#12) are defined in [spec/encryption.md](spec/encryption.md#additional-authenticated-data-aad). Python's auto serializers append the optional `original_type` fifth component; Rust, TypeScript, and interop mode always emit exactly four. Python's read path fails closed when encryption is enabled but a stored entry claims plaintext ([cachekit-py#215](https://github.com/cachekit-io/cachekit-py/pull/215)).

> ¹ **Key rotation ships in no SDK** (LAB-275 audit, corrected from the previous Python ✅ / Rust ✅): cachekit-core's `rotate_key()` is a `NotImplemented` stub (`encryption/core.rs:492`); cachekit-py's `KeyRotationState` PyO3 binding has zero Python callers — only key-fingerprint **mismatch detection** is live (fail-closed, no decrypt-with-previous-key path); cachekit-ts only monitors nonce exhaustion. Rotating a master key today invalidates all encrypted entries. Tracked fleet-wide as LAB-516.
>
> ² Runtime AES detection (`is_x86_feature_detected!("aes")`) lives in cachekit-core and is **surfaced only by Python**. cachekit-rs never re-exports it (the SDK calls the non-metrics encrypt/decrypt entry points); the TS NAPI layer exposes nothing (previous N/A was wrong — the crypto is the same Rust core). Tracked as LAB-523.

---

## Cache Backends

| Backend | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Redis (direct) | ✅ `backends/redis` (redis-py, required dep) | ✅ `redis` feature (fred) | ✅ `backends/redis.ts` (ioredis) | ❌ |
| Memcached | ✅ `backends/memcached` (`memcached` extra) | ❌ | ❌ | ❌ |
| File (local) | ✅ `backends/file` (stdlib + mmap) | ❌ | ❌ | ❌ |
| CacheKit SaaS (HTTP) | ✅ `backends/cachekitio` (httpx) | ✅ `cachekitio` feature (reqwest, default) | ✅ `backends/cachekitio.ts` (fetch) | 🔜 Planned |
| Cloudflare Workers | N/A | ✅ `workers` feature (`worker::Fetch`) | ❌ Node 22+ only¹ | N/A |
| DynamoDB | ❌² | ❌ | ❌ | ❌ |

> ¹ The TS SDK cannot run on the Workers runtime today: crypto is a native NAPI module and the Redis backend is ioredis (TCP). Recorded as ❌ (a plausible target, unsupported) rather than N/A.
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
> **Coverage, not shape, is the parity gap:** all three SDKs use the same required-base + optional-capability pattern, but Redis optional-capability coverage varies by SDK: Python has the broadest coverage (both locking and TTL inspection), Rust's Redis backend implements TTL inspection only (no locking), and TypeScript's Redis backend implements neither. Rust's Workers backend also lacks both despite speaking the same SaaS API (gap tickets under LAB-102).

---

## Reliability Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Circuit breaker | ✅ wired in decorator path | ❌ (LAB-518) | ✅ preset-gated (on in `production`/`secure`/`io`, off in `minimal`) | ❌ |
| Backpressure | ✅ semaphore + queue admission | ❌ (LAB-518) | ⚠️ SWR refresh cap only (`maxConcurrentRefreshes`)¹ | ❌ |
| Retry (exponential backoff + jitter) | ⚠️ reconnect/lock retry only — no generic backend retry (LAB-522) | ❌ `is_retryable()` classification exists, never called (LAB-518) | ✅ wired (`reliability/retry.ts`, crypto-PRNG jitter) | ❌ |
| Graceful degradation (fail-open to wrapped fn) | ✅ (encrypted paths stay fail-closed) | ❌ first error propagates (LAB-518) | ✅ on by default (`withDegradation`) | ❌ |
| Distributed locking | ✅ Redis + SaaS backends | ✅ SaaS backend only (`LockableBackend`; Redis/Workers lack impls) | ✅ SaaS backend only | ❌ |
| L1/L2 dual-layer cache | ✅ | ✅ moka (native) / `l1` feature | ✅ | ❌ |
| Cache stampede prevention | ✅ async decorators (backend lock); sync path none by design² | ❌ lock primitive never wired (LAB-518) | ⚠️ refresh path only — no cold-miss single-flight (LAB-519)³ | ❌ |
| Cross-instance invalidation (pub/sub) | ❌ built but never wired (LAB-520)⁴ | ❌ | ✅ Redis pub/sub channel, wired | ❌ |
| TTL management | ✅ Redis + SaaS | ✅ Redis + SaaS (`TtlInspectable`; Workers ❌) | ✅ SaaS only (`TTLBackend`) | ❌ |
| Stale-while-revalidate (client, L1) | ⚠️ L1-only mode (`ObjectCache`); backed modes dead code (LAB-388)⁵ | ❌ | ✅ `getWithSwr` + version tokens + background refresh | ❌ |
| Stale-while-revalidate (server stale-grace) | ❌ (spec'd, 🚧 LAB-381) | ❌ | ❌ | ❌ |

> ¹ Deliberate-partial: Node's event-loop model concentrates herd risk in refresh storms (capped) and cold misses (LAB-519); a Python-style admission semaphore is not idiomatic. Recorded as a decision, not a gap.
>
> ² cachekit-py's sync decorator documents "use async decorators" for distributed locking (`decorators/wrapper.py:1043`) — a design decision, not drift.
>
> ³ TS dedups SWR *refreshes* (`refreshingKeys` + version tokens) but on a cold L1+L2 miss concurrent callers all execute the wrapped function (`cache.ts:392`); the `LockableBackend` capability exists unwired. Under metered-misses pricing a cold-key herd multiplies billed misses.
>
> ⁴ cachekit-py ships a complete `invalidation/` pub/sub package (Redis channel, event levels) with zero references outside itself + tests — multi-pod L1 invalidation does not actually work in Python. TS ships the equivalent live (`invalidation/redis-channel.ts`).
>
> ⁵ Python's live client SWR is `ObjectCache.get_with_swr` (L1-only mode, wired in the decorator); the byte-layer `L1Cache.get_with_swr` used by backed modes is dead code — LAB-388.

> **Lock id transport (CWE-532):** the unlock call carries the lock capability token in the `X-CacheKit-Lock-Id` request header, never the `?lock_id=` query string (which leaks via access/proxy logs and OTel `http.url` spans). **Migration complete in all three SDKs** (verified 2026-07-20, LAB-273): Python (#131, closed), Rust (#24, closed), TypeScript ships the header (ts#63 remains open only for an unrelated NAPI-rebuild item). SaaS dual-reads both during the rollout window. See [spec/saas-api.md](spec/saas-api.md#delete-v1cachekeylock).

---

## Observability

Audited against code 2026-07-21 (LAB-275); TypeScript cells re-verified 2026-08-04 after [cachekit-ts#75](https://github.com/cachekit-io/cachekit-ts/pull/75) (LAB-517) merged. "Wired" means the live cache path feeds it with zero user plumbing.

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Metrics | ✅ live `prometheus_client` counters/gauges/histograms (default registry; no HTTP exposition helper — py#146) | ⚠️ `L1Stats` SaaS header telemetry only, requires a user-supplied `MetricsProvider` nothing auto-wires (LAB-521) | ✅ live Prometheus counters/gauges/histograms via optional `prom-client` peer dep — `metrics: boolean \| MetricsConfig`, custom registry supported; warns loudly once and degrades to no-op when `prom-client` is absent (LAB-517) | ❌ |
| Structured logging | ✅ JSON ring-buffer logger with sensitive-data masking | ❌ no `log`/`tracing` integration (LAB-521) | ⚠️ pluggable error-logger hook (`setLogger`), default `console.error` — still not a structured logger (LAB-517) | ❌ |
| Distributed tracing (OTel) | ❌ span-shaped API is a no-op (`NoOpSpan`) | ❌ | ❌ | ❌ |
| SaaS telemetry headers (`X-CacheKit-L1-*`) | ✅ auto | ⚠️ reports `disabled` unless user wires a provider (LAB-521) | ✅ auto-wired from live L1/L2 hit/miss counters (explicit user `metricsProvider` still wins) | ❌ |

> Distributed tracing is absent in **every** SDK (a fleet-wide roadmap item, not a parity gap); Python's no-op span API should not be mistaken for tracing support.

---

## Developer Experience

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Decorator API (`@cache`) | ✅ | ✅ `#[cachekit]` proc-macro | N/A (functional `wrap()` API) | ❌ attributes |
| Intent-based presets | ✅ `.minimal` `.production` `.secure` `.io` | ✅ `CacheKit::minimal` `::production` `::secure` `::io` | ✅ `createCache.minimal()` etc. | ❌ |
| Builder API | ✅ | ✅ `CacheKit::builder()` / `from_env()` | ✅ | ❌ |
| Async support | ✅ | ✅ | ✅ | ❌ |
| Sync support | ✅ | ✅ | ❌ | ✅ |
| WASM / CF Workers | N/A | ✅ `workers` feature (`?Send`, `Rc`) | ❌ blocked by NAPI crypto + ioredis (LAB-431) | N/A |
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
| Key generation (Blake2b) | ✅ Compliant | N/A auto mode (no spec'd keygen)¹ — interop keygen ✅ merged ([#33](https://github.com/cachekit-io/cachekit-rs/pull/33)) | ✅ Compliant | ⚠️ Untested |
| Wire format (ByteStorage) | ✅ Compliant² | ✅ Canonical (`cachekit-core`) — unused for stored values² | ✅ Compliant | ⚠️ Untested |
| Storage container (auto mode)² | CK v3 frame (Python-internal) | Plain MessagePack (`rmp` named) — no envelope | Bare ByteStorage envelope (default) | — |
| Encryption (AES-256-GCM) | ✅ Compliant | ✅ Canonical (cachekit-core) | ✅ Compliant | ⚠️ Untested |
| AAD v0x03 | ✅ Compliant (5 components — every auto serializer appends `original_type`; interop mode is the sole 4-component path) | ✅ Compliant (4 components) | ✅ Compliant (4 components) | ❌ Not implemented |
| SaaS API | ✅ Compliant | ✅ Compliant (CachekitIO backend) | ✅ Compliant | ❌ Not implemented |
| Test vectors in CI³ | ✅ interop/v1 (full set, incl. AAD + encryption through the real stack) | ✅ interop/v1 vectors vendored + run by `cargo test` in CI ([#33](https://github.com/cachekit-io/cachekit-rs/pull/33), merged 2026-07-21) | ✅ interop/v1 (full set, incl. its key vectors) + inline Python-generated AAD-construction and encryption (decrypt-Python-ciphertext) vectors | ⚠️ Pending |
| Interop mode ([spec](spec/interop-mode.md), opt-in) | ✅ Released (v0.13.0; [#220](https://github.com/cachekit-io/cachekit-py/pull/220)) | ✅ Merged ([#33](https://github.com/cachekit-io/cachekit-rs/pull/33), unreleased — crates.io still 0.3.0) | ✅ Merged ([#71](https://github.com/cachekit-io/cachekit-ts/pull/71), unreleased — npm still 0.1.2) | ❌ Not implemented |

> [!NOTE]
> ¹ "N/A" for Rust key generation means `cachekit-rs` implements no spec'd key format: `get`/`set` take caller-supplied keys, and the `#[cachekit]` macro (which has **no** `key` parameter) derives an SDK-internal legacy key — `{namespace}:{blake2b256-hex}` over the *unqualified* function name, the obsolete RFC §3.1.5 shape matching **no** current protocol key format, never usable cross-SDK. That derivation is macro-internal plumbing (it IS called at runtime by every `#[cachekit]` expansion — the LAB-424 "unused" premise was a grep miss), removed from the public API in [cachekit-rs#35](https://github.com/cachekit-io/cachekit-rs/pull/35). `cachekit-core` is a protocol primitive library with no keygen. Spec-conformant Rust keygen arrived with interop mode ([cachekit-rs#33](https://github.com/cachekit-io/cachekit-rs/pull/33), merged 2026-07-21).

> [!NOTE]
> ² Auto-mode **stored bytes** are SDK-internal and differ per SDK — see [wire-format.md → SDK Storage Containers](spec/wire-format.md#sdk-storage-containers-auto-mode). Python stores the ByteStorage envelope *inside* its CK v3 frame; `cachekit-rs` does not use the envelope for values at all (it uses `cachekit-core` only for encryption). Cross-SDK value compatibility is exclusively an [interop-mode](spec/interop-mode.md) property (protocol#11).

> [!NOTE]
> ³ "Test vectors in CI" = vectors the SDK's own default CI executes. Beyond the SDKs, this repo's `verify.yml` CI-verifies `interop-mode.json`, `encryption.json`, and `python-frame.json` against reference implementations. The former coverage holes are closed as of 2026-07-21: `wire-format.json` is byte-verified in cachekit-core CI ([core#55](https://github.com/cachekit-io/cachekit-core/pull/55), LAB-423) and `cache-keys.json` is vendored sha256-pinned into cachekit-py and byte-verified on every default CI run (LAB-425, protocol#26). **Every vector file is now enforced by at least one CI.**

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

- Published on crates.io as `cachekit-rs` v0.3.0 + `cachekit-macros` v0.3.0
- Feature flags: `redis`, `cachekitio`, `encryption`, `l1`, `macros`, `workers`, `unsync` (default = `cachekitio` + `encryption` + `l1`); MSRV 1.85
- Backends: `RedisBackend` (fred), `CachekitIO` (reqwest), `WorkersCachekitIO` (CF Workers fetch)
- L1 cache via moka (native only, `l1` feature)
- `#[cachekit]` proc-macro for decorator-style caching
- `SecureCache` for zero-knowledge encrypted caching
- SSRF protection, credential redaction, `Zeroizing` key material
- WASM/Workers support: `?Send` + `Rc` paths via `cfg(target_arch = "wasm32")`
- Depends on `cachekit-core` v0.3 for ByteStorage and encryption primitives

</details>

<details>
<summary><strong>Rust Core (cachekit-core)</strong></summary>

- Published on crates.io as `cachekit-core` v0.3.0 (`cachekit-rs` depends on the 0.3 line since [cachekit-rs#28](https://github.com/cachekit-io/cachekit-rs/pull/28))
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
- Dual output: ESM + CJS, Node 22+ (async-only API)

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
