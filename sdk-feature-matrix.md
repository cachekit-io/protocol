**[Protocol](README.md)** > **SDK Feature Matrix**

<div align="center">

# SDK Feature Matrix

**Feature parity and compliance status across all CacheKit SDK implementations.**

*Last updated: 2026-07-21 — LAB-274 Developer Experience section corrected to code-verified intent-preset / entry-point / config-surface reality*

</div>

---

## Table of Contents

- [SDK Overview](#sdk-overview)
- [Core Features](#core-features)
- [Encryption](#encryption)
- [Cache Backends](#cache-backends)
- [Reliability Features](#reliability-features)
- [Developer Experience](#developer-experience)
- [Protocol Compliance](#protocol-compliance)
- [Architecture Notes](#architecture-notes)

---

## SDK Overview

| SDK | Package | Version | Language | Status |
| :--- | :--- | :---: | :--- | :---: |
| cachekit-py | `cachekit` (PyPI) | 0.11.1 | Python 3.10+ | ✅ Production |
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
| Redis (direct) | ✅ | ✅ via fred | ✅ | ❌ |
| Memcached | ✅ (env auto-detect) | ❌ | ❌ | ❌ |
| File (local) | ✅ (env auto-detect) | ❌ | ❌ | ❌ |
| CacheKit SaaS (HTTP) | ✅ | ✅ reqwest (native) + fetch (Workers) | ✅ | 🔜 Planned |
| Cloudflare Workers | N/A | ✅ `workers` feature | N/A | N/A |
| DynamoDB | ✅ | ❌ | ❌ | ❌ |

---

## Reliability Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Circuit breaker | ✅ | ❌ | ✅ | ❌ |
| Backpressure | ✅ | ❌ | ⚠️ Concurrent refresh limits | ❌ |
| Distributed locking | ✅ | ✅ SaaS backend (`LockableBackend`) | ✅ SaaS backend only | ❌ |
| L1/L2 dual-layer cache | ✅ | ✅ moka (native) / `l1` feature | ✅ | ❌ |
| Cache stampede prevention | ✅ | ❌ | ✅ Version tokens + background L1 refresh | ❌ |
| TTL management | ✅ | ✅ `TtlInspectable` trait | ✅ | ❌ |
| Stale-while-revalidate (server stale-grace) | 🚧 LAB-381 | ❌ | ❌ | ❌ |

> **Lock id transport (CWE-532):** the unlock call carries the lock capability token in the `X-CacheKit-Lock-Id` request header, never the `?lock_id=` query string (which leaks via access/proxy logs and OTel `http.url` spans). SaaS dual-reads both during the rollout; SDKs migrate to header-only — Python (#131), TypeScript (#63), Rust (#24). See [spec/saas-api.md](spec/saas-api.md#delete-v1cachekeylock).

---

## Developer Experience

*Audited against code 2026-07-21 (LAB-274): py 0.12.0 `config/decorator.py` + `decorators/intent.py`, rs 0.3.0 `intents.rs` + `client.rs` + `cachekit-macros/lib.rs`, ts 0.1.2 `intents.ts` + `cache.ts`.*

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Decorator API | ✅ `@cache` (sync + async fns; zero-arg works) | ✅ `#[cachekit]` proc-macro — async fns returning `Result<T, CachekitError>` only; `client` + `ttl` attributes required | N/A (functional `wrap()` / curried `with()`; `namespace` + `ttl` required per call) | ❌ attributes |
| Intent-based presets | ✅ `.minimal` `.production` `.secure` `.io` (+ Python-only `.dev` `.test` `.local`) | ⚠️ `::minimal` `::production` `::encrypted` `::io` — **no `::secure` preset**; `.secure()` is a post-build accessor that errors unless encryption was configured | ✅ `createCache.minimal()` `.production()` `.secure()` `.io()` | ❌ |
| Builder / config surface | `DecoratorConfig` intent presets + kwargs (frozen dataclass, 6 nested groups) — no builder chain, intentional | ✅ `CacheKit::builder()` / `from_env()` (env: `CACHEKIT_API_KEY/API_URL/MASTER_KEY/DEFAULT_TTL`) | Options object on `createCache()` — no builder chain, no `from_env()` (env fallback only inside `.secure()`/`.io()`) | ❌ |
| Async support | ✅ | ✅ | ✅ | ❌ |
| Sync support | ✅ (same decorator wraps both) | ❌ async-only (all ops `async fn`; macro output requires async) | ❌ | ✅ |
| WASM / CF Workers | N/A | ✅ `workers` feature (`?Send`, `Rc`) | N/A | N/A |
| pydantic-settings config | ✅ (`CACHEKIT_` env prefix, `SecretStr` master key) | N/A — `from_env()` + `Zeroizing` is the Rust idiom | N/A — intentional, per-intent env fallback only | N/A |
| Type hints / strict types | ✅ | ✅ | ✅ | ✅ PHP 8.1+ |

### Intent-preset semantics (parity, not presence)

The shared preset names configure **different things per SDK**:

| Semantic | Python | Rust | TypeScript |
| :--- | :--- | :--- | :--- |
| Preset TTL defaults | **None — entries never expire** unless `ttl=` is passed (all presets) | 300 / 600 / 600 / 3 600 s (minimal/production/encrypted/io) | 300 / 600 / 600 / 3 600 s |
| `minimal`: L1 | **on** (SWR/invalidation off) | **off** (`no_l1()`) | **on** (SWR/invalidation off) |
| `minimal`: integrity checksums | **off** (`integrity_checking=False`) | n/a (values have no envelope) | **on** (ByteStorage on by default) |
| `minimal`: reliability | circuit breaker/timeout off, **backpressure on** | none (fail-fast connect, no reconnect) | circuit breaker neutered (∞ threshold), no retry, degradation off |
| `production`: reliability | circuit breaker + adaptive timeout + backpressure + full monitoring | auto-reconnect only (SDK has no circuit breaker — see [Reliability Features](#reliability-features)) | circuit breaker (threshold 5) + retry (3 attempts) + degradation + metrics |
| Encrypted preset | `.secure(master_key=hex, ≥64 hex chars)`; falls back to `CACHEKIT_MASTER_KEY` | `::encrypted(url, key: &[u8], ≥32 raw bytes)` — arg only, no env fallback | `.secure({ masterKey: hex })`; falls back to `CACHEKIT_MASTER_KEY` |
| Tenancy on encrypted preset | `tenant_extractor` callable, `single_tenant_mode`, `fail_closed` tri-state | fixed `"default"` tenant (override via builder) | `tenantId` string |
| `io`: credentials | `CACHEKIT_API_KEY` env **only** (no kwarg) | `api_key` argument **only** (env only via `from_env()`) | `apiKey` option **or** `CACHEKIT_API_KEY` |
| `CACHEKIT_MASTER_KEY` auto-enables encryption | **all presets** (serialization-handler auto-detect) | only `CacheKit::from_env()` | only `createCache.secure()` |

> [!WARNING]
> Preset names promise more parity than they deliver. The sharpest traps for a cross-SDK
> user: Python preset entries **live forever** where Rust/TypeScript expire in 300–3 600 s;
> Rust's encrypted preset is named `encrypted` (there is no `::secure`, and its `secure()`
> accessor fails without configured encryption — whereas TypeScript's `secure.wrap()`
> silently skips encryption on an unencrypted instance, LAB-513); and the same
> `CACHEKIT_MASTER_KEY` env var activates encryption everywhere in Python, only in
> `from_env()` in Rust, and only in `.secure()` in TypeScript. The canonical preset
> contract is being specified under LAB-514 (epic LAB-105).

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
- Backends: Redis, Memcached, File (local), CacheKit SaaS — Memcached and File auto-detected from environment
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
