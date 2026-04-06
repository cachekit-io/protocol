**[Protocol](README.md)** > **SDK Feature Matrix**

<div align="center">

# SDK Feature Matrix

**Feature parity and compliance status across all CacheKit SDK implementations.**

*Last updated: 2026-04-06*

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
| cachekit-py | `cachekit` (PyPI) | 0.5.0 | Python 3.10+ | ✅ Production |
| cachekit-rs | `cachekit-core` (crates.io) | 0.1.1 | Rust 1.82+ | ✅ Production (core lib) |
| cachekit-ts | `@cachekit-io/cachekit` (npm) | 0.1.0 | TypeScript | ✅ Production |
| cachekit-php | — | — | PHP 8.1+ | 🔜 Development |

---

## Core Features

| Feature | Python | Rust (core) | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| StandardSerializer (MessagePack) | ✅ | ✅ via rmp-serde | ✅ | 🔜 Planned |
| AutoSerializer (Python-specific) | ✅ | N/A | N/A | N/A |
| ArrowSerializer (columnar) | ✅ | N/A | 🔜 Planned | ❌ |
| ByteStorage (LZ4 + xxHash3-64) | ✅ via Rust FFI | ✅ canonical | ✅ via NAPI (Rust) | 🔜 Planned |
| Blake2b-256 key generation | ✅ | N/A | ✅ via @noble/hashes | 🔜 Planned |

---

## Encryption

| Feature | Python | Rust (core) | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| AES-256-GCM | ✅ via Rust FFI | ✅ ring | ✅ via NAPI (Rust) | 🔜 Planned |
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
| Redis (direct) | ✅ | ✅ | ✅ | ❌ |
| CacheKit SaaS (HTTP) | ✅ | ❌ | ✅ | 🔜 Planned |
| DynamoDB | ✅ | ❌ | ❌ | ❌ |

---

## Reliability Features

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Circuit breaker | ✅ | ❌ | ✅ | ❌ |
| Backpressure | ✅ | ❌ | ⚠️ Concurrent refresh limits | ❌ |
| Distributed locking | ✅ | ❌ | ✅ SaaS backend only | ❌ |
| L1/L2 dual-layer cache | ✅ | ❌ | ✅ | ❌ |
| Cache stampede prevention | ✅ | ❌ | ✅ Version tokens + SWR | ❌ |
| TTL management | ✅ | N/A | ✅ | ❌ |

---

## Developer Experience

| Feature | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Decorator API (`@cache`) | ✅ | ✅ proc-macro | N/A (functional `wrap()` API) | ❌ attributes |
| Async support | ✅ | ✅ | ✅ | ❌ |
| Sync support | ✅ | ✅ | ❌ | ✅ |
| pydantic-settings config | ✅ | N/A | N/A | N/A |
| Type hints / strict types | ✅ | ✅ | ✅ | ✅ PHP 8.1+ |

---

## Protocol Compliance

For cross-SDK interoperability, all SDKs MUST implement:

1. **Key Generation** — Blake2b-256 with MessagePack argument serialization ([spec/cache-key-format.md](spec/cache-key-format.md))
2. **Wire Format** — ByteStorage envelope with LZ4 block + xxHash3-64 ([spec/wire-format.md](spec/wire-format.md))
3. **Encryption** — AES-256-GCM with HKDF-SHA256 and AAD v0x03 ([spec/encryption.md](spec/encryption.md))
4. **SaaS API** — REST endpoints per [spec/saas-api.md](spec/saas-api.md)

### Compliance Status

| Requirement | Python | Rust | TypeScript | PHP |
| :--- | :---: | :---: | :---: | :---: |
| Key generation (Blake2b) | ✅ Compliant | N/A | ✅ Compliant | ⚠️ Untested |
| Wire format (ByteStorage) | ✅ Compliant | ✅ Canonical | ✅ Compliant | ⚠️ Untested |
| Encryption (AES-256-GCM) | ✅ Compliant | ✅ Canonical | ✅ Compliant | ⚠️ Untested |
| AAD v0x03 | ✅ Compliant | ✅ Compliant | ✅ Compliant | ❌ Not implemented |
| SaaS API | ✅ Compliant | N/A | ✅ Compliant | ❌ Not implemented |
| Test vectors | ⚠️ Pending | ⚠️ Pending | ✅ Python cross-SDK vectors | ⚠️ Pending |

> [!NOTE]
> "N/A" for Rust key generation means the `cachekit-core` crate is a protocol primitive library, not a full SDK. Key generation is the responsibility of the higher-level `cachekit-rs` crate.

---

## Architecture Notes

<details>
<summary><strong>Python SDK (cachekit-py)</strong></summary>

- Hybrid Python-Rust architecture: decorators and orchestration in Python, ByteStorage and encryption in Rust (via PyO3)
- The `cachekit-core` Rust crate is the canonical implementation for compression, checksums, and encryption
- 4 serializers: Standard (cross-language), Auto (Python-optimized), Orjson (JSON), Arrow (columnar)
- Config via pydantic-settings; secrets via `SecretStr`

</details>

<details>
<summary><strong>Rust Core (cachekit-core)</strong></summary>

- Published on crates.io as `cachekit-core` v0.1.1
- Provides: `ByteStorage`, `ZeroKnowledgeEncryptor`, `derive_domain_key`, `derive_tenant_keys`
- Dependencies: `lz4_flex`, `xxhash-rust`, `ring`, `hkdf`, `sha2`, `rmp-serde`
- Formally verified security properties via Kani

</details>

<details>
<summary><strong>TypeScript SDK (cachekit-ts)</strong></summary>

- Monorepo: `@cachekit-io/cachekit` (SDK) + `@cachekit-io/cachekit-core-ts` (Rust NAPI bindings)
- Redis backend via ioredis, CacheKit SaaS backend via fetch API
- Encryption via Rust NAPI (AES-256-GCM, HKDF-SHA256, counter-based nonces)
- AAD v0x03 compliant with Python cross-SDK test vectors
- L1 LRU cache with SWR, version tokens, namespace invalidation
- Circuit breaker (rolling window), retry (exponential backoff + jitter), graceful degradation
- Distributed locking via CacheKit SaaS backend
- 442 tests, 93.75% statement coverage
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
