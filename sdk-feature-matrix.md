# SDK Feature Matrix

**Last Updated**: 2026-03-26

## SDK Overview

| SDK | Package | Version | Language | Status |
|-----|---------|---------|----------|--------|
| cachekit-py | `cachekit` (PyPI) | 0.5.0 | Python 3.10+ | Production |
| cachekit-rs | `cachekit-core` (crates.io) | 0.1.1 | Rust 1.82+ | Production (core library) |
| cachekit-ts | -- | -- | TypeScript | Development |
| cachekit-php | -- | -- | PHP 8.1+ | Development |

## Feature Parity

### Core Features

| Feature | Python | Rust (core) | TypeScript | PHP |
|---------|--------|-------------|------------|-----|
| StandardSerializer (MessagePack) | Yes | Yes (via rmp-serde) | Yes | Planned |
| AutoSerializer (Python-specific) | Yes | N/A | N/A | N/A |
| ArrowSerializer (columnar) | Yes | N/A | Planned | No |
| ByteStorage (LZ4 + xxHash3-64) | Yes (via Rust FFI) | Yes (canonical) | Planned | Planned |
| Blake2b-256 key generation | Yes | N/A | Planned | Planned |

### Encryption

| Feature | Python | Rust (core) | TypeScript | PHP |
|---------|--------|-------------|------------|-----|
| AES-256-GCM | Yes (via Rust FFI) | Yes (ring) | Planned | Planned |
| HKDF-SHA256 key derivation | Yes (via Rust FFI) | Yes | Planned | Planned |
| Per-tenant key isolation | Yes | Yes | Planned | Planned |
| AAD v0x03 (cache_key binding) | Yes | Yes | Planned | Planned |
| Key rotation | Yes | Yes | No | No |
| Hardware acceleration detection | Yes | Yes | N/A | N/A |
| Counter-based nonces | Yes (via Rust) | Yes | No (use random) | No (use random) |

### Cache Backends

| Backend | Python | Rust | TypeScript | PHP |
|---------|--------|------|------------|-----|
| Redis (direct) | Yes | Yes | Yes | No |
| CacheKit SaaS (HTTP) | Yes | No | Yes | Planned |
| In-memory (L1) | Yes | No | No | No |
| DynamoDB | Yes | No | No | No |

### Reliability Features

| Feature | Python | Rust | TypeScript | PHP |
|---------|--------|------|------------|-----|
| Circuit breaker | Yes | No | No | No |
| Backpressure | Yes | No | No | No |
| Distributed locking | Yes | No | No | No |
| L1/L2 dual-layer cache | Yes | No | No | No |
| Cache stampede prevention | Yes | No | No | No |
| TTL management | Yes | N/A | Yes | No |

### Developer Experience

| Feature | Python | Rust | TypeScript | PHP |
|---------|--------|------|------------|-----|
| Decorator API (`@cache`) | Yes | Yes (proc-macro) | No | No (attributes) |
| Async support | Yes | Yes | Yes | No |
| Sync support | Yes | Yes | No | Yes |
| pydantic-settings config | Yes | N/A | N/A | N/A |
| Type hints / strict types | Yes | Yes | Yes | Yes (PHP 8.1+) |

## Protocol Compliance

For cross-SDK interoperability, all SDKs MUST implement:

1. **Key Generation**: Blake2b-256 with MessagePack argument serialization (see [cache-key-format.md](spec/cache-key-format.md))
2. **Wire Format**: ByteStorage envelope with LZ4 block + xxHash3-64 (see [wire-format.md](spec/wire-format.md))
3. **Encryption**: AES-256-GCM with HKDF-SHA256 and AAD v0x03 (see [encryption.md](spec/encryption.md))
4. **SaaS API**: REST endpoints per [saas-api.md](spec/saas-api.md)

### Compliance Status

| Requirement | Python | Rust | TypeScript | PHP |
|-------------|--------|------|------------|-----|
| Key generation (Blake2b) | Compliant | N/A | Untested | Untested |
| Wire format (ByteStorage) | Compliant | Compliant (canonical) | Untested | Untested |
| Encryption (AES-256-GCM) | Compliant | Compliant (canonical) | Untested | Untested |
| AAD v0x03 | Compliant | Compliant | Not implemented | Not implemented |
| SaaS API | Compliant | N/A | Partial | Not implemented |
| Test vectors | Pending | Pending | Pending | Pending |

## Architecture Notes

### Python SDK (cachekit-py)

- Hybrid Python-Rust architecture: decorators and orchestration in Python, ByteStorage and encryption in Rust (via PyO3)
- The `cachekit-core` Rust crate is the canonical implementation for compression, checksums, and encryption
- 4 serializers: Standard (cross-language), Auto (Python-optimized), Orjson (JSON), Arrow (columnar)
- Config via pydantic-settings; secrets via `SecretStr`

### Rust Core (cachekit-core)

- Published on crates.io as `cachekit-core` v0.1.1
- Provides: `ByteStorage`, `ZeroKnowledgeEncryptor`, `derive_domain_key`, `derive_tenant_keys`
- Dependencies: `lz4_flex`, `xxhash-rust`, `ring`, `hkdf`, `sha2`, `rmp-serde`
- Formally verified security properties via Kani

### TypeScript SDK (cachekit-ts)

- Redis backend via ioredis
- CacheKit SaaS backend via fetch API
- Encryption via Web Crypto API (AES-256-GCM)

### PHP SDK (cachekit-php)

- Targets PHP 8.1+ with ext-msgpack and paragonie/sodium_compat
- LZ4 via forked php-ext-lz4 (`lz4_compress_raw()`)
- Blake2b via ext-sodium or dedicated Blake2b extension
