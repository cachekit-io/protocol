# CacheKit Cross-SDK Protocol Specification

**Protocol Version**: 1.0
**License**: MIT
**Status**: Living specification, verified against cachekit-py v0.5.0

This repository defines the canonical protocol for CacheKit SDK interoperability. Any SDK implementation (Python, PHP, TypeScript, Go, Rust) **MUST** pass the canonical test vectors to be considered compliant.

## What This Is

CacheKit is a multi-language caching framework with optional client-side encryption. This protocol spec defines the wire formats, key generation algorithms, and API contracts that enable a cache entry created in one language to be read by another.

## Who This Is For

SDK implementors. If you are building a CacheKit SDK in a new language, these specs are your source of truth.

## Protocol Stack

```
+-----------------------------------------------------------+
| CacheKit Multi-Language Protocol Stack                     |
+-----------------------------------------------------------+
| Layer 4: Encryption        AES-256-GCM (optional)         |
| Layer 3: Wire Format       ByteStorage envelope            |
|                            (LZ4 + xxHash3-64 + MessagePack)|
| Layer 2: Serialization     MessagePack (binary, typed)     |
| Layer 1: Key Generation    Blake2b-256 (deterministic)     |
| Layer 0: Transport         SaaS REST API / Redis           |
+-----------------------------------------------------------+
```

### Data Flow (Write)

```
User data (dict, list, primitives)
  | (MessagePack serialize)
  v
MessagePack bytes
  | (LZ4 block compress)
  v
Compressed bytes + xxHash3-64 checksum of original
  | (wrap in StorageEnvelope, serialize with MessagePack)
  v
Envelope bytes
  | (optional: AES-256-GCM encrypt with AAD)
  v
Stored in cache backend (Redis or SaaS API)
```

### Data Flow (Read)

```
Cache bytes
  | (optional: AES-256-GCM decrypt, verify AAD)
  v
Envelope bytes
  | (MessagePack deserialize envelope)
  v
StorageEnvelope { compressed_data, checksum, original_size, format }
  | (LZ4 decompress, xxHash3-64 verify)
  v
MessagePack bytes
  | (MessagePack deserialize)
  v
User data restored
```

## Specification Files

| File | Contents |
|------|----------|
| [spec/cache-key-format.md](spec/cache-key-format.md) | Cache key generation algorithm (Blake2b, argument normalization) |
| [spec/wire-format.md](spec/wire-format.md) | ByteStorage envelope (LZ4 compression, xxHash3-64 integrity) |
| [spec/encryption.md](spec/encryption.md) | AES-256-GCM encryption, HKDF-SHA256 key derivation, AAD format |
| [spec/saas-api.md](spec/saas-api.md) | REST API endpoints, headers, error codes |
| [sdk-feature-matrix.md](sdk-feature-matrix.md) | Feature parity across SDK implementations |

## Versioning Policy

Protocol versions follow semver:

- **Patch** (1.0.x): Clarifications, typo fixes, additional test vectors. No behavioral changes.
- **Minor** (1.x.0): Backwards-compatible additions (new optional fields, new extension types).
- **Major** (x.0.0): Breaking changes to wire format, key generation, or encryption.

All SDKs targeting protocol v1.0 MUST produce identical cache keys and be able to deserialize each other's payloads (given the same encryption keys, if encrypted).

## Compliance Testing

An SDK is protocol-compliant when:

1. Key generation produces identical keys for identical inputs across all languages
2. ByteStorage envelopes produced by one SDK can be deserialized by any other
3. Encrypted payloads can be decrypted by any SDK with the same master key and tenant ID
4. SaaS API integration follows the documented endpoint contracts

Test vectors will be published in `/tests/vectors/` as YAML files.

## Reference Implementations

- **Python** (`cachekit-py`): Primary reference implementation, Rust core via PyO3
- **Rust** (`cachekit-core` crate on crates.io): Canonical ByteStorage and encryption
