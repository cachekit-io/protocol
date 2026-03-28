<div align="center">

# CacheKit Cross-SDK Protocol Specification

**The wire format, key generation, and API contracts that enable cross-language cache sharing.**

[![Protocol Version](https://img.shields.io/badge/protocol-v1.0-blue)](#versioning-policy)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-living%20spec-orange)](#versioning-policy)

</div>

---

## Table of Contents

- [What This Is](#what-this-is)
- [Protocol Stack](#protocol-stack)
- [Specification Files](#specification-files)
- [Quick Start for SDK Implementors](#quick-start-for-sdk-implementors)
- [Versioning Policy](#versioning-policy)
- [Compliance Testing](#compliance-testing)
- [Reference Implementations](#reference-implementations)

---

## What This Is

CacheKit is a multi-language caching framework with optional client-side encryption. This repository defines the canonical protocol for cross-SDK interoperability — the contracts that let a cache entry written by Python be read by Rust, TypeScript, or PHP.

Any SDK implementation **MUST** pass the canonical test vectors to be considered compliant.

> [!IMPORTANT]
> This spec is verified against the actual implementations, not the original RFC. Where discrepancies exist between the RFC and the implementation, **the implementation is authoritative**. Each spec file notes the exact divergences.

---

## Protocol Stack

```
┌─────────────────────────────────────────────────────────────┐
│              CacheKit Multi-Language Protocol Stack          │
├────────────────────────┬────────────────────────────────────┤
│  Layer 4: Encryption   │  AES-256-GCM (optional)            │
│  Layer 3: Wire Format  │  ByteStorage envelope              │
│                        │  (LZ4 block + xxHash3-64 + MsgPack)│
│  Layer 2: Serialization│  MessagePack (binary, typed)       │
│  Layer 1: Key Gen      │  Blake2b-256 (deterministic)       │
│  Layer 0: Transport    │  SaaS REST API / Redis             │
└────────────────────────┴────────────────────────────────────┘
```

### Data Flow (Write)

```
User data (dict, list, primitives)
  │
  │  MessagePack serialize
  ▼
MessagePack bytes
  │
  │  LZ4 block compress
  ▼
Compressed bytes + xxHash3-64 checksum of original
  │
  │  Wrap in StorageEnvelope, serialize with MessagePack
  ▼
Envelope bytes
  │
  │  [optional] AES-256-GCM encrypt with AAD
  ▼
Stored in cache backend (Redis or SaaS API)
```

### Data Flow (Read)

```
Cache bytes
  │
  │  [optional] AES-256-GCM decrypt, verify AAD
  ▼
Envelope bytes
  │
  │  MessagePack deserialize envelope
  ▼
StorageEnvelope { compressed_data, checksum, original_size, format }
  │
  │  LZ4 decompress, xxHash3-64 verify
  ▼
MessagePack bytes
  │
  │  MessagePack deserialize
  ▼
User data restored
```

---

## Specification Files

| File | Description |
| :--- | :--- |
| [spec/cache-key-format.md](spec/cache-key-format.md) | Cache key generation algorithm — Blake2b-256, argument normalization, cross-SDK key strategy |
| [spec/wire-format.md](spec/wire-format.md) | ByteStorage envelope — LZ4 block compression, xxHash3-64 integrity, decompression bomb protection |
| [spec/encryption.md](spec/encryption.md) | AES-256-GCM encryption, HKDF-SHA256 key derivation, AAD v0x03, counter-based nonces, key rotation |
| [spec/saas-api.md](spec/saas-api.md) | REST API endpoints, binary wire protocol, error codes, metrics headers |
| [spec/interop-mode.md](spec/interop-mode.md) | Cross-SDK cache sharing — language-neutral key format, canonical argument normalization *(draft)* |
| [sdk-feature-matrix.md](sdk-feature-matrix.md) | Feature parity tracking across Python, Rust, TypeScript, and PHP SDKs |

---

## Quick Start for SDK Implementors

Building a new SDK? Implement in this order:

**1. Key Generation** — [spec/cache-key-format.md](spec/cache-key-format.md)

Generate deterministic cache keys from function identity + arguments. Keys must match across SDKs for cross-language cache sharing.

**2. Wire Format** — [spec/wire-format.md](spec/wire-format.md)

Wrap serialized data in a `StorageEnvelope`. LZ4 block compression + xxHash3-64 integrity check. This is the payload stored in the backend.

**3. Encryption (optional)** — [spec/encryption.md](spec/encryption.md)

Client-side AES-256-GCM with HKDF-SHA256 key derivation. The backend stores opaque ciphertext. AAD v0x03 binds ciphertext to its intended key (critical for security).

**4. SaaS API** — [spec/saas-api.md](spec/saas-api.md)

PUT/GET/DELETE binary blobs at `/v1/cache/{key}`. The API is format-agnostic — it stores whatever bytes you send.

> [!TIP]
> Start by running the test vectors in `test-vectors/` against each layer independently. Pass key generation first, then wire format, then encryption. Each layer can be validated in isolation.

> [!NOTE]
> For cross-SDK cache sharing (Python writes, Rust reads), see [spec/interop-mode.md](spec/interop-mode.md). The default key format includes language-specific function identity, so cross-language sharing requires explicit interop keys.

---

## Versioning Policy

Protocol versions follow semver:

| Bump | Trigger | Compatibility |
| :---: | :--- | :--- |
| **Patch** `1.0.x` | Clarifications, typo fixes, additional test vectors | No behavioral changes |
| **Minor** `1.x.0` | New optional fields, new extension types | Backwards-compatible additions |
| **Major** `x.0.0` | Wire format, key generation, or encryption changes | Breaking — all SDKs must update |

All SDKs targeting protocol v1.0 **MUST** produce identical cache keys and be able to deserialize each other's payloads (given the same encryption keys, if encrypted).

---

## Compliance Testing

An SDK is protocol-compliant when:

1. Key generation produces identical keys for identical inputs across all languages
2. ByteStorage envelopes produced by one SDK can be deserialized by any other
3. Encrypted payloads can be decrypted by any SDK with the same master key and tenant ID
4. SaaS API integration follows the documented endpoint contracts

Test vectors are published in [`test-vectors/`](test-vectors/) as YAML files.

> [!CAUTION]
> Self-referential tests (SDK encrypts and decrypts its own output) are not sufficient for compliance certification. Use the canonical cross-SDK test vectors to validate interoperability.

---

## Reference Implementations

| SDK | Package | Role |
| :--- | :--- | :--- |
| **Python** (`cachekit-py`) | `cachekit` on PyPI | Primary reference implementation, Rust core via PyO3 |
| **Rust** (`cachekit-core`) | `cachekit-core` on crates.io | Canonical ByteStorage and encryption primitives |

---

<div align="center">

[Protocol Repo](https://github.com/cachekit-io/protocol) · [SDK Feature Matrix](sdk-feature-matrix.md) · [Cache Key Format](spec/cache-key-format.md) · [Wire Format](spec/wire-format.md) · [Encryption](spec/encryption.md) · [SaaS API](spec/saas-api.md)

</div>
