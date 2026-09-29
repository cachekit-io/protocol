# Changelog

All notable changes to the CacheKit Protocol Specification.

## [Unreleased]

New entries go in [`changelog.d/`](changelog.d/README.md), one file per change, and are
collected into a version section here at each release.

<!-- changelog-insert-here -->

## [1.0.0] - 2026-03-28

Initial protocol specification.

### Specs

- Cache key format (Blake2b-256, MessagePack argument normalization)
- Wire format (ByteStorage envelope: LZ4 + xxHash3-64)
- Encryption (AES-256-GCM, HKDF-SHA256, AAD v0x03, deterministic nonce)
- SaaS REST API (endpoints, headers, error codes)
- SDK feature matrix (Python, Rust, TypeScript, PHP)

### Test Vectors

- 10 canonical cache key vectors from Python reference implementation

### Draft

- Interop mode for cross-SDK cache sharing

### Notes

- 7 discrepancies between original RFC and implementation resolved in favor of implementation
