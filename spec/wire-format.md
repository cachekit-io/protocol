# Wire Format Specification (ByteStorage Envelope)

**Protocol Version**: 1.0
**Verified Against**: `cachekit-core` v0.1.1 (`src/byte_storage.rs`)

## Overview

CacheKit wraps serialized data in a **StorageEnvelope** that provides LZ4 compression and xxHash3-64 integrity checking. The envelope itself is serialized with MessagePack (via `rmp-serde` in Rust).

## StorageEnvelope Structure

The envelope is a MessagePack map with 4 fields:

```
StorageEnvelope {
    compressed_data: bytes    // LZ4 block-compressed payload
    checksum:        bytes    // xxHash3-64 of ORIGINAL (uncompressed) data, 8 bytes, big-endian
    original_size:   uint32   // Size of data before compression
    format:          string   // Serialization format identifier (e.g., "msgpack")
}
```

### MessagePack Serialization

The envelope is serialized using `rmp-serde` (Rust MessagePack with Serde derive). This produces a standard MessagePack map with string keys:

```
{
    "compressed_data": <bin>,
    "checksum": <bin 8>,
    "original_size": <uint>,
    "format": <str>
}
```

Field names are serialized as MessagePack strings. The order follows Rust struct declaration order (Serde default).

> [!WARNING] Discrepancy with RFC
> The RFC (Section 4.3.3) states the checksum is **Blake3 (32 bytes)**. The actual `cachekit-core` implementation uses **xxHash3-64 (8 bytes)**. The crate comments explain: "xxHash3-64 checksums for corruption detection (19x faster than Blake3)". xxHash3-64 is non-cryptographic -- tamper resistance is provided by the encryption layer (AES-GCM auth tag), not the checksum. **The implementation (xxHash3-64) is authoritative.**

> [!WARNING] Discrepancy with RFC
> The RFC (Section 4.3.4) states the maximum compression ratio is **100x**. The actual `cachekit-core` uses **1000x** (`MAX_COMPRESSION_RATIO: u64 = 1000`). **The implementation (1000x) is authoritative.**

## Byte Layout (Conceptual)

There is no fixed binary layout. The envelope is a MessagePack document. However, the logical byte flow is:

```
+-------------------------------------------------------------------+
| MessagePack Map (4 entries)                                        |
|-------------------------------------------------------------------|
| key: "compressed_data"  | value: <bin> LZ4 block bytes            |
| key: "checksum"         | value: <bin 8> xxHash3-64 BE            |
| key: "original_size"    | value: <uint32>                         |
| key: "format"           | value: <str> e.g. "msgpack"             |
+-------------------------------------------------------------------+
```

## Compression: LZ4 Block Format

**Algorithm**: LZ4 block compression (NOT frame format)

### Requirements

- Use LZ4 **block** format: raw compressed bytes with no framing overhead
- The `original_size` field in the envelope provides the decompression size hint
- LZ4 Frame format (magic number `0x184D2204`) is **FORBIDDEN**

### Library Mapping

| Language | Library | Function | Notes |
|----------|---------|----------|-------|
| Rust | `lz4_flex` | `lz4_flex::compress()` / `decompress()` | Canonical implementation |
| Python | `lz4` | `lz4.block.compress(data, store_size=False)` | `store_size=False` is critical |
| PHP | `php-ext-lz4` (fork) | `lz4_compress_raw()` | Standard `lz4_compress()` adds 4-byte header -- non-compliant |
| Node.js | `lz4js` | `lz4.encode()` | Block format |
| Go | `pierrec/lz4/v4` | `lz4.CompressBlock()` | Block format |

> [!WARNING] PHP
> Standard `php-ext-lz4`'s `lz4_compress()` is **not compliant** -- it prepends a proprietary 4-byte size header. Use `lz4_compress_raw()` from the forked extension at `27Bslash6/php-ext-lz4`.

## Checksum: xxHash3-64

**Algorithm**: xxHash3-64
**Input**: Original uncompressed data (NOT compressed bytes)
**Output**: 8 bytes, big-endian

```rust
let checksum: [u8; 8] = xxh3_64(&original_data).to_be_bytes();
```

### Library Mapping

| Language | Library | Function |
|----------|---------|----------|
| Rust | `xxhash-rust` | `xxh3::xxh3_64()` |
| Python | `xxhash` | `xxhash.xxh3_64(data).digest()` |
| PHP | `php-xxhash` | `xxh3_64()` |
| Node.js | `xxhash-wasm` or `xxhash-addon` | `xxh3_64()` |
| Go | `zeebo/xxh3` | `xxh3.Hash()` |

### Verification Flow

1. Deserialize envelope from MessagePack
2. Validate security limits (see below)
3. Decompress `compressed_data` using `original_size` as size hint
4. Compute `xxh3_64(decompressed_data)` as big-endian 8 bytes
5. Compare with `checksum` field
6. If mismatch: reject data (integrity failure)
7. Verify `decompressed_data.length == original_size`

## Security Limits

These limits MUST be enforced by all SDK implementations:

| Limit | Value | Purpose |
|-------|-------|---------|
| Max uncompressed size | 512 MB | Memory safety |
| Max compressed size | 512 MB | Memory safety |
| Max compression ratio | 1000:1 | Decompression bomb protection |

### Decompression Bomb Detection

The ratio check uses **integer arithmetic** to prevent floating-point precision bypass:

```
if compressed_size == 0:
    REJECT  // Zero-length compressed with non-zero original = bomb

max_allowed = MAX_COMPRESSION_RATIO * compressed_size
if max_allowed overflows:
    REJECT  // Overflow = bomb

if original_size > max_allowed:
    REJECT  // Ratio exceeded
```

## Complete Store Flow

```
Input: raw_data (bytes), format (string, default "msgpack")

1. Validate: raw_data.length <= 512 MB
2. Compress: compressed = lz4_block_compress(raw_data)
3. Validate: compressed.length <= 512 MB
4. Checksum: checksum = xxh3_64(raw_data).to_be_bytes()  // Hash ORIGINAL data
5. Envelope: StorageEnvelope {
       compressed_data: compressed,
       checksum: checksum,         // 8 bytes, big-endian
       original_size: raw_data.length,
       format: format
   }
6. Serialize: envelope_bytes = msgpack_encode(envelope)
7. Validate: envelope_bytes.length <= 512 MB
8. Return: envelope_bytes
```

## Complete Retrieve Flow

```
Input: envelope_bytes

1. Validate: envelope_bytes.length <= 512 MB
2. Deserialize: envelope = msgpack_decode(envelope_bytes) as StorageEnvelope
3. Validate: envelope.compressed_data.length <= 512 MB
4. Validate: envelope.original_size <= 512 MB
5. Bomb check: (see Decompression Bomb Detection above)
6. Decompress: data = lz4_block_decompress(envelope.compressed_data, envelope.original_size)
7. Checksum: computed = xxh3_64(data).to_be_bytes()
8. Verify: computed == envelope.checksum  // Reject on mismatch
9. Size check: data.length == envelope.original_size  // Reject on mismatch
10. Return: (data, envelope.format)
```

## MessagePack Payload Format

When `format` is `"msgpack"`, the decompressed data is a MessagePack document containing user data.

### Type Mapping (StandardSerializer)

| Source Type | MessagePack Type | Notes |
|------------|-----------------|-------|
| `None`/`null`/`nil` | nil | |
| `bool` | bool | |
| `int` | int | Arbitrary precision |
| `float` | float64 | IEEE 754 double |
| `str` | str | UTF-8 |
| `bytes` | bin | |
| `list`/`array` | array | |
| `dict`/`map` | map | |
| `datetime` | map: `{"__datetime__": true, "value": "<ISO-8601>"}` | Extension |
| `date` | map: `{"__date__": true, "value": "<ISO-8601>"}` | Extension |
| `time` | map: `{"__time__": true, "value": "<ISO-8601>"}` | Extension |

### Datetime Extension Format

Datetime values are encoded as MessagePack maps with sentinel keys:

```json
{"__datetime__": true, "value": "2025-11-14T10:30:00+00:00"}
{"__date__": true, "value": "2025-11-14"}
{"__time__": true, "value": "10:30:00"}
```

All SDKs MUST check for these sentinel keys during deserialization and reconstruct the appropriate temporal type.

### MessagePack Options

| Option | Value | Purpose |
|--------|-------|---------|
| `use_bin_type` | `true` | Encode bytes as bin type (not str) |
| `use_list` | `true` | Decode arrays as lists (not tuples) |
| `raw` | `false` | Decode strings as str (not bytes) |
| `strict_types` | `false` | For serialization; allow mixed containers |
