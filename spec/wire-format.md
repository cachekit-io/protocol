**[Protocol](../README.md)** > **Wire Format**

<div align="center">

# Wire Format Specification (ByteStorage Envelope)

**LZ4 compression + xxHash3-64 integrity wrapping for cached payloads that use the envelope.**

*Protocol Version 1.1 · Verified against `cachekit-core` v0.4.0 (`src/byte_storage.rs`); legacy envelope test vectors generated at v0.2.0 and unchanged since — `bin`-encoded twins added in protocol 1.1 ([decisions/envelope-bin-encoding.md](../decisions/envelope-bin-encoding.md))*

</div>

---

## Table of Contents

- [Scope](#scope)
- [StorageEnvelope Structure](#storageenvelope-structure)
- [Compression: LZ4 Block Format](#compression-lz4-block-format)
- [Checksum: xxHash3-64](#checksum-xxhash3-64)
- [Security Limits](#security-limits)
- [Store Flow](#store-flow)
- [Retrieve Flow](#retrieve-flow)
- [MessagePack Payload Format](#messagepack-payload-format)
- [SDK Storage Containers (auto mode)](#sdk-storage-containers-auto-mode)

---

## Scope

This document specifies two layers:

1. **The ByteStorage envelope** — the LZ4 + xxHash3-64 container implemented by
   `cachekit-core` and exposed to SDKs. This layer is byte-canonical and pinned by
   [`test-vectors/wire-format.json`](../test-vectors/wire-format.json), which is
   enforced in CI in two independent places (LAB-423): this repo's `verify.yml`
   runs [`tools/wire-format-reference.py verify`](../tools/wire-format-reference.py)
   against the stdlib-only reference implementation, and the canonical
   implementation [`cachekit-core`](https://github.com/cachekit-io/cachekit-core)
   vendors the file sha256-pinned in `tests/wire_format_vectors.rs`, asserting
   decode byte-identity for every vector and re-encode byte-identity for the
   canonical `*_bin` vectors only — legacy array-of-integers vectors are
   decode-only, retained as legacy-read proof.
2. **[SDK storage containers](#sdk-storage-containers-auto-mode)** — what each SDK
   *actually stores* in a backend in default (auto) mode. These differ per SDK, are
   **SDK-internal**, and are documented here so their bytes are identifiable — not so
   other SDKs implement them.

> [!IMPORTANT]
> **Auto-mode stored bytes are not cross-SDK.** No SDK reads another SDK's auto-mode
> entries — the key formats already diverge per language, and the value containers
> below diverge too. The only cross-SDK value format is
> [interop mode](interop-mode.md): plain MessagePack, no envelope, no container.
> This is the resolution of
> [protocol#11](https://github.com/cachekit-io/protocol/issues/11).

---

## StorageEnvelope Structure

CacheKit wraps serialized data in a **StorageEnvelope** that provides LZ4 compression and xxHash3-64 integrity checking. The envelope itself is serialized with MessagePack via `rmp_serde::to_vec` in Rust.

The envelope has 4 logical fields:

```
StorageEnvelope {
    compressed_data: bytes    // LZ4 block-compressed payload
    checksum:        bytes    // xxHash3-64 of ORIGINAL (uncompressed) data, 8 bytes, big-endian
    original_size:   uint32   // Size of data before compression
    format:          string   // Serialization format identifier (e.g., "msgpack")
}
```

### Byte Layout (canonical encoding)

`rmp_serde::to_vec` encodes the struct **positionally** — a 4-element MessagePack
**array**, not a named map:

```text
┌─────────────────────────────────────────────────────────────────────┐
│                   MessagePack Array (4 elements)                    │
├───────────────────┬─────────────────────────────────────────────────┤
│ [0] compressed_data │ <bin> LZ4 block bytes (0xc4/0xc5/0xc6)          │
│ [1] checksum        │ <array of 8 uint> xxHash3-64, big-endian        │
│ [2] original_size   │ <uint> bytes before compression                 │
│ [3] format          │ <str>  e.g. "msgpack"                           │
└───────────────────┴─────────────────────────────────────────────────┘
```

As of **protocol 1.1**, writers MUST encode `compressed_data` (element `[0]`) as
MessagePack **`bin`** (`0xc4`/`0xc5`/`0xc6`, shortest form). Readers MUST **also**
accept the legacy encoding below — a stored envelope never expires on a schedule,
so legacy-read support is permanent.

> [!NOTE]
> **Implementation status** (verified against published artifacts, 2026-08-04):
> the canonical `bin` encoding **is** shipped — `cachekit-core` v0.4.0 carries the
> writer flip, `cachekit` (Python) ≥ 0.17.0 emits it, and `cachekit-rs` ≥ 0.6.0
> resolves core `0.4` and emits it too. **TypeScript does not yet emit it on
> either path:** published `@cachekit-io/cachekit` 0.1.5 pins
> `@cachekit-io/cachekit-core-ts@0.1.2` (whose native addons embed core **0.2.0**) and
> `@cachekit-io/cachekit-core-wasm@0.1.1` (core **0.3.0**), so it writes and reads legacy only.
> Readers therefore encounter both encodings on the wire today, and a reader built
> against core ≤ 0.3.0 rejects `bin` — which is why legacy-read support is
> permanent rather than a migration window. Per-SDK rollout state, with the
> embedded-core evidence per artifact, is tabulated in
> [sdk-feature-matrix.md](../sdk-feature-matrix.md#architecture-notes).

`checksum` (element `[1]`) is **deliberately excluded** from the `bin` encoding: it
stays an array of 8 integers. The saving would be 1–7 bytes per envelope, and the
field is crypto-adjacent surface — not worth touching
([decisions/envelope-bin-encoding.md](../decisions/envelope-bin-encoding.md)).
`original_size`, `format`, and the outer `fixarray(4)` are likewise unchanged.

#### Legacy element[0] encoding (pre-1.1 writers)

Because the pre-1.1 `StorageEnvelope` routed `Vec<u8>` through Serde's
`serialize_seq`, `compressed_data` was encoded as a **MessagePack array of
integers** — one element per byte, 2 bytes on the wire for any byte ≥ `0x80`.
The envelope's logical contents are identical in both encodings; motivation and
measurements live in
[decisions/envelope-bin-encoding.md](../decisions/envelope-bin-encoding.md).

Worked example — the `simple_string` vector pair from
[`test-vectors/wire-format.json`](../test-vectors/wire-format.json), input
`"hello, cachekit!"` (16 bytes), in both encodings:

```text
Legacy (array-of-ints, pre-1.1 writers — vector `simple_string`, 44 B):
94                                        fixarray(4)
  dc 0012                                 array16(18)          compressed_data
    cc f0                                 uint8 240              LZ4 token (15 literals + ext)
    01                                    fixint 1               literal-length extension (15+1=16)
    68 65 6c 6c 6f 2c 20 63               fixints                16 literal bytes
    61 63 68 65 6b 69 74 21                                      "hello, cachekit!"
  98                                      fixarray(8)          checksum
    6d cc8a 34 ccb6 3a 3c 52 ccd3                                6d 8a 34 b6 3a 3c 52 d3
  10                                      fixint 16            original_size
  a7 6d 73 67 70 61 63 6b                 fixstr(7)            format = "msgpack"

Canonical (bin, 1.1+ writers — vector `simple_string_bin`, 42 B):
94                                        fixarray(4)
  c4 12                                   bin8(18)             compressed_data
    f0 01 68 65 6c 6c 6f 2c               raw bytes              same 18 LZ4 bytes,
    20 63 61 63 68 65 6b 69 74 21                                1 byte each on the wire
  98                                      fixarray(8)          checksum (unchanged)
    6d cc8a 34 ccb6 3a 3c 52 ccd3                                6d 8a 34 b6 3a 3c 52 d3
  10                                      fixint 16            original_size (unchanged)
  a7 6d 73 67 70 61 63 6b                 fixstr(7)            format = "msgpack" (unchanged)
```

### Encoding compatibility (dual-read)

The two encodings are **mutually intelligible in both directions** under
`rmp-serde` — this is a property of the deployed readers, not a migration
promise. Toolchain-verified (rmp-serde 1.3.1, serde_bytes 0.11.19, rmp 0.8.15,
serde 1.0.228) on all six byte-pinned vectors, including `bin` wire fed through
the shipped `ByteStorage::retrieve()` with checksum validation and
decompression-ratio guards intact (LAB-764):

| Reader | Legacy wire (array-of-ints) | Canonical wire (`bin`) |
| :--- | :---: | :---: |
| Pre-flip (plain `Vec<u8>`, shipped today) | ✅ status quo | ✅ |
| Post-flip (`serde_bytes`) | ✅ | ✅ |

Consequences:

- **This is not a breaking change, and no version field or discriminator is
  introduced.** The MessagePack marker on element `[0]` is self-describing;
  the outer envelope shape is unchanged.
- The envelope codec is **single-sourced in `cachekit-core`** — every SDK
  (py via FFI, ts via NAPI and wasm32) reaches it through the Rust core, and
  `cachekit-rs` does not use the envelope for values at all. No SDK hand-parses
  the envelope. Any future non-`rmp-serde` implementation is bound by the same
  reader requirement stated under [Byte Layout](#byte-layout-canonical-encoding).
- **Encrypted entries are unaffected structurally**: the envelope bytes are the
  AES-GCM *plaintext*, and [AAD v0x03](encryption.md#additional-authenticated-data-aad)
  is built exclusively from metadata (`tenant_id`, `cache_key`, `format` token,
  `compressed` token, optional `original_type`) — no envelope bytes feed the AAD,
  and the flip introduces no new `format` token. A stored entry decrypts to the
  envelope encoding it was written with; the dual-read rule then applies. No
  re-encryption, no AAD change.

> [!NOTE]
> **Size micro-regression on tiny envelopes.** The only length tier where `bin`
> loses is `compressed_data` ≤ 15 bytes (bin8 header 2 B vs fixarray 1 B), so an
> envelope can **grow by at most 1 byte** — and only when no payload byte is
> ≥ `0x80` (measured: the `empty` vector grows 25 → 26 B; `single_byte` is
> unchanged at 27 B). Every other envelope shrinks or stays equal; measured wins
> are in [decisions/envelope-bin-encoding.md](../decisions/envelope-bin-encoding.md).

Both encodings are pinned by
[`test-vectors/wire-format.json`](../test-vectors/wire-format.json): the legacy
vectors are retained **forever** as legacy-read proof, and each has a `*_bin`
twin appended in protocol 1.1 (marked `"envelope_encoding": "bin"`). The fixture
is append-only and verified in this repo's CI by
[`tools/wire-format-reference.py`](../tools/wire-format-reference.py); vector
provenance and the downstream re-pin plan live in
[decisions/envelope-bin-encoding.md](../decisions/envelope-bin-encoding.md).

> [!WARNING]
> **History.** Earlier revisions of this document described the envelope as a
> MessagePack *map* with `bin`-encoded byte fields — **that was never what
> `cachekit-core` emitted** (the envelope has always been the positional array
> above; protocol#11 corrected the prose). Writers emitted the array-of-ints
> element-`[0]` encoding through protocol 1.0; protocol 1.1 makes `bin` the
> canonical writer encoding for `compressed_data` only. `checksum` remains an
> array of integers in **both** revisions — a reader MUST NOT expect `bin` there.

> [!WARNING]
> **Discrepancy with RFC** — The RFC (Section 4.3.3) states the checksum is **Blake3 (32 bytes)**. The actual `cachekit-core` implementation uses **xxHash3-64 (8 bytes)**. The crate comments explain: "xxHash3-64 checksums for corruption detection (19x faster than Blake3)". xxHash3-64 is non-cryptographic — tamper resistance is provided by the encryption layer (AES-GCM auth tag), not the checksum. **The implementation (xxHash3-64) is authoritative.**

> [!NOTE]
> **Discrepancy with RFC** — The RFC (Section 4.3.4) states the maximum compression ratio is **100x**. The actual `cachekit-core` uses **1000x** (`MAX_COMPRESSION_RATIO: u64 = 1000`). **The implementation (1000x) is authoritative.**

---

## Compression: LZ4 Block Format

**Algorithm**: LZ4 block compression (NOT LZ4 frame format)

> [!CAUTION]
> Use LZ4 **block** format exclusively. LZ4 frame format (magic number `0x184D2204`) is **FORBIDDEN** — it adds framing overhead and produces incompatible output. The `original_size` field in the envelope provides the decompression size hint, replacing the size stored in frame headers.

### Library Mapping

| Language | Library | Function | Notes |
| :--- | :--- | :--- | :--- |
| Rust | `lz4_flex` | `lz4_flex::compress()` / `decompress()` | ✅ Canonical |
| Python | `lz4` | `lz4.block.compress(data, store_size=False)` | `store_size=False` is critical |
| PHP | `php-ext-lz4` (fork) | `lz4_compress_raw()` | See warning below |
| Node.js | `lz4js` | `lz4.encode()` | Block format |
| Go | `pierrec/lz4/v4` | `lz4.CompressBlock()` | Block format |

> [!WARNING]
> **PHP**: Standard `php-ext-lz4`'s `lz4_compress()` is **not compliant** — it prepends a proprietary 4-byte size header. Use `lz4_compress_raw()` from the forked extension at `27Bslash6/php-ext-lz4`.

---

## Checksum: xxHash3-64

| Property | Value |
| :--- | :--- |
| Algorithm | xxHash3-64 |
| Input | Original **uncompressed** data |
| Output | 8 bytes, big-endian |

```rust
let checksum: [u8; 8] = xxh3_64(&original_data).to_be_bytes();
```

### Library Mapping

| Language | Library | Function |
| :--- | :--- | :--- |
| Rust | `xxhash-rust` | `xxh3::xxh3_64()` |
| Python | `xxhash` | `xxhash.xxh3_64(data).digest()` |
| PHP | `php-xxhash` | `xxh3_64()` |
| Node.js | `xxhash-wasm` or `xxhash-addon` | `xxh3_64()` |
| Go | `zeebo/xxh3` | `xxh3.Hash()` |

### Verification Flow

```
1. Deserialize envelope from MessagePack
2. Validate security limits (see below)
3. Decompress compressed_data using original_size as size hint
4. Compute xxh3_64(decompressed_data) as big-endian 8 bytes
5. Compare with checksum field
6. If mismatch → reject (integrity failure)
7. Verify decompressed_data.length == original_size
```

---

## Security Limits

> [!IMPORTANT]
> All three limits below MUST be enforced by every implementation of the ByteStorage envelope. The decompression bomb check uses integer arithmetic — do not substitute floating-point.
> Additionally, a decoder MUST validate any declared MessagePack `bin`/array
> length header against the remaining input bytes **before** allocating for it —
> a 5-byte `bin32` header can otherwise declare a 4 GiB allocation from a
> ~30-byte envelope. (Slice-based decoders such as `rmp-serde` satisfy this
> inherently; readers that pre-allocate from length fields must check.)

| Limit | Value | Purpose |
| :--- | ---: | :--- |
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

---

## Store Flow

<details>
<summary>Expand full store algorithm</summary>

```
Input: raw_data (bytes), format (string, default "msgpack")

1. Validate:  raw_data.length <= 512 MB
2. Compress:  compressed = lz4_block_compress(raw_data)
3. Validate:  compressed.length <= 512 MB
4. Checksum:  checksum = xxh3_64(raw_data).to_be_bytes()  // Hash ORIGINAL
5. Envelope:  StorageEnvelope {
                  compressed_data: compressed,
                  checksum:        checksum,    // 8 bytes, big-endian
                  original_size:   raw_data.length,
                  format:          format
              }
6. Serialize: envelope_bytes = msgpack_encode(envelope)   // compressed_data as bin (1.1+)
7. Validate:  envelope_bytes.length <= 512 MB
8. Return:    envelope_bytes
```

</details>

---

## Retrieve Flow

<details>
<summary>Expand full retrieve algorithm</summary>

```
Input: envelope_bytes

1.  Validate:    envelope_bytes.length <= 512 MB
2.  Deserialize: envelope = msgpack_decode(envelope_bytes) as StorageEnvelope
                 // accept BOTH element[0] encodings: bin AND array-of-ints
3.  Validate:    envelope.compressed_data.length <= 512 MB
4.  Validate:    envelope.original_size <= 512 MB
5.  Bomb check:  (see Security Limits above)
6.  Decompress:  data = lz4_block_decompress(envelope.compressed_data, envelope.original_size)
7.  Checksum:    computed = xxh3_64(data).to_be_bytes()
8.  Verify:      computed == envelope.checksum    // Reject on mismatch
9.  Size check:  data.length == envelope.original_size  // Reject on mismatch
10. Return:      (data, envelope.format)
```

</details>

---

## MessagePack Payload Format

When `format` is `"msgpack"`, the decompressed data is a MessagePack document containing user data.

### Type Mapping (StandardSerializer)

| Source Type | MessagePack Type | Notes |
| :--- | :--- | :--- |
| `None`/`null`/`nil` | nil | |
| `bool` | bool | |
| `int` | int | Arbitrary precision |
| `float` | float64 | IEEE 754 double |
| `str` | str | UTF-8 |
| `bytes` | bin | |
| `list`/`array` | array | |
| `dict`/`map` | map | |
| `datetime` | map: `{"__datetime__": true, "value": "<ISO-8601>"}` | Extension type |
| `date` | map: `{"__date__": true, "value": "<ISO-8601>"}` | Extension type |
| `time` | map: `{"__time__": true, "value": "<ISO-8601>"}` | Extension type |

### Datetime Extension Format

Datetime values are encoded as MessagePack maps with sentinel keys:

```json
{"__datetime__": true, "value": "2025-11-14T10:30:00+00:00"}
{"__date__":     true, "value": "2025-11-14"}
{"__time__":     true, "value": "10:30:00"}
```

> [!IMPORTANT]
> All SDKs MUST check for these sentinel keys during deserialization and reconstruct the appropriate temporal type. Failing to handle them means datetime values will be returned as raw maps instead of native date objects.

### MessagePack Options

| Option | Value | Purpose |
| :--- | :---: | :--- |
| `use_bin_type` | `true` | Encode bytes as bin type (not str) |
| `use_list` | `true` | Decode arrays as lists (not tuples) |
| `raw` | `false` | Decode strings as str (not bytes) |
| `strict_types` | `false` | Allow mixed containers during serialization |

---

## SDK Storage Containers (auto mode)

Remote backends (Redis, CachekitIO SaaS, Memcached, File) store opaque bytes. (L1
behavior is SDK-specific: `cachekit-py`'s L1 holds the framed bytes; `cachekit-ts`'s
L1 holds live decoded values, not bytes.) What the stored bytes *are* differs per
SDK in auto mode:

| SDK | Stored bytes (plaintext) | Stored bytes (encrypted) |
| :--- | :--- | :--- |
| **Python** (`cachekit-py`) | **CK v3 frame** wrapping the serializer output (see below) | CK v3 frame wrapping the ciphertext ([encryption.md](encryption.md)) |
| **TypeScript** (`cachekit-ts`) | Bare ByteStorage envelope (default, `compression: true`); plain MessagePack when `compression: false` | AES-GCM ciphertext over the above |
| **Rust** (`cachekit-rs`) | Plain MessagePack (`rmp_serde::to_vec_named`) — **no envelope** | AES-GCM ciphertext over plain MessagePack |

These containers are **SDK-internal**. They exist for each SDK's own reads; they are
documented so their bytes are identifiable, and so this specification matches the
implementations ([protocol#11](https://github.com/cachekit-io/protocol/issues/11)).

> [!IMPORTANT]
> **Decision (protocol#11):** the CK v3 frame and the Arrow envelope are NOT
> cross-SDK wire formats and never will be — cross-SDK sharing goes through
> [interop mode](interop-mode.md) exclusively. An SDK MUST NOT decode another
> SDK's auto-mode container. An SDK MAY parse a foreign container *for diagnostics
> only*, using the layouts below.

### Python: CK v3 frame

Every **auto-mode** value `cachekit-py` stores — all backends, all serializers,
encrypted or not — is framed (interop-mode values are plain MessagePack, never
framed):

```text
MAGIC b"CK" (0x43 0x4B) | VERSION u8 (0x03) | HDR_LEN u32 big-endian | HEADER | PAYLOAD
```

- **HEADER**: UTF-8 JSON object `{"s": <serializer name>, "m": <metadata object>, "v": <envelope version string>}`,
  exactly `HDR_LEN` bytes. Typical metadata keys: `format`, `encoding`, `compressed`,
  `encrypted`, `original_type`.
- **PAYLOAD**: the serializer output, raw (no base64), extending to the end of the value:

| Header `s` | Payload (integrity checking on — the default) |
| :--- | :--- |
| `default`, `auto` | ByteStorage envelope (this document) over MessagePack |
| `arrow` | **Arrow envelope**: `[8-byte xxHash3-64 checksum][Arrow IPC file]` (IPC magic `b"ARROW1"` at payload offset 8) |
| `orjson` | `[8-byte xxHash3-64 checksum][JSON bytes]` |
| any, encrypted | Ciphertext per [encryption.md](encryption.md) |

With integrity checking disabled, `default`/`auto` payloads are raw MessagePack (no
ByteStorage envelope) and `orjson` payloads are raw JSON (no checksum prefix); the
**`arrow` checksum prefix is unconditional** — ArrowSerializer always writes and
validates it regardless of the integrity flag. The frame header's `m` metadata
carries the flags either way. The header's `v` is the Python wrapper's own logical
envelope version string (currently `"2.0"`) — it is unrelated to the frame VERSION
byte (`0x03`) and readers do not validate it.

A reader MUST reject: frames shorter than the 7-byte fixed prefix, `VERSION != 3`,
and a declared `HDR_LEN` that overruns the value. (`cachekit-py` additionally reads a
legacy base64-in-JSON envelope, first byte `{` — pre-v3 entries only; new writes are
always v3 frames.)

> [!CAUTION]
> **The frame header is plaintext and unauthenticated — even for encrypted entries.**
> The AAD (v0x03, [encryption.md](encryption.md)) binds tenant, cache key, format,
> and compression flags into the AES-GCM tag, but the CK header JSON itself is
> outside that binding. Two consequences are normative:
>
> 1. A reader configured for encryption MUST NOT let the header's `encrypted` /
>    `s` / `m` values downgrade it to a non-authenticated read path. If the cache
>    is configured encrypted and an entry does not authenticate as ciphertext,
>    the read MUST fail closed — an attacker with backend write access (the
>    CVSS 8.5 actor in encryption.md's threat model) must not be able to feed
>    plaintext past a secure cache by forging `"encrypted": false`.
> 2. The zero-knowledge property is **value confidentiality only**: for encrypted
>    entries the backend still sees the cleartext header metadata — serializer
>    name, format, compression flag, original type, and (as implemented today)
>    `tenant_id`, `encryption_algorithm`, and `key_fingerprint`. Do not put
>    secrets in header metadata.

Arrow IPC bytes are **not canonical across `pyarrow` versions** — one more reason the
Arrow envelope cannot be a cross-SDK format. Verify frame structure and envelope
detection only, never IPC bytes.

### Interaction with interop mode

Interop values are plain MessagePack — **never** framed, enveloped, or containered.
The normative reader requirements that keep a CK frame from being misread as an
interop value (consume exactly one document, reject trailing bytes, the
`0x43 0x4B` diagnostic) live in
[interop-mode.md → Interop Value Format](interop-mode.md#interop-value-format).

### Test vectors

[`test-vectors/python-frame.json`](../test-vectors/python-frame.json) pins the CK v3
frame against the real `cachekit-py` implementation: a minimal frame, a complete
default-path write (frame → ByteStorage envelope → inner MessagePack → value, full
round-trip) in both envelope encodings — the legacy array-of-ints original
(cachekit 0.11.1) and its protocol 1.1 `bin` twin (cachekit 0.17.0, the first
release emitting `bin`) — an Arrow-envelope frame (structural checks), and
must-reject error vectors — including a CK frame fed to a strict interop reader.

Verify:

```bash
python3 tools/python-frame-reference.py           # stdlib-only structural verify
node tools/frame-crosscheck.mjs                   # independent zero-dep JS reader (full round-trip)
```

---

<div align="center">

[Protocol](../README.md) · [Cache Key Format](cache-key-format.md) · [Encryption](encryption.md) · [SaaS API](saas-api.md) · [Interop Mode](interop-mode.md)

</div>
