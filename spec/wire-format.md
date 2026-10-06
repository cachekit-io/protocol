**[Protocol](../README.md)** > **Wire Format**

<div align="center">

# Wire Format Specification (ByteStorage Envelope)

**LZ4 compression + xxHash3-64 integrity wrapping for cached payloads that use the envelope.**

*Protocol Version 1.1 · Verified against `cachekit-core` v0.4.0 (`src/byte_storage.rs`); six original legacy envelope test vectors were generated at v0.2.0, with the `width_boundary_bin16` legacy vector added by `cachekit-core` v0.5.0 — `bin`-encoded twins added in protocol 1.1 ([decisions/envelope-bin-encoding.md](../decisions/envelope-bin-encoding.md))*

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
   [`test-vectors/wire-format.json`](../test-vectors/wire-format.json). Its hex-pinned
   `vectors` are enforced in CI in two independent places (LAB-423): this repo's
   `verify.yml` runs [`tools/wire-format-reference.py verify`](../tools/wire-format-reference.py)
   against the stdlib-only reference implementation, and the canonical
   implementation [`cachekit-core`](https://github.com/cachekit-io/cachekit-core)
   vendors the file sha256-pinned in `tests/wire_format_vectors.rs`, asserting
   decode byte-identity for every entry in `vectors` and re-encode byte-identity for the
   canonical `*_bin` vectors only — legacy array-of-integers vectors are
   decode-only, retained as legacy-read proof. That re-encode assertion covers
   only the vectors the pinned file contains. cachekit-core's vendored test reads
   only `vectors`. The `constructed_vectors`, `reject_vectors`,
   `payload_reject_vectors` and `temporal_sentinel_vectors` groups are
   verified in this repo's `verify.yml`: the reference tool rebuilds each constructed
   entry from its segment lists and reads it, and only its optional-dependency
   (`xxhash`) leg checks the entry's checksum; the stdlib leg takes it on trust. Each
   reject entry is rebuilt from its legacy base and must be rejected
   ([Reject vectors](#reject-vectors)). Each payload-reject entry must be accepted, and
   its payload rejected by the decode bounds
   ([Payload decode bounds](#payload-decode-bounds)). An implementation that supports a 32-bit
   target also runs `envelope_ratio_product_wraps_32_bits` in its own CI, per
   [Decompression Bomb Detection](#decompression-bomb-detection). Byte-canonicity scopes to the
   envelope's MessagePack encoding and to the **canonical writer's** output:
   the LZ4 bytes inside `compressed_data` are not reproducible across
   conforming compressors — see
   [Compressed-byte reproducibility](#compressed-byte-reproducibility-per-vector-scoping).
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
    original_size:   uint32   // Size of data before compression; a value ≥ 2³² exceeds the cap and is rejected, never truncated
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

As of **protocol 1.1**, writers MUST<sup id="wire-1">WIRE-1</sup> encode `compressed_data` (element `[0]`) as
MessagePack **`bin`** (`0xc4`/`0xc5`/`0xc6`, shortest form). Readers MUST<sup id="wire-2">WIRE-2</sup> **also**
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
> Readers therefore encounter both encodings on the wire today — which is fine,
> and why the flip is **not** a breaking change: dual-read is mutual, so a
> pre-flip reader shape accepts `bin` and a 1.1 reader accepts legacy, per the
> toolchain-verified table under
> [Encoding compatibility](#encoding-compatibility-dual-read) and the permanent
> CI proof in `cachekit-core/tests/dual_decode.rs`. A lagging SDK therefore
> needs no rollout ordering; it simply forgoes the size saving on its own writes
> until it picks up core ≥ 0.4.0. Per-SDK rollout state, with the embedded-core
> evidence per artifact, is tabulated in
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
serde 1.0.228) on all seven byte-pinned vectors, including `bin` wire fed
through the shipped `ByteStorage::retrieve()` with checksum validation and
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

The `vectors` group pins both sides of the `bin8` → `bin16` boundary:
`width_boundary_bin8_max` compresses to 255 bytes and `width_boundary_bin16_min`
to 256, the first 253 and 254 bytes of `width_boundary_bin16`'s 300-byte input.
It has no `bin32` pair. A pair with more than 65,535 compressed bytes would add
roughly 590 KB of hex-encoded fixture data once the legacy array-of-integers
twin is included, then be vendored into every SDK. The `bin16` → `bin32`
boundary is in `constructed_vectors` instead, described as repeated byte
segments: `envelope_bin16_max` (65,535 compressed bytes), `envelope_bin32_min`
(65,536) and `envelope_legacy_array32_min`, the latter's fields in the legacy
encoding, an `array32` (`0xdd`). Their block is the expanding block of zeros
the ratio vector below uses, which no compressor emits for their input. So a
writer is checked against them by encoding the vector's fields, never by
compressing its input. `cachekit-core/tests/dual_decode.rs::width_boundary_bin16_bin32`
also exercises `bin32` at runtime.

> [!WARNING]
> **History.** Earlier revisions of this document described the envelope as a
> MessagePack *map* with `bin`-encoded byte fields — **that was never what
> `cachekit-core` emitted** (the envelope has always been the positional array
> above; protocol#11 corrected the prose). Writers emitted the array-of-ints
> element-`[0]` encoding through protocol 1.0; protocol 1.1 makes `bin` the
> canonical writer encoding for `compressed_data` only. `checksum` remains an
> array of integers in **both** revisions — a reader MUST NOT<sup id="wire-3">WIRE-3</sup> expect `bin` there.

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

### Compressed-byte reproducibility (per-vector scoping)

The LZ4 block **format** is fixed, but conforming **encoders** are not: the
format constrains only what a block must decompress to, so two compliant
compressors may legally emit different bytes for the same input. Compressed
bytes are therefore
**not canonical**, and conformance for `compressed_data` is **read-side**:

- A conforming reader MUST<sup id="wire-4">WIRE-4</sup> decompress the `compressed_data` of every vector in
  the `vectors` and `constructed_vectors` groups to its input, **and MUST<sup id="wire-5">WIRE-5</sup> enforce
  [Retrieve Flow](#retrieve-flow) steps 2, 4, 5 and 9 while doing so, in the order
  the [ordering rule](#check-order) requires.**
  Read-side conformance is not "the vectors pass":
  every vector in the `vectors` group is well-formed and declares a truthful
  `original_size`, so those vectors evidence **none** of the bounds, and a reader
  that omits all four decompresses all of them successfully. The vectors prove decode
  interoperability. The constructed vectors are accept vectors too, so they do not
  show that a reader rejects anything. Three of them sit on the `bin16` → `bin32`
  boundary. The fourth, `envelope_ratio_product_wraps_32_bits`, tests a single
  property of step 5: the width of its product. A reader that multiplies in 32 bits
  rejects it (see [Decompression Bomb Detection](#decompression-bomb-detection)). Enforcing the
  bounds in [Security Limits](#security-limits) is a separate, non-negotiable
  obligation, tested by the `reject_vectors` group. For most of those vectors a
  failed read alone does not show the bound, so [Reject vectors](#reject-vectors)
  says what a conformance test asserts for each, and which bounds no vector
  covers. Step 2's decode bounds have their own fixture,
  [`test-vectors/decode-bounds.json`](../test-vectors/decode-bounds.json).
- A writer **other than the canonical `lz4_flex` writer** is NOT required to
  reproduce the pinned compressed bytes, and MUST NOT<sup id="wire-6">WIRE-6</sup> be judged non-conforming
  because its compressor output differs from the fixture — validate such a
  writer by decoding its envelopes per the
  [Retrieve Flow](#retrieve-flow) and checking its MessagePack encoding against
  [Byte Layout](#byte-layout-canonical-encoding).
- A writer MAY still byte-compare its compressor output against the pins as a
  **drift tripwire**, provided the expected divergences are declared per vector
  rather than treated as failures. This repo's own verifier does exactly that
  (`LZ4_ENCODE_DIVERGENT` in `tools/wire-format-reference.py`), in two halves: a
  set-level half that watches the reference **liblz4** mapping for
  divergence-set drift, and a byte-level half that pins the exact
  `compressed_data` of each declared-divergent vector. Both are needed —
  "differs from liblz4's output" alone is a one-bit assertion that any other
  valid LZ4 block satisfies, so it accepts a re-pin to unrelated bytes. Neither
  half runs `lz4_flex`, so neither can detect an `lz4_flex` **behaviour** change;
  that remains the job of the re-encode assertions in `cachekit-core` described
  below.

This is the same doctrine [interop v2](interop-v2.md) records for its
compressed-values profile. The pinned bytes are the **canonical implementation's**
output (`lz4_flex` via `cachekit-core`), enforced by the re-encode byte-identity
assertions in `cachekit-core/tests/wire_format_vectors.rs` — **for the vectors
present in the fixture that repo vendors**, which recompute each twin's
`lz4_flex` bytes and xxh3-64 checksum. Anyone vendoring the fixture should
derive each `*_bin` twin's expected marker from its decoded `compressed_data`
length (`≤255 → 0xc4`, `≤65535 → 0xc5`, else `0xc6`), as cachekit-core does. An
assertion that every twin is bin8 fails on `width_boundary_bin16_bin` (`0xc5`,
303-byte `compressed_data`), and one that accepts all three widths cannot
detect a non-shortest header. The reference liblz4 mapping above (`lz4.block`) is **decode-verified against
every accept vector** in this repo's CI (`tools/wire-format-reference.py verify`,
optional `lz4` leg); on encode it reproduces every pair except
`large_compressible` byte-for-byte, which is an observation, not a guarantee —
but one this repo's CI pins (see
`LZ4_ENCODE_DIVERGENT`), so a toolchain change that alters the divergent set
fails CI rather than quietly making this paragraph wrong.

> [!NOTE]
> **Known encode divergence — `large_compressible` / `large_compressible_bin`
> (decode-verified only).** For this pair's input (1024 × `'A'`), liblz4
> (observed at 1.9.4 via `python-lz4` 4.4.5) emits a **14-byte** block where
> the fixture pins the **15-byte** block emitted by `lz4_flex` as shipped in
> `cachekit-core` v0.2.0 (this vector's generator). Both sides are
> version-stamped deliberately: encoder output is version-dependent, which is
> the whole reason compressed bytes are not canonical. The blocks differ only in
> the end-of-block match/literal split: `lz4_flex` ends the long match one byte
> earlier and emits six trailing literals (`… e9 60` + `41`×6) where liblz4
> emits five (`… ea 50` + `41`×5). Both are valid LZ4 blocks and both
> decompress to the input; the divergence is encode-only. A third-party writer
> following the Library Mapping will therefore produce a different — equally
> conforming — envelope for this input.

---

## Checksum: xxHash3-64

| Property | Value |
| :--- | :--- |
| Algorithm | xxHash3-64 |
| Input | Original **uncompressed** payload only — `format` and `original_size` are not hashed |
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
1. Pre-scan the envelope bytes (decode bounds, see Security Limits below)
2. Deserialize envelope from MessagePack
3. Validate the size and ratio limits (see below)
4. Decompress compressed_data using original_size as size hint
5. Compute xxh3_64(decompressed_data) as big-endian 8 bytes
6. Compare with checksum field
7. If mismatch → reject (integrity failure)
8. Verify decompressed_data.length == original_size
```

The checksum covers the uncompressed payload bytes only. `original_size` sits
outside the digest but is cross-checked against the decompressed length at
step 8. `format` sits outside the digest and no step of this flow checks it.

> [!NOTE]
> **Non-normative — known limit.** A rotted `format` passes the checksum, so the
> checksum gives a reader that routes on `format` no protection for that field.
> This section places no obligation on readers; how an SDK treats an unexpected
> `format` is its own behaviour. The checksum is unkeyed and detects accidental
> corruption only: anyone who can write cache bytes can recompute it, and tamper
> resistance comes from AES-256-GCM, never from this checksum.

---

## Security Limits

> [!IMPORTANT]
> All three limits below MUST<sup id="wire-7">WIRE-7</sup> be enforced by every implementation of the ByteStorage envelope. The decompression bomb check uses integer-valued arithmetic — do not substitute a floating-point *ratio*, and see [Decompression Bomb Detection](#decompression-bomb-detection) for the normative arithmetic requirements: the ratio product, and `original_size` compared at its full wire value.
> Additionally, a decoder MUST NOT<sup id="wire-8">WIRE-8</sup> allocate for declared MessagePack lengths
> (collection, `str`, `bin`, `ext`) more than the input can back: the declared slots,
> summed over the **whole document**, MUST NOT<sup id="wire-9">WIRE-9</sup> exceed the input length minus one,
> checked **before** anything is materialised. A 5-byte `bin32` header can
> otherwise declare a 4 GiB allocation from a ~30-byte envelope. Checking each
> header against the remaining input bytes does not satisfy this: nested headers
> can each fit what follows them while together declaring far more than the input
> holds. No decoder satisfies it inherently for collections — `rmp-serde` reads
> str/bin lazily, but serde's `Vec<T>` visitor pre-allocates from declared
> lengths. The envelope bytes *and* the payload inside them are both untrusted
> MessagePack — decode each under the depth and allocation rules in
> [interop-mode.md → Decode bounds](interop-mode.md#decode-bounds) (which defines
> the slot count), pinned by `test-vectors/decode-bounds.json`, running the
> structural pre-scan before materialising `StorageEnvelope`.

| Limit | Value | Purpose |
| :--- | ---: | :--- |
| Max uncompressed size | 512 MiB (536,870,912 B) | Memory safety |
| Max compressed size | 512 MiB (536,870,912 B) | Memory safety |
| Max compression ratio | 1000:1 | Decompression bomb protection |

### Decompression Bomb Detection

All three limits above are enforced here. Both size caps MUST<sup id="wire-10">WIRE-10</sup> be checked before
the ratio product, which relies on them; their relative order is not
significant. The check uses **integer-valued arithmetic** and never a
floating-point *ratio*:

```text
if original_size > MAX_UNCOMPRESSED:
    REJECT  // 512 MiB cap

if compressed_size > MAX_COMPRESSED:
    REJECT  // 512 MiB cap

if compressed_size == 0:
    REJECT  // Empty compressed_data is never a valid LZ4 block, whatever original_size says

// BEGIN shared-block: ratio-product-pseudocode
max_allowed = MAX_COMPRESSION_RATIO * uint64(compressed_size)  // 1000; widen BEFORE multiplying
reject if original_size > max_allowed
// END shared-block: ratio-product-pseudocode
```

<a id="check-order"></a>For each envelope, a reader MUST<sup id="wire-11">WIRE-11</sup> complete these checks before it decompresses
that envelope's `compressed_data`, and before it allocates or grows any output buffer
for it, however that buffer is sized (for example from `original_size`, from the
length of `compressed_data`, from a multiple of either, or from a constant).

<!-- BEGIN shared-block: ratio-product-rule (guarded by tools/check-spec-duplication.py) -->
The `MAX_UNCOMPRESSED` comparison MUST<sup id="wire-12">WIRE-12</sup> be decided on the **full wire value** of
`original_size`. Decode it into a ≥ 64-bit unsigned or arbitrary-precision integer,
or into an IEEE-754 binary64 (which rounds only integers above 2⁵³, far past the cap,
so the comparison is unchanged), or reject it when it does not fit a narrower
destination type that still holds every value up to the cap (every value that does
not fit already exceeds it), such as a 32-bit unsigned integer. Any other decode —
one that yields neither the exact wire value nor its binary64 rounding — is
forbidden: **truncation** to the low-order bits (a narrowing cast such as `as u32`,
`>>> 0` or `& 0xFFFFFFFF`), **sign reinterpretation** (bit-casting a `uint64` into an
`i64`, so a value ≥ 2⁶³ reads as negative; a checked `i64` decode that rejects such
values conforms), or joining the two 32-bit halves in 32-bit arithmetic. Unlike the
ratio product below, truncation and the 32-bit joins fail *open*: a declared
`2³² + N` reads as `N` when truncated, or as `N + 1` or `N | 1` when its halves are
joined in 32-bit arithmetic. Each clears the `MAX_UNCOMPRESSED` cap and the ratio
bound and can match the payload exactly, so the entry is accepted where a conforming
reader rejects it. Every target language has a conforming path: Rust `u64`, or `u32` behind a range-checked decode (`rmp-serde`
rejects an out-of-range value, whatever its marker width, instead of truncating it);
Python's `int`; JavaScript `BigInt`, or `Number`.

The ratio product MUST<sup id="wire-13">WIRE-13</sup> be computed **exactly**:
promote `compressed_size` to a ≥ 64-bit unsigned or arbitrary-precision integer, or to an
IEEE-754 binary64 in which the operand and the product are exact integers
(< 2⁵³), *before* the multiply. Multiplying in pointer width and widening the
result afterwards does not satisfy this, and is invisible on a 64-bit host and in
64-bit CI — it is the failure a 32-bit target such as `wasm32` would exhibit.
Every target language has a conforming path: Rust `u64` (on every target,
`wasm32` included), Python's arbitrary-precision `int`, and JavaScript `Number` —
an IEEE-754 double represents every integer below 2⁵³ exactly and this product is
< 2³⁹, so no `BigInt` is required. Because `compressed_size` ≤ 2²⁹ once the two 512 MiB caps
have passed, the product is < 2³⁹ and cannot overflow 64 bits; that is why the
pseudocode above carries no overflow branch, and why rejecting on overflow is
**not** a substitute for widening — at 32-bit width it would refuse the 99.2 % of
the legal `compressed_size` range that lies above the wrap threshold given in the note below.

The bound MUST<sup id="wire-14">WIRE-14</sup> be computed by **multiplication**. Deriving it by division, or
as a *ratio*, is forbidden in any arithmetic — integer or floating-point.
Truncating integer division (`original_size / compressed_size > 1000`) accepts up to
`1000·compressed_size + (compressed_size − 1)`, which is looser than this specification permits, and a
floating-point ratio is the precision bypass the integer rule exists to prevent.

> [!NOTE]
> **Non-normative rationale — the *ratio product's* failure direction under
> pointer-width arithmetic is fail-closed, never a bypass.** (This covers the
> product only. It relies on the full-wire-value rule for `original_size` above,
> which makes the `MAX_UNCOMPRESSED` check apply to `original_size` as declared.)
> 32-bit pointer width is a live target: cachekit-ts ships a `wasm32` build. Wrapping
> begins at `compressed_size ≥ ⌈2³²/1000⌉ = 4,294,968` B (~4.29 MB), and it can only ever
> *tighten* the bound: for any product `p ≥ 2³²`, `wrapped(p) = p mod 2³² < 2³² ≤ p`,
> while `original_size` (≤ 512 MiB < 2³²) cannot itself wrap, so the direction
> of the comparison is preserved. The failure mode is therefore **spurious
> rejection**, not a bomb bypass — but a hard error rather than a cache miss,
> and a permanent one: the wrapped bound is a pure function of `compressed_size`, so an
> affected entry fails identically on every read. It bites only where the
> wrapped bound falls below the 512 MiB cap, and there it can collapse to almost
> nothing: 704 B at the first wrap threshold, 0 at the 512 MiB cap. Those payloads are legal under
> this specification; an implementation that refuses them is non-conforming.
<!-- END shared-block: ratio-product-rule -->

`test-vectors/wire-format.json` tests this rule with one vector,
`envelope_ratio_product_wraps_32_bits`, in its `constructed_vectors` group. The
envelope is 4.3 MB, so the file describes it and its input as lists of repeated byte
segments rather than hex (`construction_note`). Its `compressed_data` is exactly
4,294,968 B, the first size whose product overflows unsigned 32 bits (a signed 32-bit
product overflows from 2,147,484 B). Its `original_size` (8,523,079 B) is inside the
1000:1 bound but above the 704 B that a 32-bit product yields, signed or unsigned. It
is also larger than `compressed_data`, so a reader that skips the product when
`original_size` is at most the compressed size still has to compute it. A
reader that multiplies in 32 bits rejects it, and so does one that rejects on 32-bit
overflow. A conforming reader returns the constructed input, and the envelope's
`checksum` is that input's true xxHash3-64. Every other envelope in the file is
66,084 B or smaller.

The vector is built to show the product's width. It is also the file's only
multi-megabyte decode, and one of its two bin32 `compressed_data`, so a failure on it
alone does not prove a 32-bit product: check the rejection reason. It is an accept vector,
because a 32-bit product only ever tightens the bound, so no reject vector can catch
one. A pointer-width product is exact on a 64-bit host, so a pass there does not show
the rule holds on a 32-bit target. interop/v2 has its own vector for
its container's product, `lz4_ratio_product_wraps_32_bits`
([interop-v2.md → Test Vectors](interop-v2.md#test-vectors)).

An implementation of the ByteStorage envelope that supports a 32-bit target, as
[interop-v2.md → SDK Implementation Requirements](interop-v2.md#sdk-implementation-requirements),
item 7, defines that term, MUST<sup id="wire-15">WIRE-15</sup>, in its own CI, pass
`envelope_ratio_product_wraps_32_bits` on each such target, built as its consumers
get it: the artifact it distributes or, for source-distributed code, a build of its
published source for that target. It runs the vector at this spec's limits, not at a
stricter deployment limit. Anything other than returning the constructed input (a
rejection for any reason, a checksum mismatch included, a skip, a crash) is a
failure. A package that distributes a build of an envelope implementation for a
32-bit target is itself such an implementation, whichever repository the envelope
code comes from.

### Reject vectors

`test-vectors/wire-format.json` has a `reject_vectors` group: fourteen envelopes, each
hex-pinned and derived from a legacy base vector with one
[Retrieve Flow](#retrieve-flow) check broken. Each is a `bin` envelope, canonical
except where the break is in the encoding itself (the step-2 vectors), and
`reject_legacy_element_above_255` uses the legacy encoding. A conforming reader rejects
all fourteen.
`reject_step` is the Retrieve Flow step at which the reference reader,
[`tools/wire-format-reference.py`](../tools/wire-format-reference.py), rejects the
vector, and for step 2 `reject_check` names which of its two checks does: the
decode-bounds pre-scan or the typed decode. Both are metadata, not values an SDK must
reproduce. What an SDK test asserts is the last column below:

| Vector | `reject_step` | What it breaks | A reader missing only that check | An SDK test asserts |
| :--- | :---: | :--- | :--- | :--- |
| `reject_envelope_arity_5` | 2 | `simple_string_bin`'s four fields, then a fifth element, nil | accepts it if it takes the first four elements, since every field is intact | the typed-decode error |
| `reject_envelope_arity_3` | 2 | `simple_string_bin` without its fourth element, `format` | accepts it if it defaults a missing `format` to `"msgpack"` | the typed-decode error |
| `reject_checksum_nine_elements` | 2 | a ninth integer, 0, after the true 8-byte checksum | accepts it if it compares the first 8 checksum elements | the typed-decode error |
| `reject_checksum_seven_elements` | 2 | the checksum array cut to its first 7 integers | accepts it if it compares only the checksum elements it was given | the typed-decode error |
| `reject_legacy_element_above_255` | 2 | `simple_string`'s legacy element 2, `0x68`, written as uint16 360 (`cd 01 68`) | accepts it if it keeps an element's low 8 bits, as JavaScript's `Uint8Array.from` does | the typed-decode error |
| `reject_envelope_slots_overclaim` | 2 | `simple_string_bin` with its `bin8` length raised to 38, all but the last byte after the header: each header fits what follows it, and the declared slots summed over the document (42) exceed the 42-byte input minus one by one | rejects it as truncated in the typed decode | the pre-scan's own error, before anything is materialised |
| `reject_original_size_over_cap` | 4 | `original_size` 536,870,913 B, one byte over the cap, with 1,000 B of `compressed_data` that is not a valid LZ4 block | rejects it at step 5, by the ratio bound | the size-cap error, and the allocation bound below |
| `reject_original_size_wraps_u32` | 4 | `original_size` 2³² + 16 B, encoded as `uint64`, with a block and checksum that match 16 B | rejects it at step 5; one that truncates `original_size` to 32 bits accepts it, and one that joins its 32-bit halves rejects it only on length | a rejection before decompression: the size-cap error, or a step-2 error from a range-checked decode into a narrower type; never a length or checksum error |
| `reject_original_size_sign_bit` | 4 | `original_size` 2⁶³ + 16 B, encoded as `uint64`, with a block and checksum that match 16 B | rejects it at step 5; one that reinterprets the `uint64` as a signed `i64` reads it as negative, passes the size cap and the ratio bound, and fails later or crashes; one that truncates to 32 bits accepts it | a rejection before decompression: the size-cap error, or a step-2 error from a range-checked decode into a narrower type; never a length, allocation or checksum error |
| `reject_zero_length_compressed_data` | 5 | empty `compressed_data`, `original_size` 0 | rejects it at step 6 if its LZ4 decoder refuses an empty block, as liblz4 does; accepts it if the decoder returns empty output | the zero-length error |
| `reject_ratio_bomb` | 5 | `original_size` 1,000,001 B from 1,000 B of `compressed_data`, one byte past 1000:1, with a block that is not valid LZ4 | never raises the ratio error | the ratio error, and the allocation bound below |
| `reject_ratio_float32_rounds` | 5 | `original_size` 32,768,001 B from 32,768 B of `compressed_data`, one byte past 1000:1, with a block that is not valid LZ4 | never raises the ratio error; nor does a ratio taken in float32, which reads exactly 1000 here, or a truncating division | the ratio error |
| `reject_decompressed_length_mismatch` | 6 | `original_size` 17 B; the block decodes to 16 B and the checksum matches those 16 B | accepts it | a length error, at step 6 or step 9, and not a checksum error |
| `reject_checksum_mismatch` | 8 | the first and last `checksum` bytes flipped | accepts it | a rejection |

The size-cap and ratio vectors carry a literal-length extension that never ends.
Strict decoders (liblz4, `lz4_flex`) refuse it. Lenient decoders come in two kinds.
A *fixed-output* decoder writes into a buffer the reader sized in advance and returns
a short output with no error. A *growing* decoder extends its output as it goes. What
the tests detect, and miss, for a reader that runs steps 4 and 5 late:

- A reader that decompresses first with a strict decoder, and lets its error
  propagate, never raises the expected error, so it fails the error assertion.
- A reader that allocates an output of `original_size` bytes or more before steps 4
  and 5, itself or through a decoder it gives `original_size` as a size hint, fails
  the allocation bound whatever it does with that output, provided the probe counts
  the allocator that buffer comes from.
- These vectors do not detect three readers that allocate less than `original_size`.
  One decompresses first with a growing decoder. One holds a strict decoder's error
  until after steps 4 and 5. One sizes its output below `original_size`, for example
  from the length of `compressed_data`, a constant, or `original_size` clamped below
  itself, whether it decompresses into it first with a fixed-output decoder or only
  reserves it. Each raises exactly the expected error inside the allocation bound. The
  [ordering rule](#check-order) forbids all three.

The zero-length vector declares `original_size` 0 on purpose. With a non-zero size,
the ratio bound rejects it at the same step, because 1000 × 0 = 0, and the vector
could not tell a reader missing the zero-length check from a conforming one.

The u32-wrap vector tests the full-wire-value rule in
[Decompression Bomb Detection](#decompression-bomb-detection) for truncation, which
reads 16, and for the 32-bit half-joins, which both read 17. The sign-bit vector tests
it for sign reinterpretation, which needs a value of 2⁶³ or more: as an `i64`,
2⁶³ + 16 reads as −9,223,372,036,854,775,792.

The float32 vector tests the ratio rule against arithmetic it forbids. A ratio of
float32 operands loses a one-byte excess once `compressed_size` reaches 16,778 B, and a
float32 quotient of exact operands once it reaches 32,768 B, so at 32,768 B both read
exactly 1000. `reject_ratio_bomb` (1,000 B) catches neither, though it does catch a
truncating division. A binary64 ratio, or a division that rounds up, reaches the
product's verdict at every legal size, so no vector can catch it. The exact 1000:1
edge cannot be pinned by an accept vector either: a valid LZ4 block expands at most
about 255:1.

The reference reader's decoder rejects any output length other than
`original_size`, which enforces step 9 inside step 6. A decoder that returns a
shorter output without error, as liblz4 does when its destination is larger than the
block's output, leaves the rejection to step 9. Both conform. A reader that does
neither accepts the length vector. A reader that zero-pads to `original_size` and
ignores the decoded length fails at step 8 on this vector, or accepts it if it
checksums the decoded bytes before padding. Either way it fails a test that asserts
a length error.

A verdict cannot show which check rejected a vector, the same limit
[interop-mode.md → Decode bounds](interop-mode.md#decode-bounds) sets out for
`decode-bounds.json`. An SDK's conformance test for the ByteStorage envelope MUST<sup id="wire-16">WIRE-16</sup>
therefore drive each reject vector through its envelope read path, below the point
where the SDK turns the error into a cache miss, and assert what the table's last
column names. Calling a check directly as well is fine, but on its own does not show
that the read path runs it. Run the vectors at this spec's limits, not at a stricter
deployment limit.

An error assertion cannot show ordering either. A reader can allocate an
`original_size` output buffer right after step 2, free it, run steps 4 and 5, and
raise exactly the error its test expects. So for `reject_original_size_over_cap` and
`reject_ratio_bomb`, the test MUST<sup id="wire-17">WIRE-17</sup> also bound what the read allocates, and fail if it
reaches `original_size`. The measurement MUST<sup id="wire-18">WIRE-18</sup> satisfy all of these:

- It counts bytes requested from the allocator the envelope code actually allocates
  from: the Rust global allocator for Rust code, and the Python heap only for code
  that allocates there. A Python-heap probe around a call into native code does not
  see that code's buffers. Resident memory, and a wasm `memory.grow` count, do not
  qualify either, because pages that are reserved but never touched, or already
  grown, do not show.
- It counts the high-water mark, or the cumulative bytes requested, over this one
  read, so a buffer allocated and freed inside the read still counts. A net count of
  allocations minus frees does not qualify.
- It attributes allocations to this read alone: a per-thread counter with the read
  on that thread, or a single-threaded run.
- It counts every allocation exactly, never a sample.
- A positive control shows the same probe detecting an `original_size` buffer that
  is allocated and freed *inside the envelope read path*, after step 2, as a
  reserve-first reader would: a reserve-first build of the reader, or a hook after
  step 2. It runs on the read's own threads and through the read's own allocation
  calls, so a probe blind to a worker thread, or to an allocation call it does not
  wrap, fails its control. A control allocated by the test itself does not
  qualify. One control at the ratio vector's `original_size`, 1,000,001 B, covers
  both vectors; the size-cap vector needs no 512 MiB control.

[`tools/test_wire_format_reference.py`](../tools/test_wire_format_reference.py)
implements such a probe, with its positive control, for the reference reader.

An SDK whose envelope code runs inside another implementation, such as an SDK over
`cachekit-core`, may rely on that implementation's probe only when the SDK passes
the raw envelope bytes through, with no allocation of its own sized from an envelope
field, and the probe runs in CI on the exact version the SDK pins. The SDK still
asserts the named error through its own read path.

No vector covers step 1 or step 3. Step 1 needs an envelope over 512 MiB. The file
could describe one in a few repeated segments, as it does the constructed vector, but
every reader would have to materialise more than 512 MiB to run it. A short envelope
with a forged `bin32` length is not a substitute: a conforming reader and one without
step 1 both reject it as truncated at step 2. Step 3 cannot fire once step 1 has
passed, because `compressed_data` is a strict slice of an envelope that step 1 has
already bounded to 512 MiB. An implementation MUST<sup id="wire-19">WIRE-19</sup> still enforce both. Test step 1
with a lowered cap, as `check_reader_rejects` in
`tools/test_wire_format_reference.py` does.

### Payload decode bounds

The payload an envelope returns is untrusted MessagePack too, decoded under the same
bounds as the envelope's bytes ([Security Limits](#security-limits)).
`test-vectors/wire-format.json`'s `payload_reject_vectors` group pins that decode. Each
entry is a canonical `bin` envelope that every Retrieve Flow check accepts, and its
payload is a [`decode-bounds.json`](../test-vectors/decode-bounds.json) reject
document, named in `derived_from` with its `reject_reasons`. A reader that pre-scans the
envelope's bytes but decodes the payload unguarded passes every reject vector and fails
these. As with `decode-bounds.json`, a verdict cannot show when the decode rejected, so
an SDK test drives each envelope through its read path and asserts its pre-scan's own
error ([interop-mode.md → Decode bounds](interop-mode.md#decode-bounds)).
`compressed_data` is a literals-only block, which any LZ4 decoder reads; a compressor
may emit other bytes for the same payload.

---

## Store Flow

<details>
<summary>Expand full store algorithm</summary>

```
Input: raw_data (bytes), format (string, default "msgpack")

1. Validate:  raw_data.length <= 512 MiB
2. Compress:  compressed = lz4_block_compress(raw_data)
3. Validate:  compressed.length <= 512 MiB
4. Checksum:  checksum = xxh3_64(raw_data).to_be_bytes()  // Hash ORIGINAL
5. Envelope:  StorageEnvelope {
                  compressed_data: compressed,
                  checksum:        checksum,    // 8 bytes, big-endian
                  original_size:   raw_data.length,
                  format:          format
              }
6. Serialize: envelope_bytes = msgpack_encode(envelope)   // compressed_data as bin (1.1+)
7. Validate:  envelope_bytes.length <= 512 MiB
8. Return:    envelope_bytes
```

</details>

---

## Retrieve Flow

<details>
<summary>Expand full retrieve algorithm</summary>

```
Input: envelope_bytes

1.  Validate:    envelope_bytes.length <= 512 MiB
2.  Deserialize: pre-scan envelope_bytes (decode bounds, see Security Limits), then
                 envelope: StorageEnvelope = msgpack_decode(envelope_bytes)
                 // typed decode, not a cast: wrong arity or element type -> Reject
                 // accept BOTH element[0] encodings: bin AND array-of-ints
3.  Validate:    envelope.compressed_data.length <= 512 MiB
4.  Validate:    envelope.original_size <= 512 MiB
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
> All SDKs MUST<sup id="wire-20">WIRE-20</sup> check for these sentinel keys during deserialization and reconstruct the appropriate temporal type. Failing to handle them means datetime values will be returned as raw maps instead of native date objects.

`test-vectors/wire-format.json`'s `temporal_sentinel_vectors` group pins the three maps
above as payloads, each with the type and value an SDK revives it as (`revives_to`).
Which SDKs revive which map is recorded in
[sdk-feature-matrix.md](../sdk-feature-matrix.md).

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
behavior is SDK-specific: `cachekit-py`'s L1 in front of a backend holds the framed bytes; `cachekit-ts`'s
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
> [interop mode](interop-mode.md) exclusively. An SDK MUST NOT<sup id="wire-21">WIRE-21</sup> decode another
> SDK's auto-mode container. An SDK MAY parse a foreign container *for diagnostics
> only*, using the layouts below.

### Python: CK v3 frame

Two in-process modes keep live objects and store no bytes at all: `@cache.local`
reference caching (key code `l`) and a cache configured with `backend=None`, whose
keys carry its configured serializer's code. Every other **auto-mode** value
`cachekit-py` stores — all backends, all serializers, encrypted or not — is framed
(interop-mode values are plain MessagePack, never framed):

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
| A serializer instance's bare class name (`StandardSerializer`, `ArrowSerializer`, a custom class) | That serializer's own output; a built-in class writes the same payload as its string name above. Classes sharing a bare name, and differently configured instances of one class, record the same `s` (see the [`ns:` rule](cache-key-format.md#serializer-codes)) |
| any, encrypted | Ciphertext per [encryption.md](encryption.md) |

With integrity checking disabled, `default`/`auto` payloads are raw MessagePack (no
ByteStorage envelope) and `orjson` payloads are raw JSON (no checksum prefix); the
**`arrow` checksum prefix is unconditional** — ArrowSerializer always writes and
validates it regardless of the integrity flag. The frame header's `m` metadata
carries the flags either way. The header's `v` is the Python wrapper's own logical
envelope version string (currently `"2.0"`) — it is unrelated to the frame VERSION
byte (`0x03`) and readers do not validate it.

A reader MUST<sup id="wire-22">WIRE-22</sup> reject: frames shorter than the 7-byte fixed prefix, `VERSION != 3`,
and a declared `HDR_LEN` that overruns the value. (`cachekit-py` additionally reads a
legacy base64-in-JSON envelope, first byte `{` — pre-v3 entries only; new writes are
always v3 frames.)

> [!CAUTION]
> **The frame header is plaintext and unauthenticated — even for encrypted entries.**
> The AAD (v0x03, [encryption.md](encryption.md)) binds tenant, cache key, format,
> and compression flags into the AES-GCM tag, but the CK header JSON itself is
> outside that binding. Two consequences are normative:
>
> 1. A reader configured for encryption MUST NOT<sup id="wire-23">WIRE-23</sup> let the header's `encrypted` /
>    `s` / `m` values downgrade it to a non-authenticated read path. If the cache
>    is configured encrypted and an entry does not authenticate as ciphertext,
>    the read MUST<sup id="wire-24">WIRE-24</sup> fail closed — an attacker with backend write access (the
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

Each CK error vector names, in `rejected_by`, the check that rejects it: `magic`, the
7-byte `prefix_length`, `version` or `header_length`. Four sit one step from their
check's boundary, on the default write's real header where the frame has one, so a
reader whose check is off by one reaches a parsed header: a 6-byte frame, versions 2
and 4, and a header length one past the bytes present. Two are other SDKs' containers, which cachekit-py refuses: a bare
ByteStorage envelope (cachekit-ts's default) and plain MessagePack (cachekit-rs's, and
cachekit-ts's with compression off).

The `encrypted_read_vectors` group holds frames that a cache configured for encryption
(`encrypted_reader`: a master key, a tenant, a cache key, and `tenant_source`
`reader`, meaning the reader resolves its tenant itself and never takes the frame
header's) fails closed on: a plaintext payload under a header that adds
`"encrypted": false`, a plaintext `orjson` write, and two ciphertexts that do not
authenticate under the reader's key and AAD, one sealed under another master key and
one for another tenant. `header_claims` records what each header claims. The stdlib
verifier checks the frames' structure; `generate` proves against the real cachekit-py
that each read fails closed under both tamper policies.

The `bin` twin carries `"twin_of": "default_saas_write_msgpack_bytestorage"`: an
operator-owned declaration that it differs from the legacy vector **only** in
envelope encoding (same value, frame-prefix bytes, compressed bytes, checksum,
size, format and inner MessagePack). `verify` enforces the declaration as a hard
failure; `generate` never adds or removes it and only warns on divergence. When
the default write path legitimately moves, the exit is to drop `twin_of` from
the regenerated vector in the same commit — a reviewable fixture diff — not to
loosen a byte comparison. The legacy vector stays frozen (no installable wheel
emits the array-of-integers envelope any more) as legacy-read proof.

Verify:

```bash
python3 tools/test_python_frame_reference.py      # mutation suite for the stdlib verify
python3 tools/python-frame-reference.py           # stdlib-only verify (frame, envelope, LZ4 -> inner msgpack)
node tools/frame-crosscheck.mjs                   # independent zero-dep JS reader (full round-trip; the only leg that checks value_json against the decoded value)
```

---

<div align="center">

[Protocol](../README.md) · [Cache Key Format](cache-key-format.md) · [Encryption](encryption.md) · [SaaS API](saas-api.md) · [Interop Mode](interop-mode.md)

</div>
