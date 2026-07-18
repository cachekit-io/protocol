**[Protocol](../README.md)** > **Encryption**

<div align="center">

# Encryption Specification

**Client-side AES-256-GCM with zero-knowledge guarantees — the backend never sees plaintext.**

*Protocol Version 1.0 · Verified against `cachekit-core` v0.1.1 and `cachekit-py` v0.5.0*

</div>

---

## Table of Contents

- [Algorithm](#algorithm)
- [Key Derivation](#key-derivation)
- [Nonce Generation](#nonce-generation)
- [Ciphertext Format](#ciphertext-format)
- [Additional Authenticated Data (AAD)](#additional-authenticated-data-aad)
- [Encryption Header (Key Rotation)](#encryption-header-rotationawareheader)
- [Encryption Flow](#encryption-flow)
- [Decryption Flow](#decryption-flow)
- [Compliance](#compliance)

---

## Algorithm

CacheKit provides **optional** client-side encryption using AES-256-GCM. When enabled, the backend (Redis or SaaS) stores opaque ciphertext and never has access to keys or plaintext.

> [!NOTE]
> Encryption is not configurable by design. AES-256-GCM is the only supported algorithm. See the [Encryption Algorithm Decision Record](../decisions/encryption-algorithm.md) for rationale.

| Property | Value |
| :--- | :--- |
| Cipher | AES-256-GCM (Authenticated Encryption with Associated Data) |
| Key size | 256 bits (32 bytes) |
| Nonce size | 96 bits (12 bytes) |
| Auth tag size | 128 bits (16 bytes) |
| Library (Rust) | `ring` crate — wraps platform AES-NI / ARM crypto |

---

## Key Derivation

### Master Key

The customer supplies a master key via environment variable:

```
CACHEKIT_MASTER_KEY=a1b2c3d4e5f6...  (hex-encoded, minimum 32 bytes / 64 hex chars)
```

| Constraint | Value |
| :--- | :--- |
| Minimum length | 16 bytes (32 bytes strongly recommended) |
| Encoding | Hex string |
| Env var | `CACHEKIT_MASTER_KEY` |

### HKDF-SHA256 Key Derivation

Per-tenant keys are derived using HKDF (RFC 5869) with SHA-256:

```
derived_key = HKDF-SHA256(
    input_key_material = master_key,
    salt               = construct_salt(domain, tenant_salt),
    info               = domain.as_bytes(),
    output_length      = 32
)
```

#### Salt Construction

The salt uses a length-prefixed encoding to prevent collision attacks:

```
salt = "cachekit_v1_"               // 12 bytes, fixed prefix
     + [domain_length as u8]        // 1 byte
     + domain_bytes                 // variable
     + [tenant_salt_length as u16]  // 2 bytes, big-endian
     + tenant_salt_bytes            // variable
```

<details>
<summary>Byte-level example: domain=<code>"cache"</code>, tenant_salt=<code>"tenant-123"</code></summary>

```
Offset  Bytes                                  Description
──────  ─────────────────────────────────────  ───────────────────────────
 0-11   63 61 63 68 65 6b 69 74 5f 76 31 5f   "cachekit_v1_"
   12   05                                    domain length (5)
13-17   63 61 63 68 65                        "cache"
18-19   00 0a                                 tenant_salt length (10, BE)
20-29   74 65 6e 61 6e 74 2d 31 32 33         "tenant-123"
```

This length-prefixed format prevents collision between `(domain="foo", salt="bar")` and `(domain="foob", salt="ar")`.

</details>

#### Constraints

| Parameter | Limit |
| :--- | ---: |
| Minimum master key length | 16 bytes |
| Maximum domain length | 255 bytes (fits in u8) |
| Maximum tenant salt length | 1024 bytes (fits in u16) |
| Domain | Must not be empty |
| Tenant salt | Must not be empty |

### Tenant Key Derivation

Each tenant gets three domain-separated keys derived from the same master key:

```
encryption_key     = derive_domain_key(master_key, "encryption",     tenant_id)
authentication_key = derive_domain_key(master_key, "authentication", tenant_id)
cache_key_salt     = derive_domain_key(master_key, "cache_keys",     tenant_id)
```

All three are 32-byte (256-bit) keys. They are cryptographically independent due to domain separation.

### Key Fingerprint

For key identification without revealing key material:

```
fingerprint = SHA-256("key_fingerprint_v1" || key)[0..16]   // First 16 bytes
```

---

## Nonce Generation

> [!WARNING]
> **Discrepancy with RFC** — The RFC (Section 5.3) specifies random 12-byte nonces (`os.urandom(12)`). The actual implementation uses a **deterministic counter-based** approach that eliminates birthday-bound collision risk. **The implementation is authoritative.**

### Counter-Based Nonce Format

```
┌───────────────────────┬─────────────────┐
│   instance_id (8B)    │  counter (4B)   │
└───────────────────────┴─────────────────┘
│◄────────────── 12 bytes (96 bits) ─────►│
```

| Field | Size | Encoding | Source |
| :--- | :---: | :--- | :--- |
| `instance_id` | 8 bytes | Big-endian u64 | Global atomic counter (randomized start) |
| `counter` | 4 bytes | Big-endian u32 | Per-instance atomic counter (starts at 0) |

**Security properties**:
- `instance_id` is globally unique within a process (monotonic atomic counter)
- Randomized 32-bit seed in upper bits provides cross-process collision resistance
- Per-instance counter allows 2^32 encryptions per instance before exhaustion
- Total nonce space: 2^96 (far exceeds practical usage)
- Counter exhaustion (≥ 2^32 per instance) returns an error — never wraps

> [!TIP]
> SDKs that cannot replicate the counter-based nonce strategy MAY use random 12-byte nonces as a fallback. Random nonces are safe for AES-256-GCM up to ~2^32 encryptions per key (birthday bound). The counter-based approach is strictly superior but not required for interoperability — nonces are prepended to ciphertext and extracted during decryption regardless of generation strategy.

---

## Ciphertext Format

```
┌──────────────────────┬──────────────────────────────────────────┐
│     nonce (12B)      │    ciphertext  +  auth_tag (16B)         │
└──────────────────────┴──────────────────────────────────────────┘
                        │◄── variable ──►│◄── always 16 bytes ───►│
```

The output of `encrypt_aes_gcm()`:

```
result = nonce_bytes (12) || aes_gcm_seal(plaintext, key, nonce, aad)
```

Where `aes_gcm_seal` returns `ciphertext || auth_tag` (auth tag is the last 16 bytes).

**Minimum ciphertext length**: 28 bytes (12 nonce + 0 plaintext + 16 auth tag).

---

## Additional Authenticated Data (AAD)

### AAD v0x03 Format

> [!IMPORTANT]
> AAD binds ciphertext to its intended context. Without AAD, an attacker within the same tenant could swap ciphertext between different cache keys and the auth tag would still verify. With AAD v0x03, AES-GCM authentication fails if the cache key does not match. This prevents ciphertext substitution (CVSS 8.5).

> [!WARNING]
> **Discrepancy with RFC** — The RFC (Sections 5.3–5.4) shows encryption with `None` as AAD. The actual implementation uses AAD v0x03 with cache_key binding. **The implementation is authoritative.**

<details>
<summary>Expand AAD byte layout</summary>

```
┌──────┬────────┬───────────┬────────┬───────────┬────────┬────────┬────────┬───────────┬╌╌╌╌╌╌╌╌┬╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐
│ 0x03 │  len1  │ tenant_id │  len2  │ cache_key │  len3  │ format │  len4  │compressed ╎  len5  ╎ original_type ╎
└──────┴────────┴───────────┴────────┴───────────┴────────┴────────┴────────┴───────────┴╌╌╌╌╌╌╌╌┴╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘
  1 B    4 B BE   variable    4 B BE   variable    4 B BE   var      4 B BE   var         4 B BE   var

Dashed fields are present only when the writer emits the optional original_type
component (all current cachekit-py serializer paths do; cachekit-ts, cachekit-rs,
and interop mode never do — see below).
```

</details>

| Field | Type | Description |
| :--- | :--- | :--- |
| Version byte | `0x03` | AAD format version |
| `tenant_id` | Length-prefixed UTF-8 | Tenant identifier |
| `cache_key` | Length-prefixed UTF-8 | Full cache key (prevents ciphertext swapping between keys) |
| `format` | Length-prefixed UTF-8 | Serialization-format token — see [`format` tokens](#format-tokens) |
| `compressed` | Length-prefixed UTF-8 | Boolean token — exactly `True` or `False`, see [`compressed` tokens](#compressed-tokens) |
| `original_type` | Length-prefixed UTF-8 | *(Optional)* Original-type hint — see [`original_type`](#original_type-optional-fifth-component) |

Each component is prefixed with a 4-byte big-endian length.

`format` and `compressed` describe the AES-GCM **plaintext** (the serialized/enveloped
bytes fed to the cipher). They are stored as cleartext metadata alongside the
ciphertext so the reader can rebuild the AAD; they are integrity-protected — not
confidential — because any tampering changes the reconstructed AAD and fails
authentication. That failure is the intended behavior: readers MUST NOT retry
decryption with any alternative AAD input — a different `format` or `compressed`
value, or presence/absence of `original_type`. A reader that probes AAD variants
converts an authentication failure into a metadata-tamper oracle. Likewise, the
post-decryption unenvelope step MUST be selected by the reader's configured
serializer/mode — never by sniffing the decrypted bytes or falling back between
containers — and MUST hard-fail on a parse mismatch.

### `format` tokens

The `format` component is a lowercase-ASCII token naming the serialization format of
the AES-GCM plaintext. Registry of tokens produced by current SDKs:

| Token | AES-GCM plaintext content | Produced by |
| :--- | :--- | :--- |
| `msgpack` | MessagePack-family bytes; the container varies by SDK/mode (ByteStorage envelope or plain MessagePack) — see [wire-format.md](wire-format.md) / [interop mode](interop-mode.md#encryption-in-interop-mode) | cachekit-py (`StandardSerializer`, `AutoSerializer` msgpack paths), cachekit-ts, cachekit-rs |
| `orjson` | orjson JSON bytes, prefixed with an 8-byte xxHash3-64 checksum when integrity checking is enabled (the default): `[checksum(8)][JSON]`; plain JSON bytes otherwise | cachekit-py (`OrjsonSerializer`) |
| `arrow` | Arrow IPC **file**-format envelope (`ARROW1` magic, not the IPC streaming format): `[8-byte xxHash3-64 checksum][Arrow IPC file]` | cachekit-py (`ArrowSerializer`) |

The token names the serialization-format family; the exact container/envelope for
each SDK and mode is specified in [wire-format.md](wire-format.md) and
[interop-mode.md](interop-mode.md). The `compressed` component (below) — not the
`format` token — authenticates whether that container applied compression.

New serializers MUST register their token here before shipping. Tokens are
case-sensitive, and the registry is a **writer-side contract**: readers rebuild the
AAD verbatim from stored metadata, so nothing structurally rejects an off-registry
token within the SDK that wrote it — the registry exists so independent
implementations of the same entry agree on the bytes. Writers MUST emit only
registry tokens; readers SHOULD reject tokens outside the registry before attempting
decryption.

### `compressed` tokens

Exactly two legal values — **frozen ASCII byte strings**:

| Value | Bytes on the wire |
| :--- | :--- |
| `True` | `54 72 75 65` |
| `False` | `46 61 6c 73 65` |

> [!IMPORTANT]
> These tokens are **protocol constants**, not a rendering of any language's boolean
> type. They historically coincide with Python's `str(bool)` output; that coincidence
> is now frozen. Implementations in every language MUST emit exactly these byte
> sequences — `true`, `false`, `TRUE`, `1`, `0`, or a raw byte are all non-conformant
> and fail AES-GCM authentication against conformant peers.

### `original_type` (optional fifth component)

Only cachekit-py emits `original_type`; cachekit-ts and cachekit-rs always produce
four-component AADs. When present it is appended as a fifth length-prefixed
component. **All of cachekit-py's current serializers set it, so every cachekit-py
encrypted entry today carries a five-component AAD.** Values currently emitted:
`msgpack`, `orjson`, `arrow`, `numpy`, `dataframe`, `series`.

This arity asymmetry never crosses an SDK boundary in practice: auto-mode entries are
SDK-internal ([protocol#11](https://github.com/cachekit-io/protocol/issues/11)), and
[interop mode](interop-mode.md#encryption-in-interop-mode) — the only cross-SDK
encrypted surface — NEVER includes it: interop AAD is always exactly four components,
and an SDK that carried a type hint into interop AAD would fail cross-SDK
authentication.

### Version policy — resolved: these rules stay within v0x03

Decision ([protocol#12](https://github.com/cachekit-io/protocol/issues/12),
2026-07-19): pinning the token bytes above and enumerating the `format` registry is a
**specification correction, not a wire change** — no AAD version bump.

- The AAD bytes produced by every deployed SDK (cachekit-py, cachekit-ts,
  cachekit-rs) are unchanged; every existing v0x03 ciphertext remains decryptable.
- [Interop/v1](interop-mode.md) test vectors already pin `compressed = "False"` as
  normative published bytes; a re-encoding would fork that surface.
- A hypothetical v0x04 with a single-byte boolean (`0x00`/`0x01`) would invalidate
  all deployed ciphertexts or force a dual-AAD migration window, for zero security
  gain — a frozen ASCII token authenticates exactly as strongly as a byte.

**Backward compatibility**: none required — no wire bytes changed. The spec
previously *defined* the `compressed` encoding by reference to Python semantics
(`str(bool)`) and gave `format` only as an example; both are now explicit byte-level
registries.

### AAD Construction Pseudocode

```
function create_aad(tenant_id, cache_key, format, compressed, original_type=null):
    components = [
        tenant_id.encode("utf-8"),
        cache_key.encode("utf-8"),
        format.encode("utf-8"),                            // registry token: "msgpack" | "orjson" | "arrow"
        (compressed ? "True" : "False").encode("utf-8"),   // frozen ASCII tokens — see above
    ]
    if original_type is not null:
        components.append(original_type.encode("utf-8"))

    aad = bytes([0x03])  // Version byte
    for component in components:
        aad += uint32_be(len(component)) + component

    return aad
```

Reference AAD vectors — covering `compressed=False`, the `arrow` and `orjson`
tokens, four-component AADs (the cachekit-ts / cachekit-rs shape) and five-component
`original_type` AADs (the cachekit-py shape) — are published in
[`test-vectors/encryption.json`](../test-vectors/encryption.json) and verified in CI
by `tools/encryption-verify.py`.

---

## Encryption Header (RotationAwareHeader)

When key rotation is in use, a 32-byte header is prepended to identify which key encrypted the data.

```
┌──────┬──────┬──────────────────┬───────────────┬────────┬─────────┬──────────┐
│ ver  │ algo │ key_fingerprint  │ tenant_hash   │ domain │ key_ver │ reserved │
└──────┴──────┴──────────────────┴───────────────┴────────┴─────────┴──────────┘
  1 B    1 B     16 bytes           8 bytes         4 B      1 B       1 B
│◄──────────────────────── 32 bytes total ──────────────────────────────────────►│
```

| Field | Offset | Size | Description |
| :--- | :---: | :---: | :--- |
| `version` | 0 | 1 | Header version (must be `1`) |
| `algorithm` | 1 | 1 | Encryption algorithm (`0` = AES-256-GCM, only valid value) |
| `key_fingerprint` | 2 | 16 | First 16 bytes of SHA-256("key_fingerprint_v1" \|\| key) |
| `tenant_id_hash` | 18 | 8 | Tenant identifier hash |
| `domain` | 26 | 4 | Domain context (e.g., `"ench"` for encryption) |
| `key_version` | 30 | 1 | `0` = original key, `1` = rotated key |
| reserved | 31 | 1 | Reserved (must be `0x00`) |

### Key Rotation Strategy

```
1. Start rotation   → set new key, keep old key for decryption
2. New encryptions  → use new key (key_version=1)
3. Decryption       → try both keys based on key_version byte
4. Migration window → run until all old-key entries expire
5. Complete         → remove old key (complete_rotation())
```

---

## Encryption Flow

```
Input: user_data, master_key, tenant_id, cache_key

1. Serialize:  serialized_bytes = serialize(user_data)              // msgpack / orjson / arrow
2. Envelope:   plaintext_bytes  = envelope(serialized_bytes)        // See wire-format.md
3. Derive:     tenant_keys      = derive_tenant_keys(master_key, tenant_id)
4. Build AAD:  aad              = create_aad(tenant_id, cache_key, format, compressed)
5. Encrypt:    ciphertext       = aes_256_gcm_encrypt(
                                      plaintext = plaintext_bytes,
                                      key       = tenant_keys.encryption_key,
                                      aad       = aad
                                  )
               // Returns: nonce(12) || encrypted_data || auth_tag(16)
6. Store:      backend.set(cache_key, ciphertext)   // format + compressed stored as cleartext metadata
```

The AAD inputs in step 4 MUST reflect what steps 1–2 actually produced — e.g.
cachekit-py's default `StandardSerializer` path is
`("msgpack", true, original_type="msgpack")`; cachekit-ts's default is
`("msgpack", true)` with no fifth component; interop mode is always
`("msgpack", false)` with the envelope step skipped
([interop-mode.md](interop-mode.md#encryption-in-interop-mode)); cachekit-py's
`ArrowSerializer` with compression disabled is
`("arrow", false, original_type="arrow")`. Authenticating a flag that does not match
the real envelope is a conformance bug: the entry round-trips within the writing
process but fails authentication for any correct second reader (see
[cachekit-py#166](https://github.com/cachekit-io/cachekit-py/issues/166)).

---

## Decryption Flow

```
Input: ciphertext, stored metadata (format, compressed, optional original_type),
       master_key, tenant_id, cache_key

1. Derive:      tenant_keys    = derive_tenant_keys(master_key, tenant_id)
2. Build AAD:   aad            = create_aad(tenant_id, cache_key,
                                            stored.format, stored.compressed, stored.original_type)
3. Decrypt:     plaintext_bytes = aes_256_gcm_decrypt(
                                      ciphertext = ciphertext,  // nonce(12) || encrypted || tag(16)
                                      key        = tenant_keys.encryption_key,
                                      aad        = aad
                                  )
4. Unenvelope:  serialized_bytes = unenvelope(plaintext_bytes)   // per the reader's configured
                                                                 // serializer/mode — see wire-format.md
5. Deserialize: user_data = deserialize(serialized_bytes)
```

The AAD in step 2 is rebuilt from the **stored cleartext metadata**; tampering makes
step 3 fail authentication, which is a hard error — the no-retry and no-sniffing
rules in [AAD v0x03 Format](#additional-authenticated-data-aad) apply. How each SDK
stores this metadata (e.g. cachekit-py's CK frame header) is SDK-internal; the only
cross-SDK-normative AAD inputs are interop mode's pinned four components.

---

## Compliance

| Standard | Basis |
| :--- | :--- |
| HIPAA | AES-256 satisfies encryption at rest requirements |
| PCI-DSS | AES-256 satisfies data protection requirements |
| FIPS 140-3 | AES-256-GCM is FIPS-approved |
| SOC 2 | AES-256 satisfies encryption controls |
| GDPR | Zero-knowledge architecture means SaaS backend is out of scope for data processing |

---

<div align="center">

[Protocol](../README.md) · [Cache Key Format](cache-key-format.md) · [Wire Format](wire-format.md) · [SaaS API](saas-api.md) · [Interop Mode](interop-mode.md)

</div>
