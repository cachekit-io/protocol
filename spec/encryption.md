# Encryption Specification

**Protocol Version**: 1.0
**Verified Against**: `cachekit-core` v0.1.1 (`src/encryption/core.rs`, `src/encryption/key_derivation.rs`, `src/encryption/key_rotation.rs`) and `cachekit-py` (`src/cachekit/serializers/encryption_wrapper.py`)

## Overview

CacheKit provides **optional** client-side encryption using AES-256-GCM. When enabled, the backend (Redis or SaaS) stores opaque ciphertext and never has access to keys or plaintext. This is the "zero-knowledge" guarantee.

Encryption is not configurable by design. AES-256-GCM is the only supported algorithm. See the [Encryption Algorithm Decision Record](../decisions/encryption-algorithm.md) for rationale.

## Algorithm

**Cipher**: AES-256-GCM (Authenticated Encryption with Associated Data)
**Key size**: 256 bits (32 bytes)
**Nonce size**: 96 bits (12 bytes)
**Auth tag size**: 128 bits (16 bytes)
**Library**: `ring` crate (Rust), wrapping platform AES-NI/ARM crypto instructions

## Key Derivation

### Master Key

The customer supplies a master key via environment variable:

```
CACHEKIT_MASTER_KEY=a1b2c3d4e5f6...  (hex-encoded, minimum 32 bytes / 64 hex chars)
```

Minimum master key length: **16 bytes** (32 bytes strongly recommended).

### HKDF-SHA256 Key Derivation

Per-tenant keys are derived using HKDF (RFC 5869) with SHA-256.

```
derived_key = HKDF-SHA256(
    input_key_material = master_key,
    salt = construct_salt(domain, tenant_salt),
    info = domain.as_bytes(),
    output_length = 32
)
```

#### Salt Construction

The salt is a length-prefixed encoding that prevents collision attacks:

```
salt = "cachekit_v1_"                    // 12 bytes, fixed prefix
     + [domain_length as u8]             // 1 byte
     + domain_bytes                      // variable
     + [tenant_salt_length as u16 BE]    // 2 bytes, big-endian
     + tenant_salt_bytes                 // variable
```

**Example**: domain=`"cache"`, tenant_salt=`"tenant-123"`

```
Offset  Bytes                              Description
------  ---------------------------------  -----------
0-11    63 61 63 68 65 6b 69 74 5f 76 31 5f  "cachekit_v1_"
12      05                                  domain length (5)
13-17   63 61 63 68 65                      "cache"
18-19   00 0a                               tenant_salt length (10, big-endian)
20-29   74 65 6e 61 6e 74 2d 31 32 33      "tenant-123"
```

This length-prefixed format prevents collision between `(domain="foo", salt="bar")` and `(domain="foob", salt="ar")`.

#### Constraints

| Parameter | Limit |
|-----------|-------|
| Minimum master key length | 16 bytes |
| Maximum domain length | 255 bytes (fits in u8) |
| Maximum tenant salt length | 1024 bytes (fits in u16) |
| Domain | Must not be empty |
| Tenant salt | Must not be empty |

### Tenant Key Derivation

Each tenant gets three domain-separated keys derived from the same master key:

```
encryption_key     = derive_domain_key(master_key, "encryption", tenant_id.as_bytes())
authentication_key = derive_domain_key(master_key, "authentication", tenant_id.as_bytes())
cache_key_salt     = derive_domain_key(master_key, "cache_keys", tenant_id.as_bytes())
```

All three are 32-byte (256-bit) keys. They are cryptographically independent due to domain separation.

### Key Fingerprint

For key identification without revealing key material:

```
fingerprint = SHA-256("key_fingerprint_v1" || key)[0..16]   // First 16 bytes of hash
```

## Nonce Generation

> [!WARNING] Discrepancy with RFC
> The RFC (Section 5.3) specifies random 12-byte nonces (`os.urandom(12)`). The actual implementation uses a **deterministic counter-based** approach that eliminates birthday-bound collision risk. **The implementation is authoritative.**

### Counter-Based Nonce Format

```
+-------------------+-------------------+
| instance_id (8B)  |   counter (4B)    |
+-------------------+-------------------+
|<------------ 12 bytes (96 bits) ----->|
```

| Field | Size | Encoding | Source |
|-------|------|----------|--------|
| `instance_id` | 8 bytes | Big-endian u64 | Global atomic counter (randomized start) |
| `counter` | 4 bytes | Big-endian u32 | Per-instance atomic counter (starts at 0) |

**Security properties**:
- `instance_id` is globally unique within a process (monotonic atomic counter)
- Randomized 32-bit seed in upper bits provides cross-process collision resistance
- Per-instance counter allows 2^32 encryptions per instance
- Total: 2^96 unique nonces (far exceeds practical usage)
- Nonce counter exhaustion (>= 2^32 per instance) returns an error, never wraps

### SDK Implementation Note

SDKs that cannot replicate the Rust counter-based nonce strategy MAY use random 12-byte nonces as a fallback. Random nonces are safe for AES-256-GCM up to ~2^32 encryptions per key (birthday bound). The counter-based approach is strictly superior but not required for interoperability -- nonces are prepended to ciphertext and extracted during decryption regardless of generation strategy.

## Ciphertext Format

```
+-------------------+----------------------------------+
|    nonce (12B)    |   ciphertext + auth_tag          |
+-------------------+----------------------------------+
|<----- plaintext encrypted with AES-256-GCM -------->|
                    |<-- variable -->|<--- 16 bytes -->|
```

The output of `encrypt_aes_gcm()` is:

```
result = nonce_bytes (12) || aes_gcm_seal(plaintext, key, nonce, aad)
```

Where `aes_gcm_seal` returns `ciphertext || auth_tag` (the auth tag is the last 16 bytes).

**Minimum ciphertext length**: 28 bytes (12 nonce + 0 plaintext + 16 auth tag).

## Additional Authenticated Data (AAD)

### AAD v0x03 Format

The AAD binds ciphertext to its intended context, preventing ciphertext substitution attacks.

```
+--------+--------+-----------+--------+-----------+--------+--------+--------+-----------+
| 0x03   | len1   | tenant_id | len2   | cache_key | len3   | format | len4   | compressed|
+--------+--------+-----------+--------+-----------+--------+--------+--------+-----------+
  1 byte   4 bytes  variable    4 bytes  variable    4 bytes  var      4 bytes  var
           BE u32              BE u32              BE u32             BE u32
```

| Field | Type | Description |
|-------|------|-------------|
| Version byte | `0x03` | AAD format version |
| `tenant_id` | Length-prefixed UTF-8 | Tenant identifier |
| `cache_key` | Length-prefixed UTF-8 | Full cache key (prevents ciphertext swapping between keys) |
| `format` | Length-prefixed UTF-8 | Serialization format (e.g., `"msgpack"`) |
| `compressed` | Length-prefixed UTF-8 | String `"True"` or `"False"` |
| `original_type` | Length-prefixed UTF-8 | (Optional) Original type hint |

Each component is prefixed with a 4-byte big-endian length.

**Security**: The `cache_key` binding is critical. Without it, an attacker within the same tenant could swap ciphertext between different cache keys. With AAD v0x03, AES-GCM authentication fails if the cache key does not match.

> [!WARNING] Discrepancy with RFC
> The RFC (Section 5.3-5.4) shows encryption with `None` as AAD (no additional authenticated data). The actual implementation uses AAD v0x03 with cache_key binding. **The implementation is authoritative.** AAD is a security-critical feature that prevents ciphertext substitution (CVSS 8.5).

### AAD Construction Pseudocode

```
function create_aad(tenant_id, cache_key, format, compressed, original_type=null):
    components = [
        tenant_id.encode("utf-8"),
        cache_key.encode("utf-8"),
        format.encode("utf-8"),           // e.g., "msgpack"
        str(compressed).encode("utf-8"),  // "True" or "False"
    ]
    if original_type is not null:
        components.append(original_type.encode("utf-8"))

    aad = bytes([0x03])  // Version byte
    for component in components:
        aad += uint32_be(component.length) + component

    return aad
```

## Encryption Header (RotationAwareHeader)

When key rotation is in use, an encryption header is prepended to identify which key encrypted the data.

```
+------+------+------------------+---------------+--------+---------+----------+
| ver  | algo | key_fingerprint  | tenant_hash   | domain | key_ver | reserved |
+------+------+------------------+---------------+--------+---------+----------+
  1B     1B     16 bytes           8 bytes         4B       1B        1B
|<--------------------------- 32 bytes total ----------------------------------->|
```

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| `version` | 0 | 1 | Header version (must be `1`) |
| `algorithm` | 1 | 1 | Encryption algorithm (`0` = AES-256-GCM, only valid value) |
| `key_fingerprint` | 2 | 16 | First 16 bytes of SHA-256("key_fingerprint_v1" \|\| key) |
| `tenant_id_hash` | 18 | 8 | Tenant identifier hash |
| `domain` | 26 | 4 | Domain context (e.g., `"ench"` for encryption) |
| `key_version` | 30 | 1 | `0` = original key, `1` = rotated key |
| reserved | 31 | 1 | Reserved (must be `0x00`) |

### Key Rotation Strategy

1. Start rotation: set new key, keep old key for decryption
2. All new encryptions use new key (`key_version=1`)
3. Decryption tries both keys based on `key_version` byte
4. After migration window: remove old key (`complete_rotation()`)

## Complete Encryption Flow

```
Input: user_data, master_key, tenant_id, cache_key

1. Serialize: msgpack_bytes = msgpack_encode(user_data)
2. Compress:  envelope_bytes = byte_storage.store(msgpack_bytes)  // See wire-format.md
3. Derive:    tenant_keys = derive_tenant_keys(master_key, tenant_id)
4. Build AAD: aad = create_aad(tenant_id, cache_key, "msgpack", true)
5. Encrypt:   ciphertext = aes_256_gcm_encrypt(
                  plaintext = envelope_bytes,
                  key = tenant_keys.encryption_key,
                  aad = aad
              )
              // Returns: nonce(12) || encrypted_data || auth_tag(16)
6. Store:     backend.set(cache_key, ciphertext)
```

## Complete Decryption Flow

```
Input: ciphertext, master_key, tenant_id, cache_key

1. Derive:    tenant_keys = derive_tenant_keys(master_key, tenant_id)
2. Build AAD: aad = create_aad(tenant_id, cache_key, "msgpack", true)
3. Decrypt:   envelope_bytes = aes_256_gcm_decrypt(
                  ciphertext = ciphertext,  // nonce(12) || encrypted || tag(16)
                  key = tenant_keys.encryption_key,
                  aad = aad
              )
4. Extract:   (msgpack_bytes, format) = byte_storage.retrieve(envelope_bytes)
5. Deserialize: user_data = msgpack_decode(msgpack_bytes)
```

## Compliance

- HIPAA: AES-256 satisfies encryption at rest requirements
- PCI-DSS: AES-256 satisfies data protection requirements
- FIPS 140-3: AES-256-GCM is FIPS-approved
- SOC 2: AES-256 satisfies encryption controls
- GDPR: Zero-knowledge architecture means SaaS backend is out of scope for data processing
