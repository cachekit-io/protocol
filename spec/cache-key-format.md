**[Protocol](../README.md)** > **Cache Key Format**

<div align="center">

# Cache Key Format Specification

**Deterministic key generation from function identity and arguments.**

*Protocol Version 1.0 · Verified against `cachekit-py` v0.5.0 (`src/cachekit/key_generator.py`)*

</div>

---

## Table of Contents

- [Key Format](#key-format)
- [Cross-SDK Key Generation Strategy](#cross-sdk-key-generation-strategy)
- [Argument Hashing Algorithm](#argument-hashing-algorithm)
- [Character Normalization](#character-normalization)
- [Pseudocode for SDK Implementors](#pseudocode-for-sdk-implementors)

---

## Key Format

> [!IMPORTANT]
> **Cross-SDK limitation**: The default key format includes a language-specific `func:` segment (Python module path, Rust crate path, Go package path). This means **auto-generated keys are NOT compatible across different language SDKs**. For cross-SDK cache sharing, use [Interop Mode](interop-mode.md) which uses explicit, language-neutral operation names.
>
> Within a single SDK, the same function call with the same arguments will always produce the same key.

### Full Key Structure

```
ns:{namespace}:func:{module}.{qualname}:args:{blake2b_hash}:{ic_flag}{serializer_code}
```

| Segment | Description | Example |
| :--- | :--- | :--- |
| `ns:{namespace}:` | Optional namespace prefix | `ns:users:` |
| `func:{module}.{qualname}:` | Function identifier (module path + qualified name) | `func:myapp.services.get_user:` |
| `args:{blake2b_hash}:` | Blake2b-256 hash of normalized, MessagePack-serialized arguments | `args:a3c8d4...f2e1:` |
| `{ic_flag}` | Integrity checking: `1` = ByteStorage enabled, `0` = raw MessagePack | `1` |
| `{serializer_code}` | Serializer type (1 char) | `s` |

### Serializer Codes

| Code | Serializer | Cross-language? |
| :---: | :--- | :---: |
| `s` | StandardSerializer (MessagePack) | ✅ Yes |
| `a` | AutoSerializer (Python-specific) | ❌ No |
| `o` | OrjsonSerializer (JSON-based) | ⚠️ Partial |
| `w` | ArrowSerializer (columnar) | ⚠️ Partial |

For cross-SDK interoperability, always use `s` (StandardSerializer).

### Example Keys

```
# With namespace, integrity checking ON, standard serializer
ns:users:func:myapp.services.get_user:args:a3c8d4f2e1b9c6d5e4f3a2b1c0d9e8f7a3c8d4f2e1b9c6d5e4f3a2b1c0d9e8f7:1s

# Without namespace
func:myapp.services.get_user:args:a3c8d4f2e1b9c6d5e4f3a2b1c0d9e8f7a3c8d4f2e1b9c6d5e4f3a2b1c0d9e8f7:1s

# Integrity checking OFF, standard serializer
ns:cache:func:app.views.index:args:0000...0000:0s
```

### Key Length Limits

- **Maximum key length**: 250 characters (Redis/Memcached practical limit)
- If a key exceeds 250 characters: first 50 chars of original key + `:` + first 32 chars of a Blake2b-256 hash of the full key

> [!WARNING]
> **Discrepancy with RFC** — The original protocol RFC (Section 3.1.5) specifies a simpler key format: `{namespace}:{hash}`. The actual implementation includes function identity (`func:` prefix) and metadata suffix (`:{ic_flag}{serializer_code}`). **The implementation is authoritative.** For cross-SDK interoperability, SDK implementors must use explicit namespaces (the `func:` segment is language-specific and will differ).

---

## Cross-SDK Key Generation Strategy

For multi-language interoperability, all SDKs MUST use **explicit namespaces** rather than auto-generated function signatures. The `func:` segment is inherently language-specific (Python modules vs PHP namespaces vs Go packages), so cross-language cache sharing requires:

1. All SDKs agree on a namespace string (e.g., `"get_user"`)
2. All SDKs serialize arguments identically (see [Argument Hashing Algorithm](#argument-hashing-algorithm) below)
3. The resulting Blake2b hash in the `args:` segment will be identical

The `func:` and metadata segments may differ between SDKs — this is acceptable when the key is constructed to match.

> [!TIP]
> Use [Interop Mode](interop-mode.md) to remove the `func:` segment entirely. Interop mode produces the simplest possible cross-language key: `{namespace}:{operation}:{args_hash}`.

---

## Argument Hashing Algorithm

### Step 1: Normalize Arguments

All arguments are recursively normalized to cross-language-compatible types before serialization.

#### Normalization Rules

| Input Type | Normalized Form | Notes |
| :--- | :--- | :--- |
| `int` | Pass through | Arbitrary precision |
| `float` | Normalize `-0.0` → `0.0` | IEEE 754 compatibility |
| `str` | Pass through | UTF-8 |
| `bytes` | Pass through | Raw binary |
| `bool` | Pass through | |
| `None`/`null`/`nil` | Pass through | |
| `list`/`array` | Recursively normalize elements | |
| `tuple` | Normalize as list | Tuples become lists |
| `dict`/`map`/`object` | Sort by key, recursively normalize values | Sorted by string key |
| `Path` | POSIX string (`path.as_posix()`) | Cross-platform |
| `UUID` | String (`str(uuid)`) | Lowercase hex with dashes |
| `Decimal` | String (`str(decimal)`) | Exact decimal |
| `Enum` | Recursively normalize `.value` | |
| `datetime` (timezone-aware) | ISO 8601 string (`.isoformat()`) | **Naive datetimes are rejected** |
| `set`/`frozenset` | **REJECTED** | Convert to sorted list first |
| Custom objects | **REJECTED** | Convert to dict first |

> [!CAUTION]
> Naive datetimes (without timezone info) are rejected at normalization time. This is intentional — naive datetimes are ambiguous across timezones and would produce inconsistent keys depending on where the calling code runs.

#### NumPy Array Support (Constrained)

NumPy 1D arrays are supported with strict constraints:

| Constraint | Limit |
| :--- | ---: |
| Dimensions | 1D only |
| Max size per array | 100 KB |
| Max aggregate size | 5 MB across all args |
| Allowed dtypes | `int32`, `int64`, `float32`, `float64` |
| Byte order | Little-endian (forced) |
| Memory layout | C-contiguous (forced) |

Normalized form: `["__array_v1__", [shape], dtype_str, blake2b_hash_of_bytes]`

Where `dtype_str` is one of: `"i32"`, `"i64"`, `"f32"`, `"f64"`.

> [!NOTE]
> NumPy array support is Python-specific. Other SDKs receiving cache keys with `__array_v1__` markers should treat them as opaque list structures.

### Step 2: Serialize with MessagePack

The normalized `[args_list, kwargs_dict]` structure is serialized using MessagePack:

```python
msgpack.packb([normalized_args, normalized_kwargs], use_bin_type=True, strict_types=True)
```

Requirements:

| Option | Value | Reason |
| :--- | :---: | :--- |
| `use_bin_type` | `True` | Encode bytes as MessagePack `bin` type (not `str`) |
| `strict_types` | `True` | Do not coerce types |
| kwargs sort | sorted | kwargs dict keys are sorted before normalization |

> [!WARNING]
> **Discrepancy with RFC** — The RFC (Section 3.1.2–3.1.3) specifies a custom type-prefixed binary encoding scheme (e.g., `b"N"` for None, `b"B1"` for True, `b"I"` + length + little-endian int). **The actual implementation uses MessagePack serialization instead.** MessagePack is the authoritative encoding. The RFC's custom encoding was a design proposal superseded during implementation.

### Step 3: Hash with Blake2b-256

```python
hashlib.blake2b(msgpack_bytes, digest_size=32).hexdigest()
```

| Parameter | Value |
| :--- | :--- |
| Algorithm | Blake2b |
| Digest size | 32 bytes (256 bits) |
| Output | 64 hex characters (lowercase) |
| Key | None (unkeyed mode) |

---

## Character Normalization

After key construction, the following characters are replaced:

| Character | Replacement |
| :---: | :---: |
| Space (` `) | `_` |
| Newline (`\n`) | `_` |
| Carriage return (`\r`) | `_` |

---

## Pseudocode for SDK Implementors

<details>
<summary>Expand full pseudocode</summary>

```
function generate_cache_key(namespace, func_module, func_qualname, args, kwargs,
                            integrity_checking=true, serializer_type="std"):

    // Build key parts
    parts = []

    if namespace:
        parts.append("ns:" + namespace + ":")

    parts.append("func:" + func_module + "." + func_qualname + ":")

    // Hash arguments
    normalized_args = [normalize(a) for a in args]
    normalized_kwargs = {k: normalize(v) for k, v in sorted(kwargs)}
    msgpack_bytes = msgpack_encode([normalized_args, normalized_kwargs])
    hash = blake2b_256(msgpack_bytes).hex()

    parts.append("args:" + hash + ":")

    // Metadata suffix
    ic_flag = "1" if integrity_checking else "0"
    serializer_code = SERIALIZER_CODES[serializer_type]  // "s" for standard
    parts.append(ic_flag + serializer_code)

    key = join(parts)

    // Length limit enforcement
    if len(key) > 250:
        key_hash = blake2b_256(key.encode("utf-8")).hex()[:32]
        key = key[:50] + ":" + key_hash

    return key
```

</details>

---

<div align="center">

[Protocol](../README.md) · [Wire Format](wire-format.md) · [Encryption](encryption.md) · [Interop Mode](interop-mode.md) · [SaaS API](saas-api.md)

</div>
