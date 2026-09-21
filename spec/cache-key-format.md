**[Protocol](../README.md)** > **Cache Key Format**

<div align="center">

# Cache Key Format Specification

**Deterministic key generation from function identity and arguments.**

*Protocol Version 1.0 · Verified against `cachekit-py` v0.18.0 (`src/cachekit/key_generator.py`)*

</div>

---

## Table of Contents

- [Key Format](#key-format)
- [Cross-SDK Key Generation Strategy](#cross-sdk-key-generation-strategy)
- [Argument Hashing Algorithm](#argument-hashing-algorithm)
- [Character Normalization](#character-normalization)
- [Test Vectors](#test-vectors)
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
| `{serializer_code}` | Serializer identity (1 char, or `x` + 4 hex — see below) | `s` |

### Serializer Codes

| Code | Serializer | Canonical name | Cross-language? |
| :---: | :--- | :--- | :---: |
| `s` | StandardSerializer (MessagePack) | `default` | ✅ Yes |
| `a` | AutoSerializer (language-specific types) | `auto` | ❌ No |
| `o` | OrjsonSerializer (JSON-based) | `orjson` | ⚠️ Partial |
| `w` | ArrowSerializer (columnar) | `arrow` | ⚠️ Partial |
| `l` | Reference caching (no serialization) | `local` | ❌ No |
| `x` + 4 hex | Any serializer identity not in this table | — | ❌ No |

For cross-SDK interoperability, always use `s` (StandardSerializer).

An identity outside the table gets `x` followed by the first 2 bytes of
`blake2b(identity, digest_size=2)` as lowercase hex — a per-identity code, not a shared
bucket. Codes are therefore 1 character for the table entries and 5 for everything else.

> [!IMPORTANT]
> **The code MUST be derived from the serializer the cache is configured with, never a
> fixed default.** An SDK that emits one constant code collapses every serializer onto a
> single keyspace: two caches over one function then share a key, each fails the other's
> serializer-name check on read, evicts, and recomputes — a permanent 0% hit rate.
>
> **Two serializer identities that the wire format records differently MUST NOT share a
> code**, which is why the fallback is derived rather than constant. Where a derivation
> collision does occur (≈1 in 2^16), the reader-side serializer-name check in the
> [wire format](wire-format.md) is the only remaining separator, so that check is REQUIRED,
> not advisory.
>
> `cache_key` is an AES-256-GCM AAD input (see [Encryption](encryption.md)). Two serializers
> sharing a code therefore produce a **byte-identical AAD**: AAD binding does not separate
> them, and the cipher is not a backstop for a missing name check.
>
> **Conversely, one identity MUST always produce one code.** Derive it from the same value
> the wire format records as the serializer name, never from a process-local value such as
> an object address or a randomised hash, or keys stop being reproducible across processes.

> [!NOTE]
> **Python SDK specifics.** `cachekit-py` additionally accepts the alias spellings
> `std`/`standard` for `default` and `pythonic` for `auto`, canonicalizing them before the
> lookup. A serializer passed as an *instance* rather than a name is recorded under its class
> name — built-ins included — and so takes a derived `x`-prefixed code rather than the
> table's. Two instances of the same class are one identity: the SDK documents distinct
> namespaces for per-configuration serializers.

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

## Test Vectors

[`test-vectors/cache-keys.json`](../test-vectors/cache-keys.json) contains 10 auto-mode key vectors (`args` + `kwargs` + metadata → `expected_key`) covering primitives, mixed args/kwargs, `null`, booleans, nested dicts, and the no-namespace form. Keys were generated at top level, so the `func:` segment is `__main__.{qualname}` — cross-SDK implementations substitute their own module path; only the args-hash segment must match byte-for-byte.

Enforcement: the vectors are vendored (sha256-pinned) into cachekit-py and byte-verified against `CacheKeyGenerator` on every default CI run (`tests/unit/protocol/test_cache_key_vectors.py`). A vector failing there is a key-stability break to triage — never silently regenerate: a changed key orphans every existing cache entry and turns the fleet's hits into billed misses.

---

## Pseudocode for SDK Implementors

<details>
<summary>Expand full pseudocode</summary>

```
SERIALIZER_CODES = {"default": "s", "auto": "a", "orjson": "o", "arrow": "w", "local": "l"}

// Alias spellings this SDK accepts -> canonical name. Empty if the SDK accepts only
// canonical names. The SAME map must canonicalize the serializer name the wire format
// records, or a key and its stored envelope can disagree about which serializer wrote it.
SERIALIZER_ALIASES = {"std": "default", "standard": "default", "pythonic": "auto"}

function serializer_code(serializer_type):
    // Resolve any alias spelling this SDK accepts, then look the code up. An identity
    // outside the table gets its OWN derived code — never a shared constant, which would
    // put every unrecognised serializer on one keyspace.
    canonical = SERIALIZER_ALIASES.get(serializer_type, serializer_type)
    if canonical in SERIALIZER_CODES:
        return SERIALIZER_CODES[canonical]
    return "x" + hex(blake2b(canonical.utf8_bytes(), digest_size=2))

function generate_cache_key(namespace, func_module, func_qualname, args, kwargs,
                            integrity_checking=true, serializer_type="default"):

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

    // Metadata suffix. serializer_type is the serializer the cache is CONFIGURED with —
    // read it from the decorator/client configuration, never a fixed default.
    ic_flag = "1" if integrity_checking else "0"
    parts.append(ic_flag + serializer_code(serializer_type))

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
