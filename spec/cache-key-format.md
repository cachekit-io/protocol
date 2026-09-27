**[Protocol](../README.md)** > **Cache Key Format**

<div align="center">

# Cache Key Format Specification

**Deterministic key generation from function identity and arguments.**

*Protocol Version 1.0 · Serializer-code derivation verified against `cachekit-py` @ `ee65250` (the [cachekit-io/cachekit-py#311](https://github.com/cachekit-io/cachekit-py/pull/311) merge)*

</div>

---

## Table of Contents

- [Key Format](#key-format)
- [Server-Side Requirements](#server-side-requirements)
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

> [!NOTE]
> This 7-segment structure is the **Python SDK's internal convention**, not a
> server requirement. The CachekitIO backend validates keys security-only (see
> [Server-Side Requirements](#server-side-requirements)) and otherwise treats
> them as opaque strings — TypeScript/Rust `{ns}:{hash}` keys and
> [Interop Mode](interop-mode.md) keys are equally valid on the wire.

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

| Code | Serializer | Canonical name |
| :---: | :--- | :--- |
| `s` | StandardSerializer (MessagePack) | `default` |
| `a` | AutoSerializer (language-specific types) | `auto` |
| `o` | OrjsonSerializer (JSON-based) | `orjson` |
| `w` | ArrowSerializer (columnar) | `arrow` |
| `l` | Reference caching (no serialization) | `local` |
| `x` + 4 hex | Any serializer identity not in this table | — |

No code makes these keys shareable across SDKs; see
[Cross-SDK Key Generation Strategy](#cross-sdk-key-generation-strategy).

An identity outside the table gets `x` followed by the 2-byte digest
`blake2b(utf8(identity), digest_size=2)` encoded as exactly 4 lowercase hexadecimal
characters — zero-padded, no `0x` prefix, the same encoding as the args hash. Example:
identity `cbor` → `x23d5`. Codes are 1 character for the table entries and 5 for everything
else.

> [!IMPORTANT]
> **The code MUST be derived from the serializer the cache is configured with, never a
> fixed default.** An SDK that emits one constant code collapses every serializer onto a
> single keyspace: two caches over one function then share a key, each fails the other's
> serializer-name check on read, evicts, and recomputes — a permanent 0% hit rate.
>
> **Two serializer identities that the wire format records differently MUST NOT be mapped
> onto one code by construction.** The guarantee is probabilistic, not absolute: the derived
> code carries 16 bits, so two identities it records differently can still collide, at ≈1 in
> 2^16 per pair. Between honestly written entries, such a collision costs hit rate only —
> that one pair evicts each other exactly as a constant code makes every pair do — and never
> yields a wrong value, because the stored serializer name still differs and the read-side
> check below rejects it. The recorded name is not an integrity control against a writer with
> backend write access: the CK v3 frame header that carries it is plaintext and
> unauthenticated, even for encrypted entries (see the
> [frame header caution](wire-format.md#python-ck-v3-frame)).
>
> **An SDK that offers more than one serializer identity MUST record the serializer name in
> the storage container of every serialized entry it stores under a key in this format
> (Python: the `s` field of the [CK v3 frame](wire-format.md#python-ck-v3-frame)). On every
> read of a serialized entry under a key in this format, before decoding the payload, such an
> SDK MUST compare the name the container records with the name it would itself record for
> its configured serializer, and MUST reject the entry on mismatch — a miss, never a value.
> For such an SDK, an entry that records no serializer name is a mismatch.** A colliding
> entry has the same key as the reader's own, so nothing before this comparison can tell them
> apart. An SDK that offers exactly one serializer identity is exempt from both the recording
> and the comparison, because there is no second serializer in its keyspace to confuse with
> the first (`cachekit-ts` and `cachekit-rs` offer one and record none). Neither rule reaches
> a value that is not a serialized entry under a key in this format:
> [Interop Mode](interop-mode.md) entries carry no serializer code and no container, and a
> cache that keeps live objects in process memory stores nothing to compare (in
> `cachekit-py`: reference caching, code `l`, and caches configured with no backend).
>
> `cache_key` is an AES-256-GCM AAD input (see [Encryption](encryption.md)). Two serializers
> sharing a code therefore share the **`cache_key` AAD component**, and a reader takes the
> `format` component from the entry's stored metadata, not from its own serializer (see
> [Encryption](encryption.md#format-tokens)). AAD binding does not separate them,
> whatever their `format` tokens, and the cipher is not a backstop for a missing name check.
>
> **Conversely, one identity MUST always produce one code.** Derive it from the serializer
> configuration alone — the canonical name the wire format records, or an SDK-defined
> refinement of it that never merges two names (see the Python note below; a refinement
> separates keyspaces, the read-side check still sees only the recorded name) — never from a
> process-local value such as an object address or a randomised hash, or keys stop being
> reproducible across processes.
>
> **Deriving the identity.** An SDK that accepts alias spellings MUST resolve each accepted
> spelling to exactly one canonical name, and the code, the recorded name, and the serializer
> that writes the bytes MUST all be that canonical name's, or a key, its stored entry and its
> bytes can disagree about which serializer wrote it. An SDK that accepts a serializer object
> MUST reduce it to a string identity carrying a marker that no code-table name, alias
> spelling or accepted serializer name contains, so a user-named class can never take a table
> code (the Python note below gives `cachekit-py`'s marker). An empty or non-string identity
> MUST be rejected with an error, never mapped to a code: a fallback code is a shared bucket,
> and a key computed from it names an entry nothing wrote.
>
> **An SDK SHOULD make the identity distinguish configurations that write different bytes.
> Wherever its identity does not, configurations that write different bytes and would
> otherwise share a key MUST be keyed under different `ns:` namespaces**, no namespace
> counting as one. Sharing an identity, they share a code, so a key, and a recorded name, so
> the read-side check cannot tell them apart: one is served the other's bytes as a hit —
> wrong data, not an eviction. The `ns:` MUST also covers distinct identities that share one
> recorded name and write different bytes, because the 16-bit code is NOT a
> collision-resistant separator: two such identities collide at ≈1 in 2^16 per pair, and key
> and recorded name then both match. The hit-rate-only collision guarantee above covers only
> identities recorded differently. The Python SDK is the known case where the identity does not distinguish configurations (see the note below).

> [!NOTE]
> **Python SDK specifics.** `cachekit-py` additionally accepts the alias spellings `std` for
> `default` and `pythonic` for `auto`, canonicalizing them before the lookup. (Its key
> generator's alias map also lists `standard`, which the cache rejects as a serializer name.)
> A serializer passed as an *instance* rather than a name is recorded in the frame header
> under its bare class name, built-ins included, and its key identity is `<custom>:` + that
> class name, so it takes a derived code (`ArrowSerializer()` → `<custom>:ArrowSerializer` →
> `x2263`), never the table's. The prefix contains characters no Python identifier can, so a
> custom class named `auto` cannot take AutoSerializer's code. Beyond that fixed prefix, the
> identity and the recorded name both carry only the bare class name (`__name__`), so two
> instances of one class with different constructor arguments, or of any two classes sharing
> that name whatever their module or nesting, get one code and one recorded name. Where they
> write different bytes and share a `func:` segment (one function, or closures from one
> factory), the `ns:` rule above applies — across a deploy too: a changed configuration or
> implementation takes a namespace the old one never wrote.

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
> **Discrepancy with RFC** — The original protocol RFC (Section 3.1.5) specifies a simpler key format: `{namespace}:{hash}`. The actual implementation includes function identity (`func:` prefix) and metadata suffix (`:{ic_flag}{serializer_code}`). **The implementation is authoritative.** For cross-SDK sharing, use [Interop Mode](interop-mode.md) (see [Cross-SDK Key Generation Strategy](#cross-sdk-key-generation-strategy)).

---

## Server-Side Requirements

The CachekitIO SaaS stores keys as opaque strings; the ONLY structure it
enforces is security-relevant (per `saas` issue #91 / SRP refactor):

| Check | Rule |
| :--- | :--- |
| Transport | Key is percent-encoded into the URL path; the server decodes it once. |
| Length | Decoded key ≤ 400 characters. |
| Charset | `[a-zA-Z0-9_.:-]` only — no `/` (sub-resource routing), no `%`, no control chars. |
| Traversal | `..` is rejected anywhere in the key. |
| Namespace | Keys starting `ns:{namespace}:` or `nsapi:{namespace}:` must have a namespace of 1–64 chars of `[a-zA-Z0-9_-]`. Keys without either prefix scope to the `default` namespace. |
| Write spaces | `ns:` keys are mutable only by SDK (`ck_sdk_`) API keys; `nsapi:` keys only by direct (`ck_api_`) API keys. Reads are open to both. Legacy `ck_live_` keys predate the split and are exempt from it — they may write either class. No server-side retirement date is set for `ck_live_`. |
| Default namespace | Keys with neither prefix (TypeScript/Rust `{ns}:{hash}`, [Interop Mode](interop-mode.md) keys, bare hashes) are an **open** write space: any key class may write them, so the intra-tenant write-space isolation above does not protect them. Per-key namespace grants still apply — an API key restricted to named namespaces must include `default` to read or write unprefixed keys. |

Everything else in this document — segment count, `func:`/`args:` literals,
hash length, metadata flags — is SDK convention for deterministic key
generation, invisible to the server.

---

## Cross-SDK Key Generation Strategy

Keys in this format are not shared across SDKs, even under an agreed namespace. The `func:` segment is language-specific, and the values stored under these keys are SDK-internal containers that no other SDK decodes (see [SDK Storage Containers](wire-format.md#sdk-storage-containers-auto-mode)). Cross-language cache sharing uses [Interop Mode](interop-mode.md) exclusively: explicit, language-neutral operation names, keys of the form `{namespace}:{operation}:{args_hash}`, and plain MessagePack values.

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

[`test-vectors/cache-keys.json`](../test-vectors/cache-keys.json) contains 10 auto-mode key vectors (`args` + `kwargs` + metadata → `expected_key`) covering primitives, mixed args/kwargs, `null`, booleans, nested dicts, and the no-namespace form. They were generated by `cachekit-py` v0.12.0 and the `vectors` array has not changed since; every vector uses `serializer_type: "std"` (→ `1s`), cachekit-py's alias for the canonical `default`, so the derived codes above are not yet covered. Keys were generated at top level, so the `func:` segment is `__main__.{qualname}`. These vectors are **Python-SDK-only**: the `func:` segment is language-specific, so no other SDK can reproduce these keys or share the cache entries they name. Cross-SDK conformance uses [`test-vectors/interop-mode.json`](../test-vectors/interop-mode.json) (see [Interop Mode](interop-mode.md)).

Enforcement: the vectors are vendored (sha256-pinned) into cachekit-py and byte-verified against `CacheKeyGenerator` on every default CI run (`tests/unit/protocol/test_cache_key_vectors.py`). A vector failing there is a key-stability break to triage — never silently regenerate: a changed key orphans every existing cache entry and turns the fleet's hits into billed misses.

---

## Pseudocode for SDK Implementors

<details>
<summary>Expand full pseudocode</summary>

```
SERIALIZER_CODES = {"default": "s", "auto": "a", "orjson": "o", "arrow": "w", "local": "l"}

// SDK-SUPPLIED, not fixed by this spec: alias spellings THIS SDK accepts -> canonical
// name. Empty if the SDK accepts only canonical names. Using this map for the recorded name
// too, with the writer resolving to the same serializer, satisfies "Deriving the identity"
// in Serializer Codes above. Do not adopt another SDK's aliases: mapping a spelling your API
// does not accept hands that name a table code instead of the derived `x` code it should
// get. cachekit-py's accepted aliases are in the Python note above.
SERIALIZER_ALIASES = {}   // e.g. cachekit-py accepts: {"std": "default", "pythonic": "auto"}
// test-vectors/cache-keys.json records serializer_type "std": cachekit-py's alias for the
// canonical "default", so every vector's code is "s".

// SDK-SUPPLIED, not fixed by this spec: reduce whatever your API accepts as a serializer to
// the canonical STRING identity, before any lookup below. An SDK that accepts only names
// returns the name unchanged. One that also accepts a serializer OBJECT must convert it
// here — the lookups below are string operations and are undefined on an object. This is
// the "SDK-defined refinement" the one-identity-one-code rule permits.
//
// `normalize_identity()` MUST be a pure function of the serializer's configuration — never
// an object address or a randomised hash. The derived code is computed from this identity;
// the read-side check compares the recorded name instead, which the identity equals or
// refines (cachekit-py: `<custom>:ArrowSerializer` records `ArrowSerializer`). Whether the
// identity must distinguish configurations that write different bytes is the uniqueness
// rule in Serializer Codes above (SHOULD; where it does not, different `ns:` namespaces MUST).
//
// An object-to-string refinement carries a marker no table name, alias or accepted name
// contains ("Deriving the identity" above). cachekit-py maps an object to "<custom>:" + its
// bare class name (Python note above).
function normalize_identity(serializer_type):
    return serializer_type   // names-only SDK; override to handle objects

function serializer_code(serializer_type):
    // Reduce to a string identity, resolve any alias spelling this SDK accepts, then look
    // the code up. An identity outside the table gets its OWN derived code — never a shared
    // constant, which would put every unrecognised serializer on one keyspace.
    name = normalize_identity(serializer_type)
    // An empty or non-string identity is an error, never a code ("Deriving the identity").
    if name is not a string or name == "":
        raise error
    identity = SERIALIZER_ALIASES.get(name, name)
    if identity in SERIALIZER_CODES:
        return SERIALIZER_CODES[identity]
    // digest .hex(): exactly 4 lowercase zero-padded hex chars — never a numeric hex()
    return "x" + blake2b(identity.utf8_bytes(), digest_size=2).hex()

function generate_cache_key(namespace, func_module, func_qualname, args, kwargs,
                            integrity_checking=true, *, serializer_type):

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
