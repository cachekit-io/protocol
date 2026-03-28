**[Protocol](../README.md)** > **Interop Mode**

<div align="center">

# Interop Mode

**Language-neutral key format for sharing cache entries across SDK implementations.**

> **Status**: DRAFT — See [Issue #1](https://github.com/cachekit-io/protocol/issues/1) for discussion.
> This mode is NOT yet implemented in any SDK.

</div>

---

## Table of Contents

- [The Problem](#the-problem)
- [Interop Key Format](#interop-key-format)
- [Interop Value Format](#interop-value-format)
- [Canonical Argument Normalization](#canonical-argument-normalization)
- [Encryption in Interop Mode](#encryption-in-interop-mode)
- [SDK Implementation](#sdk-implementation)

---

## The Problem

The default key format includes language-specific function identity:

```diff
- Python: ns:users:func:myapp.services.get_user:args:{hash}:1s
- Go:     ns:users:func:services.GetUser:args:{hash}:1s
```

Different function paths produce different keys, so Python and Go write to different cache entries even for the same operation and arguments. Cross-SDK cache sharing requires a language-neutral key format.

> [!NOTE]
> This problem only affects the `func:` segment. The `args:{hash}` segment is identical across languages as long as arguments are canonically normalized (see [Canonical Argument Normalization](#canonical-argument-normalization) below).

---

## Interop Key Format

```
{namespace}:{operation}:{args_hash}
```

| Segment | Description | Example |
| :--- | :--- | :--- |
| `namespace` | User-specified cache namespace | `users` |
| `operation` | User-specified operation name (language-neutral) | `get_user` |
| `args_hash` | Blake2b-256 hex of canonically-serialized arguments | `a3c8d4f2...` |

No `func:` segment. No metadata suffix. The operation name is **always explicit** — it cannot be auto-derived because naming conventions differ across languages.

> [!CAUTION]
> Operation names must be agreed on out-of-band across all SDK deployments. If Python uses `"get_user"` and Go uses `"GetUser"`, they will still produce different keys. Pick a convention and document it in your service.

---

## Interop Value Format

Plain MessagePack. No ByteStorage envelope, no LZ4 compression, no xxHash3-64 checksum.

Any language with a MessagePack library can read and write interop-mode values. This trades the integrity checking and compression of the standard ByteStorage envelope for maximum portability.

---

## Canonical Argument Normalization

For the `args_hash` to match across SDKs, arguments must be normalized identically before serialization.

| Source Type | MessagePack Encoding | Normalization Rule |
| :--- | :--- | :--- |
| Integer | msgpack int | Direct encoding |
| Float | msgpack float64 | IEEE 754 double |
| String | msgpack str | UTF-8 encoded |
| Boolean | msgpack bool | Direct encoding |
| Null/None/nil | msgpack nil | Direct encoding |
| List/Array | msgpack array | Preserve element order |
| Dict/Map | msgpack map | **Sort keys lexicographically (recursive)** |
| Set | msgpack array | **Sort elements, encode as array** |
| DateTime | msgpack float64 | **Convert to UTC Unix timestamp** |
| UUID | msgpack str | Lowercase hyphenated: `"12345678-1234-..."` |
| Bytes | msgpack bin | Raw binary |

**Argument encoding**: `msgpack([positional_args, sorted_kwargs_dict])`

> [!IMPORTANT]
> Dict keys MUST be sorted lexicographically (not by insertion order). This is the most common interop bug — languages with ordered maps (Python 3.7+, JS) may preserve insertion order by default. The normalization rule overrides that.

**Example**: `get_user(42, include_profile=True)` encodes as:

```
msgpack([[42], {"include_profile": true}])
```

---

## Encryption in Interop Mode

Encryption works identically to standard mode. The AAD v0x03 format binds to the key string — since interop keys are identical across SDKs, the AAD will also be identical, and cross-SDK encrypted payloads will decrypt successfully.

See [encryption.md](encryption.md) for the full encryption specification.

---

## SDK Implementation

The interop API adds an `interop` parameter to the standard cache decorator / attribute:

```python
# Python
@cache(interop="get_user", namespace="users", ttl=300)
def get_user(user_id: int):
    return db.fetch(user_id)
```

```rust
// Rust
#[cachekit(interop = "get_user", namespace = "users", ttl = 300)]
fn get_user(user_id: i64) -> User {
    db.fetch(user_id)
}
```

```go
// Go
cache.Interop("get_user", "users", 300, GetUser)
```

All three generate the same key: `users:get_user:{identical_blake2b_hash}`

---

<div align="center">

[Protocol](../README.md) · [Cache Key Format](cache-key-format.md) · [Wire Format](wire-format.md) · [Encryption](encryption.md) · [SaaS API](saas-api.md)

</div>
