**[Protocol](../README.md)** > **Interop Mode**

<div align="center">

# Interop Mode

**Language-neutral key format and plain-MessagePack value format for sharing cache entries across SDK implementations.**

> **Status**: SPECIFIED (interop/v1) — normative, NOT yet implemented in any SDK.
> Design discussion: [Issue #1](https://github.com/cachekit-io/protocol/issues/1) ·
> Test vectors: [`test-vectors/interop-mode.json`](../test-vectors/interop-mode.json) ·
> Reference implementation: [`tools/interop-reference.py`](../tools/interop-reference.py)

</div>

---

## Table of Contents

- [The Problem](#the-problem)
- [Two Modes](#two-modes)
- [Interop Key Format](#interop-key-format)
- [The Canonical Argument Array](#the-canonical-argument-array)
- [The Interop Data Model](#the-interop-data-model)
- [Canonical MessagePack Encoding](#canonical-messagepack-encoding)
- [Interop Value Format](#interop-value-format)
- [Encryption in Interop Mode](#encryption-in-interop-mode)
- [SaaS Considerations](#saas-considerations)
- [SDK Implementation Requirements](#sdk-implementation-requirements)
- [Design Decisions](#design-decisions)
- [Test Vectors](#test-vectors)

---

## The Problem

The default (auto-mode) key format includes language-specific function identity:

```diff
- Python: ns:users:func:myapp.services.get_user:args:{hash}:1s
- Rust:   (no auto keygen — caller-supplied key)
- Go:     ns:users:func:services.GetUser:args:{hash}:1s
```

Different function paths produce different keys, so two SDKs write to different cache
entries even for the same logical operation and arguments. Values are wrapped in the
[ByteStorage envelope](wire-format.md) (LZ4 + xxHash3-64), which only `cachekit-core`
implements — an SDK without the Rust core cannot read them at all.

Interop mode fixes both, opt-in, without touching auto-mode behavior.

---

## Two Modes

| | Auto mode (default) | Interop mode (opt-in) |
| :--- | :--- | :--- |
| Key format | `ns:{ns}:func:{mod.qualname}:args:{hash}:{flags}` | `{namespace}:{operation}:{args_hash}` |
| Operation identity | Derived from language function path | **Explicit, user-supplied** |
| Value format | ByteStorage envelope (LZ4 + xxHash3-64) | **Plain MessagePack, no envelope** |
| Argument hashing | Per-SDK normalization | **Canonical, byte-identical across SDKs** |
| Cross-SDK reads | ❌ | ✅ |
| Requires cachekit-core | ✅ (for the envelope) | ❌ (any MessagePack library) |

Nothing in this spec changes auto mode. Existing keys, wire bytes, and behavior for
non-opted-in callers remain byte-for-byte identical.

---

## Interop Key Format

```
{namespace}:{operation}:{args_hash}
```

| Segment | Description | Example |
| :--- | :--- | :--- |
| `namespace` | **Required.** User-specified cache namespace | `users` |
| `operation` | **Required.** User-specified, language-neutral operation name | `get_user` |
| `args_hash` | Blake2b-256 (32-byte digest, unkeyed) of the [canonical argument array](#the-canonical-argument-array), lowercase hex, 64 chars | `a3c8d4f2…` |

### Segment grammar

`namespace` and `operation` MUST each match:

```
^[a-z0-9][a-z0-9._-]{0,63}$
```

Lowercase ASCII letters, digits, `.`, `_`, `-`; 1–64 characters; must start with a
letter or digit. SDKs MUST reject non-conforming segments with an error at decoration
/ registration time — never silently normalize.

> [!NOTE]
> **Why lowercase-only**: naming conventions differ per language (`get_user` vs
> `GetUser`). If mixed case were legal, a Python team and a Go team would each use
> their native casing and silently miss each other's entries. Forcing lowercase makes
> the failure loud and immediate instead.

The maximum possible interop key length is 64 + 1 + 64 + 1 + 64 = **194 characters**,
below the 250-character limit in [cache-key-format.md](cache-key-format.md) — the
truncation rule there **never applies** to interop keys.

There is no `func:` segment, no metadata suffix, and no version segment. The
canonicalization profile below is frozen as **interop/v1**; any future change to it
gets a new mode name, not a silent revision (see [Design Decisions](#design-decisions)).

> [!CAUTION]
> Operation names are agreed on out-of-band across deployments, exactly like queue
> names or topic names. So is the **effective argument list** (count, order, and
> types) — see the next section.

---

## The Canonical Argument Array

The `args_hash` input is the canonical MessagePack encoding of **one flat array**
containing the argument values in declaration order:

```
args_hash = blake2b_256( canonical_msgpack( [arg0, arg1, …] ) )
```

This deliberately replaces the `[positional_args, kwargs_map]` structure used by auto
mode. The two-list structure cannot produce identical keys across languages: an
idiomatic Python call `get_user(user_id=42)` would encode as `[[], {"user_id": 42}]`
while Rust and TypeScript — which have no keyword arguments — can only produce
`[[42], {}]`. Same call, different bytes, silent cache miss. See
[Design Decisions](#design-decisions).

Binding rules:

| Language feature | Rule |
| :--- | :--- |
| Named/keyword arguments | Bound to their declared positions before hashing. Python: `inspect.signature(fn).bind(*args, **kwargs)`. |
| Declared defaults | Applied where the language can introspect them (Python: `bind(...).apply_defaults()`). The hash covers the **full effective argument list**, so `get_user(42)`, `get_user(user_id=42)`, and `get_user(42, include_profile=False)` all hash identically when `include_profile` defaults to `False`. |
| Variadic positional (`*args`) | Collected into **one nested array** at its declared position. |
| Variadic keyword (`**kwargs`) | Collected into **one map** at its declared position (sorted keys, like any map). |
| Rust | All arguments are always explicit — the flat array is the argument list as written. |
| TypeScript | The wrapper receives only the arguments actually passed and **cannot see defaults**. Interop-wrapped TS functions MUST NOT use default parameters, and callers MUST pass the full declared arity. |

> [!IMPORTANT]
> The cross-SDK contract for one operation is: the operation name **plus** the
> effective argument list (arity, order, types). Two SDKs that disagree on whether
> `include_profile` exists will hash different arrays. This is inherent to any
> argument-hashing scheme; interop mode makes the contract explicit instead of
> pretending languages agree by accident.

---

## The Interop Data Model

Arguments must normalize into this **closed** set of types. Anything outside it MUST
be rejected with an error — never silently coerced or skipped.

| Source type | Normalized form | Rule |
| :--- | :--- | :--- |
| Integer | msgpack int | Range MUST be within `[-2^63, 2^64-1]`. Out of range → error. |
| Float | msgpack int **or** float64 | [Number canonicalization](#number-canonicalization) below. NaN, `+Inf`, `-Inf` → error. |
| String | msgpack str | UTF-8 bytes of the string as given. **No Unicode normalization** (no NFC/NFD) is applied. |
| Boolean | msgpack bool | |
| Null / None / nil | msgpack nil | |
| Bytes | msgpack bin | Never the str family. |
| List / Array / Tuple | msgpack array | Element order preserved; elements normalized recursively. |
| Map / Dict | msgpack map | Keys MUST be strings (non-string key → error). Keys sorted by **Unicode code point order** at every nesting level; values normalized recursively. |
| Set | msgpack array | Each element normalized **and encoded**, then elements sorted by their encoded bytes (unsigned lexicographic); duplicates after normalization removed. See note below. |
| DateTime (tz-aware) | number | UTC Unix timestamp: floor to integer microseconds since epoch, then **one** IEEE 754 float64 division by 10⁶. Naive datetime → error. Number canonicalization then applies (whole-second datetimes encode as int). |
| UUID | msgpack str | Lowercase hyphenated: `"550e8400-e29b-41d4-a716-446655440000"`. |

> [!IMPORTANT]
> **Map key sorting is by Unicode code point, which equals UTF-8 byte order.**
> JavaScript's default string sort compares UTF-16 code units and gets
> supplementary-plane characters **backwards**: `"｡"` (U+FF61) sorts *after*
> `"𐀀"` (U+10000) in UTF-16 order but *before* it in code-point order.
> The TS SDK MUST sort by comparing UTF-8-encoded key bytes (or by code point), not
> with `Array.prototype.sort()`'s default comparator. The
> `map_key_sort_supplementary` test vector exists specifically to catch this.

> [!NOTE]
> **Set ordering is not numeric order.** Sorting by encoded bytes is a total,
> language-neutral order that every SDK can compute without a cross-type comparison
> function — but it interleaves types and signs unintuitively (e.g. `10` sorts before
> `"a"`, positive fixints before negative fixints). That is fine: the order exists
> solely for determinism, never for display. Auto mode rejects sets; interop mode
> accepts them because the sorted-array form is well-defined.

### Number canonicalization

JavaScript has a single `Number` type: it cannot distinguish `2.0` from `2`, so any
rule that encodes them differently is unimplementable in the TS SDK. Interop mode
therefore adopts one uniform rule (same philosophy as [RFC 8785 / JCS](https://www.rfc-editor.org/rfc/rfc8785)
adapted to MessagePack):

```
encode_number(f: float64):
    if f is NaN or ±Infinity:        error
    if f is integral and -9223372036854775808.0 <= f < 18446744073709551616.0:
        encode as msgpack int (shortest form)     # subsumes -0.0 -> int 0
    else:
        encode as msgpack float64 (0xcb)
```

Both range bounds are exact powers of two and therefore exactly representable as
float64. Do **not** write the upper bound as `18446744073709551615.0` (2⁶⁴−1) — that
literal rounds up to 2⁶⁴ and the comparison must be strict-less-than against 2⁶⁴.

Consequences, all intentional:

- `2.0` and `2` produce the same key (`float_integral_collapse` vector).
- `-0.0` encodes as int `0`.
- A whole-second datetime encodes as an int and therefore equals the same value
  passed as a plain number. Deterministic on both sides; documented, not a bug.
- Native integers keep the full `[-2^63, 2^64-1]` range (snowflake IDs work). In
  JavaScript, integers above 2⁵³ MUST be handled as `BigInt`; the SDK MUST error on a
  non-integral-safe `Number` rather than silently rounding.

### DateTime determinism

The datetime rule is specified as *integer microseconds, then one float64 division*
because IEEE 754 division is exactly specified — every language computing
`float64(1704112245123456) / float64(10^6)` gets bit-identical results. Computing the
timestamp in floating point any other way (e.g. summing seconds and fractional parts)
is NOT guaranteed to match. Sub-microsecond precision (Rust nanoseconds, etc.) is
floored to microseconds first. JavaScript `Date` carries milliseconds; multiply by
1000 exactly.

---

## Canonical MessagePack Encoding

MessagePack permits multiple encodings of the same value (int `5` fits fixint, int8,
int16, …). For hashing, exactly one is legal: the **shortest form**.

| Value | Encoding |
| :--- | :--- |
| `0 … 127` | positive fixint |
| `-32 … -1` | negative fixint |
| positive int | uint8 / uint16 / uint32 / uint64 — smallest that fits |
| negative int | int8 / int16 / int32 / int64 — smallest that fits |
| float (non-integral) | float64 (`0xcb`) only — **float32 is forbidden** |
| str | fixstr / str8 / str16 / str32 — smallest that fits UTF-8 byte length |
| bin | bin8 / bin16 / bin32 — smallest that fits |
| array | fixarray / array16 / array32 — smallest that fits |
| map | fixmap / map16 / map32 — smallest that fits |
| ext types | **Forbidden** (including the timestamp ext, `-1`) |

This matches the default behavior of `msgpack-python` (`packb`), `rmp` /
`rmp-serde`, and `@msgpack/msgpack` — but it is normative here, not an
implementation accident: an SDK whose encoder pads widths produces wrong hashes.

---

## Interop Value Format

Interop values are a **plain MessagePack document**: no ByteStorage envelope, no LZ4,
no xxHash3-64 checksum. Any language with a MessagePack library can read and write
them. This trades the envelope's compression and corruption detection for maximum
portability; corruption/tamper protection is available by enabling
[encryption](#encryption-in-interop-mode) (AES-GCM auth tag).

- **Writers** SHOULD emit canonical encoding (shortest forms, sorted map keys) and
  MUST do so to match the published value vectors. Unlike the args profile, the
  value profile does **not** apply number canonicalization — a float value `2.0`
  stays float64 so it round-trips as a float. (JS writers cannot make this
  distinction; a JS-written `2` may come back to Python as `int`. Cross-language
  int/float value fidelity is inherently best-effort — do not depend on it.)
- **Readers** MUST accept any well-formed MessagePack document, canonical or not.
- Temporal **values** use the sentinel-map convention from
  [wire-format.md → MessagePack Payload Format](wire-format.md#messagepack-payload-format)
  (`{"__datetime__": true, "value": "<ISO-8601>"}` etc.). These are ordinary maps —
  readable by every MessagePack decoder; SDKs that know the convention revive native
  temporal types. Note the asymmetry with **argument** datetimes (Unix float64):
  keys need byte-equal hashes, values need round-trip fidelity — different
  requirements, different rules.

---

## Encryption in Interop Mode

Encryption works **unmodified**. The [AAD v0x03 format](encryption.md#additional-authenticated-data-aad)
binds to the cache-key string; interop keys are identical across SDKs, so the AAD —
and therefore the auth tag — verifies cross-SDK.

Two interop-specific pins:

1. **The AES-GCM plaintext is the plain MessagePack value bytes** — the ByteStorage
   step (step 2 of the encryption flow in encryption.md) is skipped entirely.
2. AAD components are always `format = "msgpack"`, `compressed = "False"` (there is
   no compression in interop mode).

Key derivation (HKDF-SHA256), nonces, the ciphertext layout
(`nonce ‖ ciphertext ‖ tag`), and the RotationAwareHeader are all unchanged. The
`interop_key_aad` test vector pins the exact AAD bytes for an interop key.

> [!NOTE]
> Zero-knowledge still holds: with encryption enabled, backends (including L1 for
> secure caches) store only ciphertext.

---

## SaaS Considerations

The SaaS API is format-agnostic — keys are opaque strings and values are opaque
bytes ([saas-api.md](saas-api.md)). Interop keys carry **no `ns:` prefix**; the
`{namespace}` segment is an SDK-level convention, not a SaaS routing element (tenant
isolation comes from authentication, not key parsing).

> [!WARNING]
> The deployed SaaS cache-key validator currently enforces auto-mode grammar and
> would reject interop-format keys. Shrinking that validator to security-only checks
> is tracked in [saas#91](https://github.com/cachekit-io/saas/issues/91) and MUST land
> before interop mode ships against the CachekitIO backend. The interop segment
> grammar (lowercase, no `:` beyond the two delimiters, no `/`, max 194 chars) is
> deliberately a strict subset of what a security-only validator accepts.

---

## SDK Implementation Requirements

The interop API adds an `interop` parameter naming the operation; `namespace` becomes
required alongside it:

```python
# Python
@cache(interop="get_user", namespace="users", ttl=300)
def get_user(user_id: int, include_profile: bool = False):
    return db.fetch(user_id)
```

```rust
// Rust — interop mode is cachekit-rs's first in-SDK key generation
// (auto mode delegates keys to the caller); requires a blake2 dependency.
#[cachekit(interop = "get_user", namespace = "users", ttl = 300)]
fn get_user(user_id: i64, include_profile: bool) -> User {
    db.fetch(user_id)
}
```

```typescript
// TypeScript — no default parameters on interop functions (see binding rules)
const getUser = cache.wrap(fetchUser, {
  interop: "get_user",
  namespace: "users",
  ttl: 300,
});
```

An SDK implementation of interop mode MUST:

1. Require explicit `namespace` and `operation`, validated against the segment grammar.
2. Build the canonical argument array per the binding rules (named→positional,
   defaults applied where introspectable).
3. Normalize and encode per this spec; reject out-of-model values with an error.
4. Hash with Blake2b-256 (32-byte digest, unkeyed), lowercase hex.
5. Serialize values as plain MessagePack — never the ByteStorage envelope.
6. Leave auto mode byte-for-byte unchanged.
7. Pass every vector in [`test-vectors/interop-mode.json`](../test-vectors/interop-mode.json),
   including the `error_vectors` (which MUST raise).

Convenience pre-conversions (non-normative): SDKs MAY map language-specific types
into the data model before the interop check — Python `Enum` → its value, `Path` →
POSIX string, `Decimal` → string, `tuple` → array. Anything that lands outside the
data model after conversion is still an error. Beware `Decimal`-style string forms:
`"1.0"` vs `"1.00"` hash differently; agree on the textual form across SDKs or avoid
such types in interop arguments.

---

## Design Decisions

Rationale for the choices that differ from the original draft
([Issue #1](https://github.com/cachekit-io/protocol/issues/1)); recorded so they are
not re-litigated by accident.

| Decision | Alternative rejected | Why |
| :--- | :--- | :--- |
| **Flat canonical argument array** with named→positional binding | Draft's `[positional_args, kwargs_map]` | The two-list form makes idiomatic Python (`get_user(user_id=42)`) unconditionally mismatch Rust/TS (`[[42], {}]`) — the exact bug this mode exists to fix. Binding also makes Python call-style invariant: `f(42)` ≡ `f(user_id=42)`, which auto mode never achieved. |
| **Number canonicalization** (integral float64 → int) | Draft's "float → float64 always" | JavaScript cannot distinguish `2.0` from `2`; the draft rule is unimplementable in the TS SDK. Collapsing is the only rule all three SDKs can implement identically. Full int64/uint64 range is kept (JS uses BigInt) because u64 database IDs are the canonical caching argument. |
| **Sort = Unicode code point order** (≡ UTF-8 byte order), stated explicitly | "Lexicographic" (unspecified) | "Lexicographic" is ambiguous: JS default sort (UTF-16 code units) disagrees with UTF-8 byte order on supplementary-plane characters; locale collation would be nondeterministic. Code-point order is total, locale-free, and equals the byte order of the encoded form. |
| **Sets sorted by encoded bytes** | Sort "naturally" per element type | Natural ordering needs a cross-type comparison function every language must reimplement identically (int vs str vs array…). Encoded-byte order falls out of the encoder for free and is trivially total. |
| **Datetime = floor-to-µs, one float64 division** | "UTC Unix timestamp" (unspecified arithmetic) | Naive float arithmetic differs across languages in the last bit. Integer µs + a single IEEE 754 division is bit-deterministic everywhere. |
| **Blake2b-256 retained** | SHA-256 | Every SDK already ships Blake2b for auto mode (`hashlib`, `@noble/hashes`); introducing a second hash would grow the TS bundle and the audit surface for zero benefit. |
| **No version segment in the key** | `iv1:` prefix or a 4th segment | The issue pins the 3-segment format. Versioning-by-mode-name (interop/v1 → a new mode) is sufficient: canonicalization changes alter hashes, so old and new writers merely miss each other's entries — a cache-warm cost, not corruption. |
| **Closed data model, errors on everything else** | Best-effort coercion | A value that hashes on one SDK and throws on another is annoying; a value that silently hashes *differently* on two SDKs is a debugging nightmare. Errors are loud and local. |
| **Lowercase-only segments** | Free-form segment strings | Cross-language casing conventions guarantee silent key divergence (`get_user` vs `GetUser`). Rejecting uppercase makes the divergence a startup error. |

---

## Test Vectors

[`test-vectors/interop-mode.json`](../test-vectors/interop-mode.json) contains:

| Group | Count | Verifies |
| :--- | :---: | :--- |
| `key_vectors` | 22 | Canonical argument bytes (exact hex), args hash, full key — including the `2.0`≡`2` collapse pair, supplementary-plane key sorting, heterogeneous sets, datetime edge cases |
| `value_vectors` | 4 | Plain-MessagePack value bytes (exact hex), float64 preservation in the value profile, temporal sentinel maps |
| `aad_vectors` | 1 | AAD v0x03 bytes over an interop key (`format=msgpack`, `compressed=False`) |
| `error_vectors` | 7 | Inputs that MUST be rejected (NaN, ±Inf, int overflow/underflow, naive datetime, bad segments) |

Inputs use a tagged-JSON convention (`{"$set": …}`, `{"$float": "2.0"}`,
`{"$int": "…"}`, `{"$datetime": "…"}`, `{"$uuid": "…"}`, `{"$bytes": "<hex>"}`)
documented in the file header, because JSON alone cannot express sets, bytes, floats
vs ints, or 64-bit integers safely.

Regenerate / verify:

```bash
python3 tools/interop-reference.py verify      # CPython stdlib reference
npm install @noble/hashes && node tools/interop-crosscheck.mjs   # independent JS encoder
```

The vectors were produced by the stdlib-only Python reference implementation and
byte-verified by an independently written JavaScript encoder hashing with
`@noble/hashes` (the same Blake2b dependency `cachekit-ts` ships), then decode-checked
against `msgpack-python`. SDK implementations (cachekit-py, cachekit-rs, cachekit-ts)
MUST additionally verify against these vectors in their own test suites before
claiming interop support.

---

<div align="center">

[Protocol](../README.md) · [Cache Key Format](cache-key-format.md) · [Wire Format](wire-format.md) · [Encryption](encryption.md) · [SaaS API](saas-api.md)

</div>
