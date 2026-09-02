**[Protocol](../README.md)** > **Interop v2 (Compressed Values)**

<div align="center">

# Interop v2 — Compressed-Values Profile

**Opt-in LZ4-compressed (and optionally AES-256-GCM-encrypted) cross-SDK cache values, as a versioned successor mode to [interop/v1](interop-mode.md).**

> **Status**: DRAFT (PROPOSED) — leaves DRAFT when the vectors below run in
> cachekit-py, cachekit-ts, and cachekit-rs CI. No SDK implements this profile yet;
> SDK work is follow-up, gated on ratification.
> Design discussion: [Issue #52](https://github.com/cachekit-io/protocol/issues/52) ·
> Test vectors: [`test-vectors/interop-v2.json`](../test-vectors/interop-v2.json) ·
> Reference implementation: [`tools/interop-v2-reference.py`](../tools/interop-v2-reference.py) ·
> Independent cross-check: [`tools/interop-v2-crosscheck.mjs`](../tools/interop-v2-crosscheck.mjs)

</div>

---

## Table of Contents

- [Scope — What v2 Changes and What It Inherits](#scope--what-v2-changes-and-what-it-inherits)
- [Mode Discrimination — No Sniffing, Ever](#mode-discrimination--no-sniffing-ever)
- [The v2 Value Container](#the-v2-value-container)
- [Compression Method Registry](#compression-method-registry)
- [Security Limits (Decompression Bounds)](#security-limits-decompression-bounds)
- [Reader Algorithm (Normative Order)](#reader-algorithm-normative-order)
- [Encryption in Interop v2](#encryption-in-interop-v2)
- [Threat Model: Compress-Then-Encrypt (CRIME/BREACH)](#threat-model-compress-then-encrypt-crimebreach)
- [Per-SDK LZ4 Dependency Bill](#per-sdk-lz4-dependency-bill)
- [SDK Implementation Requirements](#sdk-implementation-requirements)
- [Design Decisions](#design-decisions)
- [Test Vectors](#test-vectors)

---

## Scope — What v2 Changes and What It Inherits

Interop/v1 deliberately shipped without compression: values are bare MessagePack,
and the encryption AAD pins `compressed = "False"`
([interop-mode.md → Encryption in Interop Mode](interop-mode.md#encryption-in-interop-mode)).
That surface is **frozen** — nothing in this profile changes any v1 byte, constant,
or vector, and every published v1 vector passes unchanged (proof: the v1 vector
file and both v1 reference tools are untouched by this profile; CI runs them
side-by-side with the v2 tools).

Interop/v2 changes **exactly one thing**: the value format. Everything else is
inherited from interop/v1 normatively and by reference:

| Surface | Interop/v2 rule |
| :--- | :--- |
| Key format | **Identical to v1**: `{namespace}:{operation}:{args_hash}`, same segment grammar, same canonical argument array, same Blake2b-256. A v1 and a v2 deployment produce byte-identical keys for identical inputs. |
| Argument data model & canonicalization | Identical to v1 ([interop-mode.md](interop-mode.md#the-interop-data-model)). |
| Value **content** encoding | Identical to v1: the logical value is serialized as one plain-MessagePack document under the v1 value-profile rules (no number canonicalization, sentinel maps for temporals, exactly-one-document). |
| Value **container** | **New**: the plain-MessagePack value bytes are wrapped in the [v2 value container](#the-v2-value-container), optionally LZ4-block-compressed. |
| Encryption | AES-256-GCM + HKDF-SHA256 unchanged; the AAD `compressed` component is the frozen `"True"` token as a **per-mode constant** — see [Encryption in Interop v2](#encryption-in-interop-v2). |
| SaaS | Same as v1: keys are opaque strings, values are opaque bytes; nothing here is visible to the backend. |

The mechanism is the one interop/v1 itself sanctions
([Design Decisions → "No version segment in the key"](interop-mode.md#design-decisions)):
*versioning-by-mode-name*. Interop/v2 is a **distinct opt-in mode**, not a flag on
v1 — and explicitly not a change to v1.

---

## Mode Discrimination — No Sniffing, Ever

[spec/encryption.md](encryption.md#additional-authenticated-data-aad) forbids
retrying decryption across AAD variants and forbids selecting the post-decryption
container by sniffing bytes. A v2 entry must therefore be distinguishable from a
v1 entry **before AAD construction**. In this profile that determination is made
by **configuration, not by inspecting stored bytes**:

- A cache namespace is interop/v1-valued or interop/v2-valued **by out-of-band
  agreement across the deployment**, exactly like operation names and effective
  argument lists already are in v1. One namespace, one mode.
- A reader configured for interop/v2 builds the v2 AAD (`compressed = "True"`),
  attempts decryption **once** per permitted keyring key, and interprets the
  plaintext as a v2 container. A reader configured for interop/v1 does the same
  with the v1 constants. Neither ever probes the other mode's AAD or container.

**Why not a per-entry marker instead?** For unencrypted entries a magic prefix
would work — but an encrypted interop/v1 entry is a *bare* `nonce ‖ ciphertext ‖
tag` blob with no metadata, and the first nonce byte can take any value,
including any magic byte. Per-entry discrimination on stored bytes would
misclassify 1-in-256 legitimate v1 entries per magic byte and turn their reads
into authentication failures. Per-entry marking is unsound on this surface;
mode-level configuration is deterministic. (See [Design Decisions](#design-decisions).)

**Misconfiguration is loud, never silent.** If a v1 reader and a v2 writer are
accidentally pointed at the same namespace:

- *Unencrypted*: a v2 container begins `0xC1`, the one byte the MessagePack
  specification reserves as a **never-used marker** — it cannot be the *first
  byte* of a well-formed MessagePack document (it can, of course, appear inside
  payload bytes or multi-byte integer bodies; only the leading-byte property is
  load-bearing, and nothing in this profile scans past byte 0). A v1 reader
  MUST already reject it as malformed MessagePack. Conversely, a v2 reader reading a bare v1 value fails
  the magic check below. Both directions error; neither silently decodes wrong
  data.
- *Encrypted*: the v1 and v2 AADs differ in the `compressed` component, so
  AES-GCM authentication fails cross-mode — terminal per the existing
  [no-retry rule](encryption.md#additional-authenticated-data-aad). The keyring
  key-attempt rule is unchanged: retrying across keyring **keys** is permitted,
  retrying across AAD **variants** is not.

On a magic-check failure, a v2 reader SHOULD report a mode-mismatch diagnostic:
leading byte a plausible MessagePack marker → *"possible interop/v1 value —
namespace mode misconfiguration?"*; leading bytes `0x43 0x4B` → the same
*"Python-SDK-internal auto-mode entry"* diagnostic v1 specifies. Diagnostics are
error-message quality-of-life; the normative behavior is the hard error itself.

**Migration** between modes is a namespace-level operation: agree the new mode
out-of-band and either use a fresh namespace or accept read errors on stale
entries until TTLs drain (the same cache-warm cost the v1 spec assigns to any
canonicalization version bump). There is no in-place mixed-mode namespace.

---

## The v2 Value Container

Every interop/v2 value — compressed or not, encrypted or not — is exactly one
container:

```text
┌──────┬──────┬────────────────────────────────────────────────────────────┐
│ 0xC1 │ 0x02 │  body: one canonical MessagePack document (see below)      │
└──────┴──────┴────────────────────────────────────────────────────────────┘
 magic  version
```

| Field | Size | Rule |
| :--- | :---: | :--- |
| Magic | 1 B | `0xC1` — reserved/never-used in MessagePack, so a container is **structurally not** a MessagePack document. MUST be exactly `0xC1`. |
| Container version | 1 B | `0x02`, matching the mode name. Any other value MUST be rejected (a future interop/v3 container would carry `0x03` and its own spec). |
| Body | var | One MessagePack document, a positional 3-element array: `[method, original_size, payload]` — canonically `fixarray(3)`; readers also accept the wider array headers (see Encoding rules). The container ends where this document ends; **trailing bytes MUST be rejected** (same exactly-one-document strictness as v1 values). |

Body elements:

| Element | MessagePack type | Rule |
| :--- | :--- | :--- |
| `[0] method` | **unsigned-family** int | Compression method — see the [registry](#compression-method-registry). Unknown values MUST be rejected. |
| `[1] original_size` | **unsigned-family** int | Exact byte length of the plain-MessagePack value document. Load-bearing twice: it is the LZ4-block decompression size hint **and** the first decompression-bomb bound. Bounds in [Security Limits](#security-limits-decompression-bounds). |
| `[2] payload` | **bin** (`0xc4`/`0xc5`/`0xc6`) | `method = 0`: the plain-MessagePack value bytes verbatim. `method = 1`: one raw LZ4 block. MUST be the msgpack `bin` family — see the encoding rules below. |

Encoding rules:

- **Writers MUST emit canonical MessagePack** for the body: shortest-form
  headers, `bin` for the payload. This is the protocol-1.1 `bin` rule
  ([decisions/envelope-bin-encoding.md](../decisions/envelope-bin-encoding.md),
  [wire-format.md → Byte Layout](wire-format.md#byte-layout-canonical-encoding))
  applied from birth: no v2 container ever pays the array-of-ints ~1.5× wire tax.
- **Readers MUST accept any well-formed header width for each element type**:
  `fixarray(3)`, `array16(3)` (`0xdc`), or `array32(3)` (`0xdd`) for the body
  array; any *unsigned-family* width for the two integer elements — positive
  fixint and uint8/16/32/64 (`0xcc`–`0xcf`) are all legal on read, canonical or
  not (pinned by the `method0_noncanonical_widths` vector, whose body uses an
  `array16(3)` header); and any `bin8/16/32` width for the
  payload. Readers **MUST enforce element types at the marker level**:
  signed-family integer markers (negative fixint, int8–int64,
  `0xd0`–`0xd3`) MUST be rejected for `method` and `original_size` **even when
  the carried value is non-negative**, and a payload that is *anything other
  than `bin`* — including the msgpack `str` family and the legacy
  **array-of-ints** shape — MUST be rejected. Marker-level enforcement makes a
  negative `original_size` *structurally unrepresentable* (a negative int can
  only be carried by a signed-family marker), closing the signed-size bounds
  bypass class outright; conformant writers can never emit signed-family
  markers here anyway (canonical encoding of a non-negative int is always
  unsigned-family). Note the implementation consequence: a generic MessagePack
  decoder surfaces values, not markers, so SDKs SHOULD hand-parse the body —
  it is a three-field grammar, and both reference tools demonstrate the
  ~50-line parser. Pinned by the `reject_method_signed_marker` and
  `reject_negative_original_size` vectors.
- **The legacy array-of-ints leniency is explicitly NOT inherited.** The
  ByteStorage envelope permanently dual-reads array-of-ints because a deployed
  installed base wrote it, and because rmp-serde happens to decode both shapes
  for free. Interop/v2 has no installed base, and an independent hand-written
  reader in a new language would need *extra* code to accept both shapes — the
  opposite of interop's lowest-implementation-bar goal. Exactly one payload
  encoding is legal: `bin`. Pinned by the `reject_payload_array_of_ints` vector.
- A reader MUST validate any declared `bin` length header against the remaining
  input **before** allocating for it (a 5-byte forged `bin32` header must not
  cause a 4 GiB allocation — same rule as
  [wire-format.md → Security Limits](wire-format.md#security-limits)).

The container is deliberately **not** the ByteStorage envelope: no xxHash3-64
checksum field (integrity comes from the AES-GCM tag when encrypted, and is
absent when not — exactly v1's posture), no `format` field (the payload's
decompressed content is always one plain-MessagePack value document). Rationale
in [Design Decisions](#design-decisions).

---

## Compression Method Registry

| `method` | Name | Payload content |
| :---: | :--- | :--- |
| `0` | none | The plain-MessagePack value bytes, verbatim. `original_size` MUST equal the payload byte length; readers MUST reject a mismatch. |
| `1` | lz4-block | Exactly one raw **LZ4 block** ([wire-format.md → Compression](wire-format.md#compression-lz4-block-format)). LZ4 **frame** format (magic `0x184D2204`) is FORBIDDEN. No prepended size word of any kind — `original_size` in the container is the size hint (Python `lz4.block`: `store_size=False`; Rust `lz4_flex`: the plain `block::compress`/`decompress`, never the `_prepend_size` variants). |

New methods (e.g. zstd) require a spec revision to this registry. A new
container version byte is **not** required: the registry is versioned by this
spec, and readers reject unknown method values, which is the safe failure.
Writers MUST NOT emit unregistered methods.

Writer rules:

- Writers MUST be able to produce `method 0` (it is the escape hatch for the
  [threat model](#threat-model-compress-then-encrypt-crimebreach) and for
  incompressible values) and MAY choose the method per entry. Readers MUST
  accept both methods; the choice is invisible above the container.
- Writers SHOULD emit `method 0` when LZ4 does not strictly reduce the payload
  (`lz4_len >= original_size`) — compressing high-entropy data buys wire
  inflation for CPU. Non-normative threshold guidance: values under ~64 bytes
  rarely benefit.
- **Compressed bytes are NOT canonical.** Different conformant LZ4 encoders (and
  levels) legally produce different bytes for the same input. Cross-SDK
  conformance for `method 1` is defined on the *read side*: any conformant
  reader MUST decompress any valid LZ4 block to the same bytes. Two SDKs
  writing the same logical value MAY produce different stored bytes — interop
  never required stored-value byte equality (only **keys** are byte-canonical),
  and the published vectors pin *reference* compressed bytes for read-side
  conformance, not as the only legal writer output.

---

## Security Limits (Decompression Bounds)

A compressed container introduces a byte-level DoS axis — the decompression
bomb — that bare-MessagePack v1 does not have. These bounds reuse the
ByteStorage constants from
[wire-format.md → Security Limits](wire-format.md#security-limits) so the fleet
carries **one** set of numbers, and all of them MUST be enforced **before**
decompressing (integer arithmetic only — no floating-point *ratio*; the ratio
product's integer-width requirement is stated below):

| Limit | Value | Applies to |
| :--- | ---: | :--- |
| Max `original_size` | 512 MiB (536,870,912 B) | both methods |
| Max payload size | 512 MiB (536,870,912 B) | both methods |
| Max compression ratio | 1000:1 | `method 1` |

```text
// original_size and method are unsigned by construction — signed-family
// markers were already rejected at parse time (see The v2 Value Container).
reject if original_size > MAX_UNCOMPRESSED          // 512 MiB
reject if payload.length > MAX_COMPRESSED           // 512 MiB
if method == 1:
    reject if payload.length == 0                   // zero-length compressed = bomb
    max_allowed = 1000 * uint64(payload.length)     // widen BEFORE multiplying; see below
    reject if original_size > max_allowed
if method == 0:
    reject if original_size != payload.length
```

<!-- BEGIN shared-block: ratio-product-rule (guarded by tools/check-spec-duplication.py) -->
The ratio product MUST be computed in **at least 64-bit unsigned integers**:
promote `payload.length` to a ≥ 64-bit unsigned (or arbitrary-precision) integer *before*
the multiply. Multiplying in pointer width and widening the result afterwards
does not satisfy this, and is invisible on a 64-bit host and in 64-bit CI — it
is the wasm32 defect described below. Every target language has a conforming
path: Rust `u64` (on every target, `wasm32` included), Python's
arbitrary-precision `int`, and JavaScript `Number` — an IEEE-754 double
represents every integer below 2⁵³ exactly and this product is < 2³⁹, so no
`BigInt` is required. Because `payload.length` ≤ 2²⁹ once the two 512 MiB caps have
passed, the product is < 2³⁹ and cannot overflow 64 bits; that is why the
pseudocode above carries no overflow branch, and why rejecting on overflow is
**not** a substitute for widening — at 32-bit width it would refuse 99.2 % of
the legal `payload.length` range (see the note below).

The bound MUST be computed by **multiplication**. Deriving it by division, or
as a *ratio*, is forbidden in any arithmetic — integer or floating-point.
Truncating integer division (`original_size / payload.length > 1000`) accepts up to
`1000·payload.length + (payload.length − 1)`, which is looser than this specification permits, and a
floating-point ratio is the precision bypass the integer rule exists to prevent.

> [!NOTE]
> **Non-normative rationale — the failure direction under pointer-width
> arithmetic is fail-closed, never a bypass.** 32-bit pointer width is a live
> target: cachekit-ts ships a `wasm32` build. (That build is *not* affected — it
> computes this bound through `cachekit-core`'s `u64`.) Wrapping begins at
> `payload.length ≥ ⌈2³²/1000⌉ = 4,294,968` B (~4.29 MB), and it can only ever *tighten*
> the bound: for any product `p ≥ 2³²`, `wrapped(p) = p mod 2³² < 2³² ≤ p`,
> while `original_size` (≤ 512 MiB < 2³²) cannot itself wrap, so the direction
> of the comparison is preserved. The failure mode is therefore **spurious
> rejection** and not a bomb bypass. It is not, however, uniform: the wrapped
> bound sweeps the whole `[0, 2³²)` range in steps of 1000 as `payload.length`
> grows, so it falls below the 512 MiB uncompressed cap — the only region where
> it can reject a legal entry at all — for exactly ⅛ of each `2³²/1000 ≈ 4.29` MB
> wrap cycle (`2²⁹/2³² = 1/8`). Elsewhere in the cycle the wrapped bound still
> exceeds every permitted `original_size`, and the entry is accepted. Within
> that ⅛, an entry is rejected only when its `original_size` exceeds the wrapped
> bound; the worst positions are severe — at `payload.length = 4,294,968` B the
> bound collapses to 704 B, and at the 512 MiB cap to 0. Those payloads are
> legal under this specification; an implementation that refuses them is
> non-conforming. The two figures in this section measure different things and
> must not be conflated: *wrapping* rejects within ⅛ of each cycle, whereas
> *rejecting on overflow* refuses every payload past the same 4.29 MB threshold
> — the whole 99.2 % of the legal range — which is precisely why a checked
> multiply is not a substitute for widening the operand.
<!-- END shared-block: ratio-product-rule -->

*An earlier revision of this section claimed 32-bit wrapping would corrupt the
bound "in both directions". It cannot: wrapping is fail-closed, as derived above.
Recorded because the mis-stated failure direction, not the bound, was the part an
implementer would have acted on — a believed bypass mis-prioritises the fix.*

After `method 1` decompression, the output length MUST equal `original_size`
exactly — shorter or longer output is a hard error (the
`reject_lz4_length_mismatch` vector). Any malformed LZ4 stream (invalid offset,
truncated sequence, output overrun) is a hard error. A deployment MAY configure
*stricter* limits (e.g. its max-value-size ceiling); it MUST NOT accept beyond
these.

**Relationship to [protocol#20](https://github.com/cachekit-io/protocol/issues/20)
(one sentence, as promised):** #20 decides *element-count* bounds for the decoded
value — the same value whether it sits inside or outside a v2 container — while
this section bounds the container's *byte* axis; they are complementary
protections on orthogonal axes, and this profile inherits whatever #20 ratifies,
unchanged.

---

## Reader Algorithm (Normative Order)

Given stored bytes for an interop/v2-configured cache:

```text
1. (encrypted caches only) Build the v2 AAD from configuration —
   (tenant_id, cache_key, "msgpack", "True") — and AES-256-GCM-decrypt per
   spec/encryption.md (keyring key attempts permitted; AAD variants never).
   Authentication failure after permitted key attempts is terminal.
   The plaintext is the container. For unencrypted caches the stored bytes
   are the container.
2. Check container[0] == 0xC1 and container[1] == 0x02; else hard error
   (mode-mismatch diagnostics per Mode Discrimination).
3. Decode exactly one MessagePack document from container[2..]; reject
   trailing bytes; enforce element types (int, int, bin) and the
   header-vs-remaining-input rule.
4. Enforce every Security Limit above — before any decompression.
5. method 1: LZ4-block-decompress the payload with original_size as the
   exact output size; reject on any LZ4 error or output-length mismatch.
   method 0: the payload IS the value bytes.
6. Decode the resulting bytes as one plain-MessagePack value document under
   the interop/v1 value rules (exactly-one-document, trailing bytes
   rejected, sentinel-map temporal convention).
```

Step order is normative: bounds run before decompression (step 4 before 5), and
in the encrypted path the AES-GCM tag is verified (step 1) before any container
parsing or decompression — hostile bytes never reach the LZ4 decoder
unauthenticated when encryption is on. In the **unencrypted** path the LZ4
decoder does face untrusted bytes directly; that asymmetry is inherent (v1's
unencrypted values have no integrity protection either), and it is why the
bounds in step 4 and strict decoding in step 5 are MUSTs, not advice.

---

## Encryption in Interop v2

Encryption composes exactly as in v1, with the container as the plaintext:

1. **The AES-GCM plaintext is the entire v2 container** (magic, version, body).
   Stored bytes are the bare `nonce ‖ ciphertext ‖ tag` blob — byte-shape
   identical to an encrypted v1 entry, carrying no cleartext metadata.
2. AAD components are always `format = "msgpack"`,
   **`compressed = "True"`** — the [frozen ASCII token](encryption.md#compressed-tokens)
   `54 72 75 65` ratified in
   [protocol#12](https://github.com/cachekit-io/protocol/issues/12), reused
   verbatim. Exactly four components; `original_type` is never included
   (same rule as v1).
3. Key derivation (HKDF-SHA256), nonces, ciphertext layout, and keyring
   behavior are unchanged from [encryption.md](encryption.md).

**Token semantics (normative).** In interop/v2, `compressed = "True"`
authenticates *"the AES-GCM plaintext is an interop/v2 value container"* — the
compression-capable container — as a per-mode constant, exactly as v1's
`"False"` authenticates *"the plaintext is one bare MessagePack document"*. It
does **not** vary with the per-entry `method`: a `method 0` entry still carries
`compressed = "True"`. This keeps the AAD fully derivable from configuration
(the no-sniffing requirement) and is consistent with
[encryption.md](encryption.md#encryption-flow)'s rule that AAD inputs reflect
what the plaintext actually is: the plaintext *is* a v2 container in every
case. The per-entry `method` needs no AAD binding because it sits **inside**
the GCM-authenticated plaintext — flipping it is tamper, and tamper fails the
tag.

**Cryptographic mode separation.** Because the v1 and v2 AADs differ in the
`compressed` component, a v2 ciphertext cannot be verified with the v1 AAD or
vice versa, even under the same master key, tenant, and cache key. The
`reject_v2_ciphertext_with_v1_aad` and `reject_v1_ciphertext_with_v2_aad`
vectors pin both directions. This is the encrypted-path guarantee that mode
misconfiguration fails loudly instead of decoding wrong bytes.

**What the backend sees** is unchanged in kind from v1: an opaque key and an
opaque ciphertext blob. It is changed in one measurable respect — ciphertext
length now tracks *compressed* size. That is the subject of the next section.

---

## Threat Model: Compress-Then-Encrypt (CRIME/BREACH)

Compress-then-encrypt leaks plaintext redundancy through ciphertext length:
if attacker-influenced bytes and a secret share one compression context, the
attacker can confirm guesses of the secret by watching compressed size shrink
as guesses converge (CRIME/BREACH class).

**Where CacheKit stands.** The observer in CacheKit's zero-knowledge model is
the backend (or anyone reading it) — explicitly untrusted for confidentiality,
and it can measure ciphertext lengths precisely. So the observation channel is
IN the threat model and cannot be waved off. The remaining preconditions are:

1. **Shared context** — the secret and attacker-influenced bytes must be inside
   the *same cache value*. Interop/v2 compresses each entry independently: no
   cross-entry dictionary, no shared compression state, no compression of keys
   or AAD. Cross-entry redundancy leaks nothing; the blast radius of any attack
   is a single value's contents.
2. **Adaptive iteration** — the attacker must be able to trigger repeated
   re-encryptions of that value with varied guesses (a chosen-plaintext
   pressure v1 already tolerates, but v1's length leak — serialized size — does
   not respond to *content similarity*, only to length).

**Verdict (recorded, per the mandate that silence is not a verdict): the
CRIME-class attack is IN the threat model for interop/v2 and is accepted as a
documented residual risk, bounded by per-entry compression granularity and
governed by the following normative mitigations** — it is not "not applicable",
and it is not fully eliminated:

- Compression is **opt-in twice**: interop/v2 is a distinct mode a deployment
  must choose, and `method 0` disables compression per entry within the mode.
- Values that interleave secrets with attacker-influenced content in one entry
  MUST NOT be written with `method 1` — use `method 0` or stay on interop/v1.
  This is an application-layer obligation (an SDK cannot detect it
  mechanically); SDK documentation for the v2 opt-in MUST state it.
- No length padding is added. A padding scheme was considered and rejected:
  fixed-bucket padding gives quantized-but-real leakage while inflating every
  entry, and no cheap scheme eliminates the channel — documented honesty beats
  a false sense of security. Deployments needing length secrecy against their
  backend should not compress (which still leaks exact serialized length, as
  v1 does) — length-hiding is out of scope for this protocol.

BREACH-style amplification via shared dictionaries or cross-request compression
contexts is structurally absent: there are none.

---

## Per-SDK LZ4 Dependency Bill

Named per the mandate — the 2025-11-14 RFC's unpriced PHP fork
(`27Bslash6/php-ext-lz4`) is the cautionary tale. All entries are LZ4 **block**
format; every "frame-format-only" binding is non-conformant.

| SDK | Library | Call | Cost |
| :--- | :--- | :--- | :--- |
| cachekit-py | [`lz4`](https://pypi.org/project/lz4/) (PyPI) | `lz4.block.compress(data, store_size=False)` / `lz4.block.decompress(data, uncompressed_size=original_size)` | One new runtime dependency (C extension, prebuilt wheels for all supported CPython targets). `store_size=False` is **critical** — the default prepends a 4-byte size word that would corrupt the payload. Alternative: expose `lz4_flex` from the already-shipped cachekit-core FFI (zero new PyPI deps, small core-binding diff). |
| cachekit-rs | [`lz4_flex`](https://crates.io/crates/lz4_flex) | `lz4_flex::block::compress` / `block::decompress(input, original_size)` | Effectively free: pure Rust, no C toolchain, already in the dependency tree via cachekit-core. MUST use the plain block functions, never `compress_prepend_size`/`decompress_size_prepended`. |
| cachekit-ts | cachekit-core NAPI + wasm32 bindings (preferred) | new exported `lz4BlockCompress` / `lz4BlockDecompress` wrapping `lz4_flex` | **Zero new npm dependencies** — core already links `lz4_flex`; the cost is a small binding export in the existing NAPI and wasm builds (both artifacts, so Workers keep parity). Pure-JS fallback if ever needed: [`lz4js`](https://www.npmjs.com/package/lz4js) (block format, no native build, slower) — verified block-capable, already the documented Node binding in [wire-format.md](wire-format.md#compression-lz4-block-format). |
| Future SDK (stated cost) | a block-format LZ4 codec | — | The bill is: a conformant LZ4 *block* codec + these vectors passing in that SDK's CI. Most ecosystems have one (Go `pierrec/lz4/v4` `CompressBlock`; JVM `lz4-java`; .NET `K4os.Compression.LZ4`). **PHP remains the known expensive case**: stock `php-ext-lz4` emits a proprietary size-prefixed format; spec-compliant raw blocks need the `27Bslash6/php-ext-lz4` fork (`lz4_compress_raw()`) or FFI. Price that before promising a PHP SDK v2 implementation. |

---

## SDK Implementation Requirements

An SDK implementation of interop/v2 MUST:

1. Implement interop/v1 key generation, argument canonicalization, and the
   value-content rules unchanged (pass the v1 vectors).
2. Write every value as exactly one v2 container; emit canonical MessagePack
   body encoding with a `bin` payload; support `method 0`.
3. Reject, on read: bad magic/version, wrong element types (including non-`bin`
   payloads — the array-of-ints shape included), unknown methods, trailing
   bytes, every Security-Limits violation (before decompressing), LZ4 errors,
   and output-length mismatches.
4. When encryption is enabled: use exactly the four-component AAD with
   `format = "msgpack"`, `compressed = "True"` (frozen bytes `54 72 75 65`);
   never emit or accept `original_type` on this surface; never retry across
   AAD variants (keyring key retries per [encryption.md](encryption.md) remain
   permitted).
5. Leave interop/v1 and auto mode byte-for-byte unchanged; expose v2 as a
   distinct opt-in (per-namespace mode selection).
6. Document the [threat-model guidance](#threat-model-compress-then-encrypt-crimebreach)
   at the v2 opt-in surface.
7. Pass every vector in
   [`test-vectors/interop-v2.json`](../test-vectors/interop-v2.json), including
   all `reject_*` vectors (which MUST error) and — when the SDK supports
   encryption — the encrypted round-trip decrypt and both AAD cross-mode
   rejections.

---

## Design Decisions

| Decision | Alternative rejected | Why |
| :--- | :--- | :--- |
| **New mode name (interop/v2)** | Per-entry container marker inside interop/v1 | Sanctioned by v1's own versioning rule. The per-entry marker is unsound on the encrypted surface: a v1 encrypted entry is a bare `nonce‖ct‖tag` blob whose first byte is unconstrained, so any magic byte misclassifies 1-in-256 legitimate v1 entries into authentication failures. Configuration-determined mode is the only deterministic pre-AAD discriminator that keeps v1 frozen. |
| **Container inside the encryption** (plaintext = container) | Cleartext container header wrapping the ciphertext | Constant four-component AAD derivable purely from configuration (no cleartext metadata to tamper or bind); stored encrypted shape stays a bare blob like v1; and `original_size` stays confidential — a cleartext header would hand the observer the exact compression ratio, materially worsening the CRIME analysis for free. |
| **`compressed = "True"` as a per-mode constant, even for `method 0`** | Per-entry AAD flag tracking the method | A per-entry AAD input must be known pre-decrypt, which forces cleartext metadata and re-opens the tamper/oracle surface the no-retry rule exists to close. The method sits inside the GCM-authenticated plaintext, where tamper already fails the tag. Reuses the frozen `b"True"` constant ([protocol#12](https://github.com/cachekit-io/protocol/issues/12)) verbatim. |
| **`0xC1` magic** | msgpack-decodable container (bare array) | `0xC1` is the single byte the MessagePack spec pins as "never used": a v2 container is structurally not a MessagePack document, so a misrouted container fails loudly in any v1 reader. A bare-array container would silently decode in a v1 reader as a plausible 3-element value — the silent-wrong-data failure this protocol family refuses on principle. |
| **Minimal 3-element container** | Reuse the ByteStorage envelope | The envelope drags xxHash3-64 into every SDK — a second native dependency per language (the PHP-fork class of cost) duplicating integrity the AES-GCM tag already provides when encrypted, and exceeding v1's posture when not. Its `format` field is also dead weight here (the content is always one plain-MessagePack document). What *is* kept from the envelope experience: `bin` payload encoding as normative from birth (protocol 1.1, [decisions/envelope-bin-encoding.md](../decisions/envelope-bin-encoding.md)). |
| **Array-of-ints payload rejected** | Inherit cachekit-core's permanent dual-read leniency | That leniency serves a deployed installed base and falls out of rmp-serde for free; interop/v2 has no installed base, and hand-written readers in new languages would pay extra code to be lenient. One legal encoding is the lowest implementation bar. Pinned by vector. |
| **Compressed bytes non-canonical, read-side conformance** | Pin one canonical LZ4 output | LZ4 encoders legally differ (implementation, level, version). Pinning writer bytes would freeze one library's output as protocol law and break on its next release. Keys stay byte-canonical; values never needed to be. |
| **Bounds reuse wire-format.md constants (512 MiB / 1000:1)** | Profile-specific numbers | One set of constants fleet-wide; the guards are already implemented, reviewed, and vector-tested in cachekit-core. The integer-width rule is stated in full in both documents — edit this section and [wire-format.md → Decompression Bomb Detection](wire-format.md#decompression-bomb-detection) together; `tools/check-spec-duplication.py` fails CI if they drift. |
| **No length padding** | Bucketed padding vs CRIME | Quantized leakage at real cost is not elimination; documented guidance plus the `method 0` / stay-v1 escape hatches are honest. Length-hiding from the backend is explicitly out of protocol scope (v1 leaks exact lengths today). |

---

## Test Vectors

[`test-vectors/interop-v2.json`](../test-vectors/interop-v2.json) contains:

| Group (JSON key) | Verifies |
| :--- | :--- |
| `container_vectors` | Byte-exact containers: `method 0` wrap of the v1 `issue_example_object` value; `method 1` compressed round-trip of a compressible value (reference LZ4 bytes pinned; readers must decompress them to the pinned value bytes); a `method 1` container whose inner value is byte-identical to the published v1 `issue_example_object` value vector (asserted against `interop-mode.json` at generation time — the content profile is inherited unchanged); and a hand-built non-canonical-widths container (uint8/uint32 ints, `bin16` payload, `array16` header) that readers MUST accept. |
| `aad_vectors` | The v2 AAD (`compressed = "True"`) over the same tenant and cache key as v1's `interop_key_aad` — the two AAD hex strings differ only in the final component (`"True"` vs `"False"`), pinned side-by-side. |
| `encryption_vectors` | Full compressed+encrypted round-trip: HKDF-SHA256 (same master key and tenant as v1 / `encryption.json`, so the derived-key fingerprint `96179a9b…` is the published one), AES-256-GCM over the v2 container with the v2 AAD and a fixed nonce; decrypt-verified on every cross-check run. |
| `reject_vectors` | Structural must-rejects, including: bad magic (a bare v1 value fed to a v2 reader), bad container version, unknown method, signed-family integer markers (incl. a negative `original_size`), non-`bin` payloads (the array-of-ints leniency decision, pinned, and a `str` payload), forged `bin32` length header (4 GiB declared, input ends), `method 0` size mismatch, trailing bytes, declared-size bomb, ratio bomb (1000:1), zero-length compressed payload, malformed LZ4 (zero offset), truncated LZ4, and decompressed-length mismatch. All MUST error before or during step 5 of the reader algorithm; the `error` text is a maintainer note, not normative. |
| `crypto_reject_vectors` | `reject_v2_ciphertext_with_v1_aad` and `reject_v1_ciphertext_with_v2_aad` — both cross-mode AAD combinations MUST fail AES-GCM authentication (mode separation), pinned against real ciphertexts from this file and the v1 file. |

Regenerate / verify:

```bash
python3 tools/interop-v2-reference.py verify    # CPython stdlib reference (incl. pure-Python LZ4 block codec)
node tools/interop-v2-crosscheck.mjs            # independent JS container parser + LZ4 decoder + WebCrypto HKDF/AES-GCM (zero deps)
```

The vectors are produced by the stdlib-only Python reference (which implements
its own LZ4 block codec so vector generation has no third-party dependency) and
byte-verified by an independently written JavaScript implementation. When the
optional `lz4` package is importable, `verify` additionally proves bidirectional
conformance with the de-facto C implementation (our compressed bytes decompress
under `lz4.block`, and `lz4.block`'s compressed output decompresses under our
decoder); when `cryptography` is importable it re-verifies the AES-GCM seal
(the JS cross-check always does, via WebCrypto). The interop/v1 vectors are
untouched and continue to run beside these in CI
(`.github/workflows/verify.yml`) — that co-existence is the standing proof that
every v1 vector passes unchanged.

---

<div align="center">

[Protocol](../README.md) · [Interop Mode (v1)](interop-mode.md) · [Encryption](encryption.md) · [Wire Format](wire-format.md) · [SaaS API](saas-api.md)

</div>
