**[Protocol](../README.md)** > **Intent Presets**

<div align="center">

# Intent Presets

**The canonical contract behind `minimal` / `production` / `secure` / `io` — what a preset name MUST configure, in every SDK.**

> **Status**: SPECIFIED (protocol 1.x) — normative. Specified under LAB-514 from the
> LAB-274 parity audit and the code-verified divergence table in the
> [SDK feature matrix](../sdk-feature-matrix.md#intent-preset-semantics-parity-not-presence).
> This document changes no SDK; it is the target the per-SDK alignment tickets in
> [SDK Conformance](#sdk-conformance) converge on. Facts re-verified against
> `cachekit-py@2f7c979`, `cachekit-rs@6587ce9` and `cachekit-ts@379847c` (`main`, 2026-09-22).
> Revised 2026-09-22: tenant_id resolution (new rule), the L1/TTL rule
> contradictions, the false Python `secure`-ciphertext conformance claim, the
> silent-downgrade migration gap, and the `from_env()` activation exemption are fixed
> below; each newly-non-conformant SDK cell links its alignment ticket.

</div>

---

## Table of Contents

- [Scope](#scope)
- [Canonical Preset Table](#canonical-preset-table)
- [Default TTL](#default-ttl)
- [L1 Posture](#l1-posture)
- [Integrity Posture](#integrity-posture)
- [Reliability Floor](#reliability-floor)
- [Encrypted Preset Name](#encrypted-preset-name)
- [Master Key Input](#master-key-input)
- [Encryption Activation](#encryption-activation)
- [`io` Credentials](#io-credentials)
- [Explicit Configuration](#explicit-configuration)
- [SDK-Local Presets](#sdk-local-presets)
- [Per-SDK Spelling](#per-sdk-spelling)
- [SDK Conformance](#sdk-conformance)
- [Design Decisions](#design-decisions)

---

## Scope

An **intent preset** is a named constructor that fixes a cache's defaults for one
operational intent, so that a user who picks the preset *by name* gets the same
semantics in every SDK. Four names are canonical: **`minimal`**, **`production`**,
**`secure`**, **`io`**. This specification fixes, per preset: the default TTL, the L1
posture, the integrity posture, the reliability floor, how encryption is activated and
how its key is supplied, and where `io` takes its credentials.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

This specification does **not** govern:

- **Whether a backend is required.** Only cachekit-py can run L1-only
  (`@cache(backend=None)`); `createCache.<intent>()` (`intents-core.ts:341`) and
  `CacheKitBuilder::build()` (`client.rs:1083`) reject a missing backend. "L1" below
  always means the in-process layer *in front of* whatever L2 the SDK requires.
- **The auto-mode storage container** — SDK-internal, per protocol#11 and
  [wire-format.md → SDK Storage Containers](wire-format.md#sdk-storage-containers-auto-mode).
- **Decrypt-failure policy** (fail-open vs fail-closed on an authentication failure) and
  **key rotation** — both owned by [encryption.md](encryption.md).
- **Constructor spelling.** `@cache.production`, `createCache.production()` and
  `CacheKit::production(url)` are all the `production` preset; see
  [Per-SDK Spelling](#per-sdk-spelling).

---

## Canonical Preset Table

| Preset | Intent | Default TTL | L1 | SWR / cross-process invalidation | Encryption | Reliability stack | Required input |
| :--- | :--- | ---: | :---: | :---: | :--- | :--- | :--- |
| `minimal` | cheapest correct cache | 300 s | on | off | off | MAY be off | backend |
| `production` | default for services | 600 s | on | on | off | on | backend |
| `secure` | zero-knowledge encrypted | 600 s | on — **ciphertext only** | on | **required; construction fails without a key** | on | backend + master key (argument or `CACHEKIT_MASTER_KEY`) |
| `io` | managed CachekitIO backend | 3 600 s | on | on | off (explicit opt-in only) | on | API key (argument or `CACHEKIT_API_KEY`) |

The sections below give the normative rule and the rationale for each column.

---

## Default TTL

1. Every preset **MUST** apply a finite default TTL when the caller supplies none:
   `minimal` **300 s**, `production` **600 s**, `secure` **600 s**, `io` **3 600 s**.
2. An explicit TTL (per call, per decorator, per builder) **MUST** override the preset
   default.
3. An SDK **MUST NOT** offer a process-wide default-TTL override (an environment
   variable or equivalent global switch). The only overrides on the default TTL are rule
   1 (the preset default) and rule 2 (an explicit per-call/decorator/builder TTL). A
   process-wide override is optional in name only — an SDK that reads it in one
   constructor but not another (or not at all) makes two conformant SDKs expire the same
   namespace differently, which is exactly the divergence this specification exists to
   close. `CACHEKIT_DEFAULT_TTL` is reserved: no SDK may repurpose that name for a
   different meaning.
4. "Never expire" **MUST** be an explicit opt-in (spelling is SDK-local). It **MUST NOT**
   be a preset default.
5. An SDK that changes a shipped default to conform **MUST** announce it in its changelog
   and **SHOULD** emit a one-time deprecation warning for one minor release before the
   change takes effect.

**Rationale.** Rust and TypeScript already ship exactly these values. A default of
"never expire" bounds neither memory nor staleness, and under metered-misses pricing it
also hides cost: a cache-forever `production` entry is a stale-data incident waiting for
its first schema change, with no expiry to end it. Presets exist so the same name gives
the same freshness window everywhere; through `cachekit` 0.19.0 a Python
`@cache.production` entry outlived its Rust twin by an unbounded margin.

---

## L1 Posture

1. `minimal`, `production` and `io` **MUST** enable L1 by default.
2. `minimal` **MUST NOT** enable stale-while-revalidate or cross-process invalidation by
   default. `production` and `io` **SHOULD** enable both where the backend supports
   invalidation. **SWR** here means serving an entry after its freshness window has
   elapsed but before a refresh completes — the entry is stale, not phantom, and the
   refresh mechanism (background refresh, request-collapsed refetch, or a bounded grace
   window past TTL) is SDK-local; only the default-on behaviour for `production`/`io` is
   normative.
3. `secure` **MUST** enable L1 by default and **MUST** hold only ciphertext in it. An SDK
   **MUST NOT** place plaintext in any cache layer for the encrypted preset. This ratifies
   the 2025-11-13 cachekit-py decision ("L1 stores encrypted bytes") cross-SDK; Rust's
   `SecureCache` and TypeScript already comply.

**Rationale.** `minimal` means minimal *features*, not minimal *layers*. L1 is what turns
a hit into tens of nanoseconds instead of a network round trip, and the staleness it
introduces on `minimal` — no invalidation — is already bounded by the 300 s TTL the same
preset accepts. Rust 0.7.0's `.no_l1()` (`intents.rs:77`) made `minimal` the only preset whose
every read crosses the network, contradicting its own "speed-first" rustdoc; `cachekit-rs`
0.8.0 fixed it ([cachekit-rs#85](https://github.com/cachekit-io/cachekit-rs/pull/85)). On
`secure`, ciphertext in L1 costs nothing in the zero-knowledge model (decryption happens
only at read time, on the client) and removes the incentive to trade security for speed.

---

## Integrity Posture

Integrity checksums (xxHash3-64 in the [ByteStorage envelope](wire-format.md)) are a
property of the SDK's auto-mode storage container, which is SDK-internal (protocol#11).
This specification therefore fixes **no MUST** on integrity:

1. Where the container carries an integrity check, `production`, `secure` and `io`
   **SHOULD** enable it and `minimal` **MAY** disable it.
2. On `secure`, AES-GCM authentication already detects tampering; the checksum is
   redundant and **MAY** be disabled (forcing it on, as cachekit-py does, is conformant).
3. An SDK whose container has no checksum — cachekit-rs stores plain MessagePack — is
   conformant; its documentation **MUST** say so, and the
   [feature matrix](../sdk-feature-matrix.md#intent-preset-semantics-parity-not-presence)
   records the per-SDK reality.

---

## Reliability Floor

1. `production`, `secure` and `io` **MUST** enable the SDK's reliability stack by default —
   whatever the SDK ships of retry, circuit breaker, backpressure / timeouts and graceful
   degradation. The stack's *composition* is SDK-local; its *default-on* status is not.
2. `minimal` **MAY** run with the reliability stack off.
3. Every preset's documentation **MUST** state what happens when the backend is
   unreachable — whether the error propagates to the caller or the wrapped function runs
   uncached. The behaviour is the thing a user picks a preset to know; it is documented,
   never inferred.

**Rationale.** `minimal` is where users go to remove moving parts; a retry loop or
breaker they did not ask for makes failure modes harder to reason about. All three SDKs
already run `production`/`secure`/`io` with the stack on and diverge only inside
`minimal` (Python: breaker off, backpressure on; Rust: everything off, first error
propagates; TypeScript: breaker neutered, no retry, degradation off) — all conformant, and
recorded as such in the matrix.

---

## Encrypted Preset Name

1. The canonical name of the encrypted preset is **`secure`**. This specification, the
   feature matrix and cross-SDK documentation refer to it as `secure`.
2. Python `@cache.secure` and TypeScript `createCache.secure()` are the canonical
   spelling.
3. Rust spells it `CacheKit::secure(url, key)` from `cachekit-rs` 0.8.0. `cachekit-rs`
   0.7.0 and earlier spell it `CacheKit::encrypted` (`intents.rs:160`) because the
   `SecureCache` accessor held the name `secure` (`client.rs:664`); 0.8.0 renamed the
   accessor `secure_cache()` and removed `::encrypted`, so it is a superseded spelling,
   not a second one.
4. No SDK **MAY** introduce a further name or alias for this preset. In particular Python
   and TypeScript **MUST NOT** add `encrypted` aliases "for parity" — that creates a third
   spelling, not a second.

---

## Master Key Input

[encryption.md → Master Key](encryption.md#master-key) is normative for the key itself
(hex-encoded, `CACHEKIT_MASTER_KEY`). This section fixes how the **preset** takes it.

1. The `secure` preset **MUST** accept the master key as a **hex string** and **MUST**
   derive the key bytes as `hex_decode(string)`. The same string **MUST** yield the same
   key bytes in every SDK.
2. When no key argument is supplied, `secure` **MUST** fall back to `CACHEKIT_MASTER_KEY`.
   When neither is present it **MUST** fail at construction (raise / `Err` / throw). It
   **MUST NOT** fall back to plaintext.
3. Length: an SDK **MUST** accept a key of exactly **32 bytes (64 hex characters)** and
   **MUST** reject anything shorter. It **MAY** accept longer keys. Because TypeScript
   accepts exactly 32 bytes while Python and Rust accept ≥ 32, portability across SDKs is
   guaranteed **only at exactly 32 bytes** — documentation **MUST** recommend exactly 32.
4. An SDK **MAY** additionally accept raw key bytes (the Rust idiom) through a
   *distinctly named* parameter or method. The hex form **MUST** be available on the
   preset itself, not only on a lower-level builder. A raw-bytes entry point **MUST**
   require **exactly 32 bytes** and reject anything else — the same 64-ASCII-character
   hex string that legitimately passes the ≥ 32-byte check on the hex path derives a
   different, silently-wrong key on a raw-bytes path that only checks length.
5. The master key alone does not determine the key bytes actually used: derivation is
   domain-separated by `tenant_id` ([encryption.md → Tenant Key
   Derivation](encryption.md#tenant-key-derivation)). The `secure` preset **MUST**
   default `tenant_id` to the literal string `"default"` when the caller supplies none,
   and **MUST** use that identical resolved value for both HKDF derivation and AAD
   construction ([encryption.md → AAD](encryption.md#additional-authenticated-data-aad)).
   Two SDKs pointed at the same key and the same default `tenant_id` **MUST** derive the
   same key bytes and produce mutually decryptable ciphertext; an SDK that resolves a
   different implicit `tenant_id` (a deployment UUID, a namespace, an empty string) or
   that lets HKDF and AAD diverge on the resolved value breaks interop silently — not as
   a miss, but as a permanent authentication failure between conformant SDKs sharing a
   key.

**Rationale.** The cross-SDK hazard is not the parameter *type*; it is the same
`CACHEKIT_MASTER_KEY` *value* producing different key bytes in two SDKs. A raw-bytes-only
preset invites `CacheKit::encrypted(url, b"a1b2…")`: the 64 ASCII bytes of the hex
string pass the ≥ 32-byte check and derive a key no other SDK derives. Nothing fails —
the entries are simply unreadable from Python and TypeScript, and encrypted
[interop-mode](interop-mode.md#encryption-in-interop-mode) values silently stop
interoperating. Rust already hex-decodes in `CacheKitBuilder::encryption` and
`CacheKit::from_env()` (`client.rs:1049`, `config.rs:121`); through 0.7.0 the preset was the
only entry point that did not, and from `cachekit-rs` 0.8.0 it takes hex too.

> [!NOTE]
> The Master Key table in encryption.md previously listed a **16-byte** minimum. All
> three SDKs enforce **32 bytes** at the configuration boundary (`validation.py:95`,
> `config.rs:305`, `encryption.rs:101`, `constants.ts:138`); the 16-byte figure is the
> HKDF core's input-keying-material floor and is not user-facing. Corrected in the same
> change as this specification.

---

## Encryption Activation

**`CACHEKIT_MASTER_KEY` is a key *source*, not an activation *switch*.**

1. Encryption **MUST** be activated only by explicit intent: choosing the `secure`
   preset, or passing an explicit encryption option / builder call on another preset
   (`encryption=True`, `.encryption(...)`, `{ encryption: … }`). An explicit encryption
   option **MUST** cause every operation on the constructed client to encrypt — an SDK
   **MUST NOT** accept the option, report success, and leave any read or write path
   unencrypted (including a build where the encryption capability is compiled out); an
   unsupported combination **MUST** be rejected at construction, never silently ignored.
2. The presence of `CACHEKIT_MASTER_KEY` **MUST NOT** change the encryption state of
   `minimal`, `production` or `io` — **no constructor is exempt**, including an
   explicit *configure-everything-from-environment* constructor (e.g.
   `CacheKit::from_env()`). Such a constructor **MAY** source the master key from the
   environment for later use (the [`secure` fallback](#master-key-input) or an explicit
   encryption option), but with no portable activation variable (rationale 4, below) and
   no argument list to carry an explicit spelling, a zero-argument env constructor has
   **no path to activate encryption on its own** — it can only supply a key that a
   subsequent explicit call consumes. It **MUST NOT** infer encryption state from the
   key's mere presence any more than any other constructor does. `CACHEKIT_MASTER_KEY`'s
   only roles are:
   - the key fallback for `secure` ([above](#master-key-input));
   - the key fallback for an explicit encryption option that names no key;
   - **legacy-decrypt**: transparently decrypting ciphertext a still-encrypting peer
     already wrote, on a client whose current write path is not encrypting (see the
     migration story below, which also says why an interop cache has no such path).
     This is a read-side obligation, not an activation path — it does not put the
     client in an encrypting state and does not satisfy rule 1's "explicit intent" for
     new writes.
3. An explicit opt-out (`encryption=False` or equivalent) **MUST** be honoured even when
   a key is present.

**Rationale (security).**

1. *Auditability.* Whether a call site encrypts must be readable at the call site or its
   explicit configuration — not inferred from which pod happens to carry which variable,
   and not inferred from which *constructor* happens to read that variable either. A
   generic env-configuration constructor is still one call site per deployment; carving
   it out reintroduces the exact hazard rule 2 exists to close, just one level up — two
   SDKs on one interop namespace, one built via the env constructor and one via an
   explicit preset, would encrypt and not encrypt the same key under the same variable.
2. *Fail-closed needs intent.* `secure` without a key is an error in all three SDKs.
   Presence-activation has **no error path when the key is absent**: that is cachekit-py
   issue #128 — `@cache.io` with `CACHEKIT_MASTER_KEY` unset writes plaintext to the SaaS,
   silently. A preset that encrypts only when the environment says so cannot fail closed.
   This ground is narrower than it sounds: the adopted rule's steady state also writes
   plaintext when a key is present and no explicit spelling was given — the migration's
   construction-error branch closes that for one release only. Grounds 1, 3 and 4 carry
   the decision on their own; this one records the residual case rather than deciding it.
3. *Environment-dependent semantics.* Presence-activation makes development (no variable)
   and production (variable) run different code paths: L1 holds plaintext in one and
   ciphertext in the other, payload sizes differ, decrypt-failure policy applies in one
   and not the other. The "fleet-wide convergence point" converges only where the
   variable is set.
4. *No portable activation knob.* A dedicated activation variable (e.g.
   `CACHEKIT_ENCRYPTION=true`) was considered and rejected — it is a second knob standing
   in for the first, with the identical auditability problem one layer removed. Explicit,
   per-construction intent is the only boundary that does not reintroduce presence-based
   activation somewhere in the stack.

**Migration story (cachekit-py).** Through `cachekit` 0.20.0, Python's tri-state
`encryption=None` auto-detect enabled encryption, when the variable was set, on every
serialized preset that stated no intent (no `encryption=`, or an `EncryptionConfig`
without `enabled=`), unless `master_key=` or `tenant_extractor=` was passed. A
config-drift deployment
transparently decrypts stale ciphertext left behind after encryption is turned off
(**legacy-decrypt**) through a separate path — the encryption wrapper resolves
`CACHEKIT_MASTER_KEY` itself when the handler holds no key. Rule 2's constructor list
above governs *activation*, not this read-side role, and removing auto-activation
**MUST NOT** remove the ability to decrypt what a still-encrypting peer already wrote
into a CK-framed (cachekit-py auto-mode) cache. An interop cache never had that ability
on a non-encrypting client (step 3's `encryption=False` branch). For one transitional
minor release (`cachekit` 0.20.0) Python:

1. **MUST** keep decrypting existing ciphertext on the legacy-decrypt path.
2. **MUST** keep the auto-*activation* of new writes, but **MUST** emit a
   one-time warning via `logger.warning` (not `DeprecationWarning` alone — Python
   silences `DeprecationWarning` by default outside `__main__`, so on every
   uvicorn/gunicorn/celery deployment the notice would otherwise never surface) naming
   the explicit spellings (`@cache.secure(...)` or `encryption=True`).
3. The following release (`cachekit` 0.21.0) **MUST** remove auto-*activation* of new writes. The gate tests
   only inputs known at construction — never "does legacy-decrypt apply", which is a
   property of per-entry backend state discovered on read, not of construction inputs,
   and so cannot gate construction without leaving a branch undefined:
   - `encryption=True` (or `@cache.secure(...)`) → construct encrypting.
   - `encryption=False` → construct **not** encrypting new writes, and **MUST** still
     retain legacy-decrypt from `CACHEKIT_MASTER_KEY` if present — the read-side role
     rule 2 names above, unaffected by this branch. That obligation holds for
     cachekit-py's auto-mode caches, whose [CK v3 frame](wire-format.md#python-ck-v3-frame)
     header marks each encrypted entry. An [interop](interop-mode.md#interop-value-format)
     cache has no legacy-decrypt: its entries carry no header to mark them as
     encrypted, and a reader that is not encrypting decodes stored bytes as one plain
     MessagePack document, so stale ciphertext is never decrypted. Most such entries
     fail to decode and are recomputed, but a rare one, most often a small one, decodes
     and is served as a wrong value. So turning encryption off in an interop cache means
     moving the operation to a new `namespace` in every SDK that binds it, each of which
     also turns encryption off, in the same change: old and new writers then use
     different cache keys, and no reader meets the other side's entries. The procedure
     is cachekit-py's
     [Turning Encryption Off in an Interop Cache](https://github.com/cachekit-io/cachekit-py/blob/main/docs/features/zero-knowledge-encryption.md#turning-encryption-off-in-an-interop-cache).
   - `CACHEKIT_MASTER_KEY` present with **neither** an explicit `encryption=` nor
     `@cache.secure(...)` → construction **MUST** fail, naming both explicit spellings.
     Presence alone is no longer read as intent to activate, and a variable the
     deployment set for encryption **MUST NOT** be silently interpreted as "don't
     encrypt" either — ambiguous intent is an error, not a default.

   Every branch is decidable at construction; none strands the legacy-decrypt migration
   of a CK-framed (cachekit-py auto-mode) cache. This is the one release where
   alternative *(B)* from [Design Decisions](#design-decisions) (presence on a
   non-encrypting preset is an error) applies, on the third branch only; it is rejected
   as a *permanent* rule but is the correct transitional gate against a silent
   confidentiality downgrade.

The fleet-convenience guidance shipped under LAB-749 is rewritten in the same release.
The rejected alternatives are in [Design Decisions](#design-decisions).

---

## `io` Credentials

1. `io` **MUST** accept the API key as an explicit argument **and** fall back to
   `CACHEKIT_API_KEY` when no argument is given. An explicit argument wins.
2. When neither is present, `io` **MUST** fail at construction with a configuration error.
3. `io` **MUST NOT** read `CACHEKIT_MASTER_KEY` to activate encryption
   ([above](#encryption-activation)); it **MAY** accept an explicit encryption option.

**Rationale.** Environment-only forbids two keys in one process (multi-tenant services,
test suites); argument-only forbids twelve-factor deployment. Both are legitimate, and
the family's other secret — the master key — already does argument-or-environment in two
SDKs. Missing credentials fail where the preset is constructed, never on the first cache
call.

---

## Explicit Configuration

Across all presets:

1. An explicit argument **MUST** override the preset default.
2. An argument the preset does not support **MUST** be rejected with a configuration
   error — never silently dropped. (cachekit-py's `@cache.io(backend=…)` raises
   `ConfigurationError` from `cachekit` 0.20.0; through 0.19.0 it discarded `backend=`.)
3. A missing master key (`secure`) or API key (`io`) **MUST** fail at construction.
   Other misconfiguration **SHOULD** surface at construction rather than on first use.
4. In a language without optional arguments, the environment fallback of
   [Master Key Input](#master-key-input) rule 2 or [`io` Credentials](#io-credentials)
   rule 1 **MAY** be a companion constructor that takes no key argument (Rust:
   `CacheKit::secure_from_env`, `CacheKit::io_from_env`). It builds the same preset and is
   not a further name under [Encrypted Preset Name](#encrypted-preset-name) rule 4. It
   **MUST** read that preset's environment configuration:
   - for `secure`, `CACHEKIT_MASTER_KEY` and `CACHEKIT_PREVIOUS_MASTER_KEYS`
     ([encryption.md → Key Rotation](encryption.md#key-rotation-keyring)); if it does not
     support previous keys, it **MUST** fail at construction when that variable is set,
     never ignore it (rule 2);
   - for `io`, `CACHEKIT_API_KEY` only.

   It **MUST NOT** read a variable that changes encryption activation
   ([Encryption Activation](#encryption-activation)).

---

## SDK-Local Presets

An SDK **MAY** ship presets beyond the four canonical names (cachekit-py: `.dev`, `.test`,
`.local`). They **MUST NOT** reuse a canonical name with different semantics, **MUST** be
documented as SDK-local, and other SDKs are not required to mirror them. Python's
`.local` is an in-process object cache that bypasses backends, serialization and
encryption entirely; it is not a member of this family.

---

## Per-SDK Spelling

| Preset | Python (`cachekit`) | Rust (`cachekit-rs`) | TypeScript (`@cachekit-io/cachekit`) |
| :--- | :--- | :--- | :--- |
| `minimal` | `@cache.minimal` | `CacheKit::minimal(url)` — `redis` feature | `createCache.minimal({ url \| backend })` |
| `production` | `@cache.production` | `CacheKit::production(url)` — `redis` feature | `createCache.production({ url \| backend })` |
| `secure` | `@cache.secure(master_key=…)` | `CacheKit::secure(url, key)` — `redis` + `encryption` features¹ | `createCache.secure({ masterKey, url \| backend })` |
| `io` | `@cache.io` | `CacheKit::io(api_key)` — default features | `createCache.io({ apiKey })` |

> ¹ From `cachekit-rs` 0.8.0; 0.7.0 and earlier spell this `CacheKit::encrypted(url, key)`
> ([rule 3](#encrypted-preset-name)). Only `::io` (and, from 0.8.0, `::io_from_env`)
> compiles on a default `cargo add cachekit-rs`; the Redis presets need
> `features = ["redis"]`, and the encrypted preset needs `redis` + `encryption`
> (`intents.rs:67,107,159,209`; `Cargo.toml:26` at `cachekit-rs@6587ce9`).

---

## SDK Conformance

Code-verified 2026-09-22 against `cachekit-py@2f7c979` (0.18.0), `cachekit-rs@6587ce9`
(0.7.0) and `cachekit-ts@379847c` (0.1.5) on `main`. ❌ cells link the alignment ticket;
implementation is out of scope for the specification itself. Python claims carrying the
floor `cachekit` 0.20.0+ were verified against the published 0.20.0 wheel on 2026-10-03, and
those carrying `cachekit` 0.21.0+ against the published 0.21.0 wheel on 2026-10-03; they carry
no line cite, because this document's line refs are pinned to `cachekit-py@2f7c979`, and
releases before each floor fail its rows. Rust claims carrying the floor
`cachekit-rs` 0.8.0+ were verified against the published 0.8.0 `.crate` on 2026-09-30, and
those carrying `cachekit-rs` 0.9.0+ against the published 0.9.0 `.crate` on 2026-10-03; they
carry no line cite, because this document's line refs are pinned to `cachekit-rs@6587ce9`.

| Requirement | Python | Rust | TypeScript |
| :--- | :--- | :--- | :--- |
| Finite default TTL 300 / 600 / 600 / 3 600 s | ✅ `cachekit` 0.20.0+; explicit `ttl=` overrides | ✅ `intents.rs:76,117,167,217` | ✅ `intents-core.ts:220,242,265,297` |
| No process-wide default-TTL override (rule 3) | ✅ `cachekit` 0.20.0+ — `CACHEKIT_DEFAULT_TTL` is gone | ❌ `from_env()` reads `CACHEKIT_DEFAULT_TTL` (`config.rs:165`), an override this specification no longer defines — LAB-4664 | ✅ |
| `minimal`: L1 on, SWR / invalidation off | ✅ `decorator.py:335-350` | ✅ `CacheKit::minimal` — L1 on, SWR off — `cachekit-rs` 0.8.0+ (`.no_l1()` on 0.7.0 and earlier) | ✅ `intents-core.ts:221-230` |
| `secure`: L1 on, ciphertext only | ✅ `cachekit` 0.20.0+ — L1 holds the encrypted serializer's bytes; `@cache.secure(backend=None)` raises `ConfigurationError` at decoration | ✅ `client.rs:656` | ✅ `cache-core.ts:654,831` |
| Reliability stack on for `production` / `secure` / `io` | ✅ | ✅ `ReliabilityConfig::default()` | ✅ `PRODUCTION_RELIABILITY` |
| `secure` takes a hex key and falls back to `CACHEKIT_MASTER_KEY` | ✅ ≥ 32 B (`validation.py:95`) | ✅ hex `CacheKit::secure(url, master_key_hex)`, ≥ 32 B, and `CacheKit::secure_from_env(url)` reads `CACHEKIT_MASTER_KEY` — `cachekit-rs` 0.8.0+ (0.7.0 and earlier: `encrypted(url, &[u8])`, raw bytes, no env fallback); [Master Key Input](#master-key-input) rule 4: the raw-bytes entry points `encryption_from_bytes`, `encryption_from_bytes_with_previous`, `EncryptionLayer::new` and `EncryptionLayer::with_previous_keys` require exactly 32 B, current and previous keys alike — `cachekit-rs` 0.9.0+ (0.8.0 and earlier check `len() >= 32` and so accept more than exactly 32 B) | ✅ exactly 32 B (`constants.ts:138`) |
| Missing master key fails at construction | ✅ `intent.py:212` | ✅ required argument on `::secure`; `::secure_from_env` with `CACHEKIT_MASTER_KEY` unset or empty → `Err` at construction, before any Redis I/O (`cachekit-rs` 0.8.0+); short or non-hex key → `Err` | ✅ `intents-core.ts:257` |
| `secure` companion env constructor honours `CACHEKIT_PREVIOUS_MASTER_KEYS` ([Explicit Configuration](#explicit-configuration) rule 4) | N/A — no companion constructor; the preset's optional key argument falls back itself | ✅ `::secure_from_env` reads `CACHEKIT_MASTER_KEY` and `CACHEKIT_PREVIOUS_MASTER_KEYS`, validating the previous keys as `CachekitConfig::from_env()` does, before any Redis I/O — `cachekit-rs` 0.9.0+ (0.8.0 reads `CACHEKIT_MASTER_KEY` only and ignores `CACHEKIT_PREVIOUS_MASTER_KEYS` without an error) | N/A — no companion constructor; the preset's optional `masterKey` falls back itself |
| Default `tenant_id` is `"default"`, identical for HKDF and AAD | ✅ `cachekit` 0.20.0+ — `DEFAULT_TENANT_ID` (LAB-4666); explicit `deployment_uuid` / `CACHEKIT_DEPLOYMENT_UUID` override only, no machine-local fallback | ❌ `"default"` via `::secure` (`::encrypted` through 0.7.0), deployment namespace via `from_env()` — inconsistent by constructor — LAB-4667 | ❌ HKDF `'default'` (`manager-core.ts:206`) but AAD `''` (`manager-core.ts:375`) — mismatched within one SDK — LAB-4668 |
| `CACHEKIT_MASTER_KEY` does not activate encryption on `minimal` / `production` / `io` | ✅ `cachekit` 0.21.0+ — on `minimal`, `production`, `io` and every other preset except `secure` and `local`, a key present with no stated intent (no `encryption=`, or an `EncryptionConfig` without `enabled=`) fails at construction with `ConfigurationError` naming the explicit spellings, `backend=None` included; `secure` encrypts from the key fallback and `local` never encrypts | ❌ `from_env()` activates from key presence alone (`config.rs:112`) — no constructor is exempt under the revised rule 2 — LAB-4669 | ✅ `secure()` only (`intents-core.ts:255`) |
| Explicit encryption option encrypts every operation (activation rule 1) | ✅ `cachekit` 0.20.0+ — `encryption=True` wraps the serializer on the backend path, and `backend=None` with encryption raises `ConfigurationError` at decoration | ❌ the builder's `.encryption()` layer is consulted only by the `SecureCache` handle (`client.rs:734`); plain `set`/`get` never read it (`client.rs:537`, `:358`), and with the `encryption` feature off the builder methods return `Ok(self)` (`client.rs:1077`) — LAB-4676 | ✅ `if (this.encryption)` on both paths (`cache-core.ts:558`, `:823`) |
| Encrypted preset is spelled `secure` | ✅ `@cache.secure` | ✅ `CacheKit::secure(url, key)` — `cachekit-rs` 0.8.0+ (`CacheKit::encrypted` through 0.7.0) | ✅ `createCache.secure()` |
| `io`: API key by argument **or** `CACHEKIT_API_KEY` | ✅ `cachekit` 0.20.0+ — `@cache.io(api_key=…)` or `CACHEKIT_API_KEY`; `backend=` raises `ConfigurationError` | ✅ `CacheKit::io(api_key)` or `CacheKit::io_from_env()` — `cachekit-rs` 0.8.0+ (argument only through 0.7.0) | ✅ `intents-core.ts:283-288` |

TypeScript's `cache.secure.wrap()` fails closed on `main` since
[cachekit-ts#123](https://github.com/cachekit-io/cachekit-ts/pull/123) (LAB-513,
2026-09-19); npm 0.1.5 predates it, so the matrix warning stands for the published
artifact.

---

## Design Decisions

**`secure`, not `encrypted`.** Intents name outcomes, not mechanisms — `minimal`,
`production` and `io` describe what the user wants, and `secure` fits that vocabulary
where `encrypted` describes how. Two of three SDKs, docs.cachekit.io and the product
positioning already say `secure`.

**Rust renames rather than diverges.** `CacheKit::secure` collided with the `secure()`
`SecureCache` accessor, and Rust rejects two inherent items of one name. Documenting
`::encrypted` as a sanctioned Rust spelling was considered and rejected: pre-1.0 with no
external dependants on the constructor, one breaking release (`cachekit-rs` 0.8.0 — the
accessor becomes `secure_cache()`, the constructor becomes `::secure`) costs less than a
permanent per-SDK translation and a standing exception in this specification.

**Key source, not switch.** Alternatives considered: *(A)* presence activates
everywhere (Python through 0.20.0) — fleet convenience, rejected on the three security grounds
above; *(B)* presence on a non-encrypting preset is an error — rejected as a permanent
rule, as hostile to fleets that legitimately run encrypted and plain caches under one
environment, and shipped by `cachekit` 0.21.0 only as the migration story's
transitional gate;
*(C)* the rule adopted, which is already what TypeScript does and what Rust does
outside `from_env()`.

**Finite TTL rather than ratifying "forever".** Ratifying Python's behaviour would have
required Rust and TypeScript to *remove* expiry defaults — the only direction that makes
every deployment worse.

**No MUST on integrity.** The checksum lives in the storage container, which
protocol#11 makes SDK-internal; a MUST here would legislate the container by the back
door.

**Hex on the preset, bytes allowed elsewhere.** The contract protects the shared
environment variable, not Rust's type preferences; a raw-bytes API remains fine as long
as it is not the only door.

**No test vectors.** Nothing here is byte-level. The
[Canonical Preset Table](#canonical-preset-table) is the fixture; SDK test suites assert
the four TTLs and the postures directly.
