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
> Revised 2026-09-22 against the expert-panel G3(a) FIX-FIRST verdict and Helly R's
> cross-family HIGH finding: tenant_id resolution (new rule), the L1/TTL rule
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
the same freshness window everywhere; today a Python `@cache.production` entry outlives
its Rust twin by an unbounded margin.

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
preset accepts. Rust's `.no_l1()` (`intents.rs:77`) makes `minimal` the only preset whose
every read crosses the network, which contradicts its own "speed-first" rustdoc. On
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
3. Rust's spelling is `CacheKit::secure(url, key)`. `cachekit-rs` 0.7.0 spells it
   `CacheKit::encrypted` (`intents.rs:160`) because the `SecureCache` accessor held the
   name `secure` (`client.rs:664`); that is a non-conformance tracked in
   [SDK Conformance](#sdk-conformance) (LAB-4651), not a second spelling.
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
`CacheKit::from_env()` (`client.rs:1049`, `config.rs:121`); the preset is the only entry
point that does not.

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
     migration story below). This is a read-side obligation, not an activation path —
     it does not put the client in an encrypting state and does not satisfy rule 1's
     "explicit intent" for new writes.
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

**Migration story (cachekit-py).** Python's tri-state `encryption=None` auto-detect
(`cache_handler.py:580-585`) currently enables encryption on every preset when the
variable is set, and the same auto-detect path is also how a config-drift deployment
transparently decrypts stale ciphertext left behind after encryption is turned off
(**legacy-decrypt**) — rule 2's constructor list above governs *activation*, not this
read-side role, and removing auto-activation **MUST NOT** remove the ability to decrypt
what a still-encrypting peer already wrote. For one transitional minor release Python:

1. **MUST** keep decrypting existing ciphertext on the legacy-decrypt path.
2. **MUST** keep the current auto-*activation* of new writes, but **MUST** emit a
   one-time warning via `logger.warning` (not `DeprecationWarning` alone — Python
   silences `DeprecationWarning` by default outside `__main__`, so on every
   uvicorn/gunicorn/celery deployment the notice would otherwise never surface) naming
   the explicit spellings (`@cache.secure(...)` or `encryption=True`).
3. The following release **MUST** remove auto-*activation* of new writes. The gate tests
   only inputs known at construction — never "does legacy-decrypt apply", which is a
   property of per-entry backend state discovered on read, not of construction inputs,
   and so cannot gate construction without leaving a branch undefined:
   - `encryption=True` (or `@cache.secure(...)`) → construct encrypting, as today.
   - `encryption=False` → construct **not** encrypting new writes, and **MUST** still
     retain legacy-decrypt from `CACHEKIT_MASTER_KEY` if present — the read-side role
     rule 2 names above, unaffected by this branch.
   - `CACHEKIT_MASTER_KEY` present with **neither** an explicit `encryption=` nor
     `@cache.secure(...)` → construction **MUST** fail, naming both explicit spellings.
     Presence alone is no longer read as intent to activate, and a variable the
     deployment set for encryption **MUST NOT** be silently interpreted as "don't
     encrypt" either — ambiguous intent is an error, not a default.

   Every branch is decidable at construction; none strands the legacy-decrypt migration.
   This is the one release where alternative *(B)* from
   [Design Decisions](#design-decisions) (presence on a non-encrypting preset is an
   error) applies, on the third branch only; it is rejected as a *permanent* rule but is
   the correct transitional gate against a silent confidentiality downgrade.

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
   error — never silently dropped. (cachekit-py's `@cache.io(backend=…)` discards
   `backend=` with only a source comment, `intent.py:220-222`.)
3. A missing master key (`secure`) or API key (`io`) **MUST** fail at construction.
   Other misconfiguration **SHOULD** surface at construction rather than on first use.

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

> ¹ `cachekit-rs` 0.7.0 spells this `CacheKit::encrypted(url, key)` — see
> [SDK Conformance](#sdk-conformance) (LAB-4651). Only `::io` compiles on a default
> `cargo add cachekit-rs`; the Redis presets need `features = ["redis"]`, and the
> encrypted preset needs `redis` + `encryption` (`intents.rs:67,107,159,209`;
> `Cargo.toml:26`).

---

## SDK Conformance

Code-verified 2026-09-22 against `cachekit-py@2f7c979` (0.18.0), `cachekit-rs@6587ce9`
(0.7.0) and `cachekit-ts@379847c` (0.1.5) on `main`. ❌ cells link the alignment ticket;
implementation is out of scope for the specification itself.

| Requirement | Python | Rust | TypeScript |
| :--- | :--- | :--- | :--- |
| Finite default TTL 300 / 600 / 600 / 3 600 s | ❌ none — entries never expire (`wrapper.py:499`) — LAB-4641 | ✅ `intents.rs:76,117,167,217` | ✅ `intents-core.ts:220,242,265,297` |
| No process-wide default-TTL override (rule 3) | ❌ `CACHEKIT_DEFAULT_TTL` is offered — `settings.py:226`, env-settable and documented — even though nothing on the decorator path reads it; rule 3 forbids offering one — LAB-4641 | ❌ `from_env()` reads `CACHEKIT_DEFAULT_TTL` (`config.rs:165`), an override this specification no longer defines — LAB-4664 | ✅ |
| `minimal`: L1 on, SWR / invalidation off | ✅ `decorator.py:335-350` | ❌ `.no_l1()` (`intents.rs:77`) — LAB-4644 | ✅ `intents-core.ts:221-230` |
| `secure`: L1 on, ciphertext only | ❌ `@cache.secure(backend=None)` sets `_explicit_l1_only` (`decorators/intent.py:136`) → `ObjectCache`, which stores raw Python objects with no serializer in the path — encryption in cachekit-py is a serializer wrapper, so plaintext lands in L1 (`decorators/wrapper.py:659`) — LAB-4665 | ✅ `client.rs:656` | ✅ `cache-core.ts:654,831` |
| Reliability stack on for `production` / `secure` / `io` | ✅ | ✅ `ReliabilityConfig::default()` | ✅ `PRODUCTION_RELIABILITY` |
| `secure` takes a hex key and falls back to `CACHEKIT_MASTER_KEY` | ✅ ≥ 32 B (`validation.py:95`) | ❌ `encrypted(url, &[u8])` — raw bytes only, no env fallback, `len() >= 32` accepts more than exactly 32 B (`intents.rs:160-163`; `encryption.rs:101`) — LAB-4645, LAB-4663 | ✅ exactly 32 B (`constants.ts:138`) |
| Missing master key fails at construction | ✅ `intent.py:212` | ✅ required argument; short key → `Err` | ✅ `intents-core.ts:257` |
| Default `tenant_id` is `"default"`, identical for HKDF and AAD | ✅ `cache_handler.py` `DEFAULT_TENANT_ID` (LAB-4666); explicit `deployment_uuid` / `CACHEKIT_DEPLOYMENT_UUID` override only, no machine-local fallback | ❌ `"default"` via `::encrypted`, deployment namespace via `from_env()` — inconsistent by constructor — LAB-4667 | ❌ HKDF `'default'` (`manager-core.ts:206`) but AAD `''` (`manager-core.ts:375`) — mismatched within one SDK — LAB-4668 |
| `CACHEKIT_MASTER_KEY` does not activate encryption on `minimal` / `production` / `io` | ❌ tri-state auto-detect on every preset (`cache_handler.py:580-585`) — LAB-4642 | ❌ `from_env()` activates from key presence alone (`config.rs:112`) — no constructor is exempt under the revised rule 2 — LAB-4669 | ✅ `secure()` only (`intents-core.ts:255`) |
| Explicit encryption option encrypts every operation (activation rule 1) | ❌ `encryption=True` wraps the serializer on the backend path (`cache_handler.py:574`, `:636`), but the `backend=None` L1-only path bypasses the wrapper entirely and stores plaintext in L1 (`decorators/wrapper.py:659`) — so the option does not encrypt *every* operation — LAB-4665 | ❌ the builder's `.encryption()` layer is consulted only by the `SecureCache` handle (`client.rs:734`); plain `set`/`get` never read it (`client.rs:537`, `:358`), and with the `encryption` feature off the builder methods return `Ok(self)` (`client.rs:1077`) — LAB-4676 | ✅ `if (this.encryption)` on both paths (`cache-core.ts:558`, `:823`) |
| Encrypted preset is spelled `secure` | ✅ `@cache.secure` | ❌ `CacheKit::encrypted(url, key)` (`intents.rs:160`); the `SecureCache` accessor holds the name (`client.rs:664`) — LAB-4651 | ✅ `createCache.secure()` |
| `io`: API key by argument **or** `CACHEKIT_API_KEY` | ❌ env only; `backend=` silently dropped (`decorator.py:577`, `intent.py:220`) — LAB-4643 | ❌ argument only (`intents.rs:210`) — LAB-4647 | ✅ `intents-core.ts:283-288` |

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
everywhere (Python today) — fleet convenience, rejected on the three security grounds
above; *(B)* presence on a non-encrypting preset is an error — rejected as hostile to
fleets that legitimately run encrypted and plain caches under one environment;
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
