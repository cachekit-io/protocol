**[Protocol](../README.md)** > **Decisions** > **Key Rotation**

# Decision Record: Master-Key Rotation — Client-Side Keyring with Grace Window

| | |
| :--- | :--- |
| **Status** | Accepted (protocol [#34](https://github.com/cachekit-io/protocol/pull/34), 2026-07-23); implemented in all three SDKs by 2026-08-15 |
| **Date** | 2026-07-23 |
| **Ticket** | LAB-516 (filed by the LAB-275 cross-SDK feature-gap audit) |
| **Normative spec** | [`spec/encryption.md` → Key Rotation (Keyring)](../spec/encryption.md#key-rotation-keyring) — the spec section owns the rules; this record owns the rationale and runbooks. |
| **Implementation** | Shipped. Shared decrypt helper `Keyring` in cachekit-core 0.5.0 ([cachekit-core#67](https://github.com/cachekit-io/cachekit-core/pull/67), LAB-683 — also deleted the `rotate_key()` stub, `KeyRotationState` and `RotationAwareHeader`); SDK surfaces in [cachekit-py#261](https://github.com/cachekit-io/cachekit-py/pull/261) (LAB-684), [cachekit-rs#63](https://github.com/cachekit-io/cachekit-rs/pull/63) (LAB-686) and [cachekit-ts#103](https://github.com/cachekit-io/cachekit-ts/pull/103) (LAB-685). The [feature matrix](../sdk-feature-matrix.md#encryption) rotation row reads ✅ for all three; conformance is enforced by [`tools/encryption-verify.py`](../tools/encryption-verify.py) against the keyring vectors in [`test-vectors/encryption.json`](../test-vectors/encryption.json) (LAB-687). |

---

## Context

CacheKit's differentiator is zero-knowledge client-side encryption, which makes
"rotate the master key" a when-not-if operational event: compliance cadence,
employee offboarding, suspected compromise. As of 2026-07-23 no SDK ships a
usable rotation path (code-verified by the LAB-275 audit):

- **cachekit-core 0.3.0**: `rotate_key()` returns
  `EncryptionError::NotImplemented` (`src/encryption/core.rs:492`).
  `RotationAwareHeader` and `KeyRotationState` exist as types but are
  constructed only in tests — **no SDK writes the 32-byte header to the wire**,
  despite `spec/encryption.md` describing it as the rotation mechanism.
- **cachekit-py**: PyO3 exposes `KeyRotationState` bindings
  (`rust/src/python_bindings.rs:256-305`) that zero Python code references. The
  only live behaviour is per-entry key-fingerprint **mismatch detection**
  (`serializers/encryption_wrapper.py:341-354`): fail-open logs and lets
  AES-GCM authentication fail (→ miss), fail-closed raises. There is no
  decrypt-with-previous-key path.
- **cachekit-rs**: no rotation surface at all.
- **cachekit-ts**: nonce-exhaustion monitoring whose error text says "key
  rotation required" (`src/errors.ts:99-103`) — with no rotation mechanism to
  point at.

Consequently, rotating `CACHEKIT_MASTER_KEY` today invalidates every encrypted
entry at once: fail-open readers take a fleet-wide miss storm (billable on the
SaaS metered-misses model, and a thundering herd at origin); fail-closed
readers take hard errors.

Two structural facts drive the design:

1. **The server can never help.** Zero-knowledge means the backend stores
   ciphertext it cannot decrypt, so it cannot re-encrypt. Any rotation
   mechanism is necessarily client-side.
2. **Cache entries are ephemeral and reproducible.** Every entry expires (TTL)
   or can be recomputed from origin. Rotation never risks data loss — only
   availability and cost.

## Options considered

### A. Client-side keyring with a grace window — **chosen**

Configuration gains a small ordered list of decrypt-only master keys alongside
the current key. Writes always use the current key. Reads decrypt with
whichever keyring key encrypted the entry. Old-key entries age out via TTL or
get re-encrypted on the next write; after the longest TTL in use has elapsed,
the operator removes the retired key.

- No wire-format change: AAD v0x03 does not include key identity, and the
  ciphertext layout (`nonce ‖ ciphertext ‖ tag`) is untouched. Every deployed
  ciphertext remains format-compatible and decryptable for as long as the key
  that encrypted it is retained in the keyring (dropping a key — retirement,
  compromise cut-over — is the deliberate exception).
- No server change, no SaaS involvement.
- No state machine and no rotation API: rotation state **is** configuration.
- Contains option B as its degenerate case: an empty decrypt-only list is a
  hard cut-over.

### B. Documented invalidate-on-rotate — rejected as the *only* answer

"Caches are ephemeral; rotation = planned cold start." Zero new decrypt logic —
but it makes a routine compliance event a fleet-wide miss storm that is
billable under metered-misses pricing, hammers origin, and punishes exactly
the customers who bought the product for its encryption: the perverse
incentive is to *avoid* rotating. It remains the correct trade for compromise
response, where it appears as the empty-keyring configuration.

### C. `RotationAwareHeader` on the wire (`key_version` byte) — rejected

The direction the dead code in cachekit-core pointed at. Rejected on three
grounds:

1. **It is a wire migration.** No SDK writes the header today, so shipping it
   means every reader must handle header-present and header-absent entries
   forever, for no benefit over what per-entry metadata and a bounded keyring
   already provide.
2. **The versioning scheme is broken.** `KeyRotationState.decryption_key()`
   interprets `key_version` *relatively* (`0` = original, `1` = rotated). Data
   at rest cannot be renumbered, so the scheme cannot survive a second
   rotation. Absolute key identity already exists — the 16-byte key
   fingerprint (`SHA-256("key_fingerprint_v1" ‖ key)[0..16]`).
3. **It is redundant.** cachekit-py already stores the fingerprint per entry
   as frame metadata; surfaces without per-entry metadata (cachekit-ts,
   cachekit-rs, interop mode) are covered by bounded sequential key attempts.

## Decision

Adopt **option A: a client-side keyring with an operator-controlled grace
window**. The normative rules — keyring shape and cap, forward-only current
key, fingerprint-based selection vs sequential attempts, failure semantics,
key hygiene — live in
[`spec/encryption.md` → Key Rotation (Keyring)](../spec/encryption.md#key-rotation-keyring).
Points that are decision, not mechanism:

- **The current key is forward-only.** A master key that has ever occupied the
  encrypting slot is never re-promoted; backing out a bad rotation means
  rotating forward to a fresh key. (Re-promotion resumes a used, unknowable
  nonce budget — catastrophic for AES-GCM. The spec carries the MUST NOT.)
  A stateless SDK cannot detect re-promotion once the retired key has left the
  supplied configuration, so the invariant is **operator-enforced**: treat
  retired key material as destroyed. SDKs enforce the detectable subset only —
  a configuration where the current key also appears in the decrypt-only list
  is rejected at load.
- **The cap is 3 decrypt-only keys.** Bounds worst-case sequential decrypt
  attempts and memory while allowing a forced mid-window second rotation
  (e.g. an offboarding landing during a long-TTL compliance window).
  Exceeding the cap is a configuration error, rejected at load.
- **Dead code is deleted, not preserved**: `rotate_key()`,
  `KeyRotationState`, `RotationAwareHeader` (and its `EncryptionHeader`
  alias) leave cachekit-core; the unreferenced `KeyRotationState` PyO3
  bindings leave cachekit-py. No `NotImplemented` stub remains.

### Runbooks (normative for docs)

**Scheduled rotation** (compliance cadence, offboarding without suspected
exfiltration) — three phases; the mechanism supports zero rotation-caused
misses only with this choreography:

0. *Precondition*: audit for non-expiring encrypted entries (e.g. writes with
   no TTL where the backend permits them). Flush them or assign TTLs first —
   otherwise the migration window never closes and, under fail-closed, those
   entries become permanent errors at step 3.
1. Add the incoming key k₂ to every instance's decrypt-only list (writes
   still use k₁). Deploy fleet-wide and wait for completion — every reader
   can now decrypt both keys before any writer switches.
2. Promote k₂ to current, demote k₁ to the decrypt-only list. Deploy.
   Mixed writers during rollout are safe — all readers already hold both
   keys. **The migration-window clock starts when this deploy completes
   fleet-wide** (the moment the last writer stopped encrypting under k₁).
3. After at least the longest TTL in use has elapsed since step 2 completed,
   remove k₁. Deploy.

A single-deploy swap (new current + old into decrypt-only in one step) is
**not** zero-miss: during the rollout, a not-yet-deployed reader holding only
k₁ cannot decrypt entries already written under k₂.

**Compromise**: deploy a fresh current key with an **empty** decrypt-only list
immediately, and flush encrypted namespaces. Old entries that survive the
flush become authentication failures (misses under fail-open, errors under
fail-closed) — a deliberate cold start, because availability ranks below
confidentiality here.

**Honest limit** (state it in every doc surface): rotation cannot
retroactively protect ciphertext already captured by an attacker who holds
the old key. That is cryptographic reality, not a CacheKit limitation.
Rotation bounds exposure going forward — hence the unconditional flush above.

**Keyring exposure is all-keys exposure**: master-key material handled by
managed-language runtimes (environment variables, interpreter strings) cannot
be reliably scrubbed from memory. During a grace window the environment holds
the current *and* previous keys — operators MUST treat exposure of the keyring
configuration as exposure of every key in it.

## Consequences (→ LAB-516 sub-issues)

- **protocol**: normative spec section (ships with this record); keyring test
  vectors — one value encrypted under key₁ and key₂, verified decryptable
  with keyring `[k₂, k₁]` and rejected with keyring `[k₂]` — wired into the
  existing `tools/encryption-verify.py` CI check.
- **cachekit-core**: delete `rotate_key()`, `KeyRotationState`,
  `RotationAwareHeader`/`EncryptionHeader`; add the minimal multi-key decrypt
  helper the SDK bindings share, so decrypt-only keys stay in native memory.
  Removing public API is a breaking change: next 0.x minor.
- **cachekit-py**: `encryption.previous_master_keys` (list of `SecretStr`,
  env `CACHEKIT_PREVIOUS_MASTER_KEYS`, comma-separated hex); fingerprint-based
  keyring selection in `EncryptionWrapper`; delete the dead PyO3 bindings.
- **cachekit-ts**: `previousMasterKeys: string[]`; keyring loop behind the
  NAPI boundary; link `NonceExhaustedError` guidance to the rotation runbook.
- **cachekit-rs**: builder `.previous_master_keys(...)`; sequential-attempt
  keyring in the decrypt path.
- **docs**: rotation runbook on docs.cachekit.io + SDK READMEs; feature-matrix
  row flips to ✅ per SDK only as each implementation ships.

## Out of scope

Nonce-exhaustion handling itself (separate, already monitored in ts);
per-tenant key-derivation changes; SaaS-side anything (zero-knowledge keeps
the server out of this by construction).
