**[Protocol](../README.md)** > **Decisions** > **Envelope `bin` Encoding**

# Decision Record: StorageEnvelope `compressed_data` → MessagePack `bin` Encoding

| | |
| :--- | :--- |
| **Status** | Proposed (accepted on merge) |
| **Date** | 2026-07-25 |
| **Ticket** | LAB-783 (RFC) under tracking parent LAB-764 · [cachekit-core#54](https://github.com/cachekit-io/cachekit-core/issues/54) |
| **Normative spec** | [`spec/wire-format.md` → Byte Layout / Encoding compatibility](../spec/wire-format.md#byte-layout-canonical-encoding) — the spec owns the rules; this record owns the rationale, evidence, and rollout order. |
| **Implementation** | Not yet shipped — staged behind this RFC as LAB-764 sub-issues: one-attribute `cachekit-core` diff (`#[serde(with = "serde_bytes")]` on `compressed_data`), fixture re-pin, py wheel + ts NAPI/WASM rebuilds, benchmark proof. |

---

## Context

`StorageEnvelope.compressed_data` is a plain `Vec<u8>` in `cachekit-core`, so
`rmp_serde::to_vec` routes it through Serde's `serialize_seq` and emits a
MessagePack **array of integers** — one element per byte, 2 wire bytes for any
byte ≥ `0x80`. LZ4 output is high-entropy on any input, so roughly half the
bytes pay the 2-byte penalty on **every** enveloped value. Measured
(cachekit-core 0.3.0, 64 MiB incompressible payload, release profile):

- **Wire size:** 101,189,485 B for a 67,125,251 B LZ4 output — **1.508×
  inflation** (the ticket's 1.58× headline at 256 MB, reproduced at this scale).
- **Throughput:** envelope encode ~151–171 MB/s, decode ~123–154 MB/s. The
  shipped `store()` end-to-end runs at 128–170 MB/s — per-element MessagePack
  encoding dominates, not LZ4 (~GB/s) or xxHash3 (~36 GB/s).
- **Capacity loss:** under cachekit-py's default 100 MB value ceiling, the ~1.5×
  inflation turns the effective limit for incompressible values into ~67 MB —
  payloads that should fit are rejected.

Encoding the field as MessagePack `bin` (`0xc4`/`0xc5`/`0xc6`) removes the
inflation entirely (1.0039× — residual is LZ4 incompressible-block overhead)
and speeds the codec up 6.4–7.3× on encode, 8.9–11× on decode.

## The load-bearing fact: dual-read is mutual, both directions

The change was originally ticketed as a "breaking wire-format change". It is
not. Under the deployed decoder stack (`rmp-serde` 1.3.1 + `serde_bytes`
0.11.19), **both reader shapes accept both encodings**:

| Reader | Legacy wire (array-of-ints) | Canonical wire (`bin`) |
| :--- | :---: | :---: |
| Pre-flip (plain `Vec<u8>`, shipped today) | ✅ status quo | ✅ `bin` falls through to `visit_seq` over the buffer (`rmp-serde` `decode.rs`, `allow_bytes = false` path) |
| Post-flip (`serde_bytes`) | ✅ `ByteBufVisitor::visit_seq` | ✅ `visit_bytes` |

This was first established by source-reading the exact pinned dependency
versions (LAB-764 Feature Design panel), then **executed against the real
toolchain** (LAB-764 decision memo, 2026-07-25): all four cells pass on all six
byte-pinned `wire-format.json` vectors, including the strongest form — `bin`
envelopes fed through today's shipped `ByteStorage::retrieve()` with checksum
validation and decompression-ratio guards intact, returning byte-identical
payloads. The experiment source is attached to the LAB-764 memo and seeds the
implementation PR's unit test.

Two structural facts make the migration surface small:

1. **The envelope codec is single-sourced in `cachekit-core`.** cachekit-py
   reaches it via FFI; cachekit-ts via NAPI *and* the wasm32 build; no SDK
   hand-parses the envelope (code-verified, LAB-764). There is no non-serde
   parser anywhere to teach.
2. **cachekit-rs does not use the envelope for values at all** (plain
   MessagePack, `rmp_serde::to_vec_named`; core is used only for encryption).
   Its value path has zero migration surface.

## Options considered

### A. Flip `compressed_data` to `bin`, readers-first — **chosen**

One serde attribute on one field (`serde_bytes` is already a non-optional
dependency of cachekit-core — the diff adds zero dependencies). No version
field, no discriminator: the MessagePack marker on element `[0]` is
self-describing, and dual-read is proven in both directions. Legacy
array-of-ints remains a permanently accepted read format.

### B. Versioned envelope (add a version field / discriminator) — rejected

Strictly worse: the envelope is a bare positional `fixarray(4)` with no version
field to extend, so a discriminator means a 5th element or a new outer shape —
**that** would be the actual breaking change, invalidating every stored
envelope to solve a problem the msgpack type system already solves. Rejected
as inventing an envelope architecture mid-rollout for zero benefit.

### C. Do nothing / document the ceiling — rejected

The ~150 MB/s store ceiling and ~1.5× wire tax land on every enveloped write of
poorly-compressible data (blobs, pre-compressed content, high-entropy serialized
values) on a metered-miss-sensitive path, and the capacity loss under the 100 MB
value ceiling rejects payloads that should fit. A 6–11× codec win for a
one-attribute diff clears the bar; the fix only gets more expensive as the
installed base grows.

## Scope exclusions (explicit, normative in the spec)

- **`checksum: [u8; 8]` stays array-of-ints.** The win would be 1–7 bytes per
  envelope, and it is crypto-adjacent surface (integrity material). Excluded
  deliberately — a future RFC may revisit; implementations MUST NOT flip it
  opportunistically.
- **`format` is untouched.** It feeds
  [AAD v0x03](../spec/encryption.md#additional-authenticated-data-aad) as the
  registry token (`"msgpack"`); this change introduces no new token.
- **`original_size` and the outer `fixarray(4)` are unchanged.**

## Encryption / AAD independence

Checked against [`spec/encryption.md`](../spec/encryption.md), not assumed:
AAD v0x03 is built **exclusively from metadata** — version byte plus
length-prefixed `tenant_id`, `cache_key`, `format` token, `compressed` token,
and optional `original_type`. **No envelope bytes feed the AAD.** The envelope
bytes are the AES-GCM *plaintext*: flipping the element-`[0]` marker changes a
new entry's ciphertext exactly as any plaintext change would, with no
compatibility consequence — a stored entry decrypts to the envelope encoding it
was written with, and the dual-read rule applies post-decrypt. No re-encryption
of existing entries, no AAD version bump, no new `format` token.

(This confirms the LAB-764 panel checkpoint. One nuance corrected along the
way: the flip is AAD-independent because AAD contains *no payload-derived
bytes at all* — not because AAD covers "pre-envelope" bytes.)

## Rollout order (discipline, not necessity)

Dual-read is already mutual in both directions, so strict ordering is not
load-bearing — but expand/contract costs nothing and removes all reliance on
the fall-through behavior of old readers:

1. **Readers first:** `cachekit-core` release carrying the dual-decode unit
   test (seeded from the LAB-764 experiment) and the re-pinned fixture with the
   `*_bin` vectors — proving both encodings decode through `retrieve()` in CI.
2. **Rebuilds:** cachekit-py wheel, cachekit-ts NAPI + wasm32 artifacts pick up
   the core release. No SDK code changes — the codec is single-sourced.
   cachekit-rs bumps core (encryption-only consumer; value path unaffected).
3. **Writer flip:** the `serde_bytes` attribute lands; `store()` emits `bin`.
   Fixture re-encode-identity assertions switch to the `*_bin` vector set in
   the same diff (decode-identity keeps running against both sets, forever).

Benchmark proof (envelope ≈1.0× payload, store-throughput improvement) runs
against the LAB-510 hot-path harness as an implementation acceptance criterion.

## Documented micro-regression

A `bin` header is 2–5 bytes where a fixarray header is 1–3, so envelopes whose
`compressed_data` is only a few bytes grow slightly: bounded at **+4 bytes** by
header arithmetic; measured `empty` 25 → 26 B, `single_byte` unchanged at 27 B.
Stated here and in the spec so nobody "discovers" it later. Irrelevant beyond a
few tens of payload bytes.

## Test vectors

`test-vectors/wire-format.json` is **append-only**: the six legacy vectors are
retained forever as legacy-read proof; six `*_bin` twins (identical fields,
element `[0]` as `bin`) are appended, marked `"envelope_encoding": "bin"` +
`"derived_from"`. Twins are generated by the stdlib-only
[`tools/wire-format-reference.py`](../tools/wire-format-reference.py) — whose
`verify` mode proves codec fidelity by re-encoding the legacy vectors
byte-identically to the rmp-serde-generated pins — and were byte-verified
against real `rmp-serde 1.3.1 + serde_bytes 0.11.19` output. `verify` runs in
this repo's CI (stdlib pass + `msgpack` third-encoder conformance pass),
giving the wire-format fixture its first protocol-side CI verification.
`cachekit-core`'s vendored-fixture sha256 re-pin is a deliberate update
(LAB-423 precedent), not drift.

## Links

- Normative spec: [`spec/wire-format.md`](../spec/wire-format.md)
- GitHub: [cachekit-io/cachekit-core#54](https://github.com/cachekit-io/cachekit-core/issues/54)
- Multica: LAB-783 (this RFC), LAB-764 (tracking parent; toolchain experiment +
  decision memo), LAB-423 (fixture sha-pinning precedent), LAB-510 (benchmark
  harness), protocol#11 / PR #18 (envelope facts corrected)
