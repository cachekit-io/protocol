**[Protocol](../README.md)** > **Decisions** > **TS/RS Namespace Isolation**

# Decision Record: Namespace Isolation Is a Python-SDK + Direct-API Feature; TS/RS Namespaces Are Client-Side Conventions

| | |
| :--- | :--- |
| **Status** | Proposed (accepted on merge) |
| **Date** | 2026-09-09 |
| **Ticket** | LAB-640 |
| **Precedent** | [cachekit-io/protocol#17](https://github.com/cachekit-io/protocol/pull/17) (merged) — documents the *server* contract: the 7-segment grammar is Python SDK convention, not a server contract, and unprefixed keys are an open write space. This record chooses the *SDK* direction that contract implies. |
| **Normative spec** | [`spec/cache-key-format.md` → Server-Side Requirements](../spec/cache-key-format.md#server-side-requirements) (what the server enforces, including the `default` namespace and the write-space split), [→ Full Key Structure](../spec/cache-key-format.md#full-key-structure) (the `ns:{namespace}:` prefix), [`spec/saas-api.md` → Authentication](../spec/saas-api.md#authentication) (key classes and namespace grants), and [`spec/interop-mode.md` → SaaS Considerations](../spec/interop-mode.md#saas-considerations) (interop keys carry no `ns:` prefix). This record owns the rationale and the cross-SDK story; the specs own the rules. |
| **Implementation** | Documentation-only. No key-format change, no server change, no SDK code change. |

---

## Context

Namespace-based access control on the CachekitIO SaaS backend — per-API-key
namespace grants, per-namespace quotas, and the `ns:`/`nsapi:` intra-tenant
write-space split — is driven **entirely by the key prefix**. The server treats
every cache key as an opaque string and parses only a leading
`ns:{namespace}:` / `nsapi:{namespace}:` segment, whoever wrote the key. A key
with neither prefix is scoped to the `default` namespace, an **open** write
space that any key class may write
([Server-Side Requirements](../spec/cache-key-format.md#server-side-requirements)).

**Only cachekit-py adds the `ns:` prefix.** Its auto-mode key generator
prepends `ns:{namespace}:` when a namespace is set
([Full Key Structure](../spec/cache-key-format.md#full-key-structure)). No other
SDK's key generation adds an `ns:` token of its own; the feature matrix's
[namespace-semantics section](../sdk-feature-matrix.md#namespace-semantics-per-sdk-divergence)
records each SDK's key shape with source citations. The server cannot tell who
built a key, though, and TS and RS do not reserve the prefixes: a TS/RS
namespace such as `ns:team`, or a caller-supplied key such as `ns:team:x` (TS
always; RS only on a client built without `.namespace()`), reaches the server
as an `ns:` key scoped to namespace `team`, not `default`. That is hand-crafting
a prefix (see the caveats under [Decision](#decision)), not SDK namespace
behaviour; where this record says TS/RS or interop keys land in `default`, it
means keys that do not begin with a prefix. **Interop mode** keys are
`{namespace}:{operation}:{args_hash}`, spec-pinned to **no `ns:` prefix**
([SaaS Considerations](../spec/interop-mode.md#saas-considerations)): *"the
`{namespace}` segment is an SDK-level convention, not a SaaS routing element
(tenant isolation comes from authentication, not key parsing)."*

### Impact

The rule is not specific to TS and RS: **because the server keys isolation on
the prefix and only cachekit-py adds `ns:`, the documented TS, RS and interop
paths are affected identically**, and so is any future SDK whose keys carry no
prefix; this record writes "TS/RS" for that set. For all of them
the SDK-level "namespace" is a **client-side convention only**: the keys those
SDKs generate are unprefixed, so server-side
isolation cannot see the namespace. Concretely, within one tenant:

- Two TS/RS apps whose keys are SDK-generated cannot be isolated from each other
  by API-key namespace grants — those keys are unprefixed and all land in `default`.
- An API key that can reach `default` (granted it, or unrestricted) can read and
  write **all** unprefixed traffic in the tenant — TS/RS SDK-generated keys and
  interop keys alike.
- A per-namespace quota on `default` bounds all unprefixed traffic as **one
  pool**; no quota can divide that pool between apps.

This asymmetry is security-relevant, and when this record was drafted it was
undocumented. The bug was not that the server behaves this way; it was that a
reader could not find out that it does. The specs now state it
([Server-Side Requirements](../spec/cache-key-format.md#server-side-requirements),
"Default namespace"), and this record makes it the intended contract; the gap
itself stays open as an accepted [residual risk](#residual-risk-accepted-not-closed).

## Options

Three directions were considered. The decision is **option 2**.

### 1. TS/RS adopt the `ns:{namespace}:` prefix in generated keys — rejected

Make every SDK emit `ns:{namespace}:...` so the server's isolation applies
uniformly. Rejected on three grounds, in priority order:

1. **It is a cache-key-format change.** It must be specced as a normative
   key-format revision across every SDK and reviewed as a protocol change before
   any line ships — the largest possible blast radius for the smallest possible
   win here.
2. **It is a key-stability break.** Changing the generated key for existing
   deployments orphans every entry already written under the old format. Under
   the metered-misses SaaS pricing model, those orphans convert directly into
   **billed misses** and a fleet-wide miss storm on cut-over — the same failure
   class the [cache-key-format spec warns against by name](../spec/cache-key-format.md#test-vectors)
   ("a changed key orphans every existing cache entry and turns the fleet's hits
   into billed misses").
3. **It does not even solve interop.** Interop keys are spec-pinned to no `ns:`
   prefix (see the interop story below), so uniform SDK prefixing would still
   leave all cross-SDK interop traffic in `default`. Option 1 buys a migration
   and still ships a documented asymmetry.

### 2. Document namespace isolation as Python-SDK + direct-API (`nsapi:`); TS/RS namespaces are client-side conventions — **chosen**

State plainly, everywhere a reader would look, that server-side namespace
isolation is delivered by:

- the **Python SDK** (which emits `ns:{namespace}:`), and
- the **direct HTTP API** using the `nsapi:{namespace}:{key}` write space,

and that **TS/RS SDK namespaces, and interop-mode namespaces, are client-side
key-organisation conventions with no per-namespace isolation, quota, or ACL
effect** — the keys they generate all land in one `default` open write space.
This is the direction the server contract already documents
([Server-Side Requirements](../spec/cache-key-format.md#server-side-requirements));
this record makes it the recorded SDK-level decision.

Chosen because it is the honest description of the shipped system, it carries
**no key-stability break and no billed-miss migration**, it needs **no server
work**, and it fixes the actual defect (the silent, undocumented asymmetry)
rather than papering over it with a migration whose interop hole would keep the
asymmetry anyway.

### 3. Server-side per-API-key default-namespace override — rejected (deferred, not foreclosed)

Let an API key carry a server-side "default namespace" so that unprefixed keys
from a given key are mapped into that namespace instead of `default`. This would
give TS/RS keys isolation with no SDK-side key change. Rejected as the direction
of record because:

1. **It is net-new server behaviour and state** (a per-key namespace attribute,
   plus the mapping logic and its interaction with the write-space split and
   quotas) — real design, real testing, real security surface — for a problem
   that option 2 resolves by documentation.
2. **It changes what a key means depending on who presents it**, which is a
   sharper edge than the status quo: the same unprefixed key now routes to
   different namespaces per API key, complicating shared-cache and interop
   reasoning.

It is recorded as **deferred, not foreclosed**: if a customer later needs
server-side isolation for TS/RS without an SDK change, option 3 is the path to
reopen — as a new decision, with its own review.

## Decision

**Adopt option 2.** Server-side namespace isolation is a **Python-SDK +
direct-`nsapi:`-API** feature, and only for a namespace other than `default`.
TS/RS SDK namespaces and interop-mode namespaces are **client-side
conventions** with no per-namespace isolation, quota, or ACL effect; keys
without an `ns:`/`nsapi:` prefix are scoped to the `default` open write space
and are mutually readable and writable within a tenant. No cache-key format
changes.

Points that are decision, not mechanism:

- **`nsapi:` is the isolation path for *direct-API* writers — not a drop-in for
  the SDKs.** A caller that needs true server-side namespace isolation without
  Python uses the `nsapi:{namespace}:{key}` write space explicitly. Four caveats
  a reader must not miss:
  - **No SDK adds `nsapi:` of its own.** Writing it means hand-crafting the
    prefix — through the raw HTTP API, an SDK's caller-supplied-key `get`/`set`,
    or a TS/RS namespace value — with a direct (`ck_api_`) or legacy `ck_live_`
    API key. A hand-crafted `ns:{namespace}:` key, such as one sent through the
    TS SDK's caller-supplied-key `get`/`set` with a `ck_sdk_` key, gets the same
    server-side scoping: the server checks the prefix, not which SDK built it.
  - **`ns:` and `nsapi:` are separate write spaces under one namespace name.**
    `ns:users:` and `nsapi:users:` are the same `users` namespace for grants and
    quotas; the write-space split only decides which key class may *write* each
    prefix, reads are open to both, and legacy `ck_live_` keys are exempt from
    the split ([Server-Side Requirements](../spec/cache-key-format.md#server-side-requirements)).
  - **A prefix named `default` gets no grant isolation.** `ns:default:` and
    `nsapi:default:` keys are gated by the same `default` grant as every
    unprefixed key, so a grant cannot separate them from the tenant's
    unprefixed TS/RS and interop traffic. A Python app with no namespace set,
    or with `namespace="default"`, gets no namespace-grant isolation.
  - **Adopting `nsapi:` re-keys.** Moving keys currently written unprefixed onto
    `nsapi:` orphans the existing `default`-scoped entries into billed misses —
    the same cost class as option 1, but **scoped and opt-in** (one caller's
    keys) rather than a fleet-wide format break.

### The interop story

Interop-mode keys stay in `default` server-side, and this is deliberate. They are
spec-pinned to carry **no `ns:` prefix**
([SaaS Considerations](../spec/interop-mode.md#saas-considerations)): the
`{namespace}` segment is a cross-SDK key-organisation convention, and tenant
isolation for interop comes from **authentication**, not key parsing. This
decision does **not** change that pin. The interop
[segment grammar](../spec/interop-mode.md#segment-grammar) reserves the
namespaces `ns` and `nsapi` for exactly this reason: an interop key starting
`ns:` or `nsapi:` would be parsed as prefixed, scoped to a namespace named after
the operation (or rejected with `400` when the operation contains `.`), rather
than `default`. Which SDK releases enforce the reservation is tracked in the
feature matrix's [Compliance Status](../sdk-feature-matrix.md#compliance-status)
"Test vectors in CI" row.

Interop is therefore a *within-tenant-shared* space: within a tenant, interop
entries are mutually accessible regardless of their `{namespace}` segment.

## Residual risk (accepted, not closed)

Option 2 fixes the **documentation** defect. It explicitly **accepts** the
underlying isolation gap as a recorded risk rather than closing it. "Documented"
must not be read as "fixed":

- **Unprefixed SDK keys cannot be isolated within a tenant.** Two
  TS/RS/interop apps whose keys are SDK-generated both write `default`; a
  per-API-key namespace grant cannot separate them (dropping `default` from the
  grant denies the app its own keys), and a quota can bound them only as one
  shared pool. The isolation that *is* available:
  - **A separate tenant** (not merely a separate API key) — the only boundary
    that does not depend on namespace grants. One tenant's `default` is not
    another's.
  - **A namespace-prefixed key under restricted grants** — Python's `ns:` or a
    direct-API `nsapi:` key carries a real `{namespace}` for any name other than
    `default`, and per-key namespace grants gate **both reads and writes** on it.
    This isolates the namespace only from API keys whose grants are restricted:
    an unrestricted key in the same tenant reads every namespace, prefixed or
    not, and writes every namespace within its key class's write spaces (a
    legacy `ck_live_` key: all of them)
    ([Authentication](../spec/saas-api.md#authentication)). Moving
    currently-unprefixed traffic onto a prefix is the opt-in re-key (billed-miss)
    cost noted above.

  What does **not** isolate, and must not be published as if it does: a second
  API key that still emits *unprefixed* keys (both share `default`); and the
  `ns:`/`nsapi:` **write-space split**, which blocks cross-class *writes*
  (cache-poisoning defence, with the legacy-key exemption above) but leaves
  *reads* open to both classes — a write-space control, not read isolation.
- **Cross-tenant separation is single-control.** For every key, prefixed or
  not, server-side separation rests on authentication-layer tenant scoping,
  with no key-level second layer: no cache key carries a tenant component
  ([Authentication](../spec/saas-api.md#authentication)), and a namespace is
  never a tenant boundary. Any SDK or server change that touches how the
  tenant is derived must be treated as touching the only server-side boundary
  every key has.

## Consequences

- **SDK namespace handling stays a client-side convention.** Namespace work in
  the SDKs is convention-correctness work, not a step toward an `ns:` rewrite.

## Out of scope

Implementing any of the above; emitting `ns:` / `nsapi:` prefixes from TS/RS by
default (that is rejected option 1); building the per-key default-namespace
override (that is deferred option 3, reopenable as its own decision).
