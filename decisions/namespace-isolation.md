**[Protocol](../README.md)** > **Decisions** > **TS/RS Namespace Isolation**

# Decision Record: Namespace Isolation Is a Python-SDK + Direct-API Feature; TS/RS Namespaces Are Client-Side Conventions

| | |
| :--- | :--- |
| **Status** | Proposed (accepted on merge) |
| **Date** | 2026-09-09 |
| **Ticket** | LAB-640 (stage-1 keystone of epic LAB-680), found by the LAB-627 namespace-isolation audit |
| **Precedent** | [cachekit-io/protocol#17](https://github.com/cachekit-io/protocol/pull/17) (author Ray) — documents the *server* contract ("the 7-segment grammar is Python SDK convention, not a server contract"; unprefixed keys are an open write space). This record chooses the *SDK* direction that precedent implies. |
| **Normative spec** | [`spec/cache-key-format.md` → Full Key Structure](../spec/cache-key-format.md#full-key-structure) (the `ns:{namespace}:` prefix) and [`spec/interop-mode.md` → SaaS Considerations](../spec/interop-mode.md#saas-considerations) (interop keys carry no `ns:` prefix). This record owns the rationale and the cross-SDK story; the specs own the rules. |
| **Implementation** | Documentation-only. No key-format change, no server change, no SDK code change. Follow-ups: the [feature matrix](../sdk-feature-matrix.md) namespace-semantics row (LAB-646) and the stage-2/3 hardening children (LAB-641/642/645, LAB-643/644) are re-pointed to this direction, not to a key-format rewrite. |

---

## Context

Namespace-based access control on the CachekitIO SaaS backend — the
`allowed_namespaces` ACL, per-namespace quotas, and the `ns:`/`nsapi:`
intra-tenant write-space split — is driven **entirely by the key prefix**. The
server treats every cache key as an opaque string and parses only the leading
`ns:{namespace}:` / `nsapi:{namespace}:` segment; a key without that prefix is
scoped to `namespace='default'`, `keyClass='open'`, writable by every key class
(verified on `saas` `main`, 2026-09-09):

- `apps/cache/src/cache-key-validator.ts:118-120` — the fall-through return for
  a non-prefixed key: `{ ok: true, key, namespace: 'default', keyClass: 'open' }`,
  with the code comment naming the callers by SDK: *"Non-prefixed key (TS/Rust
  SDK format, interop mode, bare hash): scoped to the `default` namespace."*
- `apps/cache/src/index.ts:726-762` — *"The SaaS treats keys as opaque strings;
  only the ns:/nsapi: namespace prefix is load-bearing server-side (tenant
  namespace isolation, quotas)."* The write-space `403`s fire only when
  `keyClass` is `sdk` or `api`, i.e. only on prefixed keys.

**Only cachekit-py emits the `ns:` prefix.** Its auto-mode key generator
prepends `ns:{namespace}:` when a namespace is set
([`spec/cache-key-format.md:36,41`](../spec/cache-key-format.md#full-key-structure)).
The other SDKs do not (verified in the LAB-3179 grooming sweep, 2026-09-09, on
each repo's `main`):

- **cachekit-ts** emits `{namespace}:{hex}` with no `ns:` prefix
  (`packages/cachekit/src/serialization/key-generator.ts:21,44`); its own
  examples even put colons *inside* the namespace (`:23,:30`).
- **cachekit-rs** `get`/`set` take caller keys and prepend `{namespace}:` when
  `.namespace()` is set — still no `ns:` (`crates/cachekit/src/client.rs:246-250`).
- **Interop mode** keys are `{namespace}:{operation}:{args_hash}`, spec-pinned to
  **no `ns:` prefix**
  ([`spec/interop-mode.md:374-376`](../spec/interop-mode.md#saas-considerations)):
  *"the `{namespace}` segment is an SDK-level convention, not a SaaS routing
  element (tenant isolation comes from authentication, not key parsing)."*

### Consequence — the thing this record settles

The rule is not specific to TS and RS: **because only cachekit-py emits `ns:`,
every non-Python SDK is affected identically** — TS, RS, and any other SDK in
the fleet (the [feature matrix](../sdk-feature-matrix.md) also lists PHP), plus
interop mode. For all of them the SDK-level "namespace" is a **client-side
convention only**; it is invisible to server-side isolation. Concretely, within
one tenant:

- Two TS/RS apps whose keys are SDK-generated cannot be isolated from each other
  by API-key namespace grants — those keys are unprefixed and all land in `default`.
- An API key that can reach `default` (granted it, or unrestricted) can read and
  write **all** unprefixed traffic in the tenant — TS/RS SDK-generated keys and
  interop keys alike.
- Per-namespace quotas cannot scope unprefixed TS/RS SDK keys — the GLOB pattern
  never matches a key with no `ns:` prefix.

This asymmetry is real, it is security-relevant, and — critically — **it is
undocumented**. Nothing in the SDK docs or
[`sdk-feature-matrix.md`](../sdk-feature-matrix.md) tells a reader that only
Python participates in layer-2 (within-tenant) isolation. The bug is not that the
server behaves this way; the bug is that a reader cannot find out that it does.
This record closes the **documentation** defect (the silence); it does **not**
close the isolation gap itself — that gap is accepted as a recorded residual
risk (see [Residual risk](#residual-risk-accepted-not-closed) below).

## Options

Three directions were considered. The decision is **option 2**.

### 1. TS/RS adopt the `ns:{namespace}:` prefix in generated keys — rejected

Make every SDK emit `ns:{namespace}:...` so the server's isolation applies
uniformly. Rejected on three grounds, in priority order:

1. **It is a cache-key-format change**, so it trips the crypto/protocol
   expert-panel gate before any line ships, and it must be specced as a
   normative key-format revision across four SDKs — the largest possible blast
   radius for the smallest possible win here (the win is available for free under
   option 2's documentation + existing `nsapi:` path).
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
key-organisation conventions with no server-side isolation, quota, or ACL
effect** — everything they write is `default`/`open`. This is the direction the
server contract already documents in the owner's own words
([cachekit-io/protocol#17](https://github.com/cachekit-io/protocol/pull/17)); this
record makes it the recorded SDK-level decision and forces the docs to say it.

Chosen because it is the honest description of the shipped system, it carries
**no key-stability break and no billed-miss migration**, it needs **no server
work**, and it closes the actual defect (the silent, undocumented asymmetry)
rather than papering it with a migration whose interop hole would keep the
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
reopen — as a new decision, with its own gate.

## Decision

**Adopt option 2.** Server-side namespace isolation is a **Python-SDK +
direct-`nsapi:`-API** feature. TS/RS SDK namespaces and interop-mode namespaces
are **client-side conventions** with no server-side isolation, quota, or ACL
effect; keys without an `ns:`/`nsapi:` prefix are scoped to `default`/`open` and
are mutually readable and writable within a tenant. No cache-key format changes.

Points that are decision, not mechanism:

- **The asymmetry is documented, not removed.** The fix makes the shipped
  behaviour discoverable; the isolation gap itself is accepted (see Residual
  risk).
- **`nsapi:` is the isolation path for *direct-API* writers — not a drop-in for
  the SDKs.** A caller that needs true server-side namespace isolation without
  Python uses the `nsapi:{namespace}:{key}` write space explicitly. Two caveats a
  reader must not miss: (a) **no SDK emits `nsapi:`** — the TS/RS keygens produce
  `{namespace}:{...}` and interop is grammar-pinned, so reaching `nsapi:` means
  hand-crafting keys against the raw HTTP API, bypassing SDK key generation; and
  (b) `nsapi:` is the **`api`-class** write space, distinct from Python's
  **`sdk`-class** `ns:` space — they do not share a namespace for *writes* (the
  write-space `403`s enforce the split; reads are open to both within a tenant).
  Adopting `nsapi:` for keys currently written unprefixed **re-keys** them,
  orphaning the existing `default`-scoped entries into billed misses — the same
  cost class as option 1, but **scoped and opt-in** (one caller's keys) rather
  than a fleet-wide format break. Emitting `ns:`/`nsapi:` from the SDKs by default
  is out of scope here (that is option 1, rejected).
- **No key-format change ⇒ the crypto/protocol expert-panel gate does not gate
  implementation** here. This record still passes the expert-panel *design* gate
  before merge (Size M, `security`); AC3 is satisfied vacuously — no key-format
  change means no orphaned-entry/billed-miss migration to schedule.

### The interop story (required by AC2)

Interop-mode keys stay in `default` server-side, and this is deliberate. They are
spec-pinned to carry **no `ns:` prefix**
([`spec/interop-mode.md:374-376`](../spec/interop-mode.md#saas-considerations)):
the `{namespace}` segment is a cross-SDK key-organisation convention, and tenant
isolation for interop comes from **authentication**, not key parsing. This
decision does **not** change that pin.

That interop keys are *accepted at all* by the SaaS is now live: the CachekitIO
validator was shrunk to security-only checks (saas#91), so interop keys pass the
charset whitelist and fall through to `default`/`open` rather than being rejected
by the old auto-mode grammar (verified on `saas` `main`,
`apps/cache/src/cache-key-validator.ts` header + fall-through, 2026-09-09). The
`interop-mode.md` WARNING that "the deployed validator … would reject
interop-format keys" (`:378-384`) predates saas#91 and is now **stale**; its
cleanup (WARNING → NOTE) ships in
[protocol#17](https://github.com/cachekit-io/protocol/pull/17), awaiting the
owner's merge, and is tracked under LAB-646. Neither blocks this decision.

Interop is therefore a *within-tenant-shared* space: within a tenant, interop
entries are mutually accessible regardless of their `{namespace}` segment.
Cross-tenant separation holds **only insofar as the auth-layer tenant scoping is
correct** — it is the *single* control (interop keys carry no tenant routing, so
there is no second layer behind it), and sibling ticket LAB-644 tracks a live
threat to exactly that assumption (RS conflating namespace with encryption
tenant; TS AAD default mismatch). Option 1 would not have improved any of this
(interop cannot take an `ns:` prefix without breaking the cross-SDK grammar),
which is the third reason it was rejected.

## Residual risk (accepted, not closed)

Option 2 closes the **documentation** defect. It explicitly **accepts** the
underlying isolation gap as a recorded risk rather than closing it. State this
everywhere the docs land (LAB-646), because "documented" must not be misread as
"fixed":

- **Unprefixed SDK keys cannot be isolated within a tenant.** Two
  TS/RS/PHP/interop apps whose keys are SDK-generated both write `default`; a
  per-API-key `allowed_namespaces` grant cannot separate them (dropping `default`
  from the grant denies the app its own keys), and per-namespace quotas cannot
  scope them. The isolation that *is* available:
  - **A separate tenant** — the only unconditional boundary. A distinct auth
    identity is a distinct keyspace, so one tenant's `default` is not another's.
  - **A namespace-prefixed key scoped by `allowed_namespaces`** — Python's `ns:`
    or a direct-API `nsapi:` key carries a real `{namespace}` that the ACL gates
    for **both reads and writes** (`validateNamespaceAccess` runs unconditionally,
    saas `apps/cache/src/index.ts`), so a key without that namespace granted is
    denied. This is real within-tenant isolation — but only for *prefixed* keys;
    moving currently-unprefixed traffic onto it is the opt-in re-key (billed-miss)
    cost noted above.

  What does **not** isolate, and must not be published as if it does: a second
  API key that still emits *unprefixed* keys (both share `default`); and the
  `ns:`/`nsapi:` **write-space split**, which blocks cross-class *writes*
  (cache-poisoning defence) but leaves *reads* open to both classes — a
  write-space control, not read isolation of shared `default` data.
- **Cross-tenant separation is single-control.** For unprefixed and interop keys
  it rests entirely on auth-layer tenant scoping, with no key-level second layer.
  LAB-644 is a live threat to that control and must not be treated as unrelated
  hardening.
- **Documentation lag is itself the residual window.** This record sets the
  direction; the reader-facing surfaces (the `sdk-feature-matrix.md` namespace
  row, the interop-mode / cache-key prose, [protocol#17](https://github.com/cachekit-io/protocol/pull/17))
  land in LAB-646. Until LAB-646 merges, the asymmetry stays undocumented where
  readers actually look — so LAB-646 is the gating close-out of the defect, not
  this ADR alone. Treat the epic's isolation-gap item as open until LAB-646 lands.
- **Confirm `default` carries a quota ceiling.** If the `default` namespace is
  not itself quota-bounded, all non-Python/interop traffic is per-namespace
  unmetered — a cost-amplification surface under metered-misses pricing. Verify
  during LAB-646/LAB-645; if unbounded, record it as a follow-up.

## Consequences

- **protocol docs** (LAB-646): add a **namespace-semantics row** to
  [`sdk-feature-matrix.md`](../sdk-feature-matrix.md) — Python: server-side
  isolation via `ns:`; direct API: via `nsapi:`; TS/RS/interop: client-side
  convention, scoped to `default`. Tighten the interop-mode and cache-key-format
  prose to name this asymmetry where a reader meets namespaces. Land
  [cachekit-io/protocol#17](https://github.com/cachekit-io/protocol/pull/17) (or
  fold its server-contract framing in) so the server story and this SDK story
  read as one.
- **stage-2/3 children re-pointed to option 2** (this decision, AC4). The
  hardening tickets stand, but as *convention-correctness* work under the
  client-side-convention framing, **not** as steps toward an `ns:` rewrite:
  - **LAB-641** (cachekit-py auto-mode namespace validation) — unchanged in
    intent; Python is the SDK that *does* emit `ns:`, so validating its namespace
    segment at decoration time is exactly right.
  - **LAB-642** (cachekit-rs `CACHEKIT_NAMESPACE` documented-but-unread; prefix
    bypasses key validation) — reframed: the fix is to make RS namespace
    behaviour **match the documented client-side-convention semantics** (read it,
    validate it, apply it as the `{namespace}:` client prefix), not to emit `ns:`.
  - **LAB-645** (SaaS `migrate-namespace` tool: unreachable endpoint, LIKE-vs-GLOB
    scoping bleed, `nsapi:`-blind, documented as working) — its defects stand and
    must be fixed. Option 2 only *scopes* the tool: it operates on the prefixed
    write spaces (`ns:` Python + `nsapi:` direct-API), so being blind to
    **unprefixed** TS/RS/interop keys is correct (they are `default`/open, nothing
    to migrate). It must **not** be blind to `nsapi:` keys — that blindness is a
    real isolation bug in the child, not intended behaviour — and the unreachable
    endpoint, the LIKE→GLOB scoping bleed, and the false "working" documentation
    are all still in scope. The decision narrows what the tool *should* cover; it
    does not bless any of the child's defects.
  - **LAB-643** (key truncation can slice the `ns:` segment) — unchanged; a
    Python/protocol correctness bug in the one SDK that carries the prefix.
  - **LAB-644** (cross-SDK `tenant_id` divergence: RS conflates namespace with
    encryption tenant; TS AAD default mismatch) — unchanged in scope; this
    decision *reinforces* that namespace (client-side convention) and encryption
    tenant (AAD identity) are distinct axes and must not be conflated.
- **stage order** (the LAB-642-vs-LAB-644 question left open on LAB-680): under
  option 2, LAB-642 (RS namespace semantics) and LAB-644 (encryption-tenant
  divergence) are **independent** — namespace is a client-side convention, tenant
  is an AAD/encryption axis — so they need not be serialised against each other.
  Keep them in their existing stages; no cross-dependency is introduced by this
  decision.

## Out of scope

Implementing any of the above (the stage-2/3 children do that); emitting `ns:` /
`nsapi:` prefixes from TS/RS by default (that is rejected option 1); building the
per-key default-namespace override (that is deferred option 3, reopenable as its
own decision). This record produces **one direction** for epic LAB-680 to build
on — nothing more.

---

*Ratification: the epic owner's merge of this PR is the decision. If the owner
prefers option 1 or option 3, that is stated on the PR and the stage-2/3 children
are re-pointed to match before any implementation begins.*
