**[Protocol](../README.md)** > **SaaS API**

<div align="center">

# SaaS API Specification

**Format-agnostic binary blob storage over HTTPS — the backend never inspects your payload.**

*Protocol Version 1.0 · Verified against `cachekit-py` v0.5.0 (`backends/cachekitio/`)*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Content Type](#content-type)
- [Cache-Key Path Encoding](#cache-key-path-encoding)
- [Cache Endpoints](#cache-endpoints)
- [Stale-While-Revalidate](#stale-while-revalidate)
- [Consistency](#consistency)
- [Lock Endpoints](#lock-endpoints)
- [TTL Endpoints](#ttl-endpoints)
- [Health Endpoint](#health-endpoint)
- [Request Headers](#request-headers)
- [Error Handling](#error-handling)
- [SDK Configuration](#sdk-configuration)

---

## Overview

The CacheKit SaaS backend is a Cloudflare Workers deployment that provides managed cache storage. It is **format-agnostic**: it stores and retrieves raw bytes without inspecting, validating, or transforming the payload. This means the same API handles encrypted and plaintext data identically.

| Environment | URL |
| :--- | :--- |
| Production | `https://api.cachekit.io` |
| Staging | `https://api.staging.cachekit.io` |

Configurable via `CACHEKIT_API_URL` environment variable. Custom hosts require `CACHEKIT_ALLOW_CUSTOM_HOST=true`.

---

## Authentication

All requests require a Bearer token in the `Authorization` header:

```http
Authorization: Bearer ck_live_xxxxxxxxxxxxxxxxxxxxxxxxx
```

The server accepts exactly three key prefixes; any other prefix fails authentication:

| Prefix | Class | Semantics |
| :--- | :--- | :--- |
| `ck_sdk_` | SDK key | MUST<sup id="api-1">API-1</sup> send `X-CacheKit-L1-Status` on every request ([Required Headers](#required-headers)) — rejected with `400` otherwise. May mutate `ns:`-prefixed and unprefixed (`default`) cache keys; never `nsapi:`. |
| `ck_api_` | Direct-API key | May mutate `nsapi:`-prefixed and unprefixed (`default`) cache keys; never `ns:`. |
| `ck_live_` | Legacy | Predates the sdk/api write-space split; exempt from it (may mutate both key classes). |

The write-space split applies to mutations only (`PUT`, `DELETE`, lock, TTL refresh); reads are open to all key classes within the tenant's namespace grants. Namespace grants gate mutations the same way they gate reads — a key class denied a namespace gets `403` on it regardless of the write-space split below. Violations return `403 Forbidden`. The API key implicitly scopes all operations to a tenant. Multi-tenancy is enforced server-side.

> [!WARNING]
> **The split covers `ns:`- and `nsapi:`-prefixed cache keys only.** A cache key with neither prefix maps to the tenant's `default` namespace and belongs to a **shared write space**: any key class whose namespace grants include `default` **or are unrestricted** may create, overwrite, delete, or lock it. The split is an intra-tenant guard for namespaced keys, not a general write-isolation guarantee between key classes.

**CORS preflight exception.** `OPTIONS` on any path is answered `204 No Content` before authentication; no `Authorization` or `X-CacheKit-L1-Status` header is required or inspected. Every other `/v1/cache/*` request is authenticated before any other check, and the authentication outcome — `401`, or `503` for a key-store fault while checking the key — precedes every other error. Browser callers are outside this specification's scope, and **no key class is intended for delivery to browser code** — an API key in client-side JavaScript is a tenant-wide credential exposed to every visitor. The deployed CORS policy returns `Access-Control-*` headers only for a closed allowlist of first-party origins; for every other origin the preflight carries none and the browser blocks the request. Even from an allowlisted origin the policy allows `Authorization` but no `X-CacheKit-*` request header and exposes no `X-CacheKit-*` response header, so `ck_sdk_` keys cannot be used cross-origin and freshness headers are unreadable there. This specification governs `/v1/cache/*` only.

**HTTP intermediary caching is prohibited.** Servers MUST<sup id="api-2">API-2</sup> emit `Cache-Control: no-store` and `Vary: Authorization` on every response. The [cache key](cache-key-format.md) carries no tenant component — tenancy rides only in the `Authorization` header — so two tenants using the same namespace, function, and arguments produce byte-identical request paths, and a shared HTTP cache applying heuristic freshness (RFC 9111 §4.2.2) to an unmarked response could serve one tenant's bytes to another. `no-store` forbids storing the response at all; `Vary: Authorization` is the independent second control — a cache that wrongly stores despite `no-store` (or RFC 9111 §3.5's rule for authenticated requests) but honors `Vary` still cannot match tenant A's copy to tenant B's request. Any CacheKit-operated serving tier that caches responses (edge, colo) MUST<sup id="api-3">API-3</sup> partition its internal cache by tenant, never by URL alone; such tiers are part of the server, not HTTP intermediaries, and these headers govern what they emit, not what they may store.

---

## Content Type

All request and response bodies use raw bytes:

```
Content-Type: application/octet-stream
```

> [!WARNING]
> **Discrepancy with RFC** — The RFC (Section 6.1) describes a JSON-based API with base64-encoded values and `Content-Type: application/json`. The actual implementation uses **raw binary** `application/octet-stream` for cache values. The RFC also uses `POST` for writes; the implementation uses `PUT`. **The implementation is authoritative.**

---

## Cache-Key Path Encoding

Every endpoint below carries the cache key as a path segment — `/v1/cache/{key}`, `/v1/cache/{key}/ttl`, `/v1/cache/{key}/lock`. The key is caller-controlled (each SDK's `key=` escape hatch accepts an arbitrary string), so how it is placed in the path is a security boundary, not a formatting detail: an unencoded key can escape `/v1/cache/` and deliver the bearer token to a different route (CWE-22 — cachekit-py shipped exactly that until [cachekit-py#279](https://github.com/cachekit-io/cachekit-py/pull/279)). MUST<!-- not-a-requirement -->, MUST NOT<!-- not-a-requirement -->, SHOULD and MAY are used as in RFC 2119.

### Encoding rules

**1. One segment, percent-encoded.** `{key}` MUST<sup id="api-4">API-4</sup> be exactly one path segment. Clients MUST<sup id="api-5">API-5</sup> percent-encode the key's UTF-8 bytes (RFC 3986 §2.1) so that only unreserved characters — `ALPHA / DIGIT / "-" / "." / "_" / "~"` — appear raw, and MUST NOT<sup id="api-6">API-6</sup> percent-encode an unreserved character (RFC 3986 §2.3): `.` is sent as `.`, never `%2E`. Every other byte MUST<sup id="api-7">API-7</sup> be sent as `%HH` — the delimiters `/ ? # %`, `:` (a canonical key carries six), space (`%20`, never `+`), every byte ≥ `0x80` — with one tolerance: the sub-delims `! * ' ( )` MAY be left raw as a set, all five raw (the `encodeURIComponent` form) or all five encoded, never a mix (rule 4). Hex digits SHOULD be uppercase (RFC 3986 §2.1); the server decodes either case. Reference encoders: Python `urllib.parse.quote(key, safe="")`, Rust `urlencoding::encode`, JavaScript `encodeURIComponent`.

**2. Reserved segments MUST<sup id="api-8">API-8</sup> be rejected client-side.** A key of exactly `.` or `..` survives rule 1 unchanged (`.` is unreserved) and is a *dot segment*: URL parsers remove it before routing — `/v1/cache/..` becomes `/v1/`, `/v1/cache/../ttl` becomes `/v1/ttl` — so the request lands on a different route, still carrying `Authorization`, and never reaches the key validator. Percent-encoding the dots does not help. The server parses the request URL under the WHATWG URL Standard, which treats an ASCII-case-insensitive `%2e` as a single-dot segment and `%2e%2e`, `.%2e`, `%2e.` as double-dot segments (URL Standard §4.1), so `%2E%2E` is collapsed *server-side* even when the client's own parser (RFC 3986 §5.2.4, e.g. `httpx`) sent it intact; WHATWG clients (`fetch`/undici, browsers, the Workers runtime, rust-url and therefore `reqwest`) collapse it before sending. **No wire form of a `.` or `..` key reaches the validator from any client.** The literal segments `health`, `ttl` and `lock` are route tokens at this level — `/v1/cache/health` is the health endpoint, and a final `ttl` or `lock` segment selects the sub-resource — so a key equal to one of those words is routed elsewhere or read as an empty key. An empty key is an empty segment: `/v1/cache/{key}` becomes `/v1/cache/` and `/v1/cache/{key}/ttl` becomes `/v1/cache//ttl`, neither of which addresses a stored entry.

Therefore clients MUST<sup id="api-9">API-9</sup> reject a key that is empty or exactly `.`, `..`, `health`, `ttl` or `lock` before building the URL, surfacing a client-side error; servers MUST NOT<sup id="api-10">API-10</sup> be relied on to compensate. Under rule 1 each of these keys encodes to itself, so checking the key and checking its encoding are the same test. Only an *entirely*-dot segment is a dot segment: `a:..`, `..a`, `x..y` are inert and MUST<sup id="api-11">API-11</sup> be sent per rule 1 with their dots raw. Canonical and interop keys always contain `:` and never meet this rule. Because every conformant client hard-codes this reserved set, servers MUST NOT<sup id="api-12">API-12</sup> add a route under `/v1/cache/` beyond `{key}`, `{key}/ttl`, `{key}/lock` and `health`, and MUST NOT<sup id="api-13">API-13</sup> serve any operation at `/v1/cache/` itself, without a protocol version bump.

Conformance tests MUST<sup id="api-14">API-14</sup> assert that every `reject: true` vector raises before a URL is built. They MUST<sup id="api-15">API-15</sup> assert every transmittable vector on the *parsed* request path (`new URL(u).pathname`, `Url::parse(u)?.path()`, `httpx.Request.url.raw_path`), not on the un-parsed template string — a template-string test passes while the traversal ships.

**3. The server decodes exactly once.** After the WHATWG parse of rule 2, the server splits the path on raw `/`, then percent-decodes the key segment once (`decodeURIComponent`-equivalent; a malformed escape is `400 Bad Request`) and validates the *decoded* key against the key format's [Server-Side Requirements](cache-key-format.md#server-side-requirements): a key failing the Length, Charset, Traversal or Namespace check is `400 Bad Request`; a write-space or namespace-grant violation is `403 Forbidden` ([Authentication](#authentication)). Consequences clients MUST<sup id="api-16">API-16</sup> honour:

- Clients MUST NOT<sup id="api-17">API-17</sup> double-encode. A literal `%` in a key is sent as `%25` once; `%2525` decodes to `%25`, a different key.
- An encoded `%2F` never becomes a segment boundary: the split on raw `/` happens *before* decoding, so `a%2Fb` reaches the validator as `a/b` and is rejected by the charset rule. A conformant client can neither traverse nor store a key containing `/`.

**4. Interop is defined on the decoded key.** `encodeURIComponent` leaves the sub-delims `! * ' ( )` raw (legal `pchar` in a path segment; they decode to themselves); `quote(safe="")` and `urlencoding::encode` emit `%21 %2A %27 %28 %29`. Both forms are conformant because the server-side key is identical after the single decode. Cross-SDK key equality is therefore a property of the **decoded** key, not of the wire bytes in general — but every key the server accepts is drawn from `[A-Za-z0-9_.:-]`, on which all three reference encoders agree (`:` → `%3A`, the rest raw). Every canonical auto-mode key and every [interop-mode](interop-mode.md) key is thus byte-identical on the wire across SDKs; the variance set only ever appears in keys the server rejects.

### Test vectors

[`test-vectors/path-encoding.json`](../test-vectors/path-encoding.json) pins these rules as `key → encoded → decoded` rows; its `contract` field defines the row semantics and travels with every vendored copy.

---

## Cache Endpoints

All cache endpoints are prefixed with `/v1/cache/`.

### GET /v1/cache/{key}

Retrieve a cached value.

```http
GET /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

The same request with a `ck_sdk_` key, which must carry `X-CacheKit-L1-Status` ([Required Headers](#required-headers)):

```http
GET /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_sdk_xxx
X-CacheKit-L1-Status: miss
```

| Status | Meaning | SDK Behavior |
| :---: | :--- | :--- |
| `200 OK` | Cache hit | Return raw bytes to caller |
| `404 Not Found` | Cache miss | Return `None`/`null` |

**Response headers:**

| Header | Description |
| :--- | :--- |
| `X-CacheKit-Freshness` | `fresh` or `stale` — lowercase, case-sensitive tokens. Emitted on every `GET` `200 OK` by servers implementing [stale-while-revalidate](#stale-while-revalidate). For `GET` responses, SDKs MUST<sup id="api-18">API-18</sup> treat an absent header as `fresh` (pre-SWR servers do not emit it) and an unrecognized value as `stale` (revalidation is the conservative action); read behavior is specified in [Stale-While-Revalidate](#stale-while-revalidate). |
| `X-CacheKit-Fresh-For` | Remaining freshness in whole seconds. Semantics: [Remaining Freshness](#remaining-freshness). |
| `X-CacheKit-Store-Source` | Which part of the service answered the read. Informational; see [Consistency](#consistency). |
| `Age` | Present when an edge copy answered the read: the copy's age in whole seconds. See [Consistency](#consistency). |

[`test-vectors/freshness-headers.json`](../test-vectors/freshness-headers.json) pins how an SDK reads both headers as `value → result` rows; its `contract` field defines the row semantics and travels with every vendored copy.

#### Remaining Freshness

> Status: **specified** (LAB-557). Origin: without a remaining-freshness signal, an SDK that backfills a local cache (L1) from a read assigns its full configured TTL from time-of-read — an entry read near the end of its server-side freshness window is then served locally as fresh for up to another full TTL, past the server's `fresh_until` (and, with a [stale-grace window](#stale-while-revalidate), potentially past `evict_at`).

`X-CacheKit-Fresh-For` tells the reader how long the served value remains fresh, so local caches can bound their own service window to the server's.

**Server (emission):**

- A **signal-capable server** is one that implements this section. It is independent of [stale-while-revalidate](#stale-while-revalidate) support: a bounded entry has a `fresh_until` whether or not it has a stale window, so a server may emit `X-CacheKit-Fresh-For` without offering one, and a pre-signal SWR server emits `X-CacheKit-Freshness` without it.
- Emitted on **every** `GET` `200 OK` for an entry that has a freshness bound. An entry stored without a TTL — neither `X-CacheKit-TTL` nor legacy `X-TTL` ([PUT](#put-v1cachekey)) — has **no expiry**: no `fresh_until`, no remainder to report, so the header is **omitted** — the server-side bound is unbounded, `min(local_ttl, ∞)` is the SDK's configured local TTL, and that is exactly the absent-header path below. When present, the value is a non-negative integer: `max(0, floor(fresh_until − now))`, computed against the **server's clock** at response time — the client never compares server timestamps against its own clock.
- Stale-window responses (`X-CacheKit-Freshness: stale`) carry `X-CacheKit-Fresh-For: 0` — freshness is already exhausted. `X-CacheKit-Freshness: fresh` with `X-CacheKit-Fresh-For: 0` is also legal — an entry in its final sub-second of freshness floors to `0`. The response is served to the caller normally; the `0` governs only local caching (no backfill).
- Omitted by the store for no-expiry entries, and by pre-signal servers for everything. The client cannot tell the two apart, by design: both mean "no server-side freshness bound applies to this read" and both lead to the same SDK action (configured local TTL, fresh service only). Because absence carries that meaning, a tier that implements this section MUST NOT<sup id="api-19">API-19</sup> produce it for a copy it cannot positively confirm has no expiry — the tier rule below.
- **Re-serving tiers** — an edge or colo cache in front of the store that answers from a copy it read earlier — are part of the server. A tier's **coherence window** is the deployment-documented maximum time it may keep serving a copy after the store has changed or deleted the entry; a tier that refreshes its copy's lifetime from the tier below rather than from the store adds its window to the path's total, so windows **compound** along the serving path and a deployment's effective window is their sum, not its largest single tier. That governs the *bytes*. The *header* follows stricter, fail-closed rules:
  - **Decay, never re-stamp.** A tier MUST<sup id="api-20">API-20</sup> emit its copy's remaining bound minus the seconds elapsed since that bound was obtained, flooring at `0`. A copy has exactly one bound source: the response it was read from (the bound is that response's `X-CacheKit-Fresh-For`), or — for a copy the tier populated from a write it forwarded — that write, once the store has accepted it (the bound is the write's effective TTL, see [Migration](#put-v1cachekey), measured from when the tier dispatched the write; the store stamps `fresh_until` after that dispatch, from `floor(stored_at)` ([whole-second stamping](#entry-lifecycle)), so the copy's bound ends less than one second after `fresh_until`). It MUST NOT<sup id="api-21">API-21</sup> emit a value larger than that decayed remainder — its own copy TTL included — under any label. The deployed tiers decay, so the rule costs a conforming implementation nothing, and it keeps a pre-`DELETE` copy's local service within one second of the entry's `fresh_until`.
  - **Omit only on positive knowledge of no expiry; otherwise `0`.** A tier MAY omit the header only for a copy it positively knows has no expiry: a signal-capable store below omitted it (such a store omits only for no-expiry entries), or the tier populated the copy from an accepted write that carried no TTL at all — neither `X-CacheKit-TTL` nor legacy `X-TTL`. A tier MUST<sup id="api-22">API-22</sup> determine a write's TTL with the store's own precedence (`X-CacheKit-TTL`, else `X-TTL`); the absence of `X-CacheKit-TTL` alone proves nothing, because a legacy `X-TTL: 60` write is bounded. For every other copy whose remainder it does not know — populated without a hint, a header lost in transit, or a store below that is pre-signal and therefore omits for bounded entries too — the tier MUST<sup id="api-23">API-23</sup> emit `X-CacheKit-Fresh-For: 0`. It MUST NOT<sup id="api-24">API-24</sup> omit a header it received, nor drop it for such a copy: omission would claim "no bound" for an entry that may have one and silently restore the unbounded backfill this header exists to kill. A tier MUST<sup id="api-25">API-25</sup> therefore record at populate whether a copy is unbounded or merely unhinted; a tier that cannot tell the two apart MUST<sup id="api-26">API-26</sup> emit `0`. A tier fronting a pre-signal store is in exactly that position — it emits `0`, it does not pass the absence through; the cost is no local backfill behind that tier until the store signals, the fail-closed posture a mixed deployment should have. Whether the store below signals is a deployment fact the tier is configured with, never inferred per response.
  - **Positive only for `fresh` + positive.** A tier MAY emit a positive value only when its copy's bound source qualifies, and then only the decayed remainder: a response the tier below labelled exactly `X-CacheKit-Freshness: fresh` (or left unlabelled — the pre-SWR `fresh` default) and stamped with a strictly positive `X-CacheKit-Fresh-For`; or an accepted write with a positive effective TTL, whose copy is labelled `fresh` (a just-accepted write is fresh by construction). Every other shape — `stale`, `X-CacheKit-Fresh-For: 0` under any label, an unrecognized freshness token, or a missing `X-CacheKit-Fresh-For` on any entry not positively known to be no-expiry — MUST<sup id="api-27">API-27</sup> be emitted with `X-CacheKit-Fresh-For: 0` and its freshness label passed through unchanged (a `fresh` `0` stays `fresh`; a `stale` stays `stale`). Stamping a positive bound onto a stale, exhausted, or unknown value resurrects an expired (or revoked) entry as locally-cacheable fresh — the exact hole this header closes.
- `HEAD` does **not** carry this header — an existence check returns no payload, so there is nothing to backfill locally (the `X-CacheKit-Freshness` label on `HEAD` remains informational, per [Stale-While-Revalidate](#stale-while-revalidate)). Correspondingly, a `HEAD` response MUST NOT<sup id="api-28">API-28</sup> create, refresh, or extend any local entry's service bound.

**SDK (consumption):**

- On a `GET` `200 OK` labelled `X-CacheKit-Freshness: fresh` (or unlabelled) with the header present, a local cache (L1) backfill MUST<sup id="api-29">API-29</sup> bound the entry's local lifetime to at most the header value: `min(local_ttl, fresh_for)`. A value of `0` means the entry MUST NOT<sup id="api-30">API-30</sup> be backfilled at all. A `stale` or unrecognized freshness label forbids backfill regardless of the number ([Reading a stale entry](#reading-a-stale-entry)) — a positive `X-CacheKit-Fresh-For` on a `stale` response is a server bug, not a license.
- The header value is a hard local **service** bound, not merely a freshness bound: once it elapses, the local copy MUST NOT<sup id="api-31">API-31</sup> be served in any form — including by client-side stale-while-revalidate or any local stale-grace policy. (Serving server-returned stale bytes per [Reading a stale entry](#reading-a-stale-entry) is unaffected — this rule governs only the local copy.) **Why there is no local stale service, stated once:** the client receives no remaining-eviction signal, so a locally-stale copy could not honor the store's [`evict_at` bound](#reading-a-stale-entry) — and one is deliberately not provided, because it would let clients replicate the stale window locally, invisibly to server-side revalidation single-flight and metering. Stale service is the server's job: a subsequent read hits the server, which serves the stale window itself (`X-CacheKit-Freshness: stale`, `X-CacheKit-Fresh-For: 0`) until `evict_at`. Rules elsewhere refer back here rather than restating this.
- Absent header on a `GET` `200 OK` = no server-side freshness bound for this read — a no-expiry entry, or a pre-signal server. Legacy behavior: the SDK's configured local TTL applies unchanged. This makes the header purely additive — old SDKs ignore it, and new SDKs against old servers behave exactly as before. Absence licenses only *fresh* service for that configured lifetime, never local stale service (above).
- The value MUST<sup id="api-32">API-32</sup> be 1–7 ASCII digits and at most `2,592,000` (the [30-day TTL cap](#put-v1cachekey), itself seven digits). Anything else — empty, non-digit, signed, longer than seven digits, or over the cap — MUST<sup id="api-33">API-33</sup> be treated as `0` (do not extend local service — the conservative action, mirroring the unrecognized-`X-CacheKit-Freshness` → `stale` rule); a larger value is protocol-impossible, a buggy or misconfigured tier rather than a real bound. The length check MUST<sup id="api-34">API-34</sup> run first, so the range check never depends on a fixed-width integer conversion that could wrap an over-cap value back into range (a wrapping `atoi`/`strtoul` turns `4297559296` into `2,592,000`).
- Network transit slightly overstates remaining freshness at the client (the value was computed at response time). This is accepted: the error is bounded by transit latency, the same class HTTP `Age` handling tolerates, and is negligible against whole-second granularity.
- **The writer's own copy.** A `PUT` response carries no `X-CacheKit-Fresh-For`, so an SDK that keeps a local copy of a value it wrote bounds that copy by the write itself. Once the store accepts the `PUT`, the SDK MUST NOT<sup id="api-35">API-35</sup> serve that copy, in any form, after `min(local_ttl, effective_ttl)` has elapsed, where `effective_ttl` is the write's [effective TTL](#put-v1cachekey) and the clock starts when the SDK receives the store's `2xx` response. `X-CacheKit-Stale-TTL` never lengthens this bound, because local stale service is not allowed (above). A write with no effective TTL stores a no-expiry entry, so the configured local TTL applies, as for an absent header. Receipt is the first instant the SDK knows the write was accepted, but the store stamps `fresh_until` earlier, when it begins storing the write (before the rest of the work that precedes its reply), and from `floor(stored_at)` ([whole-second stamping](#entry-lifecycle)). A conforming copy can therefore outlive `fresh_until` by the time from the store's stamp to the SDK's local write (the store's remaining processing, transit, and the SDK's own processing), plus less than one second. That error is accepted; it is this section's **write-path tolerance**. An SDK may also keep a copy without having received a `2xx`: after a timeout, a transport error, or an error it absorbed. The store may still have accepted that write, and no `2xx` starts the clock, so the SDK MUST<sup id="api-36">API-36</sup> start that copy's `min(local_ttl, effective_ttl)` clock no later than its local write, and MUST NOT<sup id="api-37">API-37</sup> serve the copy, in any form, once that has elapsed. Such a copy can then outlive `fresh_until` by up to the time from the SDK's first dispatch of the `PUT` to its local write (the write call's full duration, retries included, and the SDK's own processing after it), plus a second. An SDK SHOULD measure that copy's bound from when it first dispatched the `PUT`, which keeps it less than one second past `fresh_until`.
- The local deadline SHOULD be measured against a clock that keeps counting across system suspend (wall-clock anchored, or a `CLOCK_BOOTTIME`-class monotonic source): a suspend-blind monotonic clock stops while the host sleeps and serves past the bound after resume. This is implementation guidance, not wire contract — the same clock discipline applies to all local TTL accounting.
- An issued `fresh_for` is a snapshot, not a lease the server can recall: a later `DELETE`, or a fresh-window `PATCH /ttl` that shortens the entry, does not reach copies already backfilled — remote local caches compliantly serve until their bounded lifetime expires, and a re-serving tier may compliantly hand out a copy it cached before the `DELETE` for the rest of its coherence window ([emission](#remaining-freshness) above). `evict_at` is therefore the **store's** service bound, not an end-to-end one. Revocation propagation is bounded by the **sum** of the serving path's compounded coherence windows, the largest locally applied service bound, in-flight response transit, the time from first dispatch to local write of any write whose copy the writer kept without a `2xx`, and clock or suspend error — a `GET` response already in flight when the `DELETE` lands is likewise still backfilled on arrival. For a bounded entry the local term is the decayed header, so it ends no later than the served entry's `fresh_until`, or less than one second after it when a re-serving tier's copy came from a write the tier forwarded ([emission](#remaining-freshness) above). For the writer's own copy of a bounded write the local term is the write's bound, which ends within the write-path tolerance of `fresh_until`, or up to that time plus a second after it for a copy kept without a `2xx` ([the writer's own copy](#remaining-freshness) above). For a **no-expiry** entry — or any read served without the header — there is no `fresh_until`: the local term is the full configured local TTL of each reader or writer holding a copy, re-anchored on every read and every write, so a revoked no-expiry value outlives its `DELETE` by the largest local TTL in the fleet with no server-side ceiling, and a `PATCH /ttl` or `DELETE` that later bounds or removes a formerly-no-expiry entry cannot reach copies already distributed without the header. The protocol caps none of the latency terms in this sum, so TTL bounds the revocation window only together with them. Security-sensitive caches MUST<sup id="api-38">API-38</sup> size TTL (and local TTL) to their revocation tolerance, or version their keys (see the invalidation-race note in [Semantics notes](#semantics-notes)); keys whose TTL is a revocation boundary MUST<sup id="api-39">API-39</sup> be stored with an explicit `X-CacheKit-TTL` — a no-expiry entry has no revocation tolerance to size to.

---

### PUT /v1/cache/{key}

Store a cache value.

```http
PUT /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
Content-Type: application/octet-stream
X-CacheKit-TTL: 3600

<raw bytes>
```

The same request with a `ck_sdk_` key, which must carry `X-CacheKit-L1-Status` ([Required Headers](#required-headers)):

```http
PUT /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_sdk_xxx
Content-Type: application/octet-stream
X-CacheKit-TTL: 3600
X-CacheKit-L1-Status: miss

<raw bytes>
```

| Header | Required | Description |
| :--- | :---: | :--- |
| `X-CacheKit-TTL` | No | Time-to-live in seconds. Positive integer, minimum 1, maximum 2,592,000 (30 days). Omit — together with legacy `X-TTL` — to store the entry with **no expiry** (see the **No-expiry contract** under TTL Validation Rules); servers MUST NOT<sup id="api-40">API-40</sup> substitute a hidden default. |
| `X-CacheKit-Stale-TTL` | No | Stale-grace window in seconds after freshness expiry. Requires an explicit TTL (`X-CacheKit-TTL`, or legacy `X-TTL`) on the same request. Validation and semantics: [Stale-While-Revalidate](#stale-while-revalidate). Pre-SWR servers ignore this header. |

> [!IMPORTANT]
> **TTL Validation Rules** — These rules are normative for both SDKs and the SaaS backend.
>
> | Condition | SDK Behavior | Server Behavior |
> | :--- | :--- | :--- |
> | TTL omitted | Use client default TTL. If no client default, omit `X-CacheKit-TTL` header. | Store with **no expiry** when the request carries neither `X-CacheKit-TTL` nor `X-TTL` — see **No-expiry contract** below. There is no tenant-default TTL mechanism: servers MUST NOT<sup id="api-41">API-41</sup> apply a hidden default — validation must not depend on defaults clients cannot see (the same rule as `X-CacheKit-Stale-TTL`). |
> | TTL = 0 | **Reject** — return error to caller. Zero is not a valid TTL. | **Reject** — return `400 Bad Request`. |
> | TTL < 1 second | **Round up to 1.** Sub-second durations MUST<sup id="api-42">API-42</sup> be ceiled, never truncated to 0. | N/A (header is integer seconds). |
> | TTL > 2,592,000 | **Reject** — return error to caller. | **Reject** — return `400 Bad Request`. |
> | TTL negative | **Reject** — return error to caller. | **Reject** — return `400 Bad Request`. |
> | TTL non-integer | N/A (SDK converts duration to integer seconds). | **Reject** — return `400 Bad Request`. |
>
> **No-expiry contract.** An entry stored without a TTL — neither `X-CacheKit-TTL` nor legacy `X-TTL` (see **Migration** below) — has no `fresh_until` and no `evict_at`:
> - **Reads:** permanently **fresh** — while the entry is present, `GET` and `HEAD` return `200 OK` with `X-CacheKit-Freshness: fresh`, and `GET` carries no [`X-CacheKit-Fresh-For`](#remaining-freshness). It never enters a stale window. Presence ends only on explicit `DELETE`, overwrite, or capacity eviction (below).
> - **Storage bound: deployment-configured.** No-expiry entries are never age-evicted. Whether, and at what ceiling, a deployment applies capacity eviction is deployment configuration outside this protocol; no-expiry entries are eligible victims of whatever capacity eviction the deployment applies, so "no expiry" is **not** a durability guarantee, and an evicted entry gives no client-visible signal beyond a subsequent miss. A deployment that needs a specific storage ceiling must provision a tenant or namespace quota.
> - **`GET /v1/cache/{key}/ttl`:** see the [endpoint](#get-v1cachekeyttl).
> - **`PATCH /v1/cache/{key}/ttl`:** `200`; gives the entry its first expiry (`fresh_until = floor(now) + ttl`, [whole-second stamping](#entry-lifecycle)) — the one way to bound an existing no-expiry entry without rewriting it. That `200` is indistinguishable from the [absent-key no-op](#patch-v1cachekeyttl); confirm presence separately if it matters.
>
> **Rationale:** TTL=0 is ambiguous across cache systems (Redis rejects it, Memcached treats it as "never expire", HTTP treats it as "immediately stale"). CacheKit defines TTL=0 as an error to prevent silent data loss (the Redis and HTTP readings) or an unintended no-expiry entry (the Memcached reading) — no expiry is requested by omitting the header, never by `0`. Sub-second durations are ceiled to 1 rather than truncated to 0 to avoid the same ambiguity. The 30-day maximum bounds the value range of a **stated** TTL (and with it the [`X-CacheKit-Fresh-For`](#remaining-freshness) grammar); it is not a storage-lifetime ceiling (see the no-expiry contract above). Entries that need a long but bounded life should renew explicitly via `PATCH /v1/cache/{key}/ttl`.
>
> **Migration:** The `X-TTL` header is deprecated. The server MUST<sup id="api-43">API-43</sup> accept both `X-CacheKit-TTL` and `X-TTL` during the transition period, preferring `X-CacheKit-TTL` when both are present. A write's **effective TTL** is therefore `X-CacheKit-TTL` when present, otherwise `X-TTL`; a write has no TTL — and stores a no-expiry entry — only when it carries **neither**. Every rule in this spec that depends on whether a write carried a TTL reads the effective TTL: the no-expiry rule, the stale-window requirement, and the re-serving-tier rules in [Remaining Freshness](#remaining-freshness). SDKs MUST<sup id="api-44">API-44</sup> send `X-CacheKit-TTL` only. The `X-TTL` header will be removed in protocol version 2.0 (targeted at SDK 1.0 milestone).

> [!IMPORTANT]
> **Maximum value size:** A single cache value may be at most **25 MB**. Larger values are rejected with `413 Payload Too Large` — a **permanent** error: SDKs MUST NOT<sup id="api-45">API-45</sup> retry and SHOULD surface "value too large" to the caller. This ceiling MAY change, so SDKs MUST<sup id="api-46">API-46</sup> treat any `413` as "value too large" regardless of the exact byte count. It is unrelated to the SDK serializer's 512 MiB in-memory safety bound (see `wire-format.md`) — that bound governs what the SDK will serialize, not what the service will store.

| Status | Meaning |
| :---: | :--- |
| `200 OK` | Value stored |
| `413 Payload Too Large` | Value exceeds the maximum stored value size (25 MB). Permanent — do not retry. |

---

### DELETE /v1/cache/{key}

Delete a cache entry.

```http
DELETE /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

| Status | Meaning | SDK Behavior |
| :---: | :--- | :--- |
| `200 OK` | Delete processed | Return `true` |

Delete is **idempotent and unconditional with respect to key existence**: once authentication and authorisation succeed, the server performs no existence check and returns `200` with body `{"success": true}` whether or not the key existed. The ordinary request-level errors still apply before that point — `401` (invalid/missing key), `403` (write-space or namespace-grant violation), `400` (invalid key format) — see [Error Handling](#error-handling).

---

### HEAD /v1/cache/{key}

Check if a key exists without retrieving the value.

```http
HEAD /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

| Status | Meaning | SDK Behavior |
| :---: | :--- | :--- |
| `200 OK` | Key exists | Return `true` |
| `404 Not Found` | Key does not exist (or is past `evict_at`) | Return `false` |

`HEAD` MUST<sup id="api-47">API-47</sup> return the status `GET` would return for the same key ([RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.2)), with no body. Servers implementing [stale-while-revalidate](#stale-while-revalidate) emit the same `X-CacheKit-Freshness` response header as `GET` on a `200`; on `HEAD` the header is informational and MUST NOT<sup id="api-48">API-48</sup> be used to infer existence — the status code is the existence signal. On `HEAD`, an absent or unrecognized `X-CacheKit-Freshness` value carries no information and MUST<sup id="api-49">API-49</sup> be ignored; the `GET` defaulting rules ([Response headers](#get-v1cachekey)) do not apply. `X-CacheKit-Fresh-For` is **not** emitted on `HEAD` ([Remaining Freshness](#remaining-freshness) — no payload, nothing to backfill).

---

## Stale-While-Revalidate

> Status: **specified** (LAB-381) and **shipped** on `api.cachekit.io`. SDK adoption tracked in the [feature matrix](../sdk-feature-matrix.md#reliability-features).

Stale-while-revalidate (SWR, [RFC 5861](https://www.rfc-editor.org/rfc/rfc5861) semantics) lets a client serve an expired-but-present value immediately and recompute it in the background, so no request pays the recompute cost at a TTL boundary. Because the recompute is the client's wrapped function, **the client owns revalidation**; the server's role is read-time staleness signaling and single-flight coordination.

### Entry lifecycle

An entry stored with `X-CacheKit-TTL: ttl` and `X-CacheKit-Stale-TTL: stale_ttl` has two windows:

```
stored_at ──────────── fresh_until ──────────────── evict_at
          FRESH                       STALE
          (200, fresh)                (200, stale)   404

fresh_until = floor(stored_at) + ttl
evict_at    = fresh_until + stale_ttl
```

**Whole-second stamping.** `stored_at` is the store's clock when it stores the write, between receiving the `PUT` and replying to it. The store MUST<sup id="api-50">API-50</sup> stamp the write from `floor(stored_at)`, and MUST<sup id="api-51">API-51</sup> stamp a [`PATCH /v1/cache/{key}/ttl`](#patch-v1cachekeyttl) the same way, from `floor(now)`, so `fresh_until` and `evict_at` are always whole seconds. Flooring shortens the fresh window by less than a second and never lengthens it: an entry is fresh for more than `ttl − 1` and at most `ttl` seconds after `stored_at` (for a `PATCH`, after the `now` it was stamped from). The sub-second tolerances in [Remaining Freshness](#remaining-freshness) and the [`/ttl` rounding](#get-v1cachekeyttl) rest on this rule.

| Window | `GET` / `HEAD` behavior |
| :--- | :--- |
| `now < fresh_until` | `200 OK`, `X-CacheKit-Freshness: fresh` |
| `fresh_until ≤ now < evict_at` | `200 OK` (**with the stored bytes** on `GET`; no body on `HEAD`), `X-CacheKit-Freshness: stale` |
| `now ≥ evict_at` | `404 Not Found`. The store MUST NOT<sup id="api-52">API-52</sup> serve an entry past `evict_at`. This is the **store's** bound: copies already handed to re-serving tiers or backfilled into local caches run to their own bounded lifetimes — the end-to-end revocation bound is in [Remaining Freshness](#remaining-freshness). |

All lifecycle times are computed against the **store's clock**; SDKs MUST NOT<sup id="api-53">API-53</sup> derive freshness for backed entries from their own clocks.

Without `X-CacheKit-Stale-TTL` (or with `0`), `evict_at = fresh_until` — the eviction boundary collapses to the pre-SWR hard-expiry point. This is an **arithmetic** equivalence only: a server implementing SWR still emits `X-CacheKit-Freshness` on every `GET` `200` regardless of whether `stale_ttl` was set; header emission is never conditioned on it.

Without a TTL — neither `X-CacheKit-TTL` nor legacy `X-TTL` — the entry has **no expiry**: no `fresh_until`, no `evict_at`. It is served `200 OK` `fresh` while present — until deleted, overwritten, or capacity-evicted ([no-expiry contract](#put-v1cachekey)) — never enters the stale window, and carries no `X-CacheKit-Fresh-For` ([Remaining Freshness](#remaining-freshness)). `X-CacheKit-Stale-TTL` without a TTL is rejected ([validation](#validation)) — an entry that never expires has nothing to be stale relative to. Never expiring has two consequences a writer must weigh: the entry's revocation bound has no server-side ceiling, so read the revocation bound in [Remaining Freshness](#remaining-freshness) before storing a revocation-sensitive key without a TTL; and a copy a mispartitioned tier stores under the wrong tenant never self-heals, so the [tenant-partitioning rule](#authentication) is the only control for it.

### Validation

These rules are normative for both SDKs and the SaaS backend, mirroring the [TTL validation rules](#put-v1cachekey):

| Condition | Behavior |
| :--- | :--- |
| `stale_ttl` negative, non-integer, or > 2,591,999 | `400 Bad Request`. The standalone bound is checked **before** any arithmetic (no integer wrap on `evict_at`). |
| `X-CacheKit-Stale-TTL` present without an explicit TTL (`X-CacheKit-TTL`, or legacy `X-TTL`) | `400 Bad Request`. Validation must not depend on hidden tenant defaults — clients must be able to pre-validate. |
| `ttl + stale_ttl > 2,592,000` | `400 Bad Request` (the stale window shares the [30-day TTL cap](#put-v1cachekey)) |
| `stale_ttl = 0` | Accepted; equivalent to omitting the header |
| `stale_ttl < 1` second (sub-second duration in SDK API) | SDKs MUST<sup id="api-54">API-54</sup> ceil to 1, never truncate to 0 (same rule as TTL) |

### Write semantics

- **`PUT` fully replaces the entry's timing metadata.** Both windows derive from the new request alone; a `PUT` that omits `X-CacheKit-Stale-TTL` (or sends `0`) leaves the entry with **no** stale window, regardless of what the previous entry had. A revalidation `PUT` therefore MUST<sup id="api-55">API-55</sup> re-send both the `X-CacheKit-TTL` and the stale window it intends to keep — the previous bound is never carried forward, so a recompute that carries neither `X-CacheKit-TTL` nor legacy `X-TTL` stores a **no-expiry** entry ([PUT](#put-v1cachekey)).
- **`PATCH /v1/cache/{key}/ttl` within the fresh window** resets `fresh_until = floor(now) + ttl` ([whole-second stamping](#entry-lifecycle)) and preserves the entry's stored stale window; the combined total is re-validated against the 30-day cap.
- **`PATCH /v1/cache/{key}/ttl` on an entry past `fresh_until` MUST<sup id="api-56">API-56</sup> return `409 Conflict`.** A stale entry regains freshness only via a `PUT` of recomputed bytes — otherwise a routine TTL-renewal job could indefinitely resurrect stale data without revalidation, defeating the `evict_at` bound.

### Reading a stale entry

On a `200` with `X-CacheKit-Freshness: stale`:

- An SDK MUST NOT<sup id="api-57">API-57</sup> treat the response as a protocol error.
- By default it SHOULD return the bytes to the caller immediately — a stale response is never a blocking miss.
- An SDK MAY instead treat a stale hit as a **miss** by local policy (e.g. security-sensitive caches where TTL is a revocation boundary) and take the ordinary synchronous miss path. Such caches SHOULD NOT set `X-CacheKit-Stale-TTL` on write in the first place.
- Local caches (L1) MUST NOT<sup id="api-58">API-58</sup> backfill a stale-flagged response at all — not as fresh, not as locally-stale — regardless of any `X-CacheKit-Fresh-For` value (signal-capable servers mark these `0`; the rule holds with or without the header, and the rationale is stated once under [Remaining Freshness](#remaining-freshness)). On a response carrying [`X-CacheKit-Fresh-For`](#remaining-freshness), local caching MUST NOT<sup id="api-59">API-59</sup> extend service of an entry past the store's `evict_at` — for *fresh*-labelled reads near the freshness boundary, the header is the mechanism that lets local caches honor this bound (LAB-557). A response without it — a no-expiry entry, or a pre-signal server — follows the absence rule in that section: the configured local TTL applies unchanged. From a pre-signal server that lifetime may outlive `evict_at` — the origin gap the header exists to close.
- Revalidation is triggered only by `GET`. `HEAD` freshness is informational; an existence check MUST NOT<sup id="api-60">API-60</sup> fire a background recompute.

### Revalidation flow (SDK)

An SDK that serves a stale hit and owns revalidation (the recompute is the wrapped function — the server cannot do it):

1. MUST<sup id="api-61">API-61</sup> return the stale bytes (or take its local miss policy, above) without blocking on revalidation.
2. SHOULD single-flight the recompute by attempting `POST /v1/cache/{key}/lock` (the existing [lock endpoint](#post-v1cachekeylock)) as a **non-blocking** lease. The lease is acquired **only** on `200 OK` with a non-empty `lock_id`. Contention is signalled **only** by a `200 OK` with a `null`/absent `lock_id` — or, defensively, a legacy `409 Conflict` — and means another client is revalidating: serve stale; the SDK MUST NOT<sup id="api-62">API-62</sup> wait or retry. Any other non-`200` (`401`, `403`, `429`, `5xx`, …) is **not** contention — it is an ordinary error subject to [Error Classification](#error-classification): abandon this revalidation attempt without a lease (the caller already has the stale bytes from step 1) and let a subsequent stale read re-trigger revalidation.

   > [!NOTE]
   > **Contested lock is `200 OK` with `{"lock_id": null}` (LAB-240).** The
   > lease/single-flight contract keys off `lock_id` **presence**, never the HTTP
   > status — see the [lock endpoint](#post-v1cachekeylock). Do not reintroduce a
   > `409` contested status: the deployed server never emitted one, and status-based
   > branching silently disables single-flight.

3. The lease holder recomputes in the background, `PUT`s the new value (re-sending `X-CacheKit-Stale-TTL` per [write semantics](#write-semantics)), then `DELETE`s the lock.
4. A failed recompute **or** a failed revalidation `PUT` are equivalent: release the lock, leave the entry untouched, surface no error to the caller. Subsequent stale reads MAY re-trigger revalidation until `evict_at`; past `evict_at` the next request takes the ordinary synchronous miss path. SWR degrades to pre-SWR behavior — it never serves unbounded staleness.
5. The lease is **best-effort stampede mitigation, not a correctness guarantee**: it is bounded by the lock's `timeout_ms`, and a recompute that outlives it loses exclusivity. Duplicate revalidations are benign — concurrent revalidation `PUT`s are last-write-wins between freshly computed values, the same ordering as concurrent miss-path `PUT`s today. SDKs SHOULD size `timeout_ms` at or above the expected recompute duration.

### Semantics notes

- **Metering:** a stale-window `GET` is a cache **hit** (`200`) for metered-misses billing; the revalidation `PUT` is an ordinary write. In the [SDK metrics headers](#optional-metrics-headers), a stale serve increments `X-CacheKit-L2-Hits`; a background revalidation MUST NOT<sup id="api-63">API-63</sup> increment `X-CacheKit-Misses`.
- **Invalidation race:** an explicit `DELETE /v1/cache/{key}` concurrent with an in-flight revalidation may be overwritten by the revalidation `PUT` (last-write-wins) — the same race as today's concurrent miss-path recompute. Callers that need durable invalidation must version their keys.
- **Zero-knowledge:** no change to the wire format, ByteStorage envelope, encryption, or AAD; the value bytes remain opaque.
- **`GET /v1/cache/{key}/ttl`:** the returned `ttl` is the remaining seconds until **eviction** (`evict_at`), or `null` for a no-expiry entry (mixed-reader caveat under [GET /v1/cache/{key}/ttl](#get-v1cachekeyttl)).
- **Compatibility:** additive for servers — a pre-SWR server ignores `X-CacheKit-Stale-TTL` (the entry evicts at `fresh_until`, no freshness header is emitted) and SDK behavior is exactly pre-SWR. It is **not** transparent to mixed readers: enabling `stale_ttl` on a key affects every reader of that key, and a pre-SWR SDK will consume stale-window values as fresh (`200`, no header) where it previously saw a miss. Deployments MUST NOT<sup id="api-64">API-64</sup> enable `stale_ttl` on keys whose readers rely on hard TTL expiry (pre-SWR SDKs or security-sensitive consumers).

---

## Consistency

<!-- This section is mirrored word for word on docs.cachekit.io's Consistency and Deletion page. Edit both together. -->

This section is informative: it places no requirement on SDKs, and the [Remaining Freshness](#remaining-freshness) rules still govern an SDK's own local cache.

Every namespace has an edge budget: 5 seconds by default. A read answered by the CacheKit service may come from a copy held at the edge location that received it, but only if that copy was read from or written to the store within the budget, and only while the entry is fresh. So by default such a read reflects every write and delete that completed more than 5 seconds earlier, from any region, but not necessarily a more recent one, even one made through the same edge location. When two writes to the same key race, either value may be returned for up to the budget after the later write completes. Keys without an `ns:{name}:` or `nsapi:{name}:` prefix belong to the `default` namespace: cachekit-py's `namespace=` option writes `ns:{name}:` keys, while keys from cachekit-ts and cachekit-rs, whatever their namespace setting, and interop-mode keys from any SDK belong to `default`.

A budget of 0 sends every read to the store. A higher budget, up to 300 seconds, serves more reads from the nearest edge location, and such a read may return a value overwritten or deleted up to that many seconds earlier. An edge copy is never served past the TTL it was made under. Writes, deletes and TTL changes are not pushed between edge locations, so a `PATCH` of an entry's TTL reaches copies held at other locations only within the budget. A lowered budget usually applies within about 15 seconds, and within about 7 minutes under steady traffic; a request that reaches an edge location idle for a long time can still use the old budget for up to about 17 minutes, and reads keep the old budget's guarantee until the new one applies.

After a project is deleted, its API keys can keep working for a short time: normally a few seconds and at most about 40 seconds while the service is healthy, though a key idle at an edge location can have one more request accepted there up to about 5 minutes after the delete. Reads and writes made with such a key succeed. A later cleanup normally removes the data they write within an hour, but removal is not guaranteed; once the keys stop working, that data can no longer be read. An edge copy is served only to a key that still works, and a copy made before the project's data was wiped is served for at most the namespace's budget after the wipe, which normally follows the delete within seconds.

Not-found results are held for at most 5 seconds, and values read in their `stale_ttl` window are never held as edge copies. Every `GET` of a cache key that returns a value or a not-found says where it came from (`X-CacheKit-Store-Source`) and, for an edge copy, how old it is (`Age`).

Your SDK's in-process L1 cache is separate and is not told about other processes' writes. When a response carries `X-CacheKit-Fresh-For`, SDKs that honour it (cachekit-py 0.19.0 and later, cachekit-rs 0.9.0 and later) keep a copy for at most that many seconds; otherwise the L1 copy keeps its own configured TTL. Edge age and L1 life add up.

---

## Lock Endpoints

Distributed locking for cache stampede prevention.

### POST /v1/cache/{key}/lock

Acquire a distributed lock.

```http
POST /v1/cache/{key}/lock HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
Content-Type: application/json

{"timeout_ms": 5000}
```

| Status | Meaning | Response Body |
| :---: | :--- | :--- |
| `200 OK` | Lock **acquired** | `{"lock_id": "uuid-string"}` |
| `200 OK` | Lock **contested** (held by another client) | `{"lock_id": null}` |

Contention is signalled in the response **body**, not the HTTP status: a non-empty
`lock_id` means the caller holds the lease; a `null` (or absent) `lock_id` means
another client holds it. Clients MUST<sup id="api-65">API-65</sup> branch on `lock_id` presence and MUST NOT<sup id="api-66">API-66</sup>
branch on the status code — the single-flight lease contract (see
[Revalidation flow](#revalidation-flow-sdk)) depends on it.

> **History (LAB-240):** earlier revisions of this spec specified `409 Conflict`
> for a contested lock. The deployed server never implemented that — it has always
> returned `200 OK` with `{"lock_id": null}` — so `409` is **not** part of the lock
> contract. SDKs that additionally treat a `409` as contested (e.g. cachekit-ts)
> remain correct: the body-based rule subsumes it.

---

### DELETE /v1/cache/{key}/lock

Release a distributed lock. The lock id (the capability token returned by `POST
/v1/cache/{key}/lock`) is sent in the `X-CacheKit-Lock-Id` request header.

```http
DELETE /v1/cache/{key}/lock HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
X-CacheKit-Lock-Id: uuid-string
```

| Header | Required | Description |
| :--- | :---: | :--- |
| `X-CacheKit-Lock-Id` | Yes | Lock capability token from the acquire response. An empty/whitespace value is treated as absent. |

| Status | Meaning |
| :---: | :--- |
| `200 OK` | Lock released |
| `400 Bad Request` | Lock id absent from both the header and the legacy `?lock_id=` query param |

> **Security (CWE-532):** the lock id is a short-lived capability token — anyone holding it can release the lock within its TTL. It MUST<sup id="api-67">API-67</sup> travel in the `X-CacheKit-Lock-Id` header, **not** the query string: query strings are routinely captured by access logs, proxy/CDN logs, and OpenTelemetry `http.url` spans, which would let anyone with log access replay the token.
>
> **Migration:** the legacy `?lock_id={lock_id}` query parameter is deprecated. The server MUST<sup id="api-68">API-68</sup> accept both the `X-CacheKit-Lock-Id` header and the `?lock_id=` query param during the transition period, preferring the header when both are present. SDKs MUST<sup id="api-69">API-69</sup> send the header only. The query parameter will be removed in protocol version 2.0 (targeted at the SDK 1.0 milestone).

---

## TTL Endpoints

### GET /v1/cache/{key}/ttl

Get remaining TTL for a key. The returned `ttl` is the remaining seconds until **eviction** — for entries with a [stale-grace window](#stale-while-revalidate), that is `evict_at`, not `fresh_until`. It is rounded **up** to the whole second: `evict_at` is a whole second ([whole-second stamping](#entry-lifecycle)) and the server returns `evict_at − floor(now)`, so a key in its final sub-second reads `1`, and from `evict_at` on the endpoint returns `404`. A present key therefore never reads `0`. [`X-CacheKit-Fresh-For`](#remaining-freshness) rounds the other way, down, because it bounds local service and must not overstate it. A **no-expiry** entry ([PUT](#put-v1cachekey)) returns `200 OK` with `{"ttl": null}`: the key exists, so `404` MUST NOT<sup id="api-70">API-70</sup> be returned for it, and `null` — not a negative sentinel — is the representation, because the field is typed as seconds and every SDK already models no expiry as its null / `None` / `Option::None`. SDKs MUST<sup id="api-71">API-71</sup> accept `null` and surface it as their no-expiry value. An SDK TTL read MAY surface that value and an absent key (`404`) identically — both as its null / `None` / `Option::None` — so a caller that needs existence, not a TTL, uses `GET /v1/cache/{key}` or `HEAD`. This is **not** transparent to readers that predate it: an SDK that asserts an integer `ttl`, or coerces a non-integer to `0`, reads an immortal key as missing or as expiring now. Deployments MUST NOT<sup id="api-72">API-72</sup> store no-expiry entries for keys whose `/ttl` readers predate `null` support — the same mixed-reader rule as `stale_ttl` ([Semantics notes](#semantics-notes)).

| Status | Meaning | Response Body |
| :---: | :--- | :--- |
| `200 OK` | TTL returned | `{"ttl": 3542}` (positive integer) |
| `200 OK` | Key exists with no expiry | `{"ttl": null}` |
| `404 Not Found` | Key does not exist or is past `evict_at` | — |

---

### PATCH /v1/cache/{key}/ttl

Update TTL for an existing key.

```http
PATCH /v1/cache/{key}/ttl HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
Content-Type: application/json

{"ttl": 7200}
```

The `ttl` field follows the same validation rules as `X-CacheKit-TTL`: positive integer, minimum 1, maximum 2,592,000. For entries stored with a stale-grace window, see [SWR write semantics](#write-semantics): a PATCH within the fresh window renews it; a PATCH on a stale entry MUST<sup id="api-73">API-73</sup> return `409 Conflict`. A `PATCH` on a no-expiry entry is within the fresh window by definition and bounds it: `fresh_until = floor(now) + ttl` ([whole-second stamping](#entry-lifecycle)), no stale window.

| Status | Meaning |
| :---: | :--- |
| `200 OK` | TTL updated. Also returned for an absent or evicted key — the request is a no-op; this endpoint never returns `404` |
| `400 Bad Request` | Invalid TTL (zero, negative, exceeds maximum), or `ttl` plus the entry's stored stale window exceeds 2,592,000 (the 30-day TTL cap). The client cannot pre-validate the second case: the stale window is server-side state. A `PATCH` with a smaller `ttl` can succeed |
| `409 Conflict` | Entry is past `fresh_until` ([SWR write semantics](#write-semantics)) — refresh requires a `PUT` of recomputed bytes |

---

## Health Endpoint

### GET /v1/cache/health

```http
GET /v1/cache/health HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

**Response (200 OK):**
```json
{"status": "ok", "cache_entries": <n>, "active_locks": <n>}
```

---

## Request Headers

### Required Headers

| Header | Value | Description |
| :--- | :--- | :--- |
| `Authorization` | `Bearer {api_key}` | API key for authentication and tenant scoping |
| `Content-Type` | `application/octet-stream` | Required for PUT requests with binary body |
| `X-CacheKit-L1-Status` | `hit` \| `miss` \| `disabled` | **Required on every `/v1/cache/*` request authenticated with a `ck_sdk_` key**, reads included; missing or any other value → `400 Bad Request` (evaluated after authentication, so a `401` or a key-store-fault `503` takes precedence). Optional for `ck_api_` / `ck_live_` keys. When no L1 statistics are available (e.g., no in-memory layer), send `disabled` rather than omitting the header. |

### Optional Metrics Headers

SDKs SHOULD send cache metrics headers for rate limiting and observability:

| Header | Type | Description |
| :--- | :--- | :--- |
| `X-CacheKit-Session-ID` | string | Process-scoped session identifier (UUID) |
| `X-CacheKit-Session-Start` | string | Session start timestamp (milliseconds since epoch) |
| `X-CacheKit-L1-Hits` | integer | Count of L1 (in-memory) cache hits |
| `X-CacheKit-L2-Hits` | integer | Count of L2 (backend) cache hits |
| `X-CacheKit-Misses` | integer | Count of cache misses |
| `X-CacheKit-L1-Hit-Rate` | float | L1 hit rate (0.000 to 1.000, 3 decimal places) |

`X-CacheKit-L1-Status` — see [Required Headers](#required-headers).

---

## Error Handling

### HTTP Status Codes

| Status | Meaning | SDK Behavior |
| :---: | :--- | :--- |
| `200` | Success | Return data |
| `204` | No Content | CORS preflight (`OPTIONS`) only — writes and deletes return `200` |
| `400` | Bad Request | Client error (invalid cache-key format, missing required headers other than `Authorization`) |
| `401` | Unauthorized | Authoritative denial: the `Authorization` header is missing or malformed, or the key store says the key is unknown or revoked, or its tenant is suspended or soft-deleted. Never emitted for a backend fault while checking the key (that is a `503`) |
| `403` | Forbidden | API key lacks permission for this operation/namespace |
| `404` | Not Found | Cache miss (`GET`/`HEAD /v1/cache/{key}`); key absent on `GET /v1/cache/{key}/ttl`. Never emitted by `DELETE /v1/cache/{key}` or `PATCH /v1/cache/{key}/ttl` — both are no-ops on an absent key. |
| `405` | Method Not Allowed | Method not supported on the route; the response carries `Allow`. Evaluated after authentication. `/v1/cache/{key}`: `GET, HEAD, PUT, DELETE`; `/v1/cache/{key}/ttl`: `GET, PATCH`; `/v1/cache/{key}/lock`: `POST, DELETE`; `/v1/cache/health`: `GET`. Never emitted for `OPTIONS` (answered `204` before authentication) |
| `409` | Conflict | `PATCH /v1/cache/{key}/ttl` on a stale entry past `fresh_until`; refresh requires a `PUT` of recomputed bytes ([SWR write semantics](#write-semantics)) |
| `413` | Payload Too Large | Value exceeds max stored value size (25 MB). Permanent — do not retry; surface "value too large" |
| `429` | Too Many Requests | Rate limited |
| `500` | Internal Server Error | Backend failure |
| `502` | Bad Gateway | Upstream failure |
| `503` | Service Unavailable | Backend overloaded or transiently unavailable, or a backend fault while authenticating the key (`Retry-After` set). On `/v1/cache/{key}` and its sub-resources, a transient storage fault answers `503`, on reads and writes alike; `500` is left for a genuine backend failure. Retry; do not surface as "invalid API key" |

### Error Classification

SDKs should classify errors for circuit breaker integration:

| Class | Status Codes | SDK Action |
| :--- | :--- | :--- |
| **Transient** | `429`, `500`, `502`, `503`, network timeouts | Retry with backoff |
| **Permanent** | `400`, `401`, `403`, `405`, `409`, `413` | Do not retry, surface to caller. For the `PATCH /ttl` `400` where `ttl` plus the stored stale window exceeds the 30-day TTL cap: retry only with a smaller `ttl`. For `409` (`PATCH /ttl` past `fresh_until`): do not re-`PATCH` — recompute and `PUT` ([write semantics](#write-semantics)) |
| **Cache miss** | `404` on `GET`/`HEAD /v1/cache/{key}` | Not an error — return `None`/`null` (`GET`) or `false` (`HEAD`) |
| **Key absent** | `404` on `GET /v1/cache/{key}/ttl` | Not an error — return `None`/`null` for the TTL ([GET /v1/cache/{key}/ttl](#get-v1cachekeyttl)) |

---

## SDK Configuration

### Environment Variables

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `CACHEKIT_API_KEY` | ✅ | — | API key (`ck_live_...`) |
| `CACHEKIT_API_URL` | No | `https://api.cachekit.io` | API endpoint |
| `CACHEKIT_TIMEOUT` | No | `5.0` | Request timeout (seconds) |
| `CACHEKIT_MAX_RETRIES` | No | `3` | Max retry attempts |
| `CACHEKIT_CONNECTION_POOL_SIZE` | No | `10` | HTTP connection pool size |
| `CACHEKIT_ALLOW_CUSTOM_HOST` | No | `false` | Allow non-standard API hostnames |

### SSRF Protection

> [!IMPORTANT]
> All SDKs MUST<sup id="api-74">API-74</sup> enforce SSRF protection when accepting the API URL. The following rules apply:
> - HTTPS required (HTTP must be rejected)
> - Private/internal IPs rejected: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
> - Hostname must be in allowlist (`api.cachekit.io`, `api.staging.cachekit.io`) unless `CACHEKIT_ALLOW_CUSTOM_HOST=true`

---

<div align="center">

[Protocol](../README.md) · [Cache Key Format](cache-key-format.md) · [Wire Format](wire-format.md) · [Encryption](encryption.md) · [Interop Mode](interop-mode.md)

</div>
