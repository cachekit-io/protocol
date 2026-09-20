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
- [Cache Endpoints](#cache-endpoints)
- [Stale-While-Revalidate](#stale-while-revalidate)
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

API keys follow the format `ck_live_...` (production) or `ck_test_...` (staging). The API key implicitly scopes all operations to a tenant. Multi-tenancy is enforced server-side.

**HTTP intermediary caching is prohibited.** Servers MUST emit `Cache-Control: no-store` and `Vary: Authorization` on every response. The [cache key](cache-key-format.md) carries no tenant component — tenancy rides only in the `Authorization` header — so two tenants using the same namespace, function, and arguments produce byte-identical request paths, and a shared HTTP cache applying heuristic freshness (RFC 9111 §4.2.2) to an unmarked response could serve one tenant's bytes to another. `no-store` forbids storing the response at all; `Vary: Authorization` is the independent second control — a cache that wrongly stores despite `no-store` (or RFC 9111 §3.5's rule for authenticated requests) but honors `Vary` still cannot match tenant A's copy to tenant B's request. Any CacheKit-operated serving tier that caches responses (edge, colo) MUST partition its internal cache by tenant, never by URL alone; such tiers are part of the server, not HTTP intermediaries, and these headers govern what they emit, not what they may store.

---

## Content Type

All request and response bodies use raw bytes:

```
Content-Type: application/octet-stream
```

> [!WARNING]
> **Discrepancy with RFC** — The RFC (Section 6.1) describes a JSON-based API with base64-encoded values and `Content-Type: application/json`. The actual implementation uses **raw binary** `application/octet-stream` for cache values. The RFC also uses `POST` for writes; the implementation uses `PUT`. **The implementation is authoritative.**

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

| Status | Meaning | SDK Behavior |
| :---: | :--- | :--- |
| `200 OK` | Cache hit | Return raw bytes to caller |
| `404 Not Found` | Cache miss | Return `None`/`null` |

**Response headers:**

| Header | Description |
| :--- | :--- |
| `X-CacheKit-Freshness` | `fresh` or `stale` — lowercase, case-sensitive tokens. Emitted on every `200 OK` by servers implementing [stale-while-revalidate](#stale-while-revalidate). SDKs MUST treat an absent header as `fresh` (pre-SWR servers do not emit it) and an unrecognized value as `stale` (revalidation is the conservative action). Read behavior is specified in [Stale-While-Revalidate](#stale-while-revalidate). |
| `X-CacheKit-Fresh-For` | Remaining freshness in whole seconds. Semantics: [Remaining Freshness](#remaining-freshness). |

#### Remaining Freshness

> Status: **specified** (LAB-557). Origin: without a remaining-freshness signal, an SDK that backfills a local cache (L1) from a read assigns its full configured TTL from time-of-read — an entry read near the end of its server-side freshness window is then served locally as fresh for up to another full TTL, past the server's `fresh_until` (and, with a [stale-grace window](#stale-while-revalidate), potentially past `evict_at`).

`X-CacheKit-Fresh-For` tells the reader how long the served value remains fresh, so local caches can bound their own service window to the server's.

**Server (emission):**

- A **signal-capable server** is one that implements this section. It is independent of [stale-while-revalidate](#stale-while-revalidate) support: a bounded entry has a `fresh_until` whether or not it has a stale window, so a server may emit `X-CacheKit-Fresh-For` without offering one, and a pre-signal SWR server emits `X-CacheKit-Freshness` without it.
- Emitted on **every** `GET` `200 OK` for an entry that has a freshness bound. An entry stored without `X-CacheKit-TTL` has **no expiry** ([PUT](#put-v1cachekey)): no `fresh_until`, no remainder to report, so the header is **omitted** — the server-side bound is unbounded, `min(local_ttl, ∞)` is the SDK's configured local TTL, and that is exactly the absent-header path below. When present, the value is a non-negative integer: `max(0, floor(fresh_until − now))`, computed against the **server's clock** at response time — the client never compares server timestamps against its own clock.
- Stale-window responses (`X-CacheKit-Freshness: stale`) carry `X-CacheKit-Fresh-For: 0` — freshness is already exhausted. `X-CacheKit-Freshness: fresh` with `X-CacheKit-Fresh-For: 0` is also legal — an entry in its final sub-second of freshness floors to `0`. The response is served to the caller normally; the `0` governs only local caching (no backfill).
- Omitted by the store for no-expiry entries, and by pre-signal servers for everything. The client cannot tell the two apart, by design: both mean "no server-side freshness bound applies to this read" and both lead to the same SDK action (configured local TTL, fresh service only). Because absence carries that meaning, a tier that implements this section MUST NOT produce it for a copy it cannot positively confirm has no expiry — the tier rule below.
- **Re-serving tiers** — an edge or colo cache in front of the store that answers from a copy it read earlier — are part of the server. A tier's **coherence window** is the deployment-documented maximum time it may keep serving a copy after the store has changed or deleted the entry; a tier that refreshes its copy's lifetime from the tier below rather than from the store adds its window to the path's total, so windows **compound** along the serving path and a deployment's effective window is their sum, not its largest single tier. That governs the *bytes*. The *header* follows stricter, fail-closed rules:
  - **Decay, never re-stamp.** A tier MUST emit the remaining freshness it received (or, for a copy it populated from a write, that write's own freshness bound) minus the seconds elapsed since, flooring at `0`. It MUST NOT emit a value larger than that decayed remainder — its own copy TTL included — under any label. The deployed tiers decay, so the rule costs a conforming implementation nothing, and it keeps a pre-`DELETE` copy's local service inside the entry's `fresh_until`.
  - **Omit only on positive knowledge of no expiry; otherwise `0`.** A tier MAY omit the header only for a copy it positively knows has no expiry: a signal-capable store below omitted it (such a store omits only for no-expiry entries), or the tier populated the copy from a write that carried no `X-CacheKit-TTL`. For every other copy whose remainder it does not know — populated without a hint, a header lost in transit, or a store below that is pre-signal and therefore omits for bounded entries too — the tier MUST emit `X-CacheKit-Fresh-For: 0`. It MUST NOT omit a header it received, nor drop it for such a copy: omission would claim "no bound" for an entry that may have one and silently restore the unbounded backfill this header exists to kill. A tier MUST therefore record at populate whether a copy is unbounded or merely unhinted; a tier that cannot tell the two apart MUST emit `0`. A tier fronting a pre-signal store is in exactly that position — it emits `0`, it does not pass the absence through; the cost is no local backfill behind that tier until the store signals, the fail-closed posture a mixed deployment should have. Whether the store below signals is a deployment fact the tier is configured with, never inferred per response.
  - **Positive only for `fresh` + positive.** A tier MAY emit a positive value only on a response the tier below labelled exactly `X-CacheKit-Freshness: fresh` (or left unlabelled — the pre-SWR `fresh` default) and stamped with a strictly positive `X-CacheKit-Fresh-For`, and then only the decayed remainder. Every other shape — `stale`, `X-CacheKit-Fresh-For: 0` under any label, an unrecognized freshness token, or a missing `X-CacheKit-Fresh-For` on any entry not positively known to be no-expiry — MUST be emitted with `X-CacheKit-Fresh-For: 0` and its freshness label passed through unchanged (a `fresh` `0` stays `fresh`; a `stale` stays `stale`). Stamping a positive bound onto a stale, exhausted, or unknown value resurrects an expired (or revoked) entry as locally-cacheable fresh — the exact hole this header closes.
- `HEAD` does **not** carry this header — an existence check returns no payload, so there is nothing to backfill locally (the `X-CacheKit-Freshness` label on `HEAD` remains informational, per [Stale-While-Revalidate](#stale-while-revalidate)). Correspondingly, a `HEAD` response MUST NOT create, refresh, or extend any local entry's service bound.

**SDK (consumption):**

- On a `GET` `200 OK` labelled `X-CacheKit-Freshness: fresh` (or unlabelled) with the header present, a local cache (L1) backfill MUST bound the entry's local lifetime to at most the header value: `min(local_ttl, fresh_for)`. A value of `0` means the entry MUST NOT be backfilled at all. A `stale` or unrecognized freshness label forbids backfill regardless of the number ([Reading a stale entry](#reading-a-stale-entry)) — a positive `X-CacheKit-Fresh-For` on a `stale` response is a server bug, not a license.
- The header value is a hard local **service** bound, not merely a freshness bound: once it elapses, the local copy MUST NOT be served in any form — including by client-side stale-while-revalidate or any local stale-grace policy. (Serving server-returned stale bytes per [Reading a stale entry](#reading-a-stale-entry) is unaffected — this rule governs only the local copy.) **Why there is no local stale service, stated once:** the client receives no remaining-eviction signal, so a locally-stale copy could not honor the store's [`evict_at` bound](#reading-a-stale-entry) — and one is deliberately not provided, because it would let clients replicate the stale window locally, invisibly to server-side revalidation single-flight and metering. Stale service is the server's job: a subsequent read hits the server, which serves the stale window itself (`X-CacheKit-Freshness: stale`, `X-CacheKit-Fresh-For: 0`) until `evict_at`. Rules elsewhere refer back here rather than restating this.
- Absent header on a `GET` `200 OK` = no server-side freshness bound for this read — a no-expiry entry, or a pre-signal server. Legacy behavior: the SDK's configured local TTL applies unchanged. This makes the header purely additive — old SDKs ignore it, and new SDKs against old servers behave exactly as before. Absence licenses only *fresh* service for that configured lifetime, never local stale service (above).
- The value MUST be 1–7 ASCII digits and at most `2,592,000` (the [30-day TTL cap](#put-v1cachekey), itself seven digits). Anything else — empty, non-digit, signed, longer than seven digits, or over the cap — MUST be treated as `0` (do not extend local service — the conservative action, mirroring the unrecognized-`X-CacheKit-Freshness` → `stale` rule); a larger value is protocol-impossible, a buggy or misconfigured tier rather than a real bound. The length check MUST run first, so the range check never depends on a fixed-width integer conversion that could wrap an over-cap value back into range (a wrapping `atoi`/`strtoul` turns `4297559296` into `2,592,000`).
- Network transit slightly overstates remaining freshness at the client (the value was computed at response time). This is accepted: the error is bounded by transit latency, the same class HTTP `Age` handling tolerates, and is negligible against whole-second granularity.
- The local deadline SHOULD be measured against a clock that keeps counting across system suspend (wall-clock anchored, or a `CLOCK_BOOTTIME`-class monotonic source): a suspend-blind monotonic clock stops while the host sleeps and serves past the bound after resume. This is implementation guidance, not wire contract — the same clock discipline applies to all local TTL accounting.
- An issued `fresh_for` is a snapshot, not a lease the server can recall: a later `DELETE`, or a fresh-window `PATCH /ttl` that shortens the entry, does not reach copies already backfilled — remote local caches compliantly serve until their bounded lifetime expires, and a re-serving tier may compliantly hand out a copy it cached before the `DELETE` for the rest of its coherence window ([emission](#remaining-freshness) above). `evict_at` is therefore the **store's** service bound, not an end-to-end one. Revocation propagation is bounded by the **sum** of the serving path's compounded coherence windows, the largest locally applied service bound, in-flight response transit, and clock or suspend error — a `GET` response already in flight when the `DELETE` lands is likewise still backfilled on arrival. For a bounded entry the local term is the decayed header, so it ends no later than the served entry's `fresh_until`. For a **no-expiry** entry — or any read served without the header — there is no `fresh_until`: the local term is the reader's full configured local TTL, re-anchored on every read, so a revoked no-expiry value outlives its `DELETE` by the largest local TTL in the fleet with no server-side ceiling, and a `PATCH /ttl` or `DELETE` that later bounds or removes a formerly-no-expiry entry cannot reach copies already distributed without the header. Security-sensitive caches MUST size TTL (and local TTL) to their revocation tolerance, or version their keys (see the invalidation-race note in [Semantics notes](#semantics-notes)); keys whose TTL is a revocation boundary MUST be stored with an explicit `X-CacheKit-TTL` — a no-expiry entry has no revocation tolerance to size to.

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

| Header | Required | Description |
| :--- | :---: | :--- |
| `X-CacheKit-TTL` | No | Time-to-live in seconds. Positive integer, minimum 1, maximum 2,592,000 (30 days). Omit for **no expiry** — the entry has no `fresh_until` and no `evict_at`, is served `fresh` until deleted or overwritten, and carries no `X-CacheKit-Fresh-For`; servers MUST NOT substitute a hidden default. |
| `X-CacheKit-Stale-TTL` | No | Stale-grace window in seconds after freshness expiry. Requires an explicit `X-CacheKit-TTL` on the same request. Validation and semantics: [Stale-While-Revalidate](#stale-while-revalidate). Pre-SWR servers ignore this header. |

> [!IMPORTANT]
> **TTL Validation Rules** — These rules are normative for both SDKs and the SaaS backend.
>
> | Condition | SDK Behavior | Server Behavior |
> | :--- | :--- | :--- |
> | TTL omitted | Use client default TTL. If no client default, omit `X-CacheKit-TTL` header. | Store with **no expiry**. Servers MUST NOT apply a hidden tenant default — validation must not depend on defaults clients cannot see (the same rule as `X-CacheKit-Stale-TTL`). |
> | TTL = 0 | **Reject** — return error to caller. Zero is not a valid TTL. | **Reject** — return `400 Bad Request`. |
> | TTL < 1 second | **Round up to 1.** Sub-second durations MUST be ceiled, never truncated to 0. | N/A (header is integer seconds). |
> | TTL > 2,592,000 | **Reject** — return error to caller. | **Reject** — return `400 Bad Request`. |
> | TTL negative | **Reject** — return error to caller. | **Reject** — return `400 Bad Request`. |
> | TTL non-integer | N/A (SDK converts duration to integer seconds). | **Reject** — return `400 Bad Request`. |
>
> **Rationale:** TTL=0 is ambiguous across cache systems (Redis rejects it, Memcached treats it as "never expire", HTTP treats it as "immediately stale"). CacheKit defines TTL=0 as an error to prevent silent data loss (the Redis and HTTP readings) or an unintended no-expiry entry (the Memcached reading) — no expiry is requested by omitting the header, never by `0`. Sub-second durations are ceiled to 1 rather than truncated to 0 to avoid the same ambiguity. The 30-day maximum bounds the *value range* of a stated TTL (and with it the [`X-CacheKit-Fresh-For`](#remaining-freshness) grammar); it is not a storage-lifetime ceiling — omitting the header stores a no-expiry entry, and nothing in this spec bounds how long or how many such entries accumulate (storage hygiene is the operator's control, tracked as LAB-279). Entries that need a long but bounded life should renew explicitly via `PATCH /v1/cache/{key}/ttl`.
>
> **Migration:** The `X-TTL` header is deprecated. The server MUST accept both `X-CacheKit-TTL` and `X-TTL` during the transition period, preferring `X-CacheKit-TTL` when both are present. SDKs MUST send `X-CacheKit-TTL` only. The `X-TTL` header will be removed in protocol version 2.0 (targeted at SDK 1.0 milestone).

> [!IMPORTANT]
> **Maximum value size:** A single cache value may be at most **25 MB**. Larger values are rejected with `413 Payload Too Large` — a **permanent** error: SDKs MUST NOT retry and SHOULD surface "value too large" to the caller. This ceiling MAY change, so SDKs MUST treat any `413` as "value too large" regardless of the exact byte count. It is unrelated to the SDK serializer's 512 MiB in-memory safety bound (see `wire-format.md`) — that bound governs what the SDK will serialize, not what the service will store.

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
| `200 OK` | Key deleted | Return `true` |
| `404 Not Found` | Key did not exist | Return `false` (not an error) |

---

### HEAD /v1/cache/{key}

Check if a key exists without retrieving the value.

```http
HEAD /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

| Status | Meaning |
| :---: | :--- |
| `200 OK` | Key exists |
| `404 Not Found` | Key does not exist |

Servers implementing [stale-while-revalidate](#stale-while-revalidate) emit the same `X-CacheKit-Freshness` response header as `GET`. `X-CacheKit-Fresh-For` is **not** emitted on `HEAD` ([Remaining Freshness](#remaining-freshness) — no payload, nothing to backfill).

---

## Stale-While-Revalidate

> Status: **specified** (LAB-381). Server implementation: cachekit-io/saas (pending). SDK adoption tracked in the [feature matrix](../sdk-feature-matrix.md#reliability-features).

Stale-while-revalidate (SWR, [RFC 5861](https://www.rfc-editor.org/rfc/rfc5861) semantics) lets a client serve an expired-but-present value immediately and recompute it in the background, so no request pays the recompute cost at a TTL boundary. Because the recompute is the client's wrapped function, **the client owns revalidation**; the server's role is read-time staleness signaling and single-flight coordination.

### Entry lifecycle

An entry stored with `X-CacheKit-TTL: ttl` and `X-CacheKit-Stale-TTL: stale_ttl` has two windows:

```
stored_at ──────────── fresh_until ──────────────── evict_at
          FRESH                       STALE
          (200, fresh)                (200, stale)   404

fresh_until = stored_at + ttl
evict_at    = fresh_until + stale_ttl
```

| Window | `GET` / `HEAD` behavior |
| :--- | :--- |
| `now < fresh_until` | `200 OK`, `X-CacheKit-Freshness: fresh` |
| `fresh_until ≤ now < evict_at` | `200 OK` **with the stored bytes**, `X-CacheKit-Freshness: stale` |
| `now ≥ evict_at` | `404 Not Found`. The store MUST NOT serve an entry past `evict_at`. This is the **store's** bound: copies already handed to re-serving tiers or backfilled into local caches run to their own bounded lifetimes — the end-to-end revocation bound is in [Remaining Freshness](#remaining-freshness). |

All lifecycle times are computed against the **server's clock**; SDKs MUST NOT derive freshness for backed entries from their own clocks.

Without `X-CacheKit-Stale-TTL` (or with `0`), `evict_at = fresh_until` and server behavior is identical to the pre-SWR protocol.

Without `X-CacheKit-TTL`, the entry has **no expiry**: no `fresh_until`, no `evict_at`. It is served `200 OK` `fresh` until deleted or overwritten, never enters the stale window, and carries no `X-CacheKit-Fresh-For` ([Remaining Freshness](#remaining-freshness)). `X-CacheKit-Stale-TTL` without `X-CacheKit-TTL` is rejected ([validation](#validation)) — an entry that never expires has nothing to be stale relative to. Never expiring has two consequences a writer must weigh: the entry's revocation bound has no server-side ceiling, so read the revocation bound in [Remaining Freshness](#remaining-freshness) before storing a revocation-sensitive key without a TTL; and a copy a mispartitioned tier stores under the wrong tenant never self-heals, so the [tenant-partitioning rule](#authentication) is the only control for it.

### Validation

These rules are normative for both SDKs and the SaaS backend, mirroring the [TTL validation rules](#put-v1cachekey):

| Condition | Behavior |
| :--- | :--- |
| `stale_ttl` negative, non-integer, or > 2,591,999 | `400 Bad Request`. The standalone bound is checked **before** any arithmetic (no integer wrap on `evict_at`). |
| `X-CacheKit-Stale-TTL` present without an explicit `X-CacheKit-TTL` | `400 Bad Request`. Validation must not depend on hidden tenant defaults — clients must be able to pre-validate. |
| `ttl + stale_ttl > 2,592,000` | `400 Bad Request` (the stale window shares the 30-day storage cap) |
| `stale_ttl = 0` | Accepted; equivalent to omitting the header |
| `stale_ttl < 1` second (sub-second duration in SDK API) | SDKs MUST ceil to 1, never truncate to 0 (same rule as TTL) |

### Write semantics

- **`PUT` fully replaces the entry's timing metadata.** Both windows derive from the new request alone; a `PUT` that omits `X-CacheKit-Stale-TTL` (or sends `0`) leaves the entry with **no** stale window, regardless of what the previous entry had. A revalidation `PUT` therefore MUST re-send both the `X-CacheKit-TTL` and the stale window it intends to keep — omitting `X-CacheKit-TTL` on a recompute does not carry the previous bound forward, it stores a **no-expiry** entry ([PUT](#put-v1cachekey)).
- **`PATCH /v1/cache/{key}/ttl` within the fresh window** resets `fresh_until = now + ttl` and preserves the entry's stored stale window; the combined total is re-validated against the 30-day cap.
- **`PATCH /v1/cache/{key}/ttl` on an entry past `fresh_until` MUST return `409 Conflict`.** A stale entry regains freshness only via a `PUT` of recomputed bytes — otherwise a routine TTL-renewal job could indefinitely resurrect stale data without revalidation, defeating the `evict_at` bound.

### Reading a stale entry

On a `200` with `X-CacheKit-Freshness: stale`:

- An SDK MUST NOT treat the response as a protocol error.
- By default it SHOULD return the bytes to the caller immediately — a stale response is never a blocking miss.
- An SDK MAY instead treat a stale hit as a **miss** by local policy (e.g. security-sensitive caches where TTL is a revocation boundary) and take the ordinary synchronous miss path. Such caches SHOULD NOT set `X-CacheKit-Stale-TTL` on write in the first place.
- Local caches (L1) MUST NOT backfill a stale-flagged response at all — not as fresh, not as locally-stale — regardless of any `X-CacheKit-Fresh-For` value (signal-capable servers mark these `0`; the rule holds with or without the header, and the rationale is stated once under [Remaining Freshness](#remaining-freshness)). On a response carrying [`X-CacheKit-Fresh-For`](#remaining-freshness), local caching MUST NOT extend service of an entry past the store's `evict_at` — for *fresh*-labelled reads near the freshness boundary, the header is the mechanism that lets local caches honor this bound (LAB-557). A response without it comes from a pre-signal server and follows the legacy absence rule in that section: the configured local TTL applies unchanged and may outlive `evict_at` — the origin gap the header exists to close.
- Revalidation is triggered only by `GET`. `HEAD` freshness is informational; an existence check MUST NOT fire a background recompute.

### Revalidation flow (SDK)

An SDK that serves a stale hit and owns revalidation (the recompute is the wrapped function — the server cannot do it):

1. MUST return the stale bytes (or take its local miss policy, above) without blocking on revalidation.
2. SHOULD single-flight the recompute by attempting `POST /v1/cache/{key}/lock` (the existing [lock endpoint](#post-v1cachekeylock)) as a **non-blocking** lease. The lease is acquired **only** on `200 OK` with a non-empty `lock_id`. Contention is signalled **only** by a `200 OK` with a `null`/absent `lock_id` — or, defensively, a legacy `409 Conflict` — and means another client is revalidating: serve stale; the SDK MUST NOT wait or retry. Any other non-`200` (`401`, `403`, `429`, `5xx`, …) is **not** contention — it is an ordinary error subject to [Error Classification](#error-classification): abandon this revalidation attempt without a lease (the caller already has the stale bytes from step 1) and let a subsequent stale read re-trigger revalidation.

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

- **Metering:** a stale-window `GET` is a cache **hit** (`200`) for metered-misses billing; the revalidation `PUT` is an ordinary write. In the [SDK metrics headers](#optional-metrics-headers), a stale serve increments `X-CacheKit-L2-Hits`; a background revalidation MUST NOT increment `X-CacheKit-Misses`.
- **Invalidation race:** an explicit `DELETE /v1/cache/{key}` concurrent with an in-flight revalidation may be overwritten by the revalidation `PUT` (last-write-wins) — the same race as today's concurrent miss-path recompute. Callers that need durable invalidation must version their keys.
- **Zero-knowledge:** no change to the wire format, ByteStorage envelope, encryption, or AAD; the value bytes remain opaque.
- **`GET /v1/cache/{key}/ttl`:** the returned `ttl` is the remaining seconds until **eviction** (`evict_at`), or `null` for a no-expiry entry (mixed-reader caveat under [GET /v1/cache/{key}/ttl](#get-v1cachekeyttl)).
- **Compatibility:** additive for servers — a pre-SWR server ignores `X-CacheKit-Stale-TTL` (the entry evicts at `fresh_until`, no freshness header is emitted) and SDK behavior is exactly pre-SWR. It is **not** transparent to mixed readers: enabling `stale_ttl` on a key affects every reader of that key, and a pre-SWR SDK will consume stale-window values as fresh (`200`, no header) where it previously saw a miss. Deployments MUST NOT enable `stale_ttl` on keys whose readers rely on hard TTL expiry (pre-SWR SDKs or security-sensitive consumers).

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
another client holds it. Clients MUST branch on `lock_id` presence and MUST NOT
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

> **Security (CWE-532):** the lock id is a short-lived capability token — anyone holding it can release the lock within its TTL. It MUST travel in the `X-CacheKit-Lock-Id` header, **not** the query string: query strings are routinely captured by access logs, proxy/CDN logs, and OpenTelemetry `http.url` spans, which would let anyone with log access replay the token.
>
> **Migration:** the legacy `?lock_id={lock_id}` query parameter is deprecated. The server MUST accept both the `X-CacheKit-Lock-Id` header and the `?lock_id=` query param during the transition period, preferring the header when both are present. SDKs MUST send the header only. The query parameter will be removed in protocol version 2.0 (targeted at the SDK 1.0 milestone).

---

## TTL Endpoints

### GET /v1/cache/{key}/ttl

Get remaining TTL for a key. The returned `ttl` is the remaining seconds until **eviction** — for entries with a [stale-grace window](#stale-while-revalidate), that is `evict_at`, not `fresh_until`. A **no-expiry** entry ([PUT](#put-v1cachekey)) returns `200 OK` with `{"ttl": null}`: the key exists, so `404` MUST NOT be returned for it, and `null` — not a negative sentinel — is the representation, because the field is typed as seconds and every SDK already models no expiry as its null / `None` / `Option::None`. SDKs MUST accept `null` and surface it as their no-expiry value. This is **not** transparent to readers that predate it: an SDK that asserts an integer `ttl`, or coerces a non-integer to `0`, reads an immortal key as missing or as expiring now. Deployments MUST NOT store no-expiry entries for keys whose `/ttl` readers predate `null` support — the same mixed-reader rule as `stale_ttl` ([Semantics notes](#semantics-notes)).

| Status | Meaning | Response Body |
| :---: | :--- | :--- |
| `200 OK` | TTL returned | `{"ttl": 3542}` |
| `200 OK` | Key exists with no expiry | `{"ttl": null}` |
| `404 Not Found` | Key does not exist | — |

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

The `ttl` field follows the same validation rules as `X-CacheKit-TTL`: positive integer, minimum 1, maximum 2,592,000. For entries stored with a stale-grace window, see [SWR write semantics](#write-semantics): a PATCH within the fresh window renews it; a PATCH on a stale entry MUST return `409 Conflict`. A `PATCH` on a no-expiry entry is within the fresh window by definition and bounds it: `fresh_until = now + ttl`, no stale window.

| Status | Meaning |
| :---: | :--- |
| `200 OK` | TTL updated |
| `400 Bad Request` | Invalid TTL (zero, negative, exceeds maximum) |
| `409 Conflict` | Entry is past `fresh_until` ([SWR write semantics](#write-semantics)) — refresh requires a `PUT` of recomputed bytes |

---

## Health Endpoint

### GET /v1/cache/health

```http
GET /v1/cache/health HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

**Response (200 OK)**:
```json
{"version": "1.0.0"}
```

---

## Request Headers

### Required Headers

| Header | Value | Description |
| :--- | :--- | :--- |
| `Authorization` | `Bearer {api_key}` | API key for authentication and tenant scoping |
| `Content-Type` | `application/octet-stream` | Required for PUT requests with binary body |

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
| `X-CacheKit-L1-Status` | string | `"hit"`, `"miss"`, or `"disabled"` |

> [!TIP]
> When no L1 statistics are available (e.g., standalone SDK without in-memory layer), send `X-CacheKit-L1-Status: disabled` rather than omitting the header.

---

## Error Handling

### HTTP Status Codes

| Status | Meaning | SDK Behavior |
| :---: | :--- | :--- |
| `200` | Success | Return data |
| `201` | Created | Value stored |
| `204` | No Content | Deleted successfully |
| `400` | Bad Request | Client error (invalid cache-key format, missing required headers other than `Authorization`) |
| `401` | Unauthorized | Authoritative denial: the `Authorization` header is missing or malformed, or the key store says the key is unknown or revoked, or its tenant is suspended or soft-deleted. Never emitted for a backend fault while checking the key (that is a `503`) |
| `403` | Forbidden | API key lacks permission for this operation/namespace |
| `404` | Not Found | Cache miss (GET/HEAD) or key not found (DELETE) |
| `409` | Conflict | `PATCH /v1/cache/{key}/ttl` on a stale entry past `fresh_until`; refresh requires a `PUT` of recomputed bytes ([SWR write semantics](#write-semantics)) |
| `413` | Payload Too Large | Value exceeds max stored value size (25 MB). Permanent — do not retry; surface "value too large" |
| `429` | Too Many Requests | Rate limited |
| `500` | Internal Server Error | Backend failure |
| `502` | Bad Gateway | Upstream failure |
| `503` | Service Unavailable | Backend overloaded, or a backend fault while authenticating the key (`Retry-After` set). Retry; do not surface as "invalid API key" |

### Error Classification

SDKs should classify errors for circuit breaker integration:

| Class | Status Codes | SDK Action |
| :--- | :--- | :--- |
| **Transient** | `429`, `500`, `502`, `503`, network timeouts | Retry with backoff |
| **Permanent** | `400`, `401`, `403`, `409`, `413` | Do not retry, surface to caller. For `409` (`PATCH /ttl` past `fresh_until`): do not re-`PATCH` — recompute and `PUT` ([write semantics](#write-semantics)) |
| **Cache miss** | `404` on GET/HEAD/DELETE | Not an error — return `None`/`false` |

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
> All SDKs MUST enforce SSRF protection when accepting the API URL. The following rules apply:
> - HTTPS required (HTTP must be rejected)
> - Private/internal IPs rejected: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
> - Hostname must be in allowlist (`api.cachekit.io`, `api.staging.cachekit.io`) unless `CACHEKIT_ALLOW_CUSTOM_HOST=true`

---

<div align="center">

[Protocol](../README.md) · [Cache Key Format](cache-key-format.md) · [Wire Format](wire-format.md) · [Encryption](encryption.md) · [Interop Mode](interop-mode.md)

</div>
