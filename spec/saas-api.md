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

Every endpoint below carries the cache key as a path segment — `/v1/cache/{key}`, `/v1/cache/{key}/ttl`, `/v1/cache/{key}/lock`. The key is caller-controlled (each SDK's `key=` escape hatch accepts an arbitrary string), so how it is placed in the path is a security boundary, not a formatting detail: an unencoded key can escape `/v1/cache/` and deliver the bearer token to a different route (CWE-22 — cachekit-py shipped exactly that until [cachekit-py#279](https://github.com/cachekit-io/cachekit-py/pull/279)). MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

### Encoding rules

**1. One segment, percent-encoded.** `{key}` MUST be exactly one path segment. Clients MUST percent-encode the key's UTF-8 bytes (RFC 3986 §2.1) so that only unreserved characters — `ALPHA / DIGIT / "-" / "." / "_" / "~"` — appear raw. Every other byte MUST be sent as `%HH` — the delimiters `/ ? # %`, `:` (a canonical key carries six), space (`%20`, never `+`), every byte ≥ `0x80` — with one tolerance: the sub-delims `! * ' ( )` MAY be left raw (rule 4). Hex digits SHOULD be uppercase (RFC 3986 §2.1); the server decodes either case. Reference encoders: Python `urllib.parse.quote(key, safe="")`, Rust `urlencoding::encode`, JavaScript `encodeURIComponent`.

**2. Reserved segments MUST be rejected client-side.** A key of exactly `.` or `..` survives rule 1 unchanged (`.` is unreserved) and is a *dot segment*: URL parsers remove it before routing — `/v1/cache/..` becomes `/v1/`, `/v1/cache/../ttl` becomes `/v1/ttl` — so the request lands on a different route, still carrying `Authorization`, and never reaches the key validator. Percent-encoding the dots does not help. The server parses the request URL under the WHATWG URL Standard, which treats an ASCII-case-insensitive `%2e` as a single-dot segment and `%2e%2e`, `.%2e`, `%2e.` as double-dot segments (URL Standard §4.1), so `%2E%2E` is collapsed *server-side* even when the client's own parser (RFC 3986 §5.2.4, e.g. `httpx`) sent it intact; WHATWG clients (`fetch`/undici, browsers, the Workers runtime, rust-url and therefore `reqwest`) collapse it before sending. **No wire form of an all-dot key reaches the validator from any client.** The literal segments `health`, `ttl` and `lock` are route tokens at this level — `/v1/cache/health` is the health endpoint, and a final `ttl` or `lock` segment selects the sub-resource — so a key encoding to one of those words is routed elsewhere or read as an empty key.

Therefore clients MUST reject a key whose encoded form is exactly `.`, `..`, `health`, `ttl` or `lock` before building the URL, surfacing a client-side error; servers MUST NOT be relied on to compensate. Only an *entirely*-dot segment is a dot segment: `a:..`, `..a`, `x..y` are inert and MUST be sent per rule 1 with their dots raw. Canonical and interop keys always contain `:` and never meet this rule. Conformance tests MUST assert on the *parsed* request path (`httpx.Request.url.raw_path`, `new URL(u).pathname`, `Url::parse(u)?.path()`), not on the un-parsed template string — a template-string test passes while the traversal ships.

> **Evidence (2026-09-04):** against `api.cachekit.io`, `GET /v1/cache/%2E%2E/health` returns the `/v1/health` response and `/v1/cache/%2E%2E/ttl` is routed as `/v1/ttl`, while `/v1/cache/a%3A..%2Fb/ttl` reaches the cache route. `httpx` 0.28.1 sends `%2E%2E` unchanged; Node 25 `new URL()` and rust-url 2.5.8 collapse it client-side. A fix proven on one parser is not proof for the other, and cachekit-py's `%2E` rewrite ([cachekit-py#279](https://github.com/cachekit-io/cachekit-py/pull/279), v0.18.0) moves the collapse from client to server rather than preventing it (LAB-2880).

**3. The server decodes exactly once.** After the WHATWG parse of rule 2, the server splits the path on raw `/`, then percent-decodes the key segment once (`decodeURIComponent`-equivalent; a malformed escape is `400`) and validates the *decoded* key: non-empty, within an implementation-defined maximum length (the deployed cap exceeds the 250-character SDK key limit in [cache-key-format.md](cache-key-format.md#key-length-limits)), drawn from `[A-Za-z0-9_.:-]`, free of the substring `..`, and — for `ns:` / `nsapi:` keys — of the shape `{prefix}:{namespace}:{rest}` with a non-empty namespace drawn from `[A-Za-z0-9_-]`. Anything else is `400 Bad Request`. Consequences clients MUST honour:

- Clients MUST NOT double-encode. A literal `%` in a key is sent as `%25` once; `%2525` decodes to `%25`, a different key.
- An encoded `%2F` never becomes a segment boundary: the split on raw `/` happens *before* decoding, so `a%2Fb` reaches the validator as `a/b` and is rejected by the charset rule. A conformant client can neither traverse nor store a key containing `/`.

**4. Interop is defined on the decoded key.** `encodeURIComponent` leaves the sub-delims `! * ' ( )` raw (legal `pchar` in a path segment; they decode to themselves); `quote(safe="")` and `urlencoding::encode` emit `%21 %2A %27 %28 %29`. Both forms are conformant because the server-side key is identical after the single decode. Cross-SDK key equality is therefore a property of the **decoded** key, not of the wire bytes in general — but every key the server accepts is drawn from `[A-Za-z0-9_.:-]`, on which all three reference encoders agree (`:` → `%3A`, the rest raw). Every canonical auto-mode key and every [interop-mode](interop-mode.md) key is thus byte-identical on the wire across SDKs; the variance set only ever appears in keys the server rejects.

### Test vectors

[`test-vectors/path-encoding.json`](../test-vectors/path-encoding.json) pins `key → encoded → decoded` in the reference form (`quote(safe="")`). Rows with `reject: true` are the reserved segments of rule 2 and carry no wire form; `encoded_alternates` lists the `encodeURIComponent` form where it differs (rule 4). Verified in this repo's CI by [`tools/path-encoding-verify.py`](../tools/path-encoding-verify.py).

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
| `X-CacheKit-TTL` | No | Time-to-live in seconds. Positive integer, minimum 1, maximum 2,592,000 (30 days). Omit to use server default. |
| `X-CacheKit-Stale-TTL` | No | Stale-grace window in seconds after freshness expiry. Requires an explicit `X-CacheKit-TTL` on the same request. Validation and semantics: [Stale-While-Revalidate](#stale-while-revalidate). Pre-SWR servers ignore this header. |

> [!IMPORTANT]
> **TTL Validation Rules** — These rules are normative for both SDKs and the SaaS backend.
>
> | Condition | SDK Behavior | Server Behavior |
> | :--- | :--- | :--- |
> | TTL omitted | Use client default TTL. If no client default, omit `X-CacheKit-TTL` header. | Apply tenant default TTL. |
> | TTL = 0 | **Reject** — return error to caller. Zero is not a valid TTL. | **Reject** — return `400 Bad Request`. |
> | TTL < 1 second | **Round up to 1.** Sub-second durations MUST be ceiled, never truncated to 0. | N/A (header is integer seconds). |
> | TTL > 2,592,000 | **Reject** — return error to caller. | **Reject** — return `400 Bad Request`. |
> | TTL negative | **Reject** — return error to caller. | **Reject** — return `400 Bad Request`. |
> | TTL non-integer | N/A (SDK converts duration to integer seconds). | **Reject** — return `400 Bad Request`. |
>
> **Rationale:** TTL=0 is ambiguous across cache systems (Redis rejects it, Memcached treats it as "never expire", HTTP treats it as "immediately stale"). CacheKit defines TTL=0 as an error to prevent silent data loss or unbounded storage. Sub-second durations are ceiled to 1 rather than truncated to 0 to avoid the same ambiguity. The 30-day maximum prevents unbounded storage accumulation; longer-lived entries should use explicit renewal patterns via `PATCH /v1/cache/{key}/ttl`.
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

Servers implementing [stale-while-revalidate](#stale-while-revalidate) emit the same `X-CacheKit-Freshness` response header as `GET`.

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
| `now ≥ evict_at` | `404 Not Found`. The server MUST NOT serve an entry past `evict_at`. |

All lifecycle times are computed against the **server's clock**; SDKs MUST NOT derive freshness for backed entries from their own clocks.

Without `X-CacheKit-Stale-TTL` (or with `0`), `evict_at = fresh_until` and server behavior is identical to the pre-SWR protocol.

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

- **`PUT` fully replaces the entry's timing metadata.** Both windows derive from the new request alone; a `PUT` that omits `X-CacheKit-Stale-TTL` (or sends `0`) leaves the entry with **no** stale window, regardless of what the previous entry had. A revalidation `PUT` therefore MUST re-send the stale window it intends to keep.
- **`PATCH /v1/cache/{key}/ttl` within the fresh window** resets `fresh_until = now + ttl` and preserves the entry's stored stale window; the combined total is re-validated against the 30-day cap.
- **`PATCH /v1/cache/{key}/ttl` on an entry past `fresh_until` MUST return `409 Conflict`.** A stale entry regains freshness only via a `PUT` of recomputed bytes — otherwise a routine TTL-renewal job could indefinitely resurrect stale data without revalidation, defeating the `evict_at` bound.

### Reading a stale entry

On a `200` with `X-CacheKit-Freshness: stale`:

- An SDK MUST NOT treat the response as a protocol error.
- By default it SHOULD return the bytes to the caller immediately — a stale response is never a blocking miss.
- An SDK MAY instead treat a stale hit as a **miss** by local policy (e.g. security-sensitive caches where TTL is a revocation boundary) and take the ordinary synchronous miss path. Such caches SHOULD NOT set `X-CacheKit-Stale-TTL` on write in the first place.
- Local caches (L1) MUST NOT record a stale-flagged response as fresh, and local caching MUST NOT extend service of an entry past the server's `evict_at`.
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
- **`GET /v1/cache/{key}/ttl`:** the returned `ttl` is the remaining seconds until **eviction** (`evict_at`).
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

Get remaining TTL for a key. The returned `ttl` is the remaining seconds until **eviction** — for entries with a [stale-grace window](#stale-while-revalidate), that is `evict_at`, not `fresh_until`.

| Status | Meaning | Response Body |
| :---: | :--- | :--- |
| `200 OK` | TTL returned | `{"ttl": 3542}` |
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

The `ttl` field follows the same validation rules as `X-CacheKit-TTL`: positive integer, minimum 1, maximum 2,592,000. For entries stored with a stale-grace window, see [SWR write semantics](#write-semantics): a PATCH within the fresh window renews it; a PATCH on a stale entry MUST return `409 Conflict`.

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
| `400` | Bad Request | Client error (invalid key format, missing headers) |
| `401` | Unauthorized | Invalid or missing API key |
| `403` | Forbidden | API key lacks permission for this operation/namespace |
| `404` | Not Found | Cache miss (GET/HEAD) or key not found (DELETE) |
| `409` | Conflict | `PATCH /v1/cache/{key}/ttl` on a stale entry past `fresh_until`; refresh requires a `PUT` of recomputed bytes ([SWR write semantics](#write-semantics)) |
| `413` | Payload Too Large | Value exceeds max stored value size (25 MB). Permanent — do not retry; surface "value too large" |
| `429` | Too Many Requests | Rate limited |
| `500` | Internal Server Error | Backend failure |
| `502` | Bad Gateway | Upstream failure |
| `503` | Service Unavailable | Backend overloaded |

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
