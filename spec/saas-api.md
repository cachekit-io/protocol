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

---

### PUT /v1/cache/{key}

Store a cache value.

```http
PUT /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
Content-Type: application/octet-stream
X-TTL: 3600

<raw bytes>
```

| Header | Required | Description |
| :--- | :---: | :--- |
| `X-TTL` | No | Time-to-live in seconds. Omit to use server default. |

| Status | Meaning |
| :---: | :--- |
| `200 OK` | Value stored |

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
| `200 OK` | Lock acquired | `{"lock_id": "uuid-string"}` |
| `409 Conflict` | Lock held by another client | — |

---

### DELETE /v1/cache/{key}/lock?lock_id={lock_id}

Release a distributed lock.

```http
DELETE /v1/cache/{key}/lock?lock_id=uuid-string HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

| Status | Meaning |
| :---: | :--- |
| `200 OK` | Lock released |

---

## TTL Endpoints

### GET /v1/cache/{key}/ttl

Get remaining TTL for a key.

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

| Status | Meaning |
| :---: | :--- |
| `200 OK` | TTL updated |

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
| `409` | Conflict | Lock already held |
| `429` | Too Many Requests | Rate limited |
| `500` | Internal Server Error | Backend failure |
| `502` | Bad Gateway | Upstream failure |
| `503` | Service Unavailable | Backend overloaded |

### Error Classification

SDKs should classify errors for circuit breaker integration:

| Class | Status Codes | SDK Action |
| :--- | :--- | :--- |
| **Transient** | `429`, `500`, `502`, `503`, network timeouts | Retry with backoff |
| **Permanent** | `400`, `401`, `403` | Do not retry, surface to caller |
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
