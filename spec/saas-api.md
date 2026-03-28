# SaaS API Specification

**Protocol Version**: 1.0
**Verified Against**: `cachekit-py` v0.5.0 (`src/cachekit/backends/cachekitio/backend.py`, `config.py`, `client.py`)

## Overview

The CacheKit SaaS backend is a Cloudflare Workers deployment that provides managed cache storage. It is **format-agnostic**: it stores and retrieves raw bytes without inspecting, validating, or transforming the payload. This means the same API handles both encrypted and plaintext data identically.

## Base URL

| Environment | URL |
|-------------|-----|
| Production | `https://api.cachekit.io` |
| Staging | `https://api.staging.cachekit.io` |

Configurable via `CACHEKIT_API_URL` environment variable. Custom hosts require `CACHEKIT_ALLOW_CUSTOM_HOST=true`.

## Authentication

All requests require a Bearer token in the `Authorization` header:

```
Authorization: Bearer ck_live_xxxxxxxxxxxxxxxxxxxxxxxxx
```

API keys follow the format `ck_live_...` (production) or `ck_test_...` (staging).

The API key implicitly scopes all operations to a tenant. Multi-tenancy is enforced server-side.

## Content Type

All request and response bodies use raw bytes:

```
Content-Type: application/octet-stream
```

> [!WARNING] Discrepancy with RFC
> The RFC (Section 6.1) describes a JSON-based API with base64-encoded values and `Content-Type: application/json`. The actual implementation uses **raw binary** `application/octet-stream` for cache values. The RFC also uses `POST` for writes; the implementation uses `PUT`. **The implementation is authoritative.**

## Cache Endpoints

All cache endpoints are prefixed with `/v1/cache/`.

### GET /v1/cache/{key}

Retrieve a cached value.

**Request**:
```http
GET /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

**Response (200 OK)**:
```
Content-Type: application/octet-stream

<raw bytes>
```

**Response (404 Not Found)**:
Cache miss. SDK should return `None`/`null`.

### PUT /v1/cache/{key}

Store a cache value.

**Request**:
```http
PUT /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
Content-Type: application/octet-stream
X-TTL: 3600

<raw bytes>
```

**Headers**:

| Header | Required | Description |
|--------|----------|-------------|
| `X-TTL` | No | Time-to-live in seconds. If omitted, uses server default. |

**Response (200 OK)**:
Value stored successfully.

### DELETE /v1/cache/{key}

Delete a cache entry.

**Request**:
```http
DELETE /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

**Response (200 OK)**:
Key deleted.

**Response (404 Not Found)**:
Key did not exist. SDK should return `false` (not an error).

### HEAD /v1/cache/{key}

Check if a key exists without retrieving the value.

**Request**:
```http
HEAD /v1/cache/{key} HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

**Response (200 OK)**:
Key exists.

**Response (404 Not Found)**:
Key does not exist.

## Lock Endpoints

Distributed locking for cache stampede prevention.

### POST /v1/cache/{key}/lock

Acquire a distributed lock.

**Request**:
```http
POST /v1/cache/{key}/lock HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
Content-Type: application/json

{"timeout_ms": 5000}
```

**Response (200 OK)**:
```json
{"lock_id": "uuid-string"}
```

**Response (409 Conflict)**:
Lock already held by another client.

### DELETE /v1/cache/{key}/lock?lock_id={lock_id}

Release a distributed lock.

**Request**:
```http
DELETE /v1/cache/{key}/lock?lock_id=uuid-string HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
```

**Response (200 OK)**:
Lock released.

## TTL Endpoints

### GET /v1/cache/{key}/ttl

Get remaining TTL for a key.

**Response (200 OK)**:
```json
{"ttl": 3542}
```

**Response (404 Not Found)**:
Key does not exist.

### PATCH /v1/cache/{key}/ttl

Update TTL for an existing key.

**Request**:
```http
PATCH /v1/cache/{key}/ttl HTTP/1.1
Host: api.cachekit.io
Authorization: Bearer ck_live_xxx
Content-Type: application/json

{"ttl": 7200}
```

**Response (200 OK)**:
TTL updated.

## Health Endpoint

### GET /v1/cache/health

Backend health check.

**Response (200 OK)**:
```json
{"version": "1.0.0"}
```

## Request Headers

### Required Headers

| Header | Value | Description |
|--------|-------|-------------|
| `Authorization` | `Bearer {api_key}` | API key for authentication and tenant scoping |
| `Content-Type` | `application/octet-stream` | For PUT requests with binary body |

### Optional Metrics Headers

SDKs SHOULD send cache metrics headers for rate limiting and observability:

| Header | Type | Description |
|--------|------|-------------|
| `X-CacheKit-Session-ID` | string | Process-scoped session identifier (UUID) |
| `X-CacheKit-Session-Start` | string | Session start timestamp (milliseconds since epoch) |
| `X-CacheKit-L1-Hits` | integer | Count of L1 (in-memory) cache hits |
| `X-CacheKit-L2-Hits` | integer | Count of L2 (backend) cache hits |
| `X-CacheKit-Misses` | integer | Count of cache misses |
| `X-CacheKit-L1-Hit-Rate` | float | L1 hit rate (0.000 to 1.000, 3 decimal places) |
| `X-CacheKit-L1-Status` | string | Rate limit classification: `"hit"`, `"miss"`, or `"disabled"` |

When no L1 statistics are available (e.g., standalone SDK usage), send:
```
X-CacheKit-L1-Status: disabled
```

## Error Handling

### HTTP Status Codes

| Status | Meaning | SDK Behavior |
|--------|---------|--------------|
| 200 | Success | Return data |
| 201 | Created | Value stored |
| 204 | No Content | Deleted successfully |
| 400 | Bad Request | Client error (invalid key format, missing headers) |
| 401 | Unauthorized | Invalid or missing API key |
| 403 | Forbidden | API key lacks permission for this operation/namespace |
| 404 | Not Found | Cache miss (GET/HEAD) or key not found (DELETE) |
| 409 | Conflict | Lock already held |
| 429 | Too Many Requests | Rate limited |
| 500 | Internal Server Error | Backend failure |
| 502 | Bad Gateway | Upstream failure |
| 503 | Service Unavailable | Backend overloaded |

### Error Classification

SDKs should classify errors for circuit breaker integration:

- **Transient** (retry): 429, 500, 502, 503, network timeouts
- **Permanent** (do not retry): 400, 401, 403
- **Cache miss** (not an error): 404 on GET/HEAD/DELETE

## SDK Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CACHEKIT_API_KEY` | Yes | -- | API key (`ck_live_...`) |
| `CACHEKIT_API_URL` | No | `https://api.cachekit.io` | API endpoint |
| `CACHEKIT_TIMEOUT` | No | `5.0` | Request timeout (seconds) |
| `CACHEKIT_MAX_RETRIES` | No | `3` | Max retry attempts |
| `CACHEKIT_CONNECTION_POOL_SIZE` | No | `10` | HTTP connection pool size |
| `CACHEKIT_ALLOW_CUSTOM_HOST` | No | `false` | Allow non-standard API hostnames |

### SSRF Protection

The SDK validates the API URL:
- HTTPS required (HTTP rejected)
- Private/internal IPs rejected (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
- Hostname must be in allowlist (`api.cachekit.io`, `api.staging.cachekit.io`) unless `CACHEKIT_ALLOW_CUSTOM_HOST=true`
