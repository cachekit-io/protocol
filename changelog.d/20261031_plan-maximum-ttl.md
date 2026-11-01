### SaaS API — per-plan maximum TTL, clamped; a 90-day TTL range; the applied bound on the `PUT` response

- [`spec/saas-api.md` § Plan maximum TTL](spec/saas-api.md#plan-maximum-ttl) (new): Free 86,400 s
  (24 hours), Startup 2,592,000 s (30 days), Professional 7,776,000 s (90 days), Enterprise none.
  On a plan with a maximum, a stated TTL above it is stored with the maximum, not rejected, and a
  write without a TTL is stored with the maximum instead of with no expiry
  ([API-97](spec/saas-api.md#api-97)). The maximum bounds `evict_at` from each write's stamp: the
  fresh window is kept first and the stale window gets what is left. `PATCH /ttl` is clamped the
  same way ([API-98](spec/saas-api.md#api-98)), and its response must not extend a local copy
  ([API-104](spec/saas-api.md#api-104)). Validation stays plan-independent, so a client can still
  pre-validate every write. A server that cannot determine the tenant's plan stores the write as
  stated, and so does a deployment that does not yet meet the conditions API-101 sets for
  clamping, so the plan maximum is not a guaranteed ceiling on an entry's lifetime. Entries stored
  before the change keep their timing until their next write or `PATCH`.
- The TTL range of `X-CacheKit-TTL`, of `PATCH /ttl`'s `ttl` and of `ttl + stale_ttl` rises from
  2,592,000 to 7,776,000 (`stale_ttl` alone to 7,775,999). A larger value is still a `400`.
- The plan maximum is the only default for a write without a TTL
  ([API-99](spec/saas-api.md#api-99), which merges and retires API-40 and API-41).
- A store that clamps sends `X-CacheKit-Fresh-For` on every `PUT` `2xx` for a bounded entry: the
  stored entry's remaining freshness ([API-100](spec/saas-api.md#api-100)). No write or `PATCH` is
  clamped until the store sends it, every server-side hop that relays the `PUT` `2xx` passes it
  through, and every tier that keeps a copy of a forwarded write bounds that copy by it
  ([API-101](spec/saas-api.md#api-101)). An SDK bounds its copy of its own write by
  `min(local_ttl, effective_ttl, fresh_for)` ([API-103](spec/saas-api.md#api-103), replacing API-35).
  A re-serving tier bounds its copy of a forwarded write by the same header
  ([API-105](spec/saas-api.md#api-105), [API-106](spec/saas-api.md#api-106) and
  [API-107](spec/saas-api.md#api-107), replacing API-20, API-21 and API-27) and relays it unraised
  ([API-102](spec/saas-api.md#api-102)). A tier may omit the header only on positive knowledge
  of no expiry: a `GET` `200` from a signal-capable store that omitted it, or a forwarded write
  with no TTL whose `PUT` `2xx` omitted it.
- The `X-CacheKit-Fresh-For` grammar keeps its 2,592,000 maximum: no server or tier emits a larger
  value, even for an entry with more than 30 days of freshness left.
- **Breaking for callers on a plan with a maximum TTL:** once the server applies this, a write
  without a TTL is no longer stored with no expiry, and a TTL above the plan's maximum is
  shortened to it.
- **Breaking for SDKs, in order:** the server takes the 90-day range first; until it does, a TTL
  over 2,592,000 is still a `400`, so an SDK must not widen its own TTL check before that. After it,
  an SDK that refuses a TTL over 2,592,000, or a `ttl + stale_ttl` over it, refuses writes the
  server accepts. An SDK that ignores `X-CacheKit-Fresh-For` on the `PUT` response keeps its copy
  of a clamped write past the stored entry's `fresh_until`. The
  [feature matrix](sdk-feature-matrix.md) records each SDK's state.
