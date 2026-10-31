### SaaS API — per-plan maximum TTL, clamped; a 90-day TTL range; the applied bound on the `PUT` response

- [`spec/saas-api.md` § Plan maximum TTL](spec/saas-api.md#plan-maximum-ttl) (new): Free 86,400 s
  (24 hours), Startup 2,592,000 s (30 days), Professional 7,776,000 s (90 days), Enterprise none.
  On a plan with a maximum, a stated TTL above it is stored with the maximum, not rejected, and a
  write without a TTL is stored with the maximum instead of with no expiry
  ([API-77](spec/saas-api.md#api-77)). The maximum bounds `evict_at` from each write's stamp: the
  fresh window is kept first and the stale window gets what is left. `PATCH /ttl` is clamped the
  same way ([API-78](spec/saas-api.md#api-78)), and its response must not extend a local copy
  ([API-84](spec/saas-api.md#api-84)). Validation stays plan-independent, so a client can still
  pre-validate every write. A server that cannot determine the tenant's plan stores the write as
  stated, so the plan maximum is not a guaranteed ceiling on an entry's lifetime. Entries stored
  before the change keep their timing until their next write or `PATCH`.
- The TTL range of `X-CacheKit-TTL`, of `PATCH /ttl`'s `ttl` and of `ttl + stale_ttl` rises from
  2,592,000 to 7,776,000 (`stale_ttl` alone to 7,775,999). A larger value is still a `400`.
- The plan maximum is the only default for a write without a TTL
  ([API-79](spec/saas-api.md#api-79), which merges and retires API-40 and API-41).
- A store that clamps sends `X-CacheKit-Fresh-For` on every `PUT` `2xx` for a bounded entry: the
  stored entry's remaining freshness ([API-80](spec/saas-api.md#api-80)). No write is clamped until
  the store sends it and every tier that forwards `PUT`s relays it and bounds its copy by it
  ([API-81](spec/saas-api.md#api-81)), so a `PUT` `2xx` without it means the stated TTL was
  applied. "Signal-capable" still means emitting the header on `GET`. An SDK bounds its copy of its
  own write by `min(local_ttl, effective_ttl, fresh_for)` ([API-83](spec/saas-api.md#api-83),
  replacing API-35). A re-serving tier bounds its copy of a forwarded write by the same header
  ([API-85](spec/saas-api.md#api-85), [API-86](spec/saas-api.md#api-86) and
  [API-87](spec/saas-api.md#api-87), replacing API-20, API-21 and API-27) and relays it unraised
  ([API-82](spec/saas-api.md#api-82)).
- The `X-CacheKit-Fresh-For` grammar keeps its 2,592,000 maximum: a server or tier reports an
  entry with more than 30 days of freshness left as `2592000`.
- [`CONTEXT.md`](CONTEXT.md): **No-expiry entry** is defined by its stored state, and **Plan
  maximum TTL** and **TTL range** are added.
- **Breaking for callers on a plan with a maximum TTL:** once the server applies this, a write
  without a TTL is no longer stored with no expiry, and a TTL above the plan's maximum is
  shortened to it.
- **Breaking for SDKs, in order:** the server takes the 90-day range first; until it does, a TTL
  over 2,592,000 is still a `400`, so an SDK must not widen its own TTL check before that. After it,
  an SDK that refuses a TTL over 2,592,000, or a `ttl + stale_ttl` over it, refuses writes the
  server accepts. An SDK that ignores `X-CacheKit-Fresh-For` on the `PUT` response keeps its copy
  of a clamped write past the stored entry's `fresh_until`. The
  [feature matrix](sdk-feature-matrix.md) records each SDK's state.
