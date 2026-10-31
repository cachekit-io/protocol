### SaaS API — per-plan maximum TTL, clamped; a 90-day TTL range; the applied bound on the `PUT` response

- [`spec/saas-api.md` § Plan maximum TTL](spec/saas-api.md#plan-maximum-ttl) (new): Free 86,400 s
  (24 hours), Startup 2,592,000 s (30 days), Professional 7,776,000 s (90 days), Enterprise none.
  On a plan with a maximum, a stated TTL above it is stored with the maximum, not rejected, and a
  write without a TTL is stored with the maximum instead of with no expiry
  ([API-77](spec/saas-api.md#api-77)). The maximum bounds the entry's whole stored life: the fresh
  window is kept first and the stale window gets what is left. `PATCH /ttl` is clamped the same
  way ([API-78](spec/saas-api.md#api-78)). Validation stays plan-independent, so a client can still
  pre-validate every write. On Enterprise, and for entries stored before the change, nothing
  changes.
- The value range of `X-CacheKit-TTL`, of `PATCH /ttl`'s `ttl` and of `ttl + stale_ttl` rises from
  2,592,000 to 7,776,000 (`stale_ttl` alone to 7,775,999). A larger value is still a `400`.
- The plan maximum is the only default for a write without a TTL
  ([API-79](spec/saas-api.md#api-79), which merges and retires API-40 and API-41).
- A `PUT` `2xx` now carries `X-CacheKit-Fresh-For`: the freshness bound the store applied
  ([API-80](spec/saas-api.md#api-80)), and a server that clamps must send it
  ([API-81](spec/saas-api.md#api-81)). An SDK bounds its copy of its own write by
  `min(local_ttl, effective_ttl, fresh_for)` ([API-85](spec/saas-api.md#api-85), replacing API-35).
  A re-serving tier bounds its copy of a forwarded write the same way
  ([API-82](spec/saas-api.md#api-82), replacing API-20; [API-84](spec/saas-api.md#api-84),
  replacing API-27) and relays the header unraised ([API-83](spec/saas-api.md#api-83)).
- The `X-CacheKit-Fresh-For` grammar keeps its 2,592,000 maximum: a server reports an entry with
  more than 30 days of freshness left as `2592000`.
- **Breaking for callers on a plan with a maximum TTL:** once the server applies this, a write
  without a TTL is no longer stored with no expiry, and a TTL above the plan's maximum is
  shortened to it.
- **Breaking for SDKs:** one that refuses a TTL over 2,592,000, or a `ttl + stale_ttl` over it,
  refuses writes the server accepts. One that ignores `X-CacheKit-Fresh-For` on the `PUT` response
  keeps its copy of a clamped write for the stated TTL, past the stored entry's `fresh_until`. The
  [feature matrix](sdk-feature-matrix.md) records each SDK's state.
