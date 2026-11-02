### SaaS API — L1 hit-latency sampling: the hookless-fork startup window

- [`spec/saas-api.md` § L1 hit latency](spec/saas-api.md#l1-hit-latency), **Sampling**
  ([API-81](spec/saas-api.md#api-81)): names one exception to the independent per-call draw.
  A child that inherits a backend instance through a fork that runs none of the SDK's at-fork
  handlers may repeat its parent's and siblings' draw sequence until it builds a backend
  instance of its own, or first uses an inherited instance's report (its first request other
  than the health check, or its first timed L1 hit). Each call is still timed with
  probability 1/N. No header, value format or range of N changes.
