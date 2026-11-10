### SaaS API — the writer's write-behind copy, and the receipt-delay excess

- [`spec/saas-api.md` § Remaining Freshness](spec/saas-api.md#remaining-freshness), the writer's
  own copy: [API-36](spec/saas-api.md#api-36) and [API-37](spec/saas-api.md#api-37) now cover any
  copy kept before the SDK's local cache learns of a `2xx`, including a write-behind copy, filled
  before its `PUT` is sent, while the write is pending. Once the local cache learns of the `2xx`,
  [API-103](spec/saas-api.md#api-103) binds the copy, its clock started at receipt. Receipt is now
  defined as the instant the SDK's transport receives the `2xx`.
- Code the application supplies between an SDK's transport and its local cache, such as a backend
  wrapper, can hold the `2xx` back, pass it on without its receipt instant, or drop it. The copy
  can then outlive API-103's bound: the new **receipt-delay excess**, capped for a copy filled
  before the local cache learned of the `2xx`, uncapped for one filled when it learned. Serving
  within the excess conforms to API-103 only where such code caused it, never the SDK's own code,
  and an SDK SHOULD require such code to pass the `2xx` on at once. The excess is added to the
  revocation-propagation sum.
- API-36's recommended anchor is now the earlier of the `PUT`'s first dispatch and the local
  write, so it never starts a write-behind copy's clock after the local write.
- The write-path tolerance now runs from the store's stamp to the later of receipt and the SDK's
  local write, which covers a copy filled before its `PUT` was sent.
- No wire change.
