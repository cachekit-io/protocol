### SaaS API — the writer's write-behind copy, and the receipt-delay excess

- [`spec/saas-api.md` § Remaining Freshness](spec/saas-api.md#remaining-freshness), the writer's
  own copy: [API-36](spec/saas-api.md#api-36) and [API-37](spec/saas-api.md#api-37) now cover any
  copy kept before the SDK's local cache learns of a `2xx`, including a write-behind copy, filled
  before its `PUT` is sent, while the write is pending. Once the local cache learns of the `2xx`,
  [API-103](spec/saas-api.md#api-103) binds the copy, its clock started at receipt. Receipt is now
  defined as the instant the SDK's transport receives the `2xx`.
- Code the application supplies between an SDK's transport and its local cache, such as a backend
  wrapper, can hold the `2xx` back, or pass it on without its receipt instant. The copy can then
  outlive API-103's bound by up to the time the `2xx` was held back (that time less `fresh_for`
  when the receipt instant is passed on): the new **receipt-delay excess**. A copy filled before
  the local cache learned of the `2xx` never exceeds the bound by more than
  `min(local_ttl, effective_ttl)` less `fresh_for`; a copy filled when it learned has no ceiling.
  Serving within the excess conforms to API-103 only where code the application supplies held the
  `2xx` back, never the SDK's own code. An SDK that lets such code hold the `2xx` back SHOULD
  require it to pass the `2xx` on, with its receipt instant, as soon as it arrives. The excess is
  added to the revocation-propagation sum.
- The write-path tolerance now runs from the store's stamp to the later of receipt and the SDK's
  local write, which covers a copy filled before its `PUT` was sent.
- No wire change.
