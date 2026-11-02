### SaaS API — the writer's write-behind copy, and the receipt-delay excess

- [`spec/saas-api.md` § Remaining Freshness](spec/saas-api.md#remaining-freshness), the writer's
  own copy: an SDK that serves its copy before its local cache learns whether the store accepted
  the write (write-behind) treats that copy as one kept without a `2xx`
  ([API-36](spec/saas-api.md#api-36), [API-37](spec/saas-api.md#api-37)) until the local cache
  learns of the `2xx`. From then [API-103](spec/saas-api.md#api-103) binds it at once, its clock
  started at receipt. Receipt is now defined as the instant the SDK's transport receives the `2xx`.
- Code the application supplies between an SDK's transport and its local cache, such as a backend
  wrapper, can hold the `2xx` back. For that delay the copy can outlive API-103's bound by the
  delay less `fresh_for`, and never by more than `min(local_ttl, effective_ttl)` less `fresh_for`:
  the new **receipt-delay excess**. With a `fresh_for` of `0`, which keeps no copy, the copy still
  serves for the delay, up to that cap. An SDK that lets such code hold the `2xx` back SHOULD
  require it to pass the `2xx` on as soon as it arrives. The excess is added to the
  revocation-propagation sum.
- The write-path tolerance now runs from the store's stamp to the later of receipt and the SDK's
  local write, which covers a copy filled before its `PUT` was sent.
- No wire change, and no SDK that fills its copy only after its write returns is affected.
