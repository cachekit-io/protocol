### Cache key — 7-segment format is Python SDK convention; server-side requirements

- [`spec/cache-key-format.md`](spec/cache-key-format.md): the 7-segment key
  structure is marked the Python SDK's internal convention, not a server
  contract. A new
  [Server-Side Requirements](spec/cache-key-format.md#server-side-requirements)
  section lists the only checks the CachekitIO backend enforces and which API
  key classes may write each key space — including the open `default` space
  that unprefixed keys (TypeScript/Rust `{ns}:{hash}`, interop, bare hashes)
  fall in.
- Test Vectors: `test-vectors/cache-keys.json` is Python-SDK-only. The rule
  that a cross-SDK implementation substitutes its own module path and matches
  the args-hash segment byte-for-byte is withdrawn for these vectors; cross-SDK
  conformance uses `test-vectors/interop-mode.json`. The fixture's `note` and
  `key_format` fields now say so; no vector changed.
- [`spec/interop-mode.md`](spec/interop-mode.md): the deployed validator
  accepts interop-format keys (`{namespace}:{operation}:{args_hash}`, in the
  `default` namespace), replacing the warning that it would reject them.
