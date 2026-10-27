# CacheKit

CacheKit is a multi-language caching framework with optional client-side encryption, made of per-language SDKs and the managed CachekitIO backend. This file is the one definition of the terms its specs, decision records and SDKs share; the specs stay normative wherever this glossary is shorter than they are.

## Language

### Keys and modes

**Cache key**:
The string an entry is stored under, which CachekitIO treats as opaque apart from its security checks, the `ns:` / `nsapi:` prefix among them.
_Avoid_: key (on its own, it is ambiguous with master key and API key), slot

**Logical backend key**:
The full cache key as the client hands it to a backend, including every client-side prefix and excluding any encoding the backend uses to address its store.
_Avoid_: raw key, storage key

**Auto mode**:
The default mode, in which each SDK builds its own cache keys and stores its own storage container, so no other SDK can read its entries.
_Avoid_: default mode, native mode, SDK mode

**Interop mode**:
The opt-in mode whose cache keys (`{namespace}:{operation}:{args_hash}`) and plain-MessagePack values are identical across SDKs; it is the only cross-SDK format.
_Avoid_: cross-SDK mode, compat mode, multi-language parity

**Interop profile**:
A frozen, named version of interop mode's rules (interop/v1, and the draft interop/v2); a change to the rules gets a new profile name, never a silent revision.
_Avoid_: interop version, key version

**Operation**:
The explicit, language-neutral name of the cached computation in an interop key, agreed between deployments out of band.
_Avoid_: function name, endpoint, namespace (for this meaning)

**Function identity**:
The language-specific `func:{module}.{qualname}` segment that names the cached function in a Python auto-mode key, and the reason those keys are never shared across SDKs.
_Avoid_: operation (that is the interop name)

**Serializer code**:
The one- or five-character code at the end of a Python auto-mode key that names the serializer the cache is configured with, so two serializers do not share a key.
_Avoid_: format flag, type code

### Namespaces and access

**Namespace**:
The server-side scope that API-key grants, quotas and the edge budget apply to, read from a cache key's `ns:{namespace}:` or `nsapi:{namespace}:` prefix. It is never a tenant boundary.
_Avoid_: keyspace, bucket, partition

**Default namespace**:
The namespace named `default`, which holds every cache key that carries neither prefix and is an open write space within the tenant.
_Avoid_: global namespace, root namespace, unscoped

**SDK namespace**:
The namespace value a caller sets on an SDK cache. Only cachekit-py's auto mode writes it as an `ns:` prefix, which makes it a namespace; everywhere else, interop mode included, it is a client-side key segment that lands in the default namespace.
_Avoid_: namespace (on its own, where the server scope could be meant), key prefix, tenant
In cachekit-ts auto mode the SDK namespace also identifies the operation, and the word also names the group of entries that L1 invalidation clears.

**Key prefix**:
A string a backend or its client library prepends to every cache key (a Memcached or ioredis `keyPrefix`), outside the SDK namespace; interop mode refuses a backend that hides one.
_Avoid_: namespace, hidden namespace

**Write space**:
The set of cache keys one API-key class may mutate: `ns:` keys for SDK keys, `nsapi:` keys for direct-API keys, and the open default namespace for every class. Reads are not split by write space.
_Avoid_: key space, write namespace

**API key**:
The bearer credential a client presents to CachekitIO, which fixes the tenant and carries a key class and namespace grants.
_Avoid_: token, secret, master key (that is the encryption secret)

**Key class**:
The kind of API key, read from its prefix: SDK key (`ck_sdk_`), direct-API key (`ck_api_`) or legacy key (`ck_live_`, exempt from the write-space split).
_Avoid_: key type, scope, role

**Namespace grant**:
The list of namespaces an API key may read and write; an unrestricted key reaches every namespace in its tenant.
_Avoid_: permission, ACL, scope

**Tenant**:
The server-side owner of a set of cache entries, fixed by the API key at authentication and never by anything in the cache key.
_Avoid_: tenant ID (that is the encryption input), namespace, account
Customer-facing pages call a tenant a project.

### Storage

**Entry**:
A value stored under a cache key, with its freshness window.
_Avoid_: item, record, object

**Backend**:
The byte store an SDK reads and writes entries through (Redis, Memcached, File, CachekitIO, Workers KV, the Cache API); serialization and encryption happen above it.
_Avoid_: driver, provider, adapter

**CachekitIO**:
CacheKit's managed SaaS backend, which stores entries as opaque bytes under per-tenant storage.
_Avoid_: the SaaS, cachekit.io API, cloud backend

**L1**:
An SDK's in-process cache in front of its backend.
_Avoid_: local cache, memory cache, near cache

**L2**:
The backend behind L1, shared between processes.
_Avoid_: remote cache, distributed cache

**Storage container**:
The SDK-internal byte layout an SDK stores in auto mode (cachekit-py's CK v3 frame, by default cachekit-ts's ByteStorage envelope, cachekit-rs's plain MessagePack); no SDK decodes another's.
_Avoid_: wire format, envelope (it is not always one)

**ByteStorage envelope**:
The LZ4-compressed, xxHash3-64-checked container that cachekit-core defines and some SDKs use in auto mode; interop values never use it.
_Avoid_: StorageEnvelope (the type's name), wrapper, frame

**CK v3 frame**:
cachekit-py's auto-mode storage container, a `CK`-tagged header followed by the serializer's output.
_Avoid_: ByteStorage envelope, CK header

**Interop value**:
The plain MessagePack document interop/v1 stores, with no envelope, frame or checksum.
_Avoid_: raw value, portable value

### Freshness

**Freshness window**:
The period after a write during which CachekitIO serves an entry as fresh; it ends at the entry's TTL.
_Avoid_: fresh TTL, lifetime

**Stale window**:
The period after the freshness window during which CachekitIO still serves an entry, marked stale, before it evicts it.
_Avoid_: grace period, stale TTL (that is the window's length)

**No-expiry entry**:
An entry written without a TTL, which never enters a stale window and stays until it is deleted, overwritten or evicted for capacity.
_Avoid_: permanent entry, infinite TTL

**Revalidation**:
The client recomputing a stale entry in the background and writing the result back, while callers are served the stale value.
_Avoid_: refresh (on its own), server-side recompute

**Lock**:
A best-effort claim on a cache key, identified by its `lock_id`, that lets one client recompute an entry while the others wait or serve stale.
_Avoid_: mutex, lease (on its own)

**Edge copy**:
A copy of an entry held at the CachekitIO edge location that served a request, reused for later reads within the edge budget.
_Avoid_: CDN cache, replica

**Edge budget**:
A namespace's bound, from 0 to 300 seconds and 5 by default, on how old an edge copy may be when it is served.
_Avoid_: edge TTL, staleness budget

**Store**:
CachekitIO's authoritative storage tier, whose clock decides every entry's freshness.
_Avoid_: origin, database

### Encryption

**Master key**:
The customer's secret of at least 32 bytes, supplied as hex, from which every encryption key is derived; it never leaves the client.
_Avoid_: encryption key (that is derived from it), API key, secret key

**Tenant ID**:
The client-supplied string that separates key derivation and is bound into every ciphertext's authenticated data; it defaults to `default`, and CacheKit never derives it from the server-side tenant or from a namespace.
_Avoid_: tenant (that is the server-side owner), namespace

**Keyring**:
The current master key plus up to three decrypt-only master keys, which together let a deployment rotate keys without invalidating encrypted entries.
_Avoid_: key set, key version, rotation header

**Zero-knowledge**:
The property that a backend stores only ciphertext it cannot decrypt; it covers value confidentiality only, not entry metadata.
_Avoid_: end-to-end encryption, fully private

### Configuration

**Intent preset**:
A named constructor that fixes a cache's defaults for one purpose; the four canonical presets are `minimal`, `production`, `secure` and `io`.
_Avoid_: profile, tier, mode
The encrypted preset is `secure`; `encrypted` is a retired spelling.

## Known divergences

- cachekit-py writes any SDK namespace into its `ns:` prefix unchecked, so a value outside the server's namespace grammar (1–64 of `[a-zA-Z0-9_-]`) is rejected by CachekitIO, or, if it contains `:`, lands in a different namespace.
- The 250-character key limit keeps the first 50 characters of an over-long Python auto-mode key, so an SDK namespace longer than 47 characters is cut short and the key lands in a different namespace.
