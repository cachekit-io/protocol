# File Backend Storage Format

## Scope

This optional transport format lets File backends in different CacheKit SDKs share one cache directory. It specifies only the file name and container header; the payload is the opaque byte sequence supplied by the SDK backend. It does not make an SDK auto-mode value representation cross-language compatible.

## File name

For a logical backend key encoded as UTF-8, calculate `BLAKE2b-128(key_utf8)` and write its lowercase hexadecimal encoding. The result is a 32-character file name in a flat cache directory.

The File backend does not add a key prefix. Interop mode must therefore reject a configured hidden prefix before this mapping is used.

## Entry layout

Every entry is a 14-byte header followed by zero or more payload bytes.

| Offset | Size | Field | Required value |
| ---: | ---: | --- | --- |
| 0 | 2 | Magic | ASCII `CK` (`0x43 0x4b`) |
| 2 | 1 | Version | `1` |
| 3 | 1 | Reserved | `0` |
| 4 | 2 | Flags | unsigned 16-bit big-endian; `0` |
| 6 | 8 | Expiry | unsigned 64-bit big-endian Unix seconds; `0` means no expiry |
| 14 | variable | Payload | opaque backend bytes |

Writers for version 1 MUST set the reserved byte and flags to zero. The expiry is the integer UTC Unix-second deadline. An entry with a nonzero expiry is expired when the reader wall clock reaches that timestamp; readers MAY lazily remove expired entries.

## Version and flag negotiation

A truncated header or wrong magic/version is corrupt and may be removed as a cache miss. A nonzero reserved byte or flag value is different: it can indicate a future payload transform. A reader that does not implement every indicated transform MUST return a miss and MUST NOT delete, rewrite, or return the payload. This fails closed rather than exposing transformed bytes as plaintext.

A future nonzero flag assignment requires a protocol update and canonical test vector. A writer MUST NOT set an unknown flag. A reader that implements a future flag must preserve the established fields and verify the transform before returning payload bytes.

## Write and TTL behavior

Entries are written through a temporary file in the same directory and atomically renamed into place. Refreshing TTL rewrites only bytes 6 through 13 and MUST NOT expose a torn expiry to a concurrent reader: a refresh either rewrites the entry through the same temporary-file and atomic-rename path, or updates the expiry with a single positioned 8-byte write on platforms that guarantee read/write atomicity for regular files (POSIX.1-2017 §2.9.7) — in which case readers MUST load the 14-byte header in a single read. Writers calculate the absolute deadline and store its whole-second Unix timestamp; a positive sub-second TTL can therefore expire within the current second.

The canonical examples are in [`test-vectors/file-backend.json`](../test-vectors/file-backend.json).
