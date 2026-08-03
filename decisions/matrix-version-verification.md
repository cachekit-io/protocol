**[Protocol](../README.md)** > **Decisions** > **Matrix Version Verification**

# Decision Record: Verify the Feature Matrix Against Published Artifacts, Not Branches

| | |
| :--- | :--- |
| **Status** | Accepted |
| **Date** | 2026-08-04 |
| **Ticket** | LAB-1400 (consolidation of ten conflicting `sdk-feature-matrix.md` PRs) |
| **Applies to** | [`sdk-feature-matrix.md`](../sdk-feature-matrix.md), and any version- or ship-status claim in [`spec/`](../spec) |

---

## Context

[`sdk-feature-matrix.md`](../sdk-feature-matrix.md) is a trust surface: readers use it to decide what they can rely on without reading four SDKs. In six weeks it produced **four** failures of one mechanical class — a cell describing a repository branch while claiming to describe a shipped SDK:

| # | Failure | Direction |
| :--- | :--- | :--- |
| LAB-388 | "SWR ✓" for orphaned, never-called code | claimed more than shipped |
| LAB-998 | interop/v1 ship-status false | claimed less than shipped |
| LAB-1400 (first pass) | six Rust reliability cells marked 🚧 unreleased — `cachekit-rs` 0.6.0 had published 74 minutes earlier | claimed less than shipped |
| LAB-1400 (first pass) | "cachekit-ts ships the `bin` flip as of 0.1.5" — the published 0.1.5 pins a NAPI addon embedding `cachekit-core` 0.2.0 | claimed more than shipped |

The last two were committed *by the audit that existed to remove the first two.* That is the signal: the failure is not carelessness, it is a method that cannot detect this class. Reading `main` tells you what the next release will contain, never what the current one does, and the gap between them is exactly where a trust bug lives.

Two properties make it worse than ordinary staleness:

- **It is bidirectional.** A ❌ hiding a shipped feature makes users hand-roll what they already have; a ✅ they cannot install makes them plan around vapour. Neither is safer.
- **It rots without an edit.** A registry release falsifies a cell while the file is untouched. `cachekit-rs` 0.6.0 falsified six cells and a footnote in one event.

## Decision

**A version- or ship-status claim in the matrix is verified against the published artifact, or it is not made.**

1. **Registry metadata is the floor, not the proof.** Latest version and publish timestamp come from the registry API (crates.io, npm, PyPI). That establishes *which* artifact is current — nothing more.

2. **When an embedded or transitive dependency version decides the claim, open the artifact.** Downloading and inspecting is mandatory, not optional:
   - Rust — fetch the `.crate`, read the *published* `Cargo.toml` for `[features] default` and dependency requirements, and list `src/` for the modules the claim names.
   - npm — read the exact `dependencies` pins from the registry document (caret-free pins do **not** float), fetch the `.tgz`, and `strings` the `.node` / `.wasm` for the embedded `cachekit-core-X.Y.Z`. A source-level pin bump in a monorepo does **not** mean the consumed binary was republished.
   - Python — the wheel's bundled extension, when a core version decides the claim.

3. **A merged PR is not a shipped feature.** Cite the release that carries it, not the PR that landed it. `git log` and tags describe intent; the registry describes reality.

4. **A version answering "which release do I need" is a floor (`X+`), never a snapshot.** A floor stays true as new releases publish; a snapshot is wrong the moment the next one lands and silently misleads until someone notices. That covers the SDK Overview table, the Compliance Status table, and the Architecture Notes release bullets. A version that is instead **evidence about one specific artifact** under rule 2 — an embedded `cachekit-core-0.2.0` in one `.node` binary, a caret-free `0.1.2` npm pin, a historical statement — stays bare, because appending `+` to it would make it false.

   The CI guard polices only the SDK Overview column. The other floors are reviewer discipline: distinguishing "which release do I need" from "what is inside this artifact" needs the claim's intent, which a regex cannot read.

5. **Record the verification date** next to the claim. A floor plus a date is auditable; a bare number is a guess with a decimal point.

## Consequences

- Refreshing the matrix costs a handful of artifact downloads. That is the price of the document meaning anything, and it is minutes.
- CI enforces rule 4 mechanically: [`.github/workflows/verify.yml`](../.github/workflows/verify.yml) runs [`tools/check-version-floors.py`](../tools/check-version-floors.py), which fails on any bare `X.Y.Z` in `sdk-feature-matrix.md` that is not written as a floor. It cannot catch a *wrong* floor — only a snapshot masquerading as fact. Rules 1–3 and 5 remain reviewer discipline.
- The guard is deliberately narrow. It encodes the one failure mode that recurred four times and nothing speculative.

## Rejected alternatives

- **Generate the version table from the registries in CI.** Removes the class outright, but the matrix's value is the *prose* — "shipped but unreachable", "on by default since 0.6.0" — which no generator produces. A generated table beside hand-written prose would drift from it, trading one inconsistency for another.
- **Drop versions from the matrix entirely.** "Which release do I need?" is the question the document is most often opened to answer.
- **Trust the SDK repos' own CHANGELOGs.** They record merges, and release-please tags can precede or follow publication. `cachekit-ts` 0.1.5's changelog lists the core-0.4.0 bump ([cachekit-ts#91](https://github.com/cachekit-io/cachekit-ts/pull/91)) while its published tree still pins the old addon — the changelog is exactly how the false claim was produced.
