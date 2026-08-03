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

[`sdk-feature-matrix.md`](../sdk-feature-matrix.md) is a trust surface: readers use it to decide what they can rely on without reading four SDKs. In six weeks it produced **six** failures of one family — a cell asserting something the reader would act on that the shipped artifacts did not support:

| # | Failure | Direction |
| :--- | :--- | :--- |
| LAB-388 | "SWR ✓" for orphaned, never-called code | claimed more than shipped |
| LAB-998 | interop/v1 ship-status false | claimed less than shipped |
| LAB-1400 pass 1 | six Rust reliability cells marked 🚧 unreleased — `cachekit-rs` 0.6.0 had published 74 minutes earlier | claimed less than shipped |
| LAB-1400 pass 1 | "cachekit-ts ships the `bin` flip as of 0.1.5" — the published 0.1.5 pins a NAPI addon embedding `cachekit-core` 0.2.0 | claimed more than shipped |
| LAB-1400 pass 2 | a floor-scoping instruction that, read literally, told maintainers to strip the seven floors living outside the Overview table | would have reopened LAB-998 |
| LAB-1400 pass 3 | "a reader built against core ≤ 0.3.0 rejects `bin`", with fleet-upgrade sequencing advice derived from it — contradicted by `cachekit-core/tests/dual_decode.rs`, which asserts pre-flip readers accept `bin` | invented a migration risk |

**Four of the six were committed by the audit that existed to remove the first two.** That is the signal, and it is not carelessness: each was written by someone holding the correct general rule and applying it to a claim they had not opened the artifact for. Reading `main` tells you what the *next* release will contain, never what the current one does. Reading a plausible mechanism tells you what *could* happen, never what the test asserts. The gap in both cases is where the trust bug lives.

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

6. **For a behavioural claim, cite the executed test — not a mechanism you traced.** Reading a code path and reasoning "therefore X rejects Y" produces claims that are plausible and wrong; three of the six incidents above were exactly that. Where a test already asserts the behaviour, cite the test (`cachekit-core/tests/dual_decode.rs` settles the dual-read question in one file). Where none does, trace the **whole** path including its error handling — a claim about what an SDK does on failure is worthless if the operation runs inside a `catch` you did not read — and say which layer you checked. If the two disagree, the test wins.

## Consequences

- Refreshing the matrix costs a handful of artifact downloads. That is the price of the document meaning anything, and it is minutes.
- CI partially enforces rule 4: [`.github/workflows/verify.yml`](../.github/workflows/verify.yml) runs [`tools/check-version-floors.py`](../tools/check-version-floors.py), which fails on a non-floor version in the **SDK Overview table only**, and [`tools/test_check_version_floors.py`](../tools/test_check_version_floors.py), a 17-case mutation suite that runs first so the guard cannot silently degrade to reporting OK.

- **Be honest about the guard's reach: it catches one facet of one of the six incidents above.** The pass-1 `cachekit-rs` event left a `0.5.0` snapshot in the Overview table alongside the six mis-marked Reliability cells; the guard sees the snapshot and nothing else. The other five incidents — LAB-388 (a ✅ on dead code), LAB-998 (a ship-status boolean), the pass-1 ts `bin` claim, the pass-2 floor-scoping instruction, the pass-3 dual-read claim — are all invisible to it, as are the Reliability cells from the very event it partly catches. It also cannot tell whether a floor is *accurate*. Rules 1–3, 5 and 6, and every floor outside that one table, remain reviewer discipline.

  This matters more than it looks. An earlier revision of this record and of `verify.yml` both claimed the guard encoded "the one failure mode that recurred four times" — which would tell the next auditor that CI has this covered when it does not. An overclaiming gate is worse than no gate, because it converts a known gap into an assumed-safe one. The guard's own first version also passed a snapshot hidden behind an ASCII-hyphen placeholder and rejected a valid backticked floor; the mutation suite exists because of that.

## Rejected alternatives

- **Generate the version table from the registries in CI.** Removes the class outright, but the matrix's value is the *prose* — "shipped but unreachable", "on by default since 0.6.0" — which no generator produces. A generated table beside hand-written prose would drift from it, trading one inconsistency for another.
- **Drop versions from the matrix entirely.** "Which release do I need?" is the question the document is most often opened to answer.
- **Trust the SDK repos' own CHANGELOGs.** They record merges, and release-please tags can precede or follow publication. `cachekit-ts` 0.1.5's changelog lists the core-0.4.0 bump ([cachekit-ts#91](https://github.com/cachekit-io/cachekit-ts/pull/91)) while its published tree still pins the old addon — the changelog is exactly how the false claim was produced.
