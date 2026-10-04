# Conformance index

Every MUST and MUST NOT in an indexed spec file carries a requirement id. This directory maps
each id to the test vectors that exercise it, and reports which of those vectors each SDK
vendors. It answers two questions the fixture files cannot: which requirements does no vector
reach, and which requirements do a given SDK's vendored vectors reach?

| File | What it holds |
| :--- | :--- |
| [`requirements.json`](requirements.json) | The index: every requirement id, with its vectors, tests and gaps |
| [`sdks.json`](sdks.json) | The sha256 of each fixture copy each SDK vendors, as of a named SDK commit |
| [`coverage.md`](coverage.md) | The per-SDK report, generated from the two files above and [`test-vectors/`](../test-vectors/) |

`tools/conformance.py check` runs in CI and fails on any mismatch between the spec, the index,
the fixtures and the report.

## Requirement ids

An id is written straight after its keyword, as a superscript that is also a link target:

```markdown
SDKs MUST<sup id="iop-3">IOP-3</sup> reject non-conforming segments
```

GitHub renders this as a superscript, and `spec/interop-mode.md#iop-3` links to the exact
requirement. The visible id is the file's prefix and a number; the `id` attribute is the
same text in lowercase. When the keyword is bold, the id goes after the closing `**`.

| Spec file | Prefix |
| :--- | :--- |
| [`spec/interop-mode.md`](../spec/interop-mode.md) | `IOP` |

Each keyword occurrence is one requirement. A sentence with two keywords carries two ids, and
a keyword that introduces a list ("An SDK implementation of interop mode MUST:") carries one
id for the whole list. A capitalised keyword used as a word rather than as a requirement
carries `<!-- not-a-requirement -->` in place of an id. Lowercase "must", SHOULD and MAY carry
nothing.

Ids are permanent. A new requirement takes the next free number for its file, wherever it
sits in the text; `check` names that number when it finds a keyword without an id. An id
is never renumbered or reused. When a requirement leaves the spec, move its entry from
`requirements` to `retired` with a one-line reason. Rewording a requirement keeps its id.

Adding ids changes no normative text. To confirm that for a file:

```bash
diff <(git show main:spec/interop-mode.md) <(python3 tools/conformance.py strip spec/interop-mode.md)
```

`strip` removes only the ids, so the diff still shows every `<!-- not-a-requirement -->` marker
a change adds. Each one is also listed under its file in `coverage.md`.

Keywords are found the way a Markdown renderer shows them. A keyword in fenced code, inline
code or an HTML comment needs no id; one in a table, a list, a blockquote or emphasis
(`**MUST**`, `_MUST_`) does. A fence that closes at a different indent than it opened is an
error, because a misread fence line would hide the text up to the next fence.

## The index

`requirements.json` lists the indexed spec files. Once a file is listed, every hard keyword
in it needs an id. Each requirement entry has these fields:

| Field | Meaning |
| :--- | :--- |
| `section` | The heading the id sits under. `check` compares it with the spec. |
| `binds` | Who must comply: `sdk`, `server` (the CachekitIO service) or `caller` (application code that uses an SDK). |
| `sdks` | Optional. The SDKs a language-specific requirement binds, such as `["cachekit-ts"]`. Omitted, it binds every SDK. |
| `vectors` | Vectors that exercise the requirement: `<fixture>.json:<name>`, or `<fixture>.json` for every vector in the fixture. A `path-encoding.json` vector is named by its `key`. |
| `tests` | Tests in this repository's tools that exercise it, as `tools/<file>:<name>`, where `<name>` is the function or self-test label. These run only against the reference implementations. |
| `gap` | One line naming what no vector or test reaches, and why. Required when there are no vectors and no tests. |

A mapping claims that a plausible wrong implementation fails at least one listed vector.
`check` verifies that every listed vector and test exists. It cannot verify the claim
itself, so a reviewer of a mapping should ask what wrong implementation would pass every
listed vector, and record anything it finds as a `gap`.

## Coverage statuses

For each SDK, `coverage.md` gives every requirement one status:

| Status | Meaning |
| :--- | :--- |
| covered | The SDK's vendored fixtures hold every vector the requirement maps to, identical to the vectors published here, and no gap is recorded. |
| partial | They hold some of those vectors, or hold all of them while a gap is recorded. |
| uncovered | They hold none of them, or only this repository's reference tools test the requirement. |
| gap | Nothing tests the requirement. |
| n/a | The requirement binds the server, application code or another SDK. |

Covered means the vectors are vendored. It does not show that the SDK's tests drive each
vector through every entry point the requirement names, or assert the error it requires.
[`sdk-feature-matrix.md`](../sdk-feature-matrix.md) records that per SDK.

## Updating

When a spec change adds, removes or rewords a hard requirement, update its ids and index
entries in the same change, then regenerate the report:

```bash
python3 tools/conformance.py report
python3 tools/conformance.py check
```

When an SDK vendors a new fixture copy, record the sha256 of its copy and the SDK commit you
read it from in `sdks.json`, then regenerate the report. `check` matches each sha256 to a
revision of the fixture in this repository's history and fails if none matches, so a copy
must be byte-identical to a revision committed here. `check` needs the full history: run
`git fetch --unshallow` in a shallow clone.

CI runs `check --base HEAD^1`, which on a pull request is the tip of the base branch. With a
base, only fixture revisions reachable from it (plus the working tree's) count, so a copy taken
from an unmerged commit fails; and every id the base's index holds must still be indexed or
retired, so an id is never silently dropped or brought back.
