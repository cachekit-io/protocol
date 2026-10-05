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
| [`spec/cache-key-format.md`](../spec/cache-key-format.md) | `KEY` |
| [`spec/encryption.md`](../spec/encryption.md) | `ENC` |
| [`spec/file-backend-format.md`](../spec/file-backend-format.md) | `FILE` |
| [`spec/interop-mode.md`](../spec/interop-mode.md) | `IOP` |
| [`spec/saas-api.md`](../spec/saas-api.md) | `API` |
| [`spec/wire-format.md`](../spec/wire-format.md) | `WIRE` |

Each keyword occurrence is one requirement. A sentence with two keywords carries two ids.
MUST NOT is one keyword, with its id after NOT, only where a reader sees one phrase: the two
words parted only by white space, after any emphasis that closes on MUST (`**MUST** NOT`).
On one line that holds in any block, a table row included. Across a line break, both words
must sit in one paragraph or heading, and a `>` between them must be one of the quote markers
that continue it. A MUST whose NOT starts another block, sits past a literal `>`, or opens
emphasis of its own (`MUST **NOT**`) stands alone and carries its own id. A keyword that
introduces a list ("An SDK implementation of interop mode MUST:") carries one id,
and a keyword inside one of the list's items carries its own; the lead-in's *gap* records only
what no item's id owns. A capitalised keyword used as a word rather than as a requirement
carries `<!-- not-a-requirement -->` in place of an id. Lowercase "must", SHOULD and MAY carry
nothing.

Ids are permanent, because an SDK test that cites one must keep meaning the same rule:

- A new requirement takes the number in its file's `next` field, wherever it sits in the
  text, and `next` goes up by one. `next` never goes down, so a number is never offered twice;
  `check` names it when it finds a keyword without an id.
- An editorial rewording keeps the id. A change in what is demanded (raising a bound from 32
  to 64, say), a split into two requirements, or a merge of two into one retires the old id
  or ids and mints new ones.
- When a requirement leaves the spec, delete its entry from `requirements` and add
  `"IOP-n": "<one-line reason>"` to the file's `retired` map.

`check --base` catches an id that is dropped instead of retired, a retired id brought back, and
`next` going down. It cannot catch an existing id deliberately moved onto a different rule,
because that needs the meaning compared; a reviewer has to.

Adding ids changes no normative text. To confirm that for a file:

```bash
diff <(git show main:spec/interop-mode.md) <(python3 tools/conformance.py strip spec/interop-mode.md)
```

`strip` removes only the ids, so the diff still shows every `<!-- not-a-requirement -->` marker
a change adds. Each one is also listed under its file in `coverage.md`.

Keywords are found the way GitHub renders them: `check` reads a spec file into blocks by
CommonMark's rules, as GitHub's renderer applies them, with GFM tables. A keyword in a table,
a list, a blockquote or emphasis (`**MUST**`, `_MUST_`) needs an id; one in inline code or an
inline comment does not. Inline code may cross a line break inside a paragraph, but never
leave its paragraph or table cell. A table starts where a header row is followed by a
delimiter row with the same number of cells (a one-column table needs no pipe), and its body
runs to the first blank line or the first line that starts another block, such as a heading,
a list item or an HTML block. An HTML block (a line that opens with a block tag such as
`<div>` or `<details>`, up to the next blank line) is raw HTML: a keyword in it shows even
between backticks, and only its comments are hidden.

A keyword inside a code block, or inside an HTML comment block that spans lines, is an error,
so that a block the checker misreads fails instead of hiding text:

- A code block cannot carry an id. If a fence's keywords state no requirement, put
  `<!-- not-a-requirement -->` on the line right before it; if they do, state the requirement
  in prose. Only a fence that opens at column 0, outside any blockquote, list item or HTML
  block, can be exempted, and an indented code block cannot be.
- An HTML comment block that spans lines can carry neither an id nor an exemption, so reword
  the keyword. A comment on one line is hidden like an inline comment, as on GitHub.

Only spaces count as indentation or make a line blank (a line of non-breaking spaces is text).
A tab, a vertical tab, a form feed or a carriage return that does not end a CRLF line is an
error anywhere in a spec file, because GitHub reads each differently in different places. So
is a code fence still open at the end of the file, or an HTML block that leaves a comment open:
either would turn the rest of the file into code or hide it.

## The index

`requirements.json` lists the indexed spec files. Once a file is listed, every hard keyword
in it needs an id. Each file has a `prefix`, the `next` number to assign, its `requirements`
and its `retired` ids. Each requirement entry has these fields:

| Field | Meaning |
| :--- | :--- |
| `section` | The heading the id sits under. `check` compares it with the spec. |
| `binds` | Who must comply: `sdk`, `server` (the CachekitIO service) or `caller` (application code that uses an SDK). |
| `sdks` | Optional. The SDKs a requirement binds when it binds only some of them, such as `["cachekit-ts"]`: one that is language-specific, or conditional on a format or feature only those SDKs implement. Omitted, it binds every SDK. |
| `vectors` | Vectors that exercise the requirement: `<fixture>.json:<name>`, or `<fixture>.json` for every vector in the fixture. A `path-encoding.json` vector is named by its `key`. |
| `tests` | Tests in this repository's tools that exercise it, as `tools/<file>:<name>`. `<name>` must be a function the tool defines: a `def` in a `.py` tool (found with Python's `ast`), or a `function` declared at the start of a line in a `.mjs` tool, outside comments, strings, template literals and regular expressions. These run only against the reference implementations. |
| `gap` | One line naming what no vector or test reaches, and why. Required when there are no vectors and no tests. Name what is missing by its content, not its position ("item 5" breaks when a list is reordered); an id the gap names must be an indexed requirement. A known SDK violation is not a gap: [`sdk-feature-matrix.md`](../sdk-feature-matrix.md) records it, and a gap may point there. |

A mapping claims that a plausible wrong implementation fails at least one listed vector.
`check` verifies that every listed vector and test exists. It cannot verify the claim
itself, so a reviewer of a mapping should ask what wrong implementation would pass every
listed vector, and record anything it finds as a `gap`.

## Coverage statuses

The summary counts each spec file's requirements by what their entries map to:

| Column | Entries that list |
| :--- | :--- |
| Vectors, no gap | vectors, and no gap |
| Vectors and a gap | vectors, and a gap for what they miss |
| Tests only | reference-tool tests but no vectors, so every SDK the entry binds shows it uncovered |
| Gap only | nothing but a gap |

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

CI runs `check --base` against the tip of the base branch on a pull request, and against the
commit before the push on `main`. With a base, only fixture revisions reachable from it (plus
the working tree's) count, so a copy taken from an unmerged commit fails; and every id the
base's index holds must still be indexed or retired.
