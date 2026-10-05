#!/usr/bin/env python3
"""Mutation tests for conformance.py.

A coverage check that cannot be shown to FAIL is indistinguishable from one that reports OK
unconditionally. Each case below runs the check against a copy of this repository, history
included (matching a vendored fixture copy to its revision needs it), with one thing poisoned,
and asserts both the exit status and the message that names the defect: a case that fails
through the wrong branch would otherwise pass while the branch it names is dead code.

Run: python3 tools/test_conformance.py     (exit 1 on any failure)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CHECKER = HERE / "conformance.py"
SPEC = "spec/interop-mode.md"
INDEX = "conformance/requirements.json"
SDKS = "conformance/sdks.json"
REPORT = "conformance/coverage.md"
OVERLAY = ("spec", "conformance", "test-vectors", "tools")
GIT_ID = (
    *("-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "core.hooksPath=/dev/null"),
    *("-c", "commit.gpgsign=false", "-c", "log.showSignature=false"),
)

Mutate = Callable[[Path], None]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *GIT_ID, *args], check=True, capture_output=True, text=True).stdout


def marker(rid: str) -> str:
    return f'<sup id="{rid.lower()}">{rid}</sup>'


def edit(rel: str, old: str, new: str) -> Mutate:
    def mutate(root: Path) -> None:
        path = root / rel
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise SystemExit(f"test setup broken: {old!r} not in {rel}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    return mutate


def append(rel: str, extra: str) -> Mutate:
    def mutate(root: Path) -> None:
        with (root / rel).open("a", encoding="utf-8") as f:
            f.write(extra)

    return mutate


def index(change: Callable[[dict], None]) -> Mutate:
    def mutate(root: Path) -> None:
        path = root / INDEX
        document = json.loads(path.read_text(encoding="utf-8"))
        change(document["files"][SPEC])
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return mutate


def entry(rid: str, **fields: object) -> Mutate:
    """Set (or, with None, delete) fields of one index entry."""

    def change(spec: dict) -> None:
        for key, value in fields.items():
            if value is None:
                spec["requirements"][rid].pop(key, None)
            else:
                spec["requirements"][rid][key] = value

    return index(change)


def sdks(change: Callable[[dict], None]) -> Mutate:
    def mutate(root: Path) -> None:
        path = root / SDKS
        document = json.loads(path.read_text(encoding="utf-8"))
        change(document)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    return mutate


def both(*mutations: Mutate) -> Mutate:
    def mutate(root: Path) -> None:
        for m in mutations:
            m(root)

    return mutate


def report(root: Path) -> None:
    subprocess.run([sys.executable, str(CHECKER), "report", str(root)], check=True, capture_output=True)


def retire(rid: str) -> Mutate:
    """Take the requirement out of the spec (its keyword becomes prose) and retire its id."""

    def change(spec: dict) -> None:
        del spec["requirements"][rid]
        spec["retired"][rid] = "test: the requirement left the spec"

    return both(edit(SPEC, f"MUST{marker(rid)}", "should"), index(change), report)


def commit_base(prepare: Mutate) -> Mutate:
    """Commit the tree, after `prepare`, as the base the next mutation is compared against."""

    def mutate(root: Path) -> None:
        prepare(root)
        git(root, "add", "--", *OVERLAY)
        git(root, "commit", "--quiet", "--no-verify", "--allow-empty", "-m", "base")

    return mutate


def duplicate_key(root: Path) -> None:
    path = root / INDEX
    text = path.read_text(encoding="utf-8")
    first = re.search(r'\n( +)"IOP-1": \{.*?\n\1\},?\n', text, re.DOTALL)
    if not first:
        raise SystemExit("test setup broken: IOP-1 entry not found")
    block = first.group(0).rstrip("\n")
    block = block if block.endswith(",") else block + ","
    path.write_text(text.replace(first.group(0), block + first.group(0), 1), encoding="utf-8")


def duplicate_vector(root: Path) -> None:
    path = root / "test-vectors/interop-mode.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["error_vectors"][1]["name"] = document["error_vectors"][0]["name"]
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def unreadable(rel: str) -> Mutate:
    def mutate(root: Path) -> None:
        (root / rel).unlink()
        (root / rel).mkdir()

    return mutate


def first_sdk_fixture(change: Callable[[dict, str], None]) -> Mutate:
    def apply(document: dict) -> None:
        sdk = next(iter(document))
        change(document[sdk]["fixtures"], sdk)

    return sdks(apply)


def rehash(fixtures: dict, _: str) -> None:
    fixture = next(iter(fixtures))
    fixtures[fixture] = "0" * 64


def rename_fixture(fixtures: dict, _: str) -> None:
    fixture = next(iter(fixtures))
    fixtures["no-such-fixture.json"] = fixtures.pop(fixture)


def files(change: Callable[[dict], None]) -> Mutate:
    """Change the index's map of indexed spec files."""

    def mutate(root: Path) -> None:
        path = root / INDEX
        document = json.loads(path.read_text(encoding="utf-8"))
        change(document["files"])
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return mutate


def new_requirement(rid: str, section: str) -> Mutate:
    """Index a new requirement, raising next past it as a new id must."""

    def change(spec: dict) -> None:
        spec["requirements"][rid] = {"section": section, "binds": "sdk", "gap": "test"}
        spec["next"] = max(spec["next"], int(rid.split("-")[-1]) + 1)

    return index(change)


def write_json(root: Path, rel: str, document: object) -> None:
    (root / rel).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def malformed_revision_in_history(root: Path) -> None:
    """Commit a fixture revision with a duplicate vector name, then the good one again: no SDK vendors it."""
    rel = "test-vectors/interop-mode.json"
    good = (root / rel).read_bytes()
    document = json.loads(good)
    document["error_vectors"][1]["name"] = document["error_vectors"][0]["name"]
    write_json(root, rel, document)
    git(root, "add", "--", rel)
    git(root, "commit", "--quiet", "--no-verify", "-m", "malformed")
    (root / rel).write_bytes(good)
    git(root, "add", "--", rel)
    git(root, "commit", "--quiet", "--no-verify", "-m", "fixed")


def vendored_from_unmerged_commit(root: Path) -> None:
    """Commit a fixture revision after the base commit, restore the published one, and vendor the former."""
    import hashlib

    rel = "test-vectors/file-backend.json"
    published = (root / rel).read_bytes()
    document = json.loads(published)
    document["vectors"][0]["name"] += "_renamed"
    write_json(root, rel, document)
    unmerged = (root / rel).read_bytes()
    git(root, "add", "--", rel)
    git(root, "commit", "--quiet", "--no-verify", "-m", "unmerged revision")
    (root / rel).write_bytes(published)
    sdks(lambda d: d["cachekit-rs"]["fixtures"].__setitem__("file-backend.json", hashlib.sha256(unmerged).hexdigest()))(root)


def crlf(rel: str) -> Mutate:
    """Convert a file to CRLF line endings, as a Windows checkout would."""

    def mutate(root: Path) -> None:
        path = root / rel
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))

    return mutate


IOP3 = marker("IOP-3")
# The spec's last line: a case that appends "\n<text>" puts <text> on line SPEC_END + 2.
SPEC_END = (ROOT / SPEC).read_text(encoding="utf-8").count("\n")
NBSP = chr(0xA0)  # a non-breaking space: text to CommonMark, never blank
OK = "conformance: OK"
STALE = f"{REPORT} is stale or missing"

# (name, mutate(root), expected exit, substring the output MUST contain[, extra check args[, env]])
Case = tuple[str, Mutate, int, str] | tuple[str, Mutate, int, str, list[str]] | tuple[str, Mutate, int, str, list[str], dict]
CASES: list[Case] = [
    ("unmodified tree", lambda _: None, 0, OK),
    # --- every hard keyword in an indexed file carries an id ---
    ("id removed from beside a MUST", edit(SPEC, marker("IOP-19"), ""), 1, "this MUST has no id (the next free id is IOP-37)"),
    (
        "new MUST NOT added without an id",
        append(SPEC, "\nReaders MUST NOT crash.\n"),
        1,
        f"{SPEC}:{SPEC_END + 2}: this MUST NOT has no id",
    ),
    ("MUST NOT split across a line break", append(SPEC, "\nReaders MUST\nNOT crash.\n"), 1, "this MUST NOT has no id"),
    ("MUST in a blockquote", append(SPEC, "\n> Readers MUST reject it.\n"), 1, "this MUST has no id"),
    # The id follows the closing `**`, so the check must read past it to find the marker.
    (
        "id after a bold keyword is found",
        append(SPEC, f"\nReaders **MUST**{marker('IOP-37')} reject it.\n"),
        1,
        f"IOP-37 is not in {INDEX}",
    ),
    # Opened after the file's last fenced block, so nothing closes it and IOP-36 would be hidden.
    (
        "unclosed fence",
        edit(SPEC, "SDK implementations (cachekit-py", "```text\nSDK implementations (cachekit-py"),
        1,
        "unclosed code fence",
    ),
    # --- keywords that are not requirements need no id ---
    ("MUST in inline code", append(SPEC, "\nThe keyword `MUST` is written in capitals.\n"), 0, OK),
    # A keyword inside a block is an error, so a misread block fails instead of hiding text.
    ("MUST in a code fence", append(SPEC, "\n```text\nMUST\n```\n"), 1, "sits inside the code fence opened at line"),
    # The exemption must sit on the line right before the fence, not anywhere above it.
    (
        "not-a-requirement marker that is not right before the fence",
        append(SPEC, "\n<!-- not-a-requirement -->\n\nSome text.\n\n```text\nMUST\n```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    (
        "MUST in a code fence marked not-a-requirement",
        both(append(SPEC, "\n<!-- not-a-requirement -->\n```text\nMUST\n```\n"), report),
        0,
        OK,
    ),
    (
        "MUST in an HTML comment block",
        append(SPEC, "\n<!--\nnote: readers MUST\n-->\n"),
        1,
        "sits inside the HTML comment opened at line",
    ),
    # A 4-space-indented ``` or <!-- is an indented code block, not a fence or comment opener, and a
    # quote's fence closes where the quote ends: the prose after each is prose, as GitHub renders it.
    (
        "prose between two indented fence-like lines",
        append(SPEC, "\n    ```\n\nReaders MUST reject it.\n\n    ```\n"),
        1,
        "this MUST has no id",
    ),
    (
        "prose after a blockquote that ends its fence",
        append(SPEC, "\n> ```text\n> code\n\nReaders MUST reject it.\n\n> ```\n"),
        1,
        "this MUST has no id",
    ),
    (
        "prose after an indented comment opener",
        append(SPEC, "\n    <!--\nReaders MUST reject it.\n    -->\n"),
        1,
        "this MUST has no id",
    ),
    (
        "MUST in an indented code block",
        append(SPEC, "\n    Readers MUST reject it.\n"),
        1,
        "sits inside the indented code block",
    ),
    (
        "stray backtick in a table row without leading pipes",
        append(SPEC, "\nh1 | h2 | h3\n--- | --- | ---\na ` b | Readers MUST reject it | `x`\n"),
        1,
        "this MUST has no id",
    ),
    ("MUST in an HTML comment", append(SPEC, "\n<!-- MUST -->\n"), 0, OK),
    # The report lists every exemption, so it is regenerated here.
    (
        "MUST marked not-a-requirement",
        both(append(SPEC, "\nThis names the word MUST<!-- not-a-requirement --> only.\n"), report),
        0,
        OK,
    ),
    # --- ids are well-formed, unique and beside a keyword ---
    ("id used twice", edit(SPEC, marker("IOP-26"), marker("IOP-25")), 1, "IOP-25 is already used at line"),
    (
        "marker beside no keyword",
        append(SPEC, f"\nSome text{marker('IOP-37')}.\n"),
        1,
        "IOP-37 is not beside a MUST or MUST NOT",
    ),
    (
        "anchor does not match the id",
        edit(SPEC, IOP3, '<sup id="iop-30">IOP-3</sup>'),
        1,
        'anchor id="iop-30" does not match IOP-3',
    ),
    ("marker without its anchor", edit(SPEC, IOP3, "<sup>IOP-3</sup>"), 1, "malformed id marker"),
    ("id with another file's prefix", edit(SPEC, IOP3, marker("KEY-3")), 1, "KEY-3 does not use this file's prefix IOP"),
    # --- every id is in the index, and the index matches the spec ---
    ("index entry deleted", index(lambda s: s["requirements"].pop("IOP-5")), 1, f"IOP-5 is not in {INDEX}"),
    (
        "index entry for an id the spec does not carry",
        index(lambda s: s["requirements"].__setitem__("IOP-99", s["requirements"]["IOP-4"])),
        1,
        "IOP-99 is indexed but no MUST or MUST NOT",
    ),
    ("duplicate key in the index", duplicate_key, 1, "duplicate key(s) ['IOP-1']"),
    (
        "heading renamed above an id",
        edit(SPEC, "### Segment grammar\n", "### Segment syntax\n"),
        1,
        "but the id sits under the heading 'Segment syntax'",
    ),
    ("unknown field", entry("IOP-1", vector=["interop-mode.json"]), 1, "unknown field(s) ['vector']"),
    ("unknown binds", entry("IOP-1", binds="client"), 1, "binds must be one of"),
    ("sdks names an SDK sdks.json does not list", entry("IOP-12", sdks=["cachekit-go"]), 1, "names 'cachekit-go'"),
    (
        "sdks on a requirement that binds the server",
        entry("IOP-12", binds="server"),
        1,
        "sdks narrows a requirement that binds SDKs",
    ),
    ("empty vectors list", entry("IOP-4", vectors=[]), 1, "must be a non-empty list"),
    # --- every mapping names something that exists ---
    ("entry maps to nothing", entry("IOP-4", vectors=None, gap=None), 1, "maps to no vector and no test, and records no gap"),
    (
        "vector name misspelt",
        entry("IOP-9", vectors=["interop-mode.json:reject_int_overflowed"]),
        1,
        "has no vector named 'reject_int_overflowed'",
    ),
    # Every defect is reported, not just the first: the second misspelt name must be named too.
    (
        "two misspelt vectors in one entry",
        entry("IOP-9", vectors=["interop-mode.json:reject_int_overflowed", "interop-mode.json:reject_nan_twice"]),
        1,
        "has no vector named 'reject_nan_twice'",
    ),
    (
        "fixture that does not exist",
        entry("IOP-36", vectors=["interop-modes.json"]),
        1,
        "no fixture test-vectors/interop-modes.json",
    ),
    (
        "test name that does not exist",
        entry("IOP-10", tests=["tools/interop-reference.py:_selfcheck"]),
        1,
        "defines no function '_selfcheck'",
    ),
    ("test file that does not exist", entry("IOP-10", tests=["tools/no-such-tool.py:main"]), 1, "no file tools/no-such-tool.py"),
    # The word is in the file (in a comment), but nothing defines it.
    (
        "test name that only appears in a comment",
        entry("IOP-10", tests=["tools/interop-reference.py:serde_json"]),
        1,
        "defines no function 'serde_json'",
    ),
    (
        "test in a file that is neither .py nor .mjs",
        both(
            lambda root: (root / "tools/notes.txt").write_text("def x():\n", encoding="utf-8"),
            entry("IOP-10", tests=["tools/notes.txt:x"]),
        ),
        1,
        "name a .py or .mjs tool",
    ),
    # A diagnostic label, a comment or a docstring is not a test: only a definition counts.
    (
        "mjs test cited by its FAIL label",
        entry("IOP-10", tests=["tools/interop-crosscheck.mjs:lone_surrogate_selftest"]),
        1,
        "defines no function 'lone_surrogate_selftest'",
    ),
    (
        "mjs test cited by a word in a comment",
        both(
            append("tools/interop-crosscheck.mjs", "\n// the function probe is gone\n"),
            entry("IOP-10", tests=["tools/interop-crosscheck.mjs:probe"]),
        ),
        1,
        "defines no function 'probe'",
    ),
    (
        "mjs test defined only inside a block comment",
        both(
            append("tools/interop-crosscheck.mjs", "\n/*\nfunction phantom() {}\n*/\n"),
            entry("IOP-10", tests=["tools/interop-crosscheck.mjs:phantom"]),
        ),
        1,
        "defines no function 'phantom'",
    ),
    (
        "mjs test defined only inside a template literal",
        both(
            append("tools/interop-crosscheck.mjs", "\nconst note = `\nfunction phantom() {}\n`;\n"),
            entry("IOP-10", tests=["tools/interop-crosscheck.mjs:phantom"]),
        ),
        1,
        "defines no function 'phantom'",
    ),
    # A comment opener inside a string (past an escaped quote) or a regular expression (after `=` or
    # `return`, or in a character class) opens no comment, nor does a backtick in a line comment open
    # a template: each misread would blank the test after it.
    (
        "mjs test after strings and regexes holding comment openers",
        both(
            append(
                "tools/interop-crosscheck.mjs",
                "\nconst slashes = /\\/*/;\nconst again = () => { return /\\/*/; };\nconst klass = /[/]/*2;\n"
                'const opener = "\\"/*";\n// a lone ` in a comment\nfunction realProbe() {}\n',
            ),
            entry("IOP-10", tests=["tools/interop-crosscheck.mjs:realProbe"]),
            report,
        ),
        0,
        OK,
    ),
    (
        "py test cited by a def inside a docstring",
        both(
            append("tools/interop-reference.py", '\n"""\ndef phantom():\n"""\n'),
            entry("IOP-10", tests=["tools/interop-reference.py:phantom"]),
        ),
        1,
        "defines no function 'phantom'",
    ),
    (
        "py tool that does not parse",
        both(
            lambda root: (root / "tools/broken.py").write_text("def x(:\n", encoding="utf-8"),
            entry("IOP-10", tests=["tools/broken.py:x"]),
        ),
        1,
        "does not parse",
    ),
    ("test reference outside tools/", entry("IOP-10", tests=["spec/interop-mode.md:MUST"]), 1, "is not tools/<file>:<name>"),
    ("empty gap", entry("IOP-6", gap=""), 1, "gap must be a non-empty one-line reason"),
    ("multi-line gap", entry("IOP-6", gap="two\nlines"), 1, "gap must be a non-empty one-line reason"),
    ("duplicate vector name in a fixture", duplicate_vector, 1, "duplicate vector name 'reject_nan'"),
    # A directory where a fixture should be: unreadable for any user, root included.
    (
        "fixture that cannot be read",
        unreadable("test-vectors/file-backend.json"),
        1,
        "test-vectors/file-backend.json: cannot read",
    ),
    # --- retired ids stay out of the spec ---
    (
        "retired id still in the spec",
        index(lambda s: s["retired"].__setitem__("IOP-36", "x") or s["requirements"].pop("IOP-36")),
        1,
        "IOP-36 is retired",
    ),
    (
        "id both indexed and retired",
        index(lambda s: s["retired"].__setitem__("IOP-36", "x")),
        1,
        "IOP-36 is both indexed and retired",
    ),
    # --- the vendored fixture copies resolve ---
    ("vendored sha256 from no revision", first_sdk_fixture(rehash), 1, "matches no revision"),
    (
        "vendored fixture that does not exist",
        first_sdk_fixture(rename_fixture),
        1,
        "no fixture test-vectors/no-such-fixture.json",
    ),
    (
        "sdks.json commit is not a full sha",
        sdks(lambda d: d[next(iter(d))].__setitem__("commit", "abc123")),
        1,
        "commit must be a full 40-character sha",
    ),
    # --- the report is regenerated, never hand-edited ---
    ("report edited by hand", append(REPORT, "\nHand-written note.\n"), 1, STALE),
    ("report deleted", lambda root: (root / REPORT).unlink(), 1, STALE),
    (
        "vector changed but report not regenerated",
        entry("IOP-25", vectors=["decode-bounds.json:nested_fixarray_depth_32"]),
        1,
        STALE,
    ),
    # --- keywords the way a renderer shows them ---
    ("MUST in underscore emphasis", append(SPEC, "\nReaders _MUST_ reject it.\n"), 1, "this MUST has no id"),
    ("MUST NOT in double-underscore emphasis", append(SPEC, "\nReaders __MUST NOT__ guess.\n"), 1, "this MUST NOT has no id"),
    ("bold MUST then NOT", append(SPEC, "\nReaders **MUST** NOT crash.\n"), 1, "this MUST NOT has no id"),
    ("MUST NOT across blockquote lines", append(SPEC, "\n> Readers MUST\n> NOT crash.\n"), 1, "this MUST NOT has no id"),
    (
        "id after an italic keyword is found",
        append(SPEC, f"\nReaders *MUST*{marker('IOP-37')} reject it.\n"),
        1,
        f"IOP-37 is not in {INDEX}",
    ),
    (
        "id after a bold italic keyword is found",
        append(SPEC, f"\nReaders ***MUST***{marker('IOP-37')} reject it.\n"),
        1,
        f"IOP-37 is not in {INDEX}",
    ),
    (
        "id between MUST and NOT",
        append(SPEC, f"\nReaders MUST{marker('IOP-37')} NOT crash.\n"),
        1,
        "IOP-37 sits between MUST and NOT",
    ),
    (
        "not-a-requirement marker that is not beside its keyword",
        append(SPEC, "\nThis names MUST in passing. <!-- not-a-requirement -->\n"),
        1,
        "this MUST has no id",
    ),
    # MUST and NOT are one keyword only where GitHub shows them as one phrase. Where NOT starts
    # another block, or a literal > parts the two, MUST stands alone and needs its own id, even
    # when the id after NOT is indexed.
    (
        "MUST and NOT in two paragraphs",
        both(
            append(SPEC, f"\n## Phrase\n\nReaders MUST\n\nNOT{marker('IOP-37')} accept unauthenticated bytes.\n"),
            new_requirement("IOP-37", "Phrase"),
        ),
        1,
        "this MUST has no id",
    ),
    (
        "MUST in a heading, NOT after it",
        append(SPEC, f"\n### Readers MUST\nNOT{marker('IOP-37')} crash.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "NOT in a blockquote after MUST",
        append(SPEC, f"\nReaders MUST\n> NOT{marker('IOP-37')} crash.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "MUST and NOT in two table rows",
        append(SPEC, f"\n| a | b |\n| - | - |\n| Readers MUST\nNOT{marker('IOP-37')} crash | c |\n"),
        1,
        "this MUST has no id",
    ),
    (
        "literal > between MUST and NOT",
        append(SPEC, f"\nReaders MUST > NOT{marker('IOP-37')} crash.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "literal > ending MUST's line",
        append(SPEC, f"\nReaders MUST >\nNOT{marker('IOP-37')} crash.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "literal > on an indented continuation line",
        append(SPEC, f"\nReaders MUST\n    > NOT{marker('IOP-37')} crash.\n"),
        1,
        "this MUST has no id",
    ),
    ("MUST NOT across a lazy continuation line", append(SPEC, "\n> Readers MUST\nNOT crash.\n"), 1, "this MUST NOT has no id"),
    ("MUST NOT across a setext heading's lines", append(SPEC, "\nReaders MUST\nNOT crash\n---\n"), 1, "this MUST NOT has no id"),
    # On one line the words join in any block: IOP-6 is a MUST NOT in a table row.
    (
        "MUST NOT in one table cell",
        append(SPEC, "\n| a | b |\n| - | - |\n| Readers MUST NOT crash | c |\n"),
        1,
        "this MUST NOT has no id",
    ),
    # A pre block keeps its line breaks, and the check tracks no HTML elements, so two lines of an HTML block
    # never join: the id after NOT does not mark the MUST, which needs its own.
    (
        "MUST and NOT on two lines of a pre block",
        append(SPEC, f"\n<pre>\nReaders MUST\nNOT{marker('IOP-37')} crash.\n</pre>\n"),
        1,
        "this MUST has no id",
    ),
    # A line of non-breaking spaces is not blank, so the quote's paragraph runs on and GitHub shows one phrase,
    # across two line breaks and past the quote markers. A literal > on a line between the words shows.
    (
        "MUST NOT across a line of non-breaking spaces in a blockquote",
        append(SPEC, f"\n> Readers MUST\n> {NBSP}\n> NOT crash.\n"),
        1,
        "this MUST NOT has no id",
    ),
    (
        "id between MUST and NOT across a line of non-breaking spaces",
        append(SPEC, f"\nReaders MUST{marker('IOP-37')}\n{NBSP}\nNOT crash.\n"),
        1,
        "IOP-37 sits between MUST and NOT",
    ),
    (
        "literal > on a line between MUST and NOT",
        append(SPEC, f"\nReaders MUST\n    >\nNOT{marker('IOP-37')} crash.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "id after MUST, with NOT opening the next paragraph",
        both(
            append(SPEC, f"\n## Phrase\n\nReaders MUST{marker('IOP-37')}\n\nNOT that one.\n"),
            new_requirement("IOP-37", "Phrase"),
            report,
        ),
        0,
        OK,
    ),
    # Within a paragraph a line break renders as a space, so the id after a NOT on the next line marks the MUST NOT.
    (
        "id after NOT on the line after MUST",
        both(
            append(SPEC, f"\n## Phrase\n\nReaders MUST\nNOT{marker('IOP-37')} crash.\n"),
            new_requirement("IOP-37", "Phrase"),
            report,
        ),
        0,
        OK,
    ),
    # Pipe-led lines with no delimiter row are a paragraph, so this span runs from the first line
    # to the third and the keyword is inside it, as GitHub renders it.
    (
        "pipe-led lines without a delimiter row",
        append(SPEC, "\n| a | a lone ` is literal |\n| b | Readers MUST reject them |\n| c | see `x` |\n"),
        0,
        OK,
    ),
    (
        "stray backtick in a list",
        append(SPEC, "\n- a lone ` backtick\n- Readers MUST reject it\n- see `x`\n"),
        1,
        "this MUST has no id",
    ),
    (
        "stray backtick in a heading",
        append(SPEC, "\n### The ` character\nReaders MUST reject it; see `x`.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "escaped backtick opens no code span",
        append(SPEC, "\nA key may hold a \\` character, and readers MUST reject `x`.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "backtick inside a longer run opens no code span",
        append(SPEC, "\nType ``` then readers MUST reject `x` here.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "comment opener in prose",
        append(SPEC, "\nThe <!-- sequence opens a comment.\n\nReaders MUST reject it.\n\n<!-- end -->\n"),
        1,
        "this MUST has no id",
    ),
    (
        "fence opened on a list item",
        append(SPEC, "\n2. ```json\n   {}\n   ```\n\nReaders MUST reject it.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "fence-like line with a backtick in its info string",
        append(SPEC, "\n```x``` is inline code.\nReaders MUST reject it.\n"),
        1,
        "this MUST has no id",
    ),
    # A closing fence may sit at any indent up to 3 spaces, whatever the opener's: the fence closes here.
    (
        "fence closed at a different indent",
        append(SPEC, "\n  ```text\ncode\n```\nReaders MUST reject it.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "fence inside a comment block",
        append(SPEC, "\n<!--\n```json\n-->\n\nReaders MUST reject it.\n\n```text\nx\n```\n"),
        1,
        "this MUST has no id",
    ),
    ("unclosed comment block", append(SPEC, "\n<!--\nReaders MUST reject it.\n"), 1, "unclosed HTML comment"),
    # Inside a fence, only a line of the same character, at least as long and with no info string, closes it.
    (
        "4-backtick fence holding a 3-backtick line",
        append(SPEC, "\n````text\n```\nMUST inside\n````\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    (
        "backtick fence holding a tilde line",
        append(SPEC, "\n```text\n~~~\nMUST inside\n```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    (
        "fence holding a line with an info string",
        append(SPEC, "\n```text\n```inner\nMUST inside\n```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    (
        "fence in a blockquote",
        append(SPEC, "\n> ```text\n> MUST inside\n> ```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    # GFM splits a table row into cells before it finds code spans, so a backtick cannot pair across cells.
    (
        "stray backtick in one table cell",
        append(SPEC, "\n| h1 | h2 | h3 |\n| --- | --- | --- |\n| a ` b | Readers MUST reject it | `x` |\n"),
        1,
        "this MUST has no id",
    ),
    # A table body runs to the first blank line; a row needs no pipe.
    (
        "table row after a row without pipes",
        append(SPEC, "\n| a | b |\n| - | - |\nx\n`c | MUST | y`\n"),
        1,
        "this MUST has no id",
    ),
    # Header and delimiter rows with different cell counts make no table: these lines are a paragraph.
    (
        "header and delimiter cell counts differ",
        append(SPEC, "\na | b | c\n--- | ---\nx ` y | ` MUST `\n"),
        1,
        "this MUST has no id",
    ),
    # A blank line ends a table, so the paragraph after it is masked as a paragraph.
    (
        "paragraph after a table and a blank line",
        append(SPEC, "\n| a | b |\n| - | - |\n| c | d |\n\nUse `a | b` and MUST `c`.\n"),
        1,
        "this MUST has no id",
    ),
    # A blockquote interrupts a paragraph, so no code span runs into it: the keyword here sits
    # inside the quote's own span, as GitHub renders it.
    ("blockquote after a paragraph line", append(SPEC, "\nText `x\n> y` MUST `z`\n"), 0, OK),
    # A code span may cross a line break inside a paragraph.
    ("code span across a line break", append(SPEC, "\nA key `x\ny` MUST `z` here.\n"), 1, "this MUST has no id"),
    ("MUST inside a code span across a line break", append(SPEC, "\nUse `a\nMUST b` here.\n"), 0, OK),
    ("code span across a list item's continuation", append(SPEC, "\n- item `x\n  y` MUST `z`\n"), 1, "this MUST has no id"),
    (
        "stray backtick in a blockquote paragraph",
        append(SPEC, "\n> a lone ` backtick\n>\n> Readers MUST reject it, see `x`.\n"),
        1,
        "this MUST has no id",
    ),
    # Only a fence at column 0, outside every container, can be exempted.
    (
        "exemption before an indented code block",
        append(SPEC, "\n<!-- not-a-requirement -->\n    MUST inside\n"),
        1,
        "sits inside the indented code block",
    ),
    (
        "exemption before a quoted fence",
        append(SPEC, "\n<!-- not-a-requirement -->\n> ```text\n> MUST inside\n> ```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    (
        "exemption before a fence in a list item",
        append(SPEC, "\n<!-- not-a-requirement -->\n- ```text\n  MUST inside\n  ```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    # A fence inside an HTML block that no blank line has closed is raw HTML text, so the
    # exemption before it exempts nothing and the keyword shows.
    (
        "fence inside an open HTML block",
        append(SPEC, "\n<details>\n<!-- not-a-requirement -->\n```text\nReaders MUST reject it.\n```\n</details>\n"),
        1,
        "this MUST has no id",
    ),
    # Without a delimiter row the line is a paragraph, and the keyword sits inside a code span.
    ("pipe-led line without a delimiter row", append(SPEC, "\n| a ` b | Readers MUST reject it | `x` |\n"), 0, OK),
    # A one-backtick span closes only at a run of exactly one backtick: MUST is inside the code here.
    ("code span closed only by an equal run", append(SPEC, "\nUse `x``` MUST `y` here.\n"), 0, OK),
    ("setext heading", edit(SPEC, "### Segment grammar\n", "Segment grammar\n---------------\n"), 0, OK),
    ("retired id with an empty reason", index(lambda s: s["retired"].__setitem__("IOP-99", "")), 1, "retired must map each id"),
    ("text after a comment block closes", append(SPEC, "\n<!--\nnote\n--> Readers MUST reject it.\n"), 1, "this MUST has no id"),
    ("heading with closing hashes", edit(SPEC, "### Decode bounds\n", "### Decode bounds ###\n"), 0, OK),
    # --- block structure, as GitHub's renderer builds it: a code span pairs only inside one block ---
    # An HTML block interrupts a paragraph, so no code span runs across its first line.
    (
        "comment line ends a paragraph",
        append(SPEC, "\nA lone ` backtick\n<!-- note -->\nReaders MUST reject it, see `x`.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "HTML block start ends a paragraph",
        append(SPEC, "\nA lone ` backtick\n<div>\nReaders MUST reject it, see `x`.\n</div>\n"),
        1,
        "this MUST has no id",
    ),
    # An HTML block is raw HTML up to a blank line: a backtick there is a backtick, not code.
    ("MUST in backticks inside an HTML block", append(SPEC, "\n<div>\n`MUST`\n</div>\n"), 1, "this MUST has no id"),
    # A run of dashes, even one or two, under a paragraph line makes it a heading.
    (
        "two-dash underline ends a paragraph",
        append(SPEC, "\nA lone ` backtick\n--\nReaders MUST reject it, see `x`.\n"),
        1,
        "this MUST has no id",
    ),
    # A lazy continuation line cannot be an underline, so this quote paragraph runs on and its span hides MUST.
    (
        "two-dash line continuing a quote paragraph",
        append(SPEC, "\n> A lone ` backtick\n--\nReaders MUST reject it ` here.\n"),
        0,
        OK,
    ),
    # Only a list item that starts at 1 and holds text interrupts a paragraph; these lines continue it.
    ("ordered marker 2 inside a paragraph", append(SPEC, "\nA lone ` backtick\n2. Readers MUST reject it ` here.\n"), 0, OK),
    # Splitting there instead would pair the second line's own backticks around MUST and hide it.
    (
        "ordered marker 2 inside a paragraph, keyword between backticks",
        append(SPEC, "\nA lone ` backtick\n2. so ` MUST ` here\n"),
        1,
        "this MUST has no id",
    ),
    ("empty bullet inside a paragraph", append(SPEC, "\nA lone ` backtick\n*\nReaders MUST reject it ` here.\n"), 0, OK),
    # A line that leaves the list item or quote its paragraph sits in is no continuation: 2. starts a list.
    (
        "ordered marker 2 after a list item",
        append(SPEC, "\n1. A lone ` backtick\n2. Readers MUST reject it, see ` here.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "ordered marker 2 after a blockquote",
        append(SPEC, "\n> A lone ` backtick\n2. Readers MUST reject it, see ` here.\n"),
        1,
        "this MUST has no id",
    ),
    # A table ends with the list item it sits in; the dedented lines are a paragraph.
    (
        "table body ends with its list item",
        append(SPEC, "\n- item\n  | a | b |\n  | - | - |\n  | c | d |\ndedented ` text\n`MUST` here\n"),
        1,
        "this MUST has no id",
    ),
    # A header row must continue every container of its paragraph; these lines are all one list paragraph.
    (
        "header lazily continuing a list paragraph",
        append(SPEC, "\n- item ` text\n| a | b |\n| - | - |\n| `MUST` | c |\n"),
        1,
        "this MUST has no id",
    ),
    ("HTML block ends a table body", append(SPEC, "\n| a | b |\n| - | - |\n<div>\n`MUST`\n</div>\n"), 1, "this MUST has no id"),
    # A table body runs to the first blank line or line that starts another block, such as a list item.
    ("list item ends a table body", append(SPEC, "\n| a | b |\n| - | - |\n- a `\n  b | `MUST` |\n"), 1, "this MUST has no id"),
    # A one-column table needs no pipe; each row is one cell, so neither backtick pairs.
    ("one-column table without pipes", append(SPEC, "\na `\n:-:\nReaders MUST reject it `\n"), 1, "this MUST has no id"),
    # cmark-gfm tries a paragraph as a table once: after a delimiter row with the wrong cell count,
    # a later matching one makes no table, and the paragraph's span leaves MUST outside it.
    (
        "paragraph whose first delimiter row failed",
        append(SPEC, "\na | b\n--- | --- | ---\nc ` | d\n--- | ---\n`MUST` | e\n"),
        1,
        "this MUST has no id",
    ),
    # Container rules: how far a line must be indented to stay in a list item or blockquote decides
    # whether it is prose there, prose outside, or an indented code block.
    (
        "quote marker indented four spaces",
        append(SPEC, "\n> a\n>\n    > Readers MUST reject it.\n"),
        1,
        "sits inside the indented code block",
    ),
    ("blockquote takes one space after its marker", append(SPEC, "\n>    Readers MUST reject it.\n"), 1, "this MUST has no id"),
    ("indented line continuing a paragraph", append(SPEC, "\nReaders reject it\n    MUST here.\n"), 1, "this MUST has no id"),
    (
        "line indented less than its list item leaves it",
        append(SPEC, "\n- ```\n code: Readers MUST reject it.\n  ```\n```\n"),
        1,
        "this MUST has no id",
    ),
    (
        "blank line ends an empty list item",
        append(SPEC, "\n-\n\n    Readers MUST reject it.\n"),
        1,
        "sits inside the indented code block",
    ),
    ("blank line inside a list item", append(SPEC, "\n- a\n\n    Readers MUST reject it.\n"), 1, "this MUST has no id"),
    (
        "list item content after a three-space gap",
        append(SPEC, "\n-   a\n\n      Readers MUST reject it.\n"),
        1,
        "this MUST has no id",
    ),
    (
        "list item opening with indented code",
        append(SPEC, "\n-      Readers MUST reject it.\n"),
        1,
        "sits inside the indented code block",
    ),
    ("bare quote marker ends a paragraph", append(SPEC, "\nA lone ` backtick\n>\nso ` MUST ` here\n"), 0, OK),
    # Interrupting blocks: each ends the paragraph, so the span pairs on the next line and hides MUST.
    ("thematic break ends a paragraph", append(SPEC, "\nA lone ` backtick\n***\nso ` MUST ` here\n"), 0, OK),
    ("ordered marker 1 ends a paragraph", append(SPEC, "\nA lone ` backtick\n1. so ` MUST ` here\n"), 0, OK),
    # A line holding one tag (HTML block type 7) cannot interrupt a paragraph; after a blank line it opens a raw block.
    ("tag line inside a paragraph", append(SPEC, "\nA lone ` backtick\n<span>\nReaders MUST reject it ` here.\n"), 0, OK),
    ("tag line opening an HTML block", append(SPEC, "\n<span>\n`MUST`\n</span>\n"), 1, "this MUST has no id"),
    # Two dashes under a paragraph line make a heading, not a one-column table, so the next lines are a paragraph.
    (
        "two-dash underline is not a delimiter row",
        append(SPEC, "\nTitle\n--\nA lone ` backtick\nReaders MUST reject it ` here.\n"),
        0,
        OK,
    ),
    # A table takes the paragraph's last line as its header; the lines before it stay a paragraph.
    (
        "table header row leaves its paragraph",
        append(SPEC, "\nReaders ` MUST reject it\n| b ` | c |\n| - | - |\n"),
        1,
        "this MUST has no id",
    ),
    ("trailing pipe on one table row only", append(SPEC, "\n| a ` | b\n| - | - |\n| MUST ` | c\n"), 1, "this MUST has no id"),
    # A delimiter row inside a blockquote the line opens cannot turn the paragraph before it into a table.
    ("delimiter row inside a new blockquote", append(SPEC, "\n| a ` | MUST ` |\n> | - | - |\n"), 0, OK),
    # A closing fence is indented at most 3 spaces and holds nothing but the fence.
    (
        "fence closer indented four spaces",
        append(SPEC, "\n```text\ncode\n    ```\nMUST inside\n```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    (
        "fence closer with an info string",
        append(SPEC, "\n```text\n``` inner\nMUST inside\n```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    # An HTML block passes through as it stands, so a comment it leaves open hides the rest of the file.
    (
        "comment left open in an HTML block",
        append(SPEC, "\n<div>\n<!-- note\n\nReaders MUST reject it.\n"),
        1,
        "unclosed HTML comment",
    ),
    ("tab in a spec file", append(SPEC, "\n\tReaders MUST reject it.\n"), 1, "a tab; indent with spaces"),
    # Only spaces make a line blank, so a line of non-breaking spaces keeps an HTML block open and is a table row.
    (
        "line of non-breaking spaces in an HTML block",
        append(SPEC, f"\n<div>\n{NBSP}\n`MUST`\n</div>\n"),
        1,
        "this MUST has no id",
    ),
    (
        "line of non-breaking spaces in a table body",
        append(SPEC, f"\n| a | b |\n| - | - |\n{NBSP}\n| `MUST | x` |\n"),
        1,
        "this MUST has no id",
    ),
    # A non-breaking space after a header row's last pipe is one more cell, so no table forms and the span hides MUST.
    (
        "non-breaking space after a header row's last pipe",
        append(SPEC, f"\n| a ` | b |{NBSP}\n| - | - |\n| MUST ` | c |\n"),
        0,
        OK,
    ),
    # GitHub ends a line at a lone carriage return, and reads a form feed or vertical tab as space only in some places.
    (
        "lone carriage return",
        append(SPEC, "\nIntro text\r<div>\r`x MUST y`\n"),
        1,
        "a carriage return that does not end a CRLF line",
    ),
    (
        "form feed after a delimiter row",
        append(SPEC, "\n| a ` | b |\n| - | - |\f\n| MUST ` | c |\n"),
        1,
        "a vertical tab or form feed",
    ),
    ("vertical tab in a spec file", append(SPEC, "\nReaders\vMUST reject it.\n"), 1, "a vertical tab or form feed"),
    ("spec checked out with CRLF line endings", crlf(SPEC), 0, OK),
    # The exemption is the marker alone on its line, trailing spaces aside: a non-breaking space is text.
    (
        "exemption marker followed by a non-breaking space",
        append(SPEC, f"\n<!-- not-a-requirement -->{NBSP}\n```text\nMUST\n```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    # --- definitions: GitHub moves or hides their text, which the check does not model, so they are errors ---
    # A footnote definition interrupts a paragraph, and GitHub moves it to the end of the page (or drops it when
    # nothing cites it). Read as part of the paragraph, the stray backtick before it would hide MUST.
    (
        "footnote definition interrupting a paragraph",
        append(SPEC, "\nSee the note[^1]. A lone ` backtick\n[^1]: Readers MUST reject it ` here.\n"),
        1,
        "a footnote definition",
    ),
    # A footnote label holds no space and is never empty, and a definition opens its line, indented less than four
    # spaces: these lines are text.
    (
        "footnote-like lines that are text",
        append(SPEC, "\nA lone ` backtick\n[^a b]: one [^1]: two\n    [^1]: three\n[^]: four, readers MUST reject it ` here.\n"),
        0,
        OK,
    ),
    # A link reference definition opens a paragraph or heading, and GitHub shows none of it, so a backtick in its
    # title or label opens no code span. Its label may span lines and hold an escaped bracket.
    (
        "link reference definition with a backtick in its title",
        append(SPEC, '\n[a]: /u "`"\nReaders MUST reject it `x`.\n'),
        1,
        "a link reference definition",
    ),
    (
        "link reference definition whose label spans lines",
        append(SPEC, "\n[a`\nb]: /u\nReaders MUST reject it `.\n"),
        1,
        "a link reference definition",
    ),
    (
        "link reference definition indented in a blockquote, with an escaped bracket",
        append(SPEC, "\n>   [a\\]`]: /u\n> Readers MUST reject it `.\n"),
        1,
        "a link reference definition",
    ),
    (
        "link reference definition opening a setext heading",
        append(SPEC, '\n[a]: /u "`"\nReaders MUST `x\n---\n'),
        1,
        "a link reference definition",
    ),
    # Inside a paragraph a bracketed label and a colon are text, so the span hides MUST, as on GitHub.
    (
        "bracketed label and colon inside a paragraph",
        append(SPEC, '\nIntro line\n[a]: /u "`"\nReaders MUST reject it `x`.\n'),
        0,
        OK,
    ),
    # --- ids are never reused: next only grows ---
    (
        "new id at or above next",
        both(
            append(SPEC, f"\nReaders MUST{marker('IOP-37')} reject it.\n"),
            index(lambda s: s["requirements"].__setitem__("IOP-37", {"section": "Test Vectors", "binds": "sdk", "gap": "t"})),
        ),
        1,
        "IOP-37 is at or above next (37)",
    ),
    (
        # Dropping IOP-36 must not make the hint offer its number again.
        "hint skips a dropped id",
        both(
            edit(SPEC, f"MUST{marker('IOP-36')}", "should"),
            index(lambda s: s["requirements"].pop("IOP-36")),
            append(SPEC, "\nReaders MUST reject it.\n"),
        ),
        1,
        "the next free id is IOP-37",
    ),
    ("next missing", index(lambda s: s.pop("next")), 1, "next must be the number the next new id gets"),
    # A lead-in's entry may list vectors its items' entries list too: only its gap is limited to what no item owns.
    (
        "lead-in and item entries mapping the same vector",
        both(
            append(
                SPEC,
                f"\n## Lead-in\n\nA reader MUST{marker('IOP-37')}:\n\n"
                f"- reject NaN, and it MUST{marker('IOP-38')} say so.\n",
            ),
            new_requirement("IOP-37", "Lead-in"),
            new_requirement("IOP-38", "Lead-in"),
            entry("IOP-37", vectors=["interop-mode.json:reject_nan"], gap=None),
            entry("IOP-38", vectors=["interop-mode.json:reject_nan"], gap=None),
            report,
        ),
        0,
        OK,
    ),
    (
        "gap naming an id that is not indexed",
        entry("IOP-6", gap="See IOP-99."),
        1,
        "gap names IOP-99, which is not an indexed requirement",
    ),
    # --- malformed index and sdks.json shapes are reported, never a traceback ---
    ("binds given as a list", entry("IOP-1", binds=["sdk"]), 1, "binds must be one of"),
    ("index lists no spec file", files(lambda f: f.clear()), 1, "lists no spec file"),
    (
        "non-spec file indexed",
        files(lambda f: f.__setitem__("README.md", {"prefix": "RM", "requirements": {}})),
        1,
        "must be a spec/*.md file",
    ),
    (
        "two files with one prefix",
        files(lambda f: f.__setitem__("spec/file-backend-format.md", {"prefix": "IOP", "requirements": {}})),
        1,
        "prefix IOP is already used",
    ),
    ("unknown field on an indexed file", index(lambda s: s.__setitem__("prefixes", "IOP")), 1, "unknown field(s) ['prefixes']"),
    ("retired is not a map", index(lambda s: s.__setitem__("retired", ["IOP-99"])), 1, "retired must map each id"),
    (
        "retired id malformed",
        index(lambda s: s["retired"].__setitem__("IOP-07", "x")),
        1,
        "'IOP-07' is not an id of the form IOP-<n>",
    ),
    (
        "vector listed twice",
        entry("IOP-4", vectors=["interop-mode.json:reservation_scope", "interop-mode.json:reservation_scope"]),
        1,
        "lists an entry twice",
    ),
    (
        "test name that is only a prefix of a real one",
        entry("IOP-10", tests=["tools/interop-reference.py:_self_che"]),
        1,
        "defines no function '_self_che'",
    ),
    (
        "sdks.json repository that is not https",
        sdks(lambda d: d["cachekit-py"].__setitem__("repository", "http://example.invalid")),
        1,
        "repository must be an https URL",
    ),
    ("sdks.json unknown field", sdks(lambda d: d["cachekit-py"].__setitem__("commits", [])), 1, "unknown field(s) ['commits']"),
    (
        "deeply nested fixture",
        lambda root: (root / "test-vectors/deep.json").write_text("[" * 200000 + "]" * 200000, encoding="utf-8"),
        1,
        "test-vectors/deep.json: not valid JSON",
    ),
    # A code span holding `<!--` must not swallow the keyword when the report quotes it.
    (
        "comment opener inside code beside a requirement",
        both(
            append(
                SPEC, f"\n## Comments\n\nA comment opens with `<!--`; a reader MUST{marker('IOP-37')} skip to the next `-->`.\n"
            ),
            new_requirement("IOP-37", "Comments"),
        ),
        1,
        STALE,
    ),
    # --- vendored copies resolve against published history only ---
    ("malformed revision no SDK vendors", malformed_revision_in_history, 0, OK),
    (
        "vendored copy from a commit not on the base",
        commit_base(lambda _: None),
        1,
        "matches no revision of test-vectors/file-backend.json",
    ),
    ("requirements not a map, with --base", commit_base(lambda _: None), 1, "expected prefix, next, requirements and retired"),
    ("next lowered since the base", commit_base(lambda _: None), 1, "next went down from 37"),
    # A copy of cachekit-py's entry under a name no index entry narrows to, so dropping it fails only here.
    (
        "SDK dropped from sdks.json since the base",
        commit_base(both(sdks(lambda d: d.__setitem__("cachekit-go", dict(d["cachekit-py"]))), report)),
        1,
        "cachekit-go was listed at HEAD and is now gone",
    ),
    # --- ids are never dropped or reused (--base) ---
    (
        "id dropped instead of retired",
        commit_base(lambda _: None),
        1,
        "IOP-36 was indexed at HEAD and is now gone; retire it instead",
    ),
    ("id retired properly", commit_base(lambda _: None), 0, "no id dropped or un-retired since HEAD"),
    ("retired id brought back", commit_base(retire("IOP-36")), 1, "IOP-36 was retired at HEAD; a retired id stays retired"),
    ("base without an index", lambda _: None, 0, "does not exist at"),
    ("base that does not exist", lambda _: None, 1, "--base no-such-ref: not a commit in this repository"),
]

# Cases whose mutation runs after the base commit, and the --base each one checks against.
AFTER_BASE: dict[str, tuple[Mutate, str]] = {
    "id dropped instead of retired": (
        both(edit(SPEC, f"MUST{marker('IOP-36')}", "should"), index(lambda s: s["requirements"].pop("IOP-36"))),
        "HEAD",
    ),
    "id retired properly": (retire("IOP-36"), "HEAD"),
    "retired id brought back": (lambda root: restore(root), "HEAD"),
    "base without an index": (lambda _: None, "BEFORE_INDEX"),
    "base that does not exist": (lambda _: None, "no-such-ref"),
    "vendored copy from a commit not on the base": (vendored_from_unmerged_commit, "HEAD~1"),
    "requirements not a map, with --base": (index(lambda s: s.__setitem__("requirements", 7)), "HEAD"),
    "next lowered since the base": (index(lambda s: s.__setitem__("next", 36)), "HEAD"),
    "SDK dropped from sdks.json since the base": (both(sdks(lambda d: d.pop("cachekit-go")), report), "HEAD"),
}

PRISTINE: Path | None = None


def restore(root: Path) -> None:
    """Put the unmodified spec, index and report back over a case's tree."""
    for rel in (SPEC, INDEX, REPORT):
        shutil.copyfile(PRISTINE / rel, root / rel)


def prepare(tmp: Path) -> Path:
    """A clone of this repository at HEAD, with the working tree's files laid over it."""
    repo = tmp / "pristine"
    subprocess.run(["git", "clone", "--quiet", "--shared", "--no-checkout", str(ROOT), str(repo)], check=True)
    git(repo, "checkout", "--quiet", "--detach", git(ROOT, "rev-parse", "HEAD").strip())
    for rel in OVERLAY:
        shutil.copytree(ROOT / rel, repo / rel, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))
    return repo


def run_case(tmp: Path, number: int, case: Case) -> bool:
    name, mutate, expected, needle, *rest = case
    args = list(rest[0]) if rest else []
    env = rest[1] if len(rest) > 1 else {}
    root = tmp / f"case-{number}"
    shutil.copytree(PRISTINE, root, symlinks=True)
    mutate(root)
    if name in AFTER_BASE:
        after, base = AFTER_BASE[name]
        after(root)
        if base == "BEFORE_INDEX":
            # The parent of the commit that added the index: every published fixture revision, no index.
            added = git(root, "log", "--diff-filter=A", "--format=%H", "--", INDEX).split()
            base = f"{added[-1]}^" if added else "HEAD"
        args += ["--base", base]
    proc = subprocess.run(
        [sys.executable, str(CHECKER), "check", *args, str(root)],
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="backslashreplace",
        env={**os.environ, **env},
    )
    output = proc.stdout + proc.stderr
    if proc.returncode == expected and needle in output:
        print(f"  ok   {name} (exit {proc.returncode})")
        return True
    print(
        f"  FAIL {name}: expected exit {expected} with {needle!r}, got {proc.returncode}\n"
        f"       stdout: {proc.stdout.strip()[:300]}\n"
        f"       stderr: {proc.stderr.strip()[:600]}"
    )
    return False


def test_shallow(tmp: Path) -> bool:
    """A shallow clone cannot match vendored copies to older revisions, so the check must refuse it."""
    shallow = tmp / "shallow"
    subprocess.run(["git", "clone", "--quiet", "--depth", "1", f"file://{PRISTINE}", str(shallow)], check=True)
    for rel in OVERLAY:
        shutil.copytree(PRISTINE / rel, shallow / rel, dirs_exist_ok=True)
    proc = subprocess.run([sys.executable, str(CHECKER), "check", str(shallow)], check=False, capture_output=True, text=True)
    good = proc.returncode == 1 and "shallow clone" in proc.stderr
    print(f"  {'ok  ' if good else 'FAIL'} shallow clone is refused (exit {proc.returncode})")
    return good


def revision_sha(root: Path, fixture: str, version: str) -> str:
    """The sha256 of the committed revision of `fixture` whose version field is `version`."""
    import hashlib

    rel = f"test-vectors/{fixture}"
    for commit in git(root, "log", "--format=%H", "--", rel).split():
        blob = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{rel}"], check=True, capture_output=True).stdout
        if json.loads(blob).get("version") == version:
            return hashlib.sha256(blob).hexdigest()
    raise SystemExit(f"test setup broken: no {fixture} revision at version {version}")


def pin(sdk: str, fixture: str, version: str | None) -> Mutate:
    """Point an SDK's copy of a fixture at an older revision, or (None) drop the copy."""

    def mutate(root: Path) -> None:
        def change(document: dict) -> None:
            if version is None:
                del document[sdk]["fixtures"][fixture]
            else:
                document[sdk]["fixtures"][fixture] = revision_sha(root, fixture, version)

        sdks(change)(root)

    return mutate


def reworded(fixture: str, name: str) -> Mutate:
    """Change one published vector in place, so every vendored copy of it is now out of date."""

    def mutate(root: Path) -> None:
        path = root / "test-vectors" / fixture
        document = json.loads(path.read_text(encoding="utf-8"))
        for vectors in (v for k, v in document.items() if k.endswith("vectors")):
            for vector in vectors:
                if vector["name"] == name:
                    vector["error"] = vector.get("error", "") + " (reworded)"
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    return mutate


def renamed_section(old: str, new: str) -> Mutate:
    """Rename a heading and every index entry that sits under it."""

    def change(spec: dict) -> None:
        for fields in spec["requirements"].values():
            if fields["section"] == old:
                fields["section"] = new

    return both(edit(SPEC, f"### {old}\n", f"### {new}\n"), index(change))


def retyped(fixture: str, name: str, path: tuple[str, ...], value: object) -> Mutate:
    """Replace one field inside a published vector with an equal-looking value of another type."""

    def mutate(root: Path) -> None:
        rel = f"test-vectors/{fixture}"
        document = json.loads((root / rel).read_text(encoding="utf-8"))
        for vectors in (v for k, v in document.items() if k.endswith("vectors")):
            for vector in vectors:
                if vector["name"] == name:
                    target = vector
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = value
        write_json(root, rel, document)

    return mutate


ROW_CELLS = 6  # Id, Requirement, Vectors-tests-gaps, and one per SDK
# Every SDK's interop-mode.json at 1.2.0, for cases whose counts must not move as SDKs re-vendor.
INTEROP_1_2_0 = tuple(pin(sdk, "interop-mode.json", "1.2.0") for sdk in ("cachekit-py", "cachekit-ts", "cachekit-rs"))
# (name, mutate(root), {requirement id: expected [cachekit-py, cachekit-ts, cachekit-rs] cells}, substrings)
# These pin what each status MEANS, independently of the code that renders it.
REPORT_CASES: list[tuple[str, Mutate, dict[str, list[str]], list[str]]] = [
    (
        "statuses on the unmodified tree",
        lambda _: None,
        {
            "IOP-5": ["partial (gap)"] * 3,
            "IOP-9": ["partial (4/8)", "partial (4/8)", "covered"],
            "IOP-17": ["partial (4/6)", "partial (4/6)", "partial (gap)"],
            "IOP-2": ["partial (3/19)", "partial (3/19)", "partial (gap)"],
            "IOP-10": ["uncovered"] * 3,
            "IOP-13": ["uncovered (0/1)", "uncovered (0/1)", "partial (gap)"],
            "ENC-4": ["gap"] * 3,  # no sdk-bound IOP requirement is gap only any more
            "IOP-6": ["n/a"] * 3,
            "IOP-14": ["n/a", "partial (3/7)", "n/a"],
        },
        # Tests-only requirements are uncovered in every SDK, so the summary counts them apart.
        ["| [`spec/interop-mode.md`](../spec/interop-mode.md) | 36 | 7 | 21 | 4 | 4 |"],
    ),
    (
        # Every SDK holds every listed vector, identical to this repo's, and no gap is recorded.
        "a requirement whose vectors every SDK holds is covered",
        entry("IOP-17", vectors=[f"interop-mode.json:{name}" for name in (
            "issue_example_object", "float_value_stays_float64", "mixed_array", "datetime_sentinel_value")], gap=None),
        {"IOP-17": ["covered"] * 3},
        [],
    ),
    (
        # Tests but no vectors: uncovered in every SDK the requirement binds, and n/a in the others.
        "a tests-only requirement that binds one SDK",
        lambda _: None,
        {"IOP-12": ["n/a", "uncovered", "n/a"], "IOP-10": ["uncovered"] * 3},
        [],
    ),
    (
        # interop-mode.json 1.1.0 predates the `..` vectors and lone_dots_stay_valid.
        "an SDK on an older revision lacks the newer vectors",
        pin("cachekit-ts", "interop-mode.json", "1.1.0"),
        {"IOP-5": ["partial (gap)", "uncovered (0/3)", "partial (gap)"], "IOP-4": ["partial (gap)"] * 3},
        [],
    ),
    (
        # Every SDK is pinned to interop-mode.json 1.2.0, so the IOP-17 control does not move as SDKs re-vendor.
        "an SDK that does not vendor a fixture holds none of its vectors",
        both(pin("cachekit-rs", "decode-bounds.json", None), *INTEROP_1_2_0),
        {"IOP-17": ["partial (4/6)"] * 3, "IOP-26": ["partial (gap)", "partial (gap)", "uncovered (0/2)"]},
        [],
    ),
    (
        "a vector changed in place no longer counts as held",
        both(reworded("interop-mode.json", "reject_nan"), *INTEROP_1_2_0),
        {"IOP-22": ["partial (12/34)"] * 3, "IOP-17": ["partial (4/6)"] * 3},
        [],
    ),
    (
        # 30 and 30.0 compare equal in Python, but interop mode encodes them differently.
        "an int retyped as a float no longer counts as held",
        both(retyped("interop-mode.json", "issue_example_object", ("value", "age"), 30.0), *INTEROP_1_2_0),
        {"IOP-17": ["partial (3/6)"] * 3},
        [],
    ),
    (
        "a pipe in a heading stays inside its cell",
        renamed_section("Decode bounds", "Decode | bounds"),
        {"IOP-26": ["partial (gap)"] * 3},
        ["*Decode \\| bounds*"],
    ),
    (
        # A tab or line break in a name would show as nothing or end the row; a backtick would end the span.
        # Every SDK is pinned to 1.1.0, which lacks these rows, so the statuses do not move as SDKs re-vendor.
        "vector names with a tab, a line break or a backtick stay inside their span and cell",
        both(
            entry(
                "IOP-13",
                vectors=["path-encoding.json:.\t.", "path-encoding.json:.\r\n.", 'path-encoding.json:a"b<c>d^e`f{g|h}i'],
            ),
            *(pin(sdk, "path-encoding.json", "1.1.0") for sdk in ("cachekit-py", "cachekit-ts", "cachekit-rs")),
        ),
        {"IOP-13": ["uncovered (0/3)"] * 3},
        ['`".\\t."`, `".\\r\\n."`, ``a"b<c>d^e`f{g\\|h}i``'],
    ),
    (
        # The quoted sentence, not the whole line, even when a code span holds a comment opener.
        "excerpt picks the keyword's sentence beside a comment opener in code",
        both(
            append(
                SPEC,
                "\n## Comments\n\nComments are allowed. A comment opens with `<!--`; a reader "
                f"MUST{marker('IOP-37')} skip to the next `-->`. Then it continues.\n",
            ),
            new_requirement("IOP-37", "Comments"),
        ),
        {},
        ["a reader **MUST** skip to the next `-->`."],
    ),
    (
        "a not-a-requirement marker is listed",
        append(SPEC, "\nThis names the word MUST<!-- not-a-requirement --> only.\n"),
        {},
        ["Marked not-a-requirement in `spec/interop-mode.md`:", "This names the word **MUST** only."],
    ),
    (
        # An excerpt is the keyword's paragraph as GitHub reads it: an ordered marker 2 continues the paragraph.
        "excerpt runs to the end of its paragraph",
        both(
            append(SPEC, f"\n## Leaf\n\nA reader MUST{marker('IOP-37')} reject a length of\n2. or more bytes past the bound.\n"),
            new_requirement("IOP-37", "Leaf"),
        ),
        {},
        ["*Leaf*: A reader **MUST** reject a length of 2. or more bytes past the bound."],
    ),
    (
        "excerpt leaves out an alert's marker",
        both(
            append(SPEC, f"\n## Alert\n\n> [!NOTE]\n> A reader MUST{marker('IOP-37')} reject it.\n"),
            new_requirement("IOP-37", "Alert"),
        ),
        {},
        ["*Alert*: A reader **MUST** reject it."],
    ),
    (
        "excerpt of a table keyword is its cell",
        both(
            append(SPEC, f"\n## Cell\n\n| a | b |\n| - | - |\n| x | A reader MUST{marker('IOP-37')} reject it |\n"),
            new_requirement("IOP-37", "Cell"),
        ),
        {},
        ["*Cell*: A reader **MUST** reject it |"],
    ),
    (
        "excerpt of a fenced keyword leaves out the fence lines",
        append(SPEC, "\n<!-- not-a-requirement -->\n```text\nMUST in a fence\n```\n"),
        {},
        [": **MUST** in a fence"],
    ),
]


def run_report_case(tmp: Path, number: int, case: tuple[str, Mutate, dict[str, list[str]], list[str]]) -> bool:
    name, mutate, expected, contains = case
    root = tmp / f"report-{number}"
    shutil.copytree(PRISTINE, root, symlinks=True)
    mutate(root)
    proc = subprocess.run([sys.executable, str(CHECKER), "report", str(root)], check=False, capture_output=True, text=True)
    text = (root / REPORT).read_text(encoding="utf-8") if proc.returncode == 0 else ""
    rows: dict[str, list[str]] = {}
    for line in text.splitlines():
        if m := re.match(r"\| \[([A-Z]+-\d+)\]", line):
            cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip()[1:-1])]
            rows[m.group(1)] = cells[-3:] if len(cells) == ROW_CELLS else [f"{len(cells)} cells"]
    wrong = {rid: rows.get(rid) for rid, cells in expected.items() if rows.get(rid) != cells}
    missing = [needle for needle in contains if needle not in text]
    if proc.returncode == 0 and not wrong and not missing:
        print(f"  ok   {name}")
        return True
    print(f"  FAIL {name}: exit {proc.returncode}; wrong rows {wrong}; missing {missing}\n       {proc.stderr.strip()[:300]}")
    return False


def test_strip(tmp: Path) -> bool:
    """`strip` removes exactly the id markers, keeps not-a-requirement markers, and writes UTF-8 bytes."""
    text = (ROOT / SPEC).read_text(encoding="utf-8")
    sample = tmp / "sample.md"
    sample.write_text(f"A MUST{marker('IOP-1')} and a word MUST<!-- not-a-requirement --> — dash\n", encoding="utf-8")
    run = [sys.executable, str(CHECKER), "strip"]
    proc = subprocess.run([*run, str(ROOT / SPEC)], capture_output=True, check=False)
    latin = subprocess.run(
        [*run, str(sample)], capture_output=True, check=False, env={**os.environ, "PYTHONIOENCODING": "latin-1"}
    )
    markers = re.findall(r'<sup id="[a-z0-9-]+">[A-Z][A-Z0-9]*-[0-9]+</sup>', text)
    stripped = proc.stdout.decode("utf-8")
    good = (
        proc.returncode == 0
        and markers
        and "<sup id=" not in stripped
        and len(text) - len(stripped) == sum(map(len, markers))
        and stripped.count("MUST") == text.count("MUST")
        and latin.stdout == "A MUST and a word MUST<!-- not-a-requirement --> — dash\n".encode()
    )
    print(f"  {'ok  ' if good else 'FAIL'} strip removes exactly the {len(markers)} id markers, keeps exemptions, writes UTF-8")
    return bool(good)


def test_code_spans() -> bool:
    """The report shows each vector name exactly: every branch of code(), read back the way a GFM table cell reads it."""
    sys.path.insert(0, str(HERE))
    import conformance

    def shown(cell: str) -> str:
        """What GitHub shows for a cell that is one code span: \\| unescaped, then the fence and one pad space dropped."""
        text = re.sub(r"\\\|", "|", cell)
        fence = re.match("`+", text)
        if fence is None:  # no code span at all: returned as is, so the comparison below reports a FAIL, not a crash
            return text
        inner = text[len(fence[0]) : -len(fence[0])]
        return inner[1:-1] if inner.startswith(" ") and inner.endswith(" ") and inner.strip(" ") else inner

    # name -> what the report must show for it
    cases = {
        "ns:key": "ns:key",
        "a|b": "a|b",
        "a\\|b": "a\\|b",  # its own backslash survives the pipe escaping
        "a`b": "a`b",  # a longer fence
        "`a`": "`a`",  # padded, so the end backticks stay out of the fence
        ".\t.": '".\\t."',  # not printable: its JSON string literal
        "a\x7fb": '"a\\u007fb"',  # DEL, which json.dumps leaves raw
        " a": '" a"',  # a span would drop the space
        '".\\t."': '"\\".\\\\t.\\""',  # printable, but it would pass for the tab key
        "cafe\u0301": '"cafe\\u0301"',  # decomposed, so it would pass for the precomposed spelling
    }
    wrong = {name: shown(conformance.cell(conformance.code(name))) for name in cases}
    wrong = {name: got for name, got in wrong.items() if got != cases[name]}
    print(f"  {'ok  ' if not wrong else 'FAIL'} report shows each vector name exactly{f': {wrong}' if wrong else ''}")
    return not wrong


def test_optimized() -> bool:
    """`python -OO` strips docstrings; the checker must not depend on its own."""
    proc = subprocess.run(
        [sys.executable, "-OO", str(CHECKER), "check", str(PRISTINE)], check=False, capture_output=True, text=True
    )
    good = proc.returncode == 0 and OK in proc.stdout
    print(f"  {'ok  ' if good else 'FAIL'} runs under python -OO (exit {proc.returncode})")
    return good


def main() -> int:
    global PRISTINE
    if not CHECKER.exists():
        print(f"checker not found: {CHECKER}", file=sys.stderr)
        return 1
    shallow = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--is-shallow-repository"], check=False, capture_output=True, text=True
    )
    if shallow.stdout.strip() == "true":
        print("a shallow clone cannot run these cases (git fetch --unshallow)", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        PRISTINE = prepare(Path(tmp))
        results = [run_case(Path(tmp), n, case) for n, case in enumerate(CASES)]
        results.append(test_shallow(Path(tmp)))
        results += [run_report_case(Path(tmp), n, case) for n, case in enumerate(REPORT_CASES)]
        results.append(test_optimized())
        results.append(test_strip(Path(tmp)))
        results.append(test_code_spans())
    failed = results.count(False)
    if failed:
        print(f"\n{failed}/{len(results)} case(s) failed", file=sys.stderr)
        return 1
    print(f"\nall {len(results)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
