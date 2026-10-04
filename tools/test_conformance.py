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


IOP3 = marker("IOP-3")
OK = "conformance: OK"
STALE = f"{REPORT} is stale or missing"

# (name, mutate(root), expected exit, substring the output MUST contain[, extra check args[, env]])
Case = tuple[str, Mutate, int, str] | tuple[str, Mutate, int, str, list[str]] | tuple[str, Mutate, int, str, list[str], dict]
CASES: list[Case] = [
    ("unmodified tree", lambda _: None, 0, OK),
    # --- every hard keyword in an indexed file carries an id ---
    ("id removed from beside a MUST", edit(SPEC, marker("IOP-19"), ""), 1, "this MUST has no id (the next free id is IOP-37)"),
    ("new MUST NOT added without an id", append(SPEC, "\nReaders MUST NOT crash.\n"), 1, "this MUST NOT has no id"),
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
    (
        "prose between two indented fence-like lines",
        append(SPEC, "\n    ```\n\nReaders MUST reject it.\n\n    ```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    (
        "prose after a blockquote that ends its fence",
        append(SPEC, "\n> ```text\n> code\n\nReaders MUST reject it.\n\n> ```\n"),
        1,
        "sits inside the code fence opened at line",
    ),
    (
        "prose after an indented comment opener",
        append(SPEC, "\n    <!--\nReaders MUST reject it.\n    -->\n"),
        1,
        "sits inside the HTML comment opened at line",
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
        "defines no '_selfcheck'",
    ),
    ("test file that does not exist", entry("IOP-10", tests=["tools/no-such-tool.py:main"]), 1, "no file tools/no-such-tool.py"),
    # The word is in the file (in a comment), but nothing defines it.
    (
        "test name that only appears in a comment",
        entry("IOP-10", tests=["tools/interop-reference.py:serde_json"]),
        1,
        "defines no 'serde_json'",
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
    (
        "stray backtick in a table row",
        append(SPEC, "\n| a | a lone ` is literal |\n| b | Readers MUST reject them |\n| c | see `x` |\n"),
        1,
        "this MUST has no id",
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
    (
        "fence closed at a different indent",
        append(SPEC, "\nExample:\n\n    ```\n    code\n\nReaders MUST reject it.\n\n```text\nx\n```\n"),
        1,
        "at a different indent",
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
    # Without a delimiter row the line is a paragraph, and the keyword sits inside a code span.
    ("pipe-led line without a delimiter row", append(SPEC, "\n| a ` b | Readers MUST reject it | `x` |\n"), 0, OK),
    # A one-backtick span closes only at a run of exactly one backtick: MUST is inside the code here.
    ("code span closed only by an equal run", append(SPEC, "\nUse `x``` MUST `y` here.\n"), 0, OK),
    ("setext heading", edit(SPEC, "### Segment grammar\n", "Segment grammar\n---------------\n"), 0, OK),
    ("retired id with an empty reason", index(lambda s: s["retired"].__setitem__("IOP-99", "")), 1, "retired must map each id"),
    ("text after a comment block closes", append(SPEC, "\n<!--\nnote\n--> Readers MUST reject it.\n"), 1, "this MUST has no id"),
    ("heading with closing hashes", edit(SPEC, "### Decode bounds\n", "### Decode bounds ###\n"), 0, OK),
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
        "defines no '_self_che'",
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
    (
        "SDK dropped from sdks.json since the base",
        commit_base(lambda _: None),
        1,
        "cachekit-py was listed at HEAD and is now gone",
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
    "SDK dropped from sdks.json since the base": (both(sdks(lambda d: d.pop("cachekit-py")), report), "HEAD"),
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
# (name, mutate(root), {requirement id: expected [cachekit-py, cachekit-ts, cachekit-rs] cells}, substrings)
# These pin what each status MEANS, independently of the code that renders it.
REPORT_CASES: list[tuple[str, Mutate, dict[str, list[str]], list[str]]] = [
    (
        "statuses on the unmodified tree",
        lambda _: None,
        {
            "IOP-5": ["partial (gap)"] * 3,
            "IOP-9": ["covered"] * 3,
            "IOP-2": ["partial (gap)"] * 3,
            "IOP-10": ["uncovered"] * 3,
            "IOP-13": ["gap"] * 3,
            "IOP-6": ["n/a"] * 3,
            "IOP-14": ["n/a", "partial (gap)", "n/a"],
        },
        # Tests-only requirements are uncovered in every SDK, so the summary counts them apart.
        ["| [`spec/interop-mode.md`](../spec/interop-mode.md) | 36 | 5 | 3 | 22 | 6 |"],
    ),
    (
        # interop-mode.json 1.1.0 predates the `..` vectors and lone_dots_stay_valid.
        "an SDK on an older revision lacks the newer vectors",
        pin("cachekit-ts", "interop-mode.json", "1.1.0"),
        {"IOP-5": ["partial (gap)", "uncovered (0/3)", "partial (gap)"], "IOP-4": ["partial (gap)"] * 3},
        [],
    ),
    (
        "an SDK that does not vendor a fixture holds none of its vectors",
        pin("cachekit-rs", "decode-bounds.json", None),
        {"IOP-9": ["covered"] * 3, "IOP-26": ["partial (gap)", "partial (gap)", "uncovered (0/2)"]},
        [],
    ),
    (
        "a vector changed in place no longer counts as held",
        reworded("interop-mode.json", "reject_nan"),
        {"IOP-22": ["partial (12/13)"] * 3, "IOP-9": ["covered"] * 3},
        [],
    ),
    (
        # 30 and 30.0 compare equal in Python, but interop mode encodes them differently.
        "an int retyped as a float no longer counts as held",
        retyped("interop-mode.json", "issue_example_object", ("value", "age"), 30.0),
        {"IOP-17": ["partial (3/4)"] * 3},
        [],
    ),
    (
        "a pipe in a heading stays inside its cell",
        renamed_section("Decode bounds", "Decode | bounds"),
        {"IOP-26": ["partial (gap)"] * 3},
        ["*Decode \\| bounds*"],
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
        if m := re.match(r"\| \[(IOP-\d+)\]", line):
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
    failed = results.count(False)
    if failed:
        print(f"\n{failed}/{len(results)} case(s) failed", file=sys.stderr)
        return 1
    print(f"\nall {len(results)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
