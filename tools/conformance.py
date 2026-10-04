#!/usr/bin/env python3
"""Requirement ids for the spec's MUSTs, the index that maps them to vectors, and per-SDK coverage.

A spec file says what an implementation MUST do, and a vector pins one input it has to
handle, but nothing tied the two together. "Does this SDK conform?" could only be answered
per fixture file, and a MUST that no vector exercises was invisible. This tool keeps three
things in step:

- Every MUST and MUST NOT in an indexed spec file carries an id written right after the
  keyword, as `MUST<sup id="iop-3">IOP-3</sup>`. The `id` attribute makes each requirement
  linkable (GitHub renders it as `#iop-3`). A keyword used as a word rather than as a
  requirement ("fixes no MUST") carries `<!-- not-a-requirement -->` instead.
- conformance/requirements.json is the index. A spec file is indexed when it is listed there,
  and from then on every hard keyword in it needs an id. Each id maps to the vectors that
  exercise it (`<fixture>.json:<name>`, or `<fixture>.json` for all of a fixture's vectors),
  to named tests in this repository's tools (`tools/<file>:<name>`), and to a one-line `gap`
  for whatever no vector or test reaches. An id is never reused or renumbered: a requirement
  that leaves the spec moves to the file's `retired` map.
- conformance/coverage.md is generated from the index, conformance/sdks.json (the sha256 of
  every fixture copy each SDK vendors, as of a named SDK commit) and test-vectors/. Each
  vendored copy is matched to a revision of the fixture in this repository's history, so a
  requirement counts as covered for an SDK only when its copy holds every mapped vector,
  identical to the vector published here.

**What this does NOT catch.** It checks that a mapping exists and that it names real vectors
and tests. It cannot check that they exercise the requirement: whether a plausible wrong
implementation passes every mapped vector is a reviewer's question, and a gap is only as
honest as its reason. "Covered" means an SDK vendors the vectors, not that its tests drive
each one through every entry point a requirement names or assert the error it requires. A
`tools/<file>:<name>` reference is checked for existence only. With `--base`, it catches an
id that was dropped instead of retired and a retired id brought back; it cannot tell a
renumbered id from a new one.

Fails closed: an unreadable or malformed file, a duplicate JSON key, a duplicate vector name,
an unclosed code fence, or a vendored sha256 that matches no revision of its fixture is an
error, not a pass. A guard that silently checks nothing is worse than no guard. Uses explicit
failures rather than `assert`, so it cannot be defanged by `-O`.

Usage:
    python3 tools/conformance.py check [--base REF] [ROOT]   exit 1 on any defect
    python3 tools/conformance.py report [ROOT]               rewrite conformance/coverage.md
    python3 tools/conformance.py strip FILE                  FILE with its ids removed, to stdout

`check` needs the repository's full history (a shallow clone cannot resolve older fixture
revisions); `--base` names the commit to compare the index against, `HEAD^1` in CI.
`strip` shows that adding ids changed no normative text:
    diff <(git show main:spec/interop-mode.md) <(python3 tools/conformance.py strip spec/interop-mode.md)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

INDEX = "conformance/requirements.json"
SDKS = "conformance/sdks.json"
REPORT = "conformance/coverage.md"
FIXTURES = "test-vectors"
# The field that names a fixture's vectors; every other fixture uses "name". A vector array
# is any array under a key ending in "vectors".
NAME_FIELD = {"path-encoding.json": "key"}
BINDS = {"sdk": "SDKs", "server": "the server", "caller": "application code"}
FIELDS = {"section", "binds", "sdks", "vectors", "tests", "gap"}

KEYWORD = re.compile(r"\bMUST(?:[\s>]+NOT)?\b")
MARKER = re.compile(r'<sup id="([a-z0-9-]+)">([A-Z][A-Z0-9]*-([1-9][0-9]*))</sup>')
EXEMPT = "<!-- not-a-requirement -->"
CLOSER = re.compile(r"\*\*|__|\*|_")
FENCE = re.compile(r"[ \t>]*(`{3,}|~{3,})")
HEADING = re.compile(r"^#{1,6}[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$", re.MULTILINE)
# Inline code and HTML comments, whichever opens first; a code span never crosses a blank line.
INLINE = re.compile(r"(`+)(?!`)(?:(?!\n[ \t]*\n).)+?(?<!`)\1(?!`)|<!--.*?-->", re.DOTALL)
PREFIX = re.compile(r"[A-Z][A-Z0-9]*")
TEST_REF = re.compile(r"(tools/[A-Za-z0-9_.-]+):([A-Za-z0-9_]+)")
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")


class Defect(Exception):
    """A defect in the inputs: reported, never a crash."""


@dataclass(frozen=True)
class Keyword:
    word: str  # "MUST" or "MUST NOT"
    start: int  # offset of the keyword in the file
    line: int
    section: str
    rid: str | None  # the id beside it; None when it has none, "" when it is marked not-a-requirement
    problem: str = ""  # a malformed marker beside it


@dataclass(frozen=True)
class Spec:
    text: str
    keywords: list[Keyword]
    stray: list[tuple[int, str]]  # (line, id) of markers that sit beside no keyword


# --- spec scanning ---------------------------------------------------------------------------


def blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def mask(text: str) -> tuple[str, str]:
    """(text with fenced code blanked, that with inline code and HTML comments blanked too).

    Blanking keeps every offset and line break, so positions in either map back to `text`.
    """
    lines = text.split("\n")
    fence = ""
    opened = 0
    for i, line in enumerate(lines):
        m = FENCE.match(line)
        if not fence:
            if m:
                fence, opened = m.group(1), i + 1
                lines[i] = " " * len(line)
            continue
        if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line[m.end() :].strip():
            fence = ""
        lines[i] = " " * len(line)
    if fence:
        raise Defect(f"line {opened}: unclosed code fence (everything after it would go unchecked)")
    fenced = "\n".join(lines)
    return fenced, INLINE.sub(blank, fenced)


def scan(text: str) -> Spec:
    fenced, masked = mask(text)
    headings = [(m.start(), m.group(1)) for m in HEADING.finditer(fenced)]
    markers = {m.start(): m for m in MARKER.finditer(masked)}
    used: set[int] = set()
    keywords: list[Keyword] = []
    for m in KEYWORD.finditer(masked):
        word = "MUST NOT" if m.group(0) != "MUST" else "MUST"
        pos = m.end()
        if closer := CLOSER.match(text, pos):
            pos = closer.end()
        section = next((title for at, title in reversed(headings) if at < m.start()), "")
        line = text.count("\n", 0, m.start()) + 1
        rid: str | None = None
        problem = ""
        if text.startswith(EXEMPT, pos):
            rid = ""
        elif pos in markers:
            marker = markers[pos]
            used.add(pos)
            rid = marker.group(2)
            if marker.group(1) != rid.lower():
                problem = f'anchor id="{marker.group(1)}" does not match {rid} (it must be "{rid.lower()}")'
        elif text.startswith("<sup", pos):
            problem = 'malformed id marker (expected <sup id="iop-3">IOP-3</sup>)'
        keywords.append(Keyword(word, m.start(), line, section, rid, problem))
    stray = [(text.count("\n", 0, at) + 1, mk.group(2)) for at, mk in markers.items() if at not in used]
    return Spec(text, keywords, stray)


def strip(text: str) -> str:
    """`text` with every id marker and not-a-requirement marker removed."""
    return MARKER.sub("", text).replace(EXEMPT, "")


# --- loading ---------------------------------------------------------------------------------


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [k for k, _ in pairs]
    if dupes := sorted({k for k in keys if keys.count(k) > 1}):
        raise Defect(f"duplicate key(s) {dupes} (JSON keeps only the last, so one would vanish)")
    return dict(pairs)


def parse_json(raw: bytes | str, what: str) -> object:
    try:
        return json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except Defect as exc:
        raise Defect(f"{what}: {exc}") from None
    except ValueError as exc:
        raise Defect(f"{what}: not valid JSON ({exc})") from None


def read(root: Path, rel: str) -> bytes:
    try:
        return (root / rel).read_bytes()
    except OSError as exc:
        raise Defect(f"{rel}: cannot read ({exc.strerror or exc})") from None


def fixture_vectors(document: object, fixture: str) -> dict[str, object]:
    """Every vector in a fixture document, by name; a name must be unique in its file."""
    field = NAME_FIELD.get(fixture, "name")
    found: dict[str, object] = {}

    def walk(node: object) -> None:
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if key.endswith("vectors") and isinstance(value, list):
                for vector in value:
                    name = vector.get(field) if isinstance(vector, dict) else None
                    if not isinstance(name, str):
                        raise Defect(f"{fixture}: an entry in {key!r} has no string {field!r}")
                    if name in found:
                        raise Defect(f"{fixture}: duplicate vector name {name!r} (vector ids would alias)")
                    found[name] = vector
            else:
                walk(value)

    walk(document)
    if not found:
        raise Defect(f"{fixture}: no vectors found (no array under a key ending in 'vectors')")
    return found


def git(root: Path, *args: str) -> bytes:
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    except OSError as exc:
        raise Defect(f"cannot run git ({exc})") from None
    if proc.returncode != 0:
        raise Defect(f"git {' '.join(args)}: {proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout


@dataclass(frozen=True)
class Revision:
    vectors: dict[str, object]
    version: str  # the fixture's own "version" field


def revisions(root: Path, fixture: str) -> dict[str, Revision]:
    """sha256 -> revision, for every committed revision of a fixture plus the working copy."""
    rel = f"{FIXTURES}/{fixture}"
    found: dict[str, Revision] = {}
    commits = git(root, "log", "--full-history", "--diff-filter=ACMRT", "--format=%H", "--", rel).decode().split()
    blobs = [(commit, git(root, "show", f"{commit}:{rel}")) for commit in reversed(commits)]
    blobs.append(("", read(root, rel)))
    for commit, blob in blobs:
        sha = hashlib.sha256(blob).hexdigest()
        if sha not in found:
            document = parse_json(blob, f"{rel} at {commit[:12] or 'working tree'}")
            version = document.get("version") if isinstance(document, dict) else None
            found[sha] = Revision(fixture_vectors(document, fixture), str(version or "unversioned"))
    return found


# --- the model -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Requirement:
    rid: str
    file: str
    section: str
    binds: str
    sdks: tuple[str, ...]  # empty: every SDK
    vectors: tuple[str, ...]  # vector ids as written in the index
    tests: tuple[str, ...]
    gap: str
    keyword: Keyword


@dataclass
class Model:
    requirements: list[Requirement]
    unindexed: list[str]  # spec files the index does not list
    fixtures: dict[str, dict[str, object]]  # fixture -> name -> vector, as published here
    sdks: dict[str, dict[str, object]]
    vendored: dict[str, dict[str, tuple[Revision, bool]]]  # sdk -> fixture -> (revision, is current)
    specs: dict[str, Spec]


def as_strings(value: object, what: str, errors: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        errors.append(f"{what}: must be a non-empty list of non-empty strings (omit the field instead of [])")
        return ()
    if len(set(value)) != len(value):
        errors.append(f"{what}: lists an entry twice")
    return tuple(value)


def expand(ref: str, fixtures: dict[str, dict[str, object]]) -> list[tuple[str, str]]:
    """(fixture, name) pairs a vector reference stands for; raises Defect if it names nothing."""
    fixture, sep, name = ref.partition(":")
    if fixture not in fixtures:
        raise Defect(f"vector {ref!r}: no fixture {FIXTURES}/{fixture}")
    if not sep:
        return [(fixture, n) for n in fixtures[fixture]]
    if name not in fixtures[fixture]:
        raise Defect(f"vector {ref!r}: {fixture} has no vector named {name!r}")
    return [(fixture, name)]


def build(root: Path, errors: list[str]) -> Model:
    index = parse_json(read(root, INDEX), INDEX)
    sdks = parse_json(read(root, SDKS), SDKS)
    if not isinstance(index, dict) or index.get("schema") != 1 or not isinstance(index.get("files"), dict):
        raise Defect(f'{INDEX}: expected {{"schema": 1, "files": {{...}}}}')
    if not isinstance(sdks, dict):
        raise Defect(f"{SDKS}: expected an object keyed by SDK name")

    fixtures = {
        path.name: fixture_vectors(parse_json(path.read_bytes(), f"{FIXTURES}/{path.name}"), path.name)
        for path in sorted((root / FIXTURES).glob("*.json"))
    }
    if not fixtures:
        raise Defect(f"{FIXTURES}/: no fixtures found")

    vendored: dict[str, dict[str, tuple[Revision, bool]]] = {}
    history: dict[str, dict[str, Revision]] = {}
    if sdks and git(root, "rev-parse", "--is-shallow-repository").strip() == b"true":
        raise Defect("shallow clone: vendored fixture copies cannot be matched to older revisions (git fetch --unshallow)")
    for sdk, entry in sdks.items():
        vendored[sdk] = {}
        if not isinstance(entry, dict) or not isinstance(entry.get("fixtures"), dict):
            errors.append(f"{SDKS}: {sdk}: expected repository, commit and fixtures")
            continue
        if unknown := sorted(set(entry) - {"repository", "commit", "fixtures"}):
            errors.append(f"{SDKS}: {sdk}: unknown field(s) {unknown}")
        if not isinstance(entry.get("repository"), str) or not str(entry["repository"]).startswith("https://"):
            errors.append(f"{SDKS}: {sdk}: repository must be an https URL")
        if not isinstance(entry.get("commit"), str) or not HEX40.fullmatch(entry["commit"]):
            errors.append(f"{SDKS}: {sdk}: commit must be a full 40-character sha")
        for fixture, sha in entry["fixtures"].items():
            if fixture not in fixtures:
                errors.append(f"{SDKS}: {sdk}: no fixture {FIXTURES}/{fixture}")
                continue
            if not isinstance(sha, str) or not HEX64.fullmatch(sha):
                errors.append(f"{SDKS}: {sdk}: {fixture}: expected a lowercase sha256")
                continue
            if fixture not in history:
                history[fixture] = revisions(root, fixture)
            revs = history[fixture]
            if sha not in revs:
                errors.append(
                    f"{SDKS}: {sdk}: {fixture} sha256 {sha[:12]}… matches no revision of {FIXTURES}/{fixture} "
                    "in this repository's history (a modified copy, or one taken from an unmerged branch)"
                )
                continue
            current = hashlib.sha256((root / FIXTURES / fixture).read_bytes()).hexdigest()
            vendored[sdk][fixture] = (revs[sha], sha == current)

    specs: dict[str, Spec] = {}
    requirements: list[Requirement] = []
    prefixes: dict[str, str] = {}
    for rel, entry in index["files"].items():
        if not rel.startswith("spec/") or not rel.endswith(".md"):
            errors.append(f"{INDEX}: {rel}: an indexed file must be a spec/*.md file")
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("requirements"), dict):
            errors.append(f"{INDEX}: {rel}: expected prefix, requirements and retired")
            continue
        if unknown := sorted(set(entry) - {"prefix", "requirements", "retired"}):
            errors.append(f"{INDEX}: {rel}: unknown field(s) {unknown}")
        prefix = entry.get("prefix")
        if not isinstance(prefix, str) or not PREFIX.fullmatch(prefix):
            errors.append(f"{INDEX}: {rel}: prefix must be uppercase letters and digits")
            continue
        if prefix in prefixes:
            errors.append(f"{INDEX}: {rel}: prefix {prefix} is already used by {prefixes[prefix]}")
            continue
        prefixes[prefix] = rel
        retired = entry.get("retired", {})
        if not isinstance(retired, dict) or not all(isinstance(v, str) and v.strip() for v in retired.values()):
            errors.append(f"{INDEX}: {rel}: retired must map each id to a non-empty reason")
            retired = {}
        try:
            spec = scan(read(root, rel).decode("utf-8"))
        except (Defect, UnicodeDecodeError) as exc:
            errors.append(f"{rel}: {exc}")
            continue
        specs[rel] = spec
        mapped = entry["requirements"]
        shape = re.compile(rf"{prefix}-[1-9][0-9]*")
        for rid in [*mapped, *retired]:
            if not shape.fullmatch(rid):
                errors.append(f"{INDEX}: {rel}: {rid!r} is not an id of the form {prefix}-<n>")
        numbers = [int(r.split("-")[-1]) for r in [*mapped, *retired] if shape.fullmatch(r)]
        next_id = f"{prefix}-{max(numbers, default=0) + 1}"

        seen: dict[str, int] = {}
        for kw in spec.keywords:
            where = f"{rel}:{kw.line}"
            if kw.problem:
                errors.append(f"{where}: {kw.word}: {kw.problem}")
                continue
            if kw.rid is None:
                errors.append(f"{where}: this {kw.word} has no id (the next free id is {next_id})")
                continue
            if kw.rid == "":
                continue
            if not kw.rid.startswith(f"{prefix}-"):
                errors.append(f"{where}: {kw.rid} does not use this file's prefix {prefix}")
                continue
            if kw.rid in seen:
                errors.append(f"{where}: {kw.rid} is already used at line {seen[kw.rid]}")
                continue
            seen[kw.rid] = kw.line
            if kw.rid in retired:
                errors.append(f"{where}: {kw.rid} is retired ({retired[kw.rid]}); a new requirement gets {next_id}")
                continue
            if kw.rid not in mapped:
                errors.append(f"{where}: {kw.rid} is not in {INDEX}")
                continue
            if req := requirement(rel, kw, mapped[kw.rid], fixtures, sdks, root, errors):
                requirements.append(req)
        for line, rid in spec.stray:
            errors.append(f"{rel}:{line}: {rid} is not beside a MUST or MUST NOT")
        for rid in mapped:
            if rid not in seen:
                errors.append(f"{INDEX}: {rid} is indexed but no MUST or MUST NOT in {rel} carries it")
            if rid in retired:
                errors.append(f"{INDEX}: {rid} is both indexed and retired")

    unindexed = sorted(f"spec/{p.name}" for p in (root / "spec").glob("*.md") if f"spec/{p.name}" not in index["files"])
    requirements.sort(key=lambda r: (r.file, int(r.rid.split("-")[-1])))
    return Model(requirements, unindexed, fixtures, sdks, vendored, specs)


def requirement(
    rel: str,
    kw: Keyword,
    entry: object,
    fixtures: dict[str, dict[str, object]],
    sdks: dict[str, object],
    root: Path,
    errors: list[str],
) -> Requirement | None:
    what = f"{INDEX}: {kw.rid}"
    if not isinstance(entry, dict):
        errors.append(f"{what}: expected an object")
        return None
    if unknown := sorted(set(entry) - FIELDS):
        errors.append(f"{what}: unknown field(s) {unknown}")
    if entry.get("section") != kw.section:
        errors.append(f"{what}: section is {entry.get('section')!r}, but the id sits under the heading {kw.section!r}")
    binds = entry.get("binds")
    if binds not in BINDS:
        errors.append(f"{what}: binds must be one of {sorted(BINDS)}")
    only = as_strings(entry.get("sdks"), f"{what}: sdks", errors)
    if only and binds != "sdk":
        errors.append(f"{what}: sdks narrows a requirement that binds SDKs; this one binds {binds}")
    for sdk in only:
        if sdk not in sdks:
            errors.append(f"{what}: sdks names {sdk!r}, which {SDKS} does not list")
    vectors = as_strings(entry.get("vectors"), f"{what}: vectors", errors)
    for ref in vectors:
        try:
            expand(ref, fixtures)
        except Defect as exc:
            errors.append(f"{what}: {exc}")
    tests = as_strings(entry.get("tests"), f"{what}: tests", errors)
    for ref in tests:
        if not (m := TEST_REF.fullmatch(ref)):
            errors.append(f"{what}: test {ref!r} is not tools/<file>:<name>")
            continue
        path = root / m.group(1)
        if not path.is_file():
            errors.append(f"{what}: test {ref!r}: no file {m.group(1)}")
        elif not re.search(rf"\b{re.escape(m.group(2))}\b", path.read_text(encoding="utf-8")):
            errors.append(f"{what}: test {ref!r}: {m.group(1)} has no {m.group(2)!r}")
    gap = entry.get("gap", "")
    if not isinstance(gap, str) or "\n" in gap or (gap != gap.strip()) or ("gap" in entry and not gap):
        errors.append(f"{what}: gap must be a non-empty one-line reason")
        gap = ""
    if not vectors and not tests and not gap:
        errors.append(f"{what}: maps to no vector and no test, and records no gap")
    return Requirement(kw.rid or "", rel, kw.section, str(binds), only, vectors, tests, gap, kw)


def compare_base(root: Path, base: str, errors: list[str]) -> str:
    """Ids at `base` must still be indexed or retired here, and retired ids must stay retired."""
    git(root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}")
    listed = git(root, "ls-tree", "--name-only", base, "--", INDEX).decode().strip()
    if not listed:
        return f"{INDEX} does not exist at {base}; nothing to compare"
    then = parse_json(git(root, "show", f"{base}:{INDEX}"), f"{INDEX} at {base}")
    now = parse_json(read(root, INDEX), INDEX)

    def files(document: object) -> dict[str, dict]:
        found = document.get("files") if isinstance(document, dict) else None
        return {k: v for k, v in found.items() if isinstance(v, dict)} if isinstance(found, dict) else {}

    for rel, old in files(then).items():
        new = files(now).get(rel, {})
        active, retired = new.get("requirements") or {}, new.get("retired") or {}
        for rid in old.get("requirements") or {}:
            if rid not in active and rid not in retired:
                errors.append(f"{INDEX}: {rid} was indexed at {base} and is now gone; retire it instead (ids are never reused)")
        for rid in old.get("retired") or {}:
            if rid not in retired:
                errors.append(f"{INDEX}: {rid} was retired at {base}; a retired id stays retired")
    return f"no id dropped or un-retired since {base}"


# --- coverage --------------------------------------------------------------------------------


def status(req: Requirement, sdk: str, model: Model) -> str:
    if req.binds != "sdk" or (req.sdks and sdk not in req.sdks):
        return "n/a"
    if not req.vectors:
        return "uncovered" if req.tests else "gap"
    wanted = {pair for ref in req.vectors for pair in expand(ref, model.fixtures)}
    held = sum(
        1
        for fixture, name in wanted
        if fixture in model.vendored[sdk] and model.vendored[sdk][fixture][0].vectors.get(name) == model.fixtures[fixture][name]
    )
    if held == 0:
        return f"uncovered (0/{len(wanted)})"
    if held < len(wanted):
        return f"partial ({held}/{len(wanted)})"
    return "partial (gap)" if req.gap else "covered"


def kind(req: Requirement) -> str:
    if req.gap:
        return "partial" if req.vectors or req.tests else "gap"
    return "vectors" if req.vectors else "tests only"


ABBREVIATIONS = re.compile(r"\b(?:e\.g|i\.e|etc|vs|incl|cf)\.$")


def excerpt(text: str, start: int) -> str:
    """The sentence holding the keyword at `start`, from its paragraph, list item or table cell."""
    marked = text[:start] + "\0" + text[start:]
    lines = marked.split("\n")
    at = marked.count("\n", 0, start)

    def body(line: str) -> str:
        return re.sub(r"^(?:[ \t]*>)*[ \t]*", "", line)

    def opens_item(line: str) -> bool:
        return bool(re.match(r"(?:[-*+]|\d+[.)])[ \t]", body(line)))

    def boundary(line: str) -> bool:
        b = body(line)
        return not b.strip() or b.startswith(("#", "|", "```", "~~~", "[!"))

    if body(lines[at]).startswith("|"):
        row = lines[at]
        pos = row.index("\0")
        end = row.find("|", pos)
        block = row[row.rfind("|", 0, pos) + 1 : end if end >= 0 else len(row)]
    else:
        first = at
        while not opens_item(lines[first]) and first > 0 and not boundary(lines[first - 1]):
            first -= 1
        last = at
        while last + 1 < len(lines) and not boundary(lines[last + 1]) and not opens_item(lines[last + 1]):
            last += 1
        block = " ".join(re.sub(r"^(?:[-*+]|\d+[.)])[ \t]+", "", body(ln)) for ln in lines[first : last + 1])
    clean = strip(block)
    clean = re.sub(r"<!--.*?-->", "", clean)
    clean = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", clean)
    clean = re.sub(r"\*\*|__", "", clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    pos = clean.index("\0")
    begin = 0
    for m in re.finditer(r"[.!?](?=\s)", clean[:pos]):
        if not ABBREVIATIONS.search(clean[: m.end()]):
            begin = m.end()
    end = len(clean)
    for m in re.finditer(r"[.!?](?=\s|$)", clean[pos:]):
        if not ABBREVIATIONS.search(clean[: pos + m.end()]):
            end = pos + m.end()
            break
    sentence = clean[begin:end].strip()
    pos = sentence.index("\0")
    if len(sentence) > 240:
        # A window around the keyword, cut at spaces so no word is split.
        lo = sentence.find(" ", pos - 100, pos) + 1 if pos > 100 else 0
        hi = sentence.rfind(" ", pos, pos + 140) if pos + 140 < len(sentence) else len(sentence)
        hi = hi if hi > pos else len(sentence)
        sentence = ("… " if lo else "") + sentence[lo:hi].strip() + (" …" if hi < len(sentence) else "")
    return sentence.replace("\0", "").replace("|", "\\|")


def evidence(req: Requirement, model: Model) -> str:
    parts: list[str] = []
    named: dict[str, list[str]] = {}
    for ref in req.vectors:
        fixture, sep, name = ref.partition(":")
        if not sep:
            parts.append(f"`{fixture}` (all {len(model.fixtures[fixture])})")
        else:
            named.setdefault(fixture, []).append(f"`{name}`" if name else "the empty key")
    parts.extend(f"`{fixture}`: " + ", ".join(names) for fixture, names in named.items())
    parts.extend(f"`{ref}`" for ref in req.tests)
    if req.gap:
        parts.append(f"**Gap:** {req.gap}")
    if req.binds != "sdk":
        parts.insert(0, f"Binds {BINDS[req.binds]}.")
    elif req.sdks:
        parts.insert(0, f"Binds {', '.join(req.sdks)} only.")
    return "<br>".join(p.replace("|", "\\|") for p in parts)


def render(model: Model) -> str:
    sdks = list(model.sdks)
    out = [
        "# Conformance coverage",
        "",
        "<!-- Generated by tools/conformance.py report. Do not edit by hand: CI fails when this file is stale. -->",
        "",
        "Which normative requirements each SDK's vendored test vectors reach. Every MUST and MUST NOT in an",
        "indexed spec file carries an id, written beside it as a superscript. [`requirements.json`](requirements.json)",
        "maps each id to the vectors and reference-tool tests that exercise it, or records a gap;",
        "[`sdks.json`](sdks.json) records the fixture copies each SDK vendors.",
        "How ids are assigned and how to add one: [README.md](README.md).",
        "",
        "Per SDK, a requirement is **covered** when the SDK's vendored fixtures hold every vector it maps to,",
        "identical to the vector published here, and no gap is recorded for it; **partial** when they hold some",
        "of those vectors, or all of them while part of the requirement is a recorded gap; **uncovered** when",
        "they hold none, or when only this repository's reference tools test it; **gap** when nothing tests it;",
        "and **n/a** when it binds the server, application code, or only other SDKs. Covered means the vectors",
        "are vendored, not that the SDK's tests drive each one through every entry point the requirement names:",
        "[sdk-feature-matrix.md](../sdk-feature-matrix.md) records that per SDK.",
        "",
        "## SDKs",
        "",
        "| SDK | Read at | Vendored fixtures |",
        "| :--- | :--- | :--- |",
    ]
    for sdk in sdks:
        entry = model.sdks[sdk]
        commit = str(entry.get("commit", ""))
        copies = []
        for fixture in sorted(model.vendored[sdk]):
            rev, current = model.vendored[sdk][fixture]
            copies.append(f"`{fixture}` {rev.version}" + ("" if current else " (not the current revision)"))
        out.append(f"| {sdk} | [`{commit[:7]}`]({entry.get('repository')}/commit/{commit}) | {', '.join(copies) or 'none'} |")

    out += [
        "",
        "## Summary",
        "",
        "| Spec file | Requirements | Vectors | Tests only | Partial | Gap |",
        "| :--- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for rel in sorted(model.specs):
        reqs = [r for r in model.requirements if r.file == rel]
        counts = [sum(kind(r) == k for r in reqs) for k in ("vectors", "tests only", "partial", "gap")]
        out.append(f"| [`{rel}`](../{rel}) | {len(reqs)} | " + " | ".join(map(str, counts)) + " |")
    if sdks:
        out += ["", "| SDK | Covered | Partial | Uncovered | Gap | n/a |", "| :--- | ---: | ---: | ---: | ---: | ---: |"]
        for sdk in sdks:
            cells = [status(r, sdk, model).split(" ")[0] for r in model.requirements]
            out.append(
                f"| {sdk} | " + " | ".join(str(cells.count(k)) for k in ("covered", "partial", "uncovered", "gap", "n/a")) + " |"
            )
    if model.unindexed:
        out += ["", "Not indexed yet: " + ", ".join(f"[`{rel}`](../{rel})" for rel in model.unindexed) + "."]

    for rel in sorted(model.specs):
        text = model.specs[rel].text
        out += ["", f"## {rel}", "", "| Id | Requirement | Vectors, tests and gaps | " + " | ".join(sdks) + " |"]
        out.append("| :--- | :--- | :--- |" + " :--- |" * len(sdks))
        for req in (r for r in model.requirements if r.file == rel):
            link = f"[{req.rid}](../{rel}#{req.rid.lower()})"
            said = f"*{req.section}*: {excerpt(text, req.keyword.start)}"
            cells = " | ".join(status(req, sdk, model) for sdk in sdks)
            out.append(f"| {link} | {said} | {evidence(req, model)} | {cells} |")
    return "\n".join(out) + "\n"


# --- commands --------------------------------------------------------------------------------


def run_check(root: Path, base: str | None) -> int:
    errors: list[str] = []
    notes: list[str] = []
    try:
        model = build(root, errors)
        if base:
            notes.append(compare_base(root, base, errors))
        if not errors:
            expected = render(model)
            try:
                actual = (root / REPORT).read_text(encoding="utf-8")
            except OSError:
                actual = None
            if actual != expected:
                errors.append(f"{REPORT} is stale or missing: run python3 tools/conformance.py report")
    except Defect as exc:
        errors.append(str(exc))
    if errors:
        print("conformance: FAILED\n", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    kinds = [kind(r) for r in model.requirements]
    print(
        f"conformance: OK -- {len(model.requirements)} requirement id(s) in {len(model.specs)} indexed spec file(s): "
        f"{kinds.count('vectors')} vectors, {kinds.count('tests only')} tests only, "
        f"{kinds.count('partial')} partial, {kinds.count('gap')} gap; {REPORT} is current"
        + "".join(f"; {note}" for note in notes)
    )
    return 0


def run_report(root: Path) -> int:
    errors: list[str] = []
    try:
        model = build(root, errors)
    except Defect as exc:
        errors.append(str(exc))
    if errors:
        print("conformance: cannot generate the report\n", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    (root / REPORT).write_text(render(model), encoding="utf-8")
    print(f"conformance: wrote {REPORT} ({len(model.requirements)} requirement ids)")
    return 0


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="exit 1 on any defect")
    check.add_argument("--base", help="git revision whose index this one must not drop or un-retire ids from")
    check.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parent.parent)
    report = commands.add_parser("report", help=f"rewrite {REPORT}")
    report.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parent.parent)
    stripper = commands.add_parser("strip", help="print FILE without its id markers")
    stripper.add_argument("file", type=Path)
    args = parser.parse_args(argv[1:])
    if args.command == "check":
        return run_check(args.root, args.base)
    if args.command == "report":
        return run_report(args.root)
    sys.stdout.write(strip(args.file.read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
