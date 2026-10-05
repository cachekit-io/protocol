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
  to tests defined in this repository's tools (`tools/<file>:<name>`), and to a one-line `gap`
  for whatever no vector or test reaches. An id is never reused or renumbered: each file's
  `next` number only grows, and a requirement that leaves the spec moves to its `retired` map.
- conformance/coverage.md is generated from the index, conformance/sdks.json (the sha256 of
  every fixture copy each SDK vendors, as of a named SDK commit) and test-vectors/. Each
  vendored copy is matched to a revision of the fixture in this repository's history, so a
  requirement counts as covered for an SDK only when its copy holds every mapped vector,
  identical to the vector published here.

Keywords are found the way GitHub renders them. The file is read into blocks by CommonMark's
parsing strategy as GitHub's cmark-gfm applies it: blockquotes and list items, lazy
continuation lines, HTML blocks, and GFM tables. Inline code and inline comments are skipped
within one paragraph, heading or table cell, so a code span may cross a line break but never
a block or cell boundary. MUST NOT is one keyword only where a reader sees one phrase: both
words on one line, or across a line break inside one paragraph or heading, with nothing a
reader sees between them. So an id after a NOT in another block, or past a literal >, never
marks the MUST before it. An HTML block is raw HTML, so only its comments are hidden. A
keyword inside a code block, or inside an HTML comment block that spans lines, is an error
(a comment on one line is hidden like an inline one), unless the block is a fence that opens
at column 0, outside every container, with <!-- not-a-requirement --> on the line before it:
if a block were misread, an error fails closed where skipping would hide text.

**What this does NOT catch.** It checks that a mapping exists and that it names real vectors
and tests. It cannot check that they exercise the requirement: whether a plausible wrong
implementation passes every mapped vector is a reviewer's question, and a gap is only as
honest as its reason. "Covered" means an SDK vendors the vectors, not that its tests drive
each one through every entry point a requirement names or assert the error it requires. A
`tools/<file>:<name>` reference is checked for a definition, not for what it asserts. With
`--base`, it catches an id that was dropped instead of retired, a retired id brought back,
and `next` going down; it cannot tell an existing id moved onto a different rule.

Fails closed: an unreadable or malformed file, a duplicate JSON key, a duplicate vector name,
a tab, vertical tab, form feed or lone carriage return in a spec file (only spaces and line
feeds are modelled), a code fence open at the end of the file, an HTML block that leaves a
comment open, an index that lists no spec file, or a vendored sha256 that matches no revision
of its fixture is an error, not a pass. A guard that silently checks
nothing is worse than no guard. Uses explicit failures rather than `assert`, so it cannot be
defanged by `-O`.

Usage:
    python3 tools/conformance.py check [--base REF] [ROOT]   exit 1 on any defect
    python3 tools/conformance.py report [ROOT]               rewrite conformance/coverage.md
    python3 tools/conformance.py strip FILE                  FILE without its id markers, to stdout

`check` and `report` need the repository's full history: a vendored copy is matched to a
revision of its fixture, and a shallow clone holds too few. With `--base`, only revisions
reachable from that commit (plus the working tree's) count, so a copy taken from a commit
that never reached the base branch fails. CI passes the base tip on a pull request and the
commit before the push on main.
`strip` shows that adding ids changed no other text (not-a-requirement markers stay, so the
diff shows every exemption):
    diff <(git show main:spec/interop-mode.md) <(python3 tools/conformance.py strip spec/interop-mode.md)
"""

from __future__ import annotations

import argparse
import ast
import hashlib
from bisect import bisect_right
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
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
FILE_FIELDS = {"prefix", "next", "requirements", "retired"}

# A hard keyword is a whole word (an underscore around it is emphasis, not a letter). MUST NOT
# may be split by a line break, a blockquote marker, or emphasis closed after MUST; scan() keeps
# the two words together only where a renderer shows them as one phrase.
KEYWORD = re.compile(r"(?<![A-Za-z0-9])MUST(?:(?:\*{1,3}|_{1,3})?[\s>]+NOT)?(?![A-Za-z0-9])")
MARKER = re.compile(r'<sup id="([a-z0-9-]+)">([A-Z][A-Z0-9]*-([1-9][0-9]*))</sup>')
EXEMPT = "<!-- not-a-requirement -->"
CLOSER = re.compile(r"\*{1,3}|_{1,3}")
NOT_AFTER = re.compile(r"(?:\*{1,3}|_{1,3})?[\s>]+NOT(?![A-Za-z0-9])")
# Block starts, as GitHub's cmark-gfm reads them, matched against a line's text past its
# container prefix and indentation.
ATX_OPEN = re.compile(r"#{1,6}(?: |$)")
FENCE_OPEN = re.compile(r"`{3,}(?!.*`)|~{3,}")
THEMATIC_BREAK = re.compile(r"(?:\* *){3,}|(?:- *){3,}|(?:_ *){3,}")
SETEXT_UNDERLINE = re.compile(r"(?:=+|-+) *")
LIST_MARKER = re.compile(r"(?:[-+*]|([0-9]{1,9})[.)])(?= |$)")
# A GFM table's delimiter row: cells of dashes, optionally aligned with colons. It needs no pipe.
DELIMITER_ROW = re.compile(r" *\|? *:?-+:? *(?:\| *:?-+:? *)*\|? *")
BLOCK_TAGS = (
    "address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl"
    "|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link"
    "|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|section|source|summary|table|tbody|td|tfoot|th"
    "|thead|title|tr|track|ul"
)
# HTML block types 1 to 6, which may interrupt a paragraph, as (start, end). Type 6 ends at a blank line.
HTML_BLOCKS = (
    (re.compile(r"<(?:pre|script|style|textarea)(?:[ >]|$)", re.I), re.compile(r"</(?:pre|script|style|textarea)>", re.I)),
    (re.compile(r"<!--"), re.compile(r"-->")),
    (re.compile(r"<\?"), re.compile(r"\?>")),
    (re.compile(r"<![A-Za-z]"), re.compile(r">")),
    (re.compile(r"<!\[CDATA\["), re.compile(r"\]\]>")),
    (re.compile(rf"</?(?:{BLOCK_TAGS})(?:[ >]|/>|$)", re.I), None),
)
ATTRIBUTE = r" +[A-Za-z_:][A-Za-z0-9_.:-]*(?: *= *(?:[^ \"'=<>`]+|'[^']*'|\"[^\"]*\"))?"
# HTML block type 7: one complete open or closing tag alone on its line. It ends at a blank line.
HTML_TAG_LINE = re.compile(rf"(?:<[A-Za-z][A-Za-z0-9-]*(?:{ATTRIBUTE})* */?>|</[A-Za-z][A-Za-z0-9-]* *>) *")
PIPE = re.compile(r"(?<!\\)\|")
# Inline code or an inline comment, whichever opens first, within one paragraph (so it may
# cross a line break) or one table cell. A backtick that is escaped, or that sits inside a
# longer run, opens no code span.
INLINE = re.compile(r"(?<![`\\])(`+)(?!`).+?(?<!`)\1(?!`)|<!--.*?-->", re.DOTALL)
# An HTML block is raw HTML: a renderer hides its comments and nothing else.
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
PREFIX = re.compile(r"[A-Z][A-Z0-9]*")
TEST_REF = re.compile(r"(tools/[A-Za-z0-9_.-]+):([A-Za-z0-9_]+)")
# A named test in a .mjs tool must be a function declared at the start of a line, in code: not
# in a comment, a string, a template literal or a regular expression.
MJS_FUNCTION = r"^[ \t]*(?:export[ \t]+)?(?:async[ \t]+)?function\*?[ \t]+{name}[ \t]*\("
JS_WORD = re.compile(r"[A-Za-z0-9_$]+")
JS_KEYWORDS_BEFORE_REGEX = {
    "await", "case", "delete", "do", "else", "in", "instanceof", "new", "of", "return", "throw", "typeof", "void", "yield",
}
ID_MENTION = re.compile(r"\b([A-Z][A-Z0-9]*)-([1-9][0-9]*)\b")
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
    problem: str = ""  # a malformed or misplaced marker beside it


@dataclass(frozen=True)
class Block:
    kind: str  # "code fence", "indented code block" or "HTML comment"
    start: int  # offset where it opens
    end: int  # offset just past where it closes
    line: int  # the line it opens on
    exempt: bool  # a code fence with <!-- not-a-requirement --> on the line before it


@dataclass(frozen=True)
class Spec:
    text: str  # the file, with CRLF line endings normalised to LF
    keywords: list[Keyword]
    stray: list[tuple[int, str]]  # (line, id) of markers that sit beside no keyword
    rows: frozenset[int]  # indexes of the lines in a table


QUOTE = ">"  # an open blockquote, on the stack of open containers


@dataclass
class Item:
    """An open list item, on the stack of open containers."""

    width: int  # how far its content is indented past its parent's
    filled: bool = False  # it holds a block; a blank line continues only an item that does


@dataclass
class Leaf:
    """One leaf block: the lines a renderer puts in one paragraph, heading, table, code block or HTML block."""

    kind: str  # "paragraph", "heading", "table", "code fence", "indented code block", "html" or "break"
    lines: list[int] = field(default_factory=list)  # their indexes
    starts: list[int] = field(default_factory=list)  # where each one's text starts, past its containers' prefixes
    fence: str = ""  # a code fence's opening run of backticks or tildes
    end: re.Pattern[str] | None = None  # what ends an HTML block of types 1 to 5
    comment: bool = False  # an HTML block that opens with <!--
    tried: bool = False  # a paragraph that a delimiter row failed to make a table; cmark-gfm tries once

    def add(self, line: int, start: int) -> None:
        self.lines.append(line)
        self.starts.append(start)


# --- spec scanning ---------------------------------------------------------------------------


def indentation(text: str) -> int:
    return len(text) - len(text.lstrip(" "))


def is_blank(text: str) -> bool:
    """Whether a line, past its containers, is blank: CommonMark counts only spaces and tabs (and a tab is an
    error here), so a non-breaking space or a form feed is text, not blank."""
    return not text.strip(" ")


def cells(row: str) -> int:
    """How many cells a table row has: one more than its unescaped pipes, outer pipes aside.

    Only spaces around the row are trimmed: GitHub reads a non-breaking space after the last
    pipe as one more cell.
    """
    row = row.strip(" ")
    row = row.removeprefix("|")
    row = row[:-1] if row.endswith("|") and not row.endswith("\\|") else row
    return len(PIPE.findall(row)) + 1


def closes(text: str, fence: str) -> bool:
    """Whether a line closes the code fence opened by `fence`: the same character, at least as many, nothing else."""
    body = text[indentation(text) :].rstrip(" ")
    return indentation(text) < 4 and len(body) >= len(fence) and body == fence[0] * len(body)


def html_start(body: str, interrupts: bool) -> int:
    """The HTML block type, 1 to 7, that a line opens, or 0. Type 7 cannot interrupt a paragraph."""
    for kind, (start, _) in enumerate(HTML_BLOCKS, 1):
        if start.match(body):
            return kind
    return 7 if not interrupts and HTML_TAG_LINE.fullmatch(body) else 0


def layout(lines: list[str]) -> list[Leaf]:
    """The leaf blocks of a Markdown file, in order, by CommonMark's parsing strategy as cmark-gfm implements it.

    Each line first continues every open blockquote and list item it can. It may then open
    new ones, and a new leaf block. A line that opens nothing joins the open paragraph, even
    one whose containers it did not continue (a lazy continuation line), or else continues an
    open table or starts a paragraph. Only a list item that holds text and, if ordered, starts
    at 1 interrupts a paragraph, and an HTML block of type 7 never does; a setext underline or
    a table's delimiter row acts only on a paragraph whose containers the line continues. Only
    spaces are read as indentation and only spaces make a line blank, so a tab, a vertical tab,
    a form feed and a lone carriage return are errors, and so is a code fence still open at the
    end of the file.
    """
    stack: list[object] = []  # open containers, outermost first: QUOTE or an Item
    leaves: list[Leaf] = []
    leaf: Leaf | None = None  # the open leaf block, which sits in every container on the stack
    for i, line in enumerate(lines):
        if "\t" in line:
            raise Defect(
                f"line {i + 1}: a tab; indent with spaces (how far a tab indents depends on its column, "
                "which this check does not model)"
            )
        if "\r" in line:
            raise Defect(
                f"line {i + 1}: a carriage return that does not end a CRLF line; GitHub ends a line there, "
                "and this check reads only LF and CRLF line endings"
            )
        if "\v" in line or "\f" in line:
            raise Defect(
                f"line {i + 1}: a vertical tab or form feed; remove it (GitHub reads it as a space in table rows "
                "and HTML tags but as text elsewhere, which this check does not model)"
            )
        pos = matched = 0
        for container in stack:
            rest = line[pos:]
            indent = indentation(rest)
            if container is QUOTE and indent < 4 and rest[indent:].startswith(">"):
                pos += indent + 1 + rest[indent + 1 : indent + 2].count(" ")
            elif isinstance(container, Item) and not is_blank(rest) and indent >= container.width:
                pos += container.width
            elif isinstance(container, Item) and is_blank(rest) and container.filled:
                pos = len(line)
            else:
                break
            matched += 1
        rest = line[pos:]
        continued = matched == len(stack)

        # An open code fence, indented code block or HTML block takes the line if every container continued.
        if leaf and continued:
            if leaf.kind == "code fence":
                leaf.add(i, pos)
                if closes(rest, leaf.fence):
                    leaf = None
                continue
            if leaf.kind == "html" and (leaf.end or not is_blank(rest)):
                leaf.add(i, pos)
                if leaf.end and leaf.end.search(rest):
                    leaf = None
                continue
            if leaf.kind == "indented code block" and (is_blank(rest) or indentation(rest) >= 4):
                leaf.add(i, pos)
                continue
        if is_blank(rest):
            # A blank line closes any other leaf, and every container it did not continue.
            del stack[matched:]
            leaf = None
            continue

        paragraph = leaf is not None and leaf.kind == "paragraph"
        interrupts = paragraph and continued  # a block opened here interrupts the open paragraph
        opened = False  # a container or leaf opened on this line
        kind = ""
        html = 0
        while True:
            rest = line[pos:]
            indent = indentation(rest)
            body = rest[indent:]
            if not body:
                break
            if indent >= 4:
                # While a paragraph is open, an indented line continues it instead of opening code.
                kind = "" if paragraph and not opened else "indented code block"
                break
            container: object | None = None
            step = 0
            item = LIST_MARKER.match(body)
            if body.startswith(">"):
                container, step = QUOTE, indent + 1 + body[1:2].count(" ")
            elif ATX_OPEN.match(body):
                kind = "heading"
            elif FENCE_OPEN.match(body):
                kind = "code fence"
            elif html := html_start(body, interrupts):
                kind = "html"
            elif interrupts and SETEXT_UNDERLINE.fullmatch(body):
                kind = "setext"
            elif THEMATIC_BREAK.fullmatch(body):
                kind = "break"
            elif item and not (
                interrupts and (is_blank(body[item.end() :]) or (item.group(1) is not None and int(item.group(1)) != 1))
            ):
                # The content starts 1 to 4 spaces past the marker; past more, or with none, 1 space past it.
                gap = indentation(body[item.end() :])
                width = item.end() + (gap if not is_blank(body[item.end() :]) and gap <= 4 else 1)
                container, step = Item(indent + width), indent + min(width, item.end() + gap)
            elif interrupts and not leaf.tried and DELIMITER_ROW.fullmatch(body):
                if cells(lines[leaf.lines[-1]][leaf.starts[-1] :]) == cells(body):
                    kind = "table"
                else:
                    leaf.tried = True
            if container is None:
                break
            if not opened:
                del stack[matched:]
                opened = True
            if stack and isinstance(stack[-1], Item):
                stack[-1].filled = True
            stack.append(container)
            matched = len(stack)
            pos += step
            interrupts = False
        rest = line[pos:]

        if kind == "setext":
            # The paragraph becomes a heading, and the underline its last line.
            leaf.kind = "heading"
            leaf.add(i, pos)
            leaf = None
            continue
        if kind == "table":
            # The paragraph's last line becomes the header row; any lines before it stay a paragraph.
            table = Leaf("table")
            table.add(leaf.lines.pop(), leaf.starts.pop())
            if not leaf.lines:
                leaves.remove(leaf)
            table.add(i, pos)
            leaves.append(table)
            leaf = table
            continue
        if not kind and not opened and leaf is not None:
            if paragraph or (leaf.kind == "table" and continued):
                leaf.add(i, pos)  # a paragraph line (lazy if a container did not continue) or a table row
                continue
        if not opened:
            del stack[matched:]
        if is_blank(rest):
            leaf = None  # a line of container markers alone opens no leaf
            continue
        if stack and isinstance(stack[-1], Item):
            stack[-1].filled = True
        leaf = Leaf(kind or "paragraph")
        leaf.add(i, pos)
        leaves.append(leaf)
        if kind == "code fence":
            leaf.fence = FENCE_OPEN.match(rest.lstrip(" ")).group(0)
        elif kind == "html":
            leaf.end = HTML_BLOCKS[html - 1][1] if html <= len(HTML_BLOCKS) else None
            leaf.comment = html == 2
            if leaf.end and leaf.end.search(rest):
                leaf = None
        elif kind in ("heading", "break"):
            leaf = None
    if leaf is not None and leaf.kind == "code fence":
        raise Defect(f"line {leaf.lines[0] + 1}: unclosed code fence (the rest of the file would render as code)")
    return leaves


def blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def mask_cells(row: str) -> str:
    """A table row with its inline code and comments blanked cell by cell: GFM splits cells first."""
    out, start = [], 0
    for pipe in PIPE.finditer(row):
        out += [INLINE.sub(blank, row[start : pipe.start()]), "|"]
        start = pipe.end()
    return "".join(out) + INLINE.sub(blank, row[start:])


def title(leaf: Leaf, lines: list[str]) -> str:
    """A heading's text: an ATX heading's without its # runs, a setext heading's lines without the underline."""
    if len(leaf.lines) > 1:
        return " ".join(lines[i][s:].strip(" ") for i, s in zip(leaf.lines[:-1], leaf.starts[:-1]))
    text = lines[leaf.lines[0]][leaf.starts[0] :].strip(" ").lstrip("#")
    return re.sub(r"(?:^| +)#+ *$", "", text).strip(" ")


def mask(text: str) -> tuple[str, list[Block], list[tuple[int, str]], frozenset[int], list[tuple[int, int] | None]]:
    """(text with what a renderer hides blanked, the code and comment blocks, (offset, title) of each heading, table
    lines, and per line its (paragraph or heading number, column its text starts at), None for any other line).

    Blanked are code blocks, comment blocks, and inline code and comments. Blanking keeps every
    offset and line break, so a position in the masked text maps back to `text`.
    """
    lines = text.split("\n")
    at = [0]
    for line in lines:
        at.append(at[-1] + len(line) + 1)
    masked = list(lines)
    found: list[Block] = []
    headings: list[tuple[int, str]] = []
    rows: set[int] = set()
    prose: list[tuple[int, int] | None] = [None] * len(lines)
    for number, leaf in enumerate(layout(lines)):
        first, last = leaf.lines[0], leaf.lines[-1]
        if leaf.kind in ("paragraph", "heading"):
            for i, start in zip(leaf.lines, leaf.starts):
                prose[i] = (number, start)
            # A code span may cross a line break inside one paragraph or heading, never out of it.
            spans = leaf.lines[:-1] if leaf.kind == "heading" and len(leaf.lines) > 1 else leaf.lines
            for i, part in zip(spans, INLINE.sub(blank, "\n".join(lines[i] for i in spans)).split("\n")):
                masked[i] = part
            if leaf.kind == "heading":
                headings.append((at[first], title(leaf, lines)))
        elif leaf.kind == "table":
            rows.update(leaf.lines)
            for i in leaf.lines:
                masked[i] = mask_cells(lines[i])
        elif leaf.kind in ("code fence", "indented code block"):
            # Only a fence at column 0, outside every container, can be exempted: a line that starts
            # with its run of backticks or tildes, which no indented code block can.
            exempt = lines[first].startswith(("`", "~")) and first > 0 and lines[first - 1].rstrip() == EXEMPT
            found.append(Block(leaf.kind, at[first], at[last] + len(lines[last]), first + 1, exempt))
            for i in leaf.lines:
                masked[i] = " " * len(lines[i])
        elif leaf.kind == "html":
            raw = COMMENT.sub(blank, "\n".join(lines[i] for i in leaf.lines))
            if "<!--" in raw:
                # A renderer passes an HTML block through as it stands, so a comment it leaves open hides
                # everything after it, whatever the Markdown after it says.
                raise Defect(f"line {first + 1}: unclosed HTML comment (the rest of the file would be hidden)")
            for i, part in zip(leaf.lines, raw.split("\n")):
                masked[i] = part
            if leaf.comment and len(leaf.lines) > 1:
                # A comment block: its last line is the first to hold -->.
                end = at[last] + lines[last].index("-->") + 3
                found.append(Block("HTML comment", at[first] + lines[first].index("<!--"), end, first + 1, False))
    return "\n".join(masked), found, headings, frozenset(rows), prose


def scan(text: str) -> Spec:
    """Every hard keyword in `text` (LF line endings), with the id beside it and its section."""
    masked, regions, headings, rows, prose = mask(text)
    line_starts = [0, *(i + 1 for i, c in enumerate(text) if c == "\n")]

    def one_phrase(gap_start: int, gap_end: int) -> bool:
        """Whether the text between MUST and a NOT after it renders as space, so the two read as one MUST NOT.

        On one line the words join in any block unless a > parts them. Across lines, both words must
        sit in one paragraph or heading, and a > between them must be one of the container markers
        that open a continuation line; anywhere else a renderer shows it.
        """
        first = bisect_right(line_starts, gap_start) - 1
        last = bisect_right(line_starts, gap_end) - 1
        blocks = {prose[i][0] if prose[i] is not None else None for i in range(first, last + 1)}
        if first != last and (None in blocks or len(blocks) > 1):
            return False
        for p in range(gap_start, gap_end):
            if text[p] == ">":
                line = bisect_right(line_starts, p) - 1
                if line == first or p - line_starts[line] >= prose[line][1]:
                    return False
        return True

    markers = {m.start(): m for m in MARKER.finditer(masked)}
    used: set[int] = set()
    keywords: list[Keyword] = []
    for m in KEYWORD.finditer(text):
        start = m.start()
        # MUST and NOT are one keyword only where a renderer shows them as one phrase; otherwise MUST stands alone.
        end = m.end() if m.group(0).endswith("NOT") and one_phrase(start + 4, m.end() - 3) else start + 4
        word = "MUST NOT" if end > start + 4 else "MUST"
        section = next((title for at, title in reversed(headings) if at < start), "")
        line = text.count("\n", 0, start) + 1
        # A keyword inside a block is reported, not skipped: if a block was misread, a keyword
        # the renderer shows still fails the check instead of vanishing.
        if block := next((b for b in regions if b.start <= start < b.end), None):
            if block.exempt:
                keywords.append(Keyword(word, start, line, section, ""))
            elif block.kind == "code fence":
                problem = (
                    f"sits inside the code fence opened at line {block.line}, which cannot carry an id: put "
                    f"{EXEMPT} on the line before the fence if it states no requirement, or state it in prose"
                )
                keywords.append(Keyword(word, start, line, section, None, problem))
            elif block.kind == "indented code block":
                problem = (
                    f"sits inside the indented code block at line {block.line}, which can carry neither an id nor an "
                    "exemption: fence it at column 0 if it states no requirement, or state it in prose"
                )
                keywords.append(Keyword(word, start, line, section, None, problem))
            else:
                problem = (
                    f"sits inside the HTML comment opened at line {block.line}, which can carry neither an id "
                    "nor an exemption: reword it"
                )
                keywords.append(Keyword(word, start, line, section, None, problem))
            continue
        if masked[start] == " ":
            continue  # inline code or an inline comment
        pos = end
        if closer := CLOSER.match(text, pos):
            pos = closer.end()
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
            elif (
                word == "MUST"
                and (after := NOT_AFTER.match(text, marker.end()))
                and one_phrase(marker.end(), after.end() - 3)
            ):
                problem = f"{rid} sits between MUST and NOT; it goes after NOT"
        elif text.startswith("<sup", pos):
            problem = 'malformed id marker (expected <sup id="iop-3">IOP-3</sup>)'
        keywords.append(Keyword(word, start, line, section, rid, problem))
    stray = [(text.count("\n", 0, at) + 1, mk.group(2)) for at, mk in markers.items() if at not in used]
    return Spec(text, keywords, stray, rows)


def strip(text: str) -> str:
    """`text` without its id markers. Not-a-requirement markers stay, so a diff shows each exemption."""
    return MARKER.sub("", text.replace("\r\n", "\n"))


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
    except (ValueError, RecursionError) as exc:
        raise Defect(f"{what}: not valid JSON ({exc})") from None


def read(root: Path, rel: str) -> bytes:
    """A file's bytes, with CRLF line endings normalised to LF (a Windows checkout)."""
    try:
        return (root / rel).read_bytes().replace(b"\r\n", b"\n")
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


def canonical(vector: object) -> str:
    """A vector's content as one string, so 30 and 30.0 (or false and 0) never compare equal."""
    return json.dumps(vector, sort_keys=True, ensure_ascii=False)


def git(root: Path, *args: str) -> bytes:
    try:
        proc = subprocess.run(["git", "-c", "log.showSignature=false", "-C", str(root), *args], capture_output=True, check=False)
    except OSError as exc:
        raise Defect(f"cannot run git ({exc})") from None
    if proc.returncode != 0:
        raise Defect(f"git {' '.join(args)}: {proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout


@dataclass(frozen=True)
class Revision:
    vectors: dict[str, str]  # name -> canonical content
    version: str  # the fixture's own "version" field


def revisions(root: Path, fixture: str, ref: str) -> dict[str, tuple[str, bytes]]:
    """sha256 -> (where, bytes) for every revision of a fixture reachable from `ref`, plus the working tree's.

    The bytes are parsed only when a vendored copy matches them, so a malformed revision that no
    SDK vendors cannot break the check.
    """
    rel = f"{FIXTURES}/{fixture}"
    found: dict[str, tuple[str, bytes]] = {}
    commits = git(root, "log", "--full-history", "--diff-filter=ACMRT", "--format=%H", ref, "--", rel).decode().split()
    for commit in reversed(commits):
        blob = git(root, "show", f"{commit}:{rel}")
        found.setdefault(hashlib.sha256(blob).hexdigest(), (commit[:12], blob))
    current = read(root, rel)
    found.setdefault(hashlib.sha256(current).hexdigest(), ("the working tree", current))
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
    fixtures: dict[str, dict[str, str]]  # fixture -> name -> canonical content, as published here
    sdks: dict[str, dict[str, object]]
    vendored: dict[str, dict[str, tuple[Revision, bool]]]  # sdk -> fixture -> (revision, is current)
    specs: dict[str, Spec]
    index: dict  # requirements.json as parsed


def as_strings(value: object, what: str, errors: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        errors.append(f"{what}: must be a non-empty list of non-empty strings (omit the field instead of [])")
        return ()
    if len(set(value)) != len(value):
        errors.append(f"{what}: lists an entry twice")
    return tuple(value)


def expand(ref: str, fixtures: dict[str, dict[str, str]]) -> list[tuple[str, str]]:
    """(fixture, name) pairs a vector reference stands for; raises Defect if it names nothing."""
    fixture, sep, name = ref.partition(":")
    if fixture not in fixtures:
        raise Defect(f"vector {ref!r}: no fixture {FIXTURES}/{fixture}")
    if not sep:
        return [(fixture, n) for n in fixtures[fixture]]
    if name not in fixtures[fixture]:
        raise Defect(f"vector {ref!r}: {fixture} has no vector named {name!r}")
    return [(fixture, name)]


def as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def build(root: Path, errors: list[str], base: str | None = None) -> Model:
    index = parse_json(read(root, INDEX), INDEX)
    sdks = parse_json(read(root, SDKS), SDKS)
    if not isinstance(index, dict) or index.get("schema") != 1 or not isinstance(index.get("files"), dict):
        raise Defect(f'{INDEX}: expected {{"schema": 1, "files": {{...}}}}')
    if not index["files"]:
        raise Defect(f"{INDEX}: lists no spec file, so nothing would be checked")
    if not isinstance(sdks, dict):
        raise Defect(f"{SDKS}: expected an object keyed by SDK name")

    fixtures = {
        path.name: {
            name: canonical(vector)
            for name, vector in fixture_vectors(
                parse_json(read(root, f"{FIXTURES}/{path.name}"), f"{FIXTURES}/{path.name}"), path.name
            ).items()
        }
        for path in sorted((root / FIXTURES).glob("*.json"))
    }
    if not fixtures:
        raise Defect(f"{FIXTURES}/: no fixtures found")

    vendored: dict[str, dict[str, tuple[Revision, bool]]] = {}
    history: dict[str, dict[str, tuple[str, bytes]]] = {}
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
                history[fixture] = revisions(root, fixture, base or "HEAD")
            if sha not in history[fixture]:
                errors.append(
                    f"{SDKS}: {sdk}: {fixture} sha256 {sha[:12]}… matches no revision of {FIXTURES}/{fixture} "
                    f"reachable from {base or 'HEAD'} (a modified copy, or one taken from an unmerged commit)"
                )
                continue
            where, blob = history[fixture][sha]
            try:
                document = parse_json(blob, f"{FIXTURES}/{fixture} at {where}")
                vectors = {name: canonical(v) for name, v in fixture_vectors(document, fixture).items()}
            except Defect as exc:
                errors.append(f"{SDKS}: {sdk}: the {fixture} revision it vendors does not load: {exc}")
                continue
            version = str(document.get("version") or "unversioned") if isinstance(document, dict) else "unversioned"
            current = hashlib.sha256(read(root, f"{FIXTURES}/{fixture}")).hexdigest()
            vendored[sdk][fixture] = (Revision(vectors, version), sha == current)

    specs: dict[str, Spec] = {}
    requirements: list[Requirement] = []
    prefixes: dict[str, str] = {}
    for rel, entry in index["files"].items():
        if not rel.startswith("spec/") or not rel.endswith(".md"):
            errors.append(f"{INDEX}: {rel}: an indexed file must be a spec/*.md file")
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("requirements"), dict):
            errors.append(f"{INDEX}: {rel}: expected prefix, next, requirements and retired")
            continue
        if unknown := sorted(set(entry) - FILE_FIELDS):
            errors.append(f"{INDEX}: {rel}: unknown field(s) {unknown}")
        high = entry.get("next")
        if not isinstance(high, int) or isinstance(high, bool) or high < 1:
            errors.append(f"{INDEX}: {rel}: next must be the number the next new id gets (a positive integer)")
            high = 0
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
        # `next` only ever grows, so a dropped id's number is never offered again.
        for rid in [*mapped, *retired]:
            if high and shape.fullmatch(rid) and int(rid.split("-")[-1]) >= high:
                errors.append(f"{INDEX}: {rel}: {rid} is at or above next ({high}); raise next past it")
        next_id = f"{prefix}-{high}" if high else f"{prefix}-?"

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

    # A gap may name another requirement; that id must exist, or the reason points nowhere.
    active = {req.rid for req in requirements}
    for req in requirements:
        for mention in ID_MENTION.finditer(req.gap):
            if mention.group(1) in prefixes and mention.group(0) not in active:
                errors.append(f"{INDEX}: {req.rid}: gap names {mention.group(0)}, which is not an indexed requirement")

    unindexed = sorted(f"spec/{p.name}" for p in (root / "spec").glob("*.md") if f"spec/{p.name}" not in index["files"])
    requirements.sort(key=lambda r: (r.file, int(r.rid.split("-")[-1])))
    return Model(requirements, unindexed, fixtures, sdks, vendored, specs, index)


def requirement(
    rel: str,
    kw: Keyword,
    entry: object,
    fixtures: dict[str, dict[str, str]],
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
    if not isinstance(binds, str) or binds not in BINDS:
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
        if not (root / m.group(1)).is_file():
            errors.append(f"{what}: test {ref!r}: no file {m.group(1)}")
            continue
        try:
            source = read(root, m.group(1)).decode("utf-8", "replace")
        except Defect as exc:
            errors.append(f"{what}: test {ref!r}: {exc}")
            continue
        suffix = Path(m.group(1)).suffix
        if suffix == ".py":
            try:
                tree = ast.parse(source)
            except SyntaxError as exc:
                errors.append(f"{what}: test {ref!r}: {m.group(1)} does not parse ({exc.msg})")
                continue
            defined = any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == m.group(2) for node in ast.walk(tree)
            )
        elif suffix == ".mjs":
            defined = re.search(MJS_FUNCTION.format(name=re.escape(m.group(2))), js_code(source), re.MULTILINE) is not None
        else:
            errors.append(f"{what}: test {ref!r}: name a .py or .mjs tool")
            continue
        if not defined:
            errors.append(f"{what}: test {ref!r}: {m.group(1)} defines no function {m.group(2)!r}")
    gap = entry.get("gap", "")
    if not isinstance(gap, str) or "\n" in gap or (gap != gap.strip()) or ("gap" in entry and not gap):
        errors.append(f"{what}: gap must be a non-empty one-line reason")
        gap = ""
    if not vectors and not tests and not gap:
        errors.append(f"{what}: maps to no vector and no test, and records no gap")
    return Requirement(kw.rid or "", rel, kw.section, str(binds), only, vectors, tests, gap, kw)


def js_code(source: str) -> str:
    """JavaScript source with its comments, strings, template literals and regular expressions blanked.

    A `/` opens a regular expression after an operator, an opening bracket, a keyword such as
    `return`, or at the start; after an operand it divides. This is a heuristic, not a parser:
    it does not track `${…}` substitutions, and it can read a regular expression as division
    (after `)`, say). A backtick met in the wrong state flips what counts as code, so contrived
    source can reveal a declaration written in a comment or a template literal.
    """
    out: list[str] = []
    operand = False  # the last token was an operand, so a `/` divides
    i = 0
    while i < len(source):
        c, two = source[i], source[i : i + 2]
        if two in ("//", "/*"):
            end = source.find("\n" if two == "//" else "*/", i + 2)
            j = len(source) if end < 0 else end + (0 if two == "//" else 2)
        elif c in "'\"`" or (c == "/" and not operand):
            j, in_class = i + 1, False
            while j < len(source) and (source[j] != c or in_class) and (c == "`" or source[j] != "\n"):
                if source[j] == "\\":
                    j += 1
                elif c == "/":
                    in_class = (in_class or source[j] == "[") and source[j] != "]"
                j += 1
            j += 1
            while c == "/" and j < len(source) and source[j].isalnum():
                j += 1  # the flags
            operand = True
        elif word := JS_WORD.match(source, i):
            operand = word.group(0) not in JS_KEYWORDS_BEFORE_REGEX
            out.append(word.group(0))
            i = word.end()
            continue
        else:
            operand = c in ")]}" if not c.isspace() else operand
            out.append(c)
            i += 1
            continue
        out.append(re.sub(r"[^\n]", " ", source[i:j]))
        i = j
    return "".join(out)


def verify_base(root: Path, base: str) -> None:
    try:
        git(root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}")
    except Defect:
        raise Defect(f"--base {base}: not a commit in this repository") from None


def compare_base(root: Path, base: str, now: dict, sdks: dict, errors: list[str]) -> str:
    """Against `base`: every id is still indexed or retired, retired ids stay retired, `next` never goes
    down, and every SDK is still listed (dropping one would drop its column from the report silently)."""
    if git(root, "ls-tree", "--name-only", base, "--", SDKS).decode().strip():
        for sdk in as_dict(parse_json(git(root, "show", f"{base}:{SDKS}"), f"{SDKS} at {base}")):
            if sdk not in sdks:
                errors.append(f"{SDKS}: {sdk} was listed at {base} and is now gone; its column would vanish from the report")
    listed = git(root, "ls-tree", "--name-only", base, "--", INDEX).decode().strip()
    if not listed:
        return f"{INDEX} does not exist at {base}; nothing to compare"
    then = parse_json(git(root, "show", f"{base}:{INDEX}"), f"{INDEX} at {base}")

    def files(document: object) -> dict[str, dict]:
        return {k: v for k, v in as_dict(as_dict(document).get("files")).items() if isinstance(v, dict)}

    for rel, old in files(then).items():
        new = files(now).get(rel, {})
        active, retired = as_dict(new.get("requirements")), as_dict(new.get("retired"))
        for rid in as_dict(old.get("requirements")):
            if rid not in active and rid not in retired:
                errors.append(f"{INDEX}: {rid} was indexed at {base} and is now gone; retire it instead (ids are never reused)")
        for rid in as_dict(old.get("retired")):
            if rid not in retired:
                errors.append(f"{INDEX}: {rid} was retired at {base}; a retired id stays retired")
        was, is_now = old.get("next"), new.get("next")
        if isinstance(was, int) and isinstance(is_now, int) and is_now < was:
            errors.append(f"{INDEX}: {rel}: next went down from {was} at {base} to {is_now}; ids are never reused")
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
    """The best status the requirement can reach in any SDK, so the summary agrees with the rows."""
    if req.vectors:
        return "partial" if req.gap else "vectors"
    return "tests only" if req.tests else "gap"


def cell(text: str) -> str:
    """Text made safe for a Markdown table cell: every pipe escaped exactly once."""
    return text.replace("\\|", "|").replace("|", "\\|")


def excerpt(text: str, start: int, word: str, rows: frozenset[int]) -> str:
    """The text around the keyword at `start`, from its paragraph, list item or table cell, keyword in bold.

    Display only: a construct it does not follow degrades the excerpt, never the check.
    """
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

    if at in rows:
        row = lines[at]
        pos = row.index("\0")
        pipes = [p.start() for p in PIPE.finditer(row)]
        block = row[max((p for p in pipes if p < pos), default=-1) + 1 : min((p for p in pipes if p > pos), default=len(row))]
    else:
        first = at
        while not opens_item(lines[first]) and first > 0 and not boundary(lines[first - 1]):
            first -= 1
        last = at
        while last + 1 < len(lines) and not boundary(lines[last + 1]) and not opens_item(lines[last + 1]):
            last += 1
        block = " ".join(re.sub(r"^(?:[-*+]|\d+[.)])[ \t]+", "", body(ln)) for ln in lines[first : last + 1])
    clean = MARKER.sub("", block)
    clean = re.sub(r"<!--(?:(?!\0).)*?-->", "", clean)
    clean = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", clean)
    # Emphasis markers go, but not inside code: `2**53` and `__init__` stay as written.
    parts = re.split(r"(`+[^`]*`+)", clean)
    clean = "".join(part if i % 2 else re.sub(r"\*\*|__", "", part) for i, part in enumerate(parts))
    clean = re.sub(r"\s+", " ", clean).strip()
    pos = clean.find("\0")
    if pos < 0 or not clean.startswith(word, pos + 1):
        return cell(re.sub(r"\s+", " ", MARKER.sub("", lines[at]).replace("\0", "")).strip()[:240])
    after = pos + 1 + len(word)
    lo = clean.find(" ", pos - 100, pos) + 1 if pos > 100 else 0
    hi = clean.rfind(" ", after, after + 120) if after + 120 < len(clean) else len(clean)
    hi = hi if hi > after else len(clean)
    shown = ("… " if lo else "") + clean[lo:pos] + f"**{word}**" + clean[after:hi] + (" …" if hi < len(clean) else "")
    return cell(shown)


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
    return "<br>".join(cell(p) for p in parts)


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
        "How ids are assigned, and what each status means: [README.md](README.md#coverage-statuses).",
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
        "| Spec file | Requirements | Vectors, no gap | Vectors and a gap | Tests only | Gap only |",
        "| :--- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for rel in sorted(model.specs):
        reqs = [r for r in model.requirements if r.file == rel]
        counts = [sum(kind(r) == k for r in reqs) for k in ("vectors", "partial", "tests only", "gap")]
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
        spec = model.specs[rel]
        out += ["", f"## {rel}", "", "| Id | Requirement | Vectors, tests and gaps | " + " | ".join(sdks) + " |"]
        out.append("| :--- | :--- | :--- |" + " :--- |" * len(sdks))
        for req in (r for r in model.requirements if r.file == rel):
            link = f"[{req.rid}](../{rel}#{req.rid.lower()})"
            said = f"*{cell(req.section)}*: {excerpt(spec.text, req.keyword.start, req.keyword.word, spec.rows)}"
            cells = " | ".join(status(req, sdk, model) for sdk in sdks)
            out.append(f"| {link} | {said} | {evidence(req, model)} | {cells} |")
        exempt = [kw for kw in spec.keywords if kw.rid == ""]
        if exempt:
            out += ["", f"Marked not-a-requirement in `{rel}`:", ""]
            out += [f"- line {kw.line}: {excerpt(spec.text, kw.start, kw.word, spec.rows)}" for kw in exempt]
    return "\n".join(out) + "\n"


# --- commands --------------------------------------------------------------------------------


def run_check(root: Path, base: str | None) -> int:
    errors: list[str] = []
    notes: list[str] = []
    try:
        if base:
            verify_base(root, base)
        model = build(root, errors, base)
        if base:
            notes.append(compare_base(root, base, model.index, model.sdks, errors))
        if not errors:
            expected = render(model)
            try:
                actual = (root / REPORT).read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
            except (OSError, UnicodeDecodeError):
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
        f"{kinds.count('vectors')} vectors with no gap, {kinds.count('partial')} vectors and a gap, "
        f"{kinds.count('tests only')} tests only, {kinds.count('gap')} gap only; {REPORT} is current"
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
    try:
        (root / REPORT).write_text(render(model), encoding="utf-8", newline="\n")
    except OSError as exc:
        print(f"conformance: cannot write {REPORT} ({exc.strerror or exc})", file=sys.stderr)
        return 1
    print(f"conformance: wrote {REPORT} ({len(model.requirements)} requirement ids)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
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
    try:
        text = args.file.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"conformance: cannot read {args.file} ({exc})", file=sys.stderr)
        return 1
    # Bytes, not text: the output must not depend on the terminal's encoding.
    sys.stdout.buffer.write(strip(text).encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
