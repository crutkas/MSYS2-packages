#!/usr/bin/env python3
"""ARM64 package-admission governance gate.

Deterministic, offline, pure static analyzer for PR-0 of the ARM64 bootstrap
ratchet. It never executes, sources, builds, fetches, or links any PKGBUILD
or toolchain artifact -- it only reads UTF-8 text and applies a narrow,
conservative bash-word tokenizer to the specific fields the rule set cares
about (`source`/`source_<arch>` arrays, scalar variable assignments used for
the quarantine scan, and the scalar `pkgver` assignment).

Fail-closed predicate (see .ci/arm64-cone.txt / arm64-cone.sha256 /
arm64-rules.toml / the design note carried in the PR description for the
full rationale):

  PASS iff:
    1. A (current absolute-rule hits: TOOLCHAIN_QUARANTINE, PARSE_FAIL,
       SCHEMA_INVALID) is empty.
    2. The registry, cone (and its pinned digest), and ledger are
       structurally valid, canonical, sorted, unique, and scope-safe; no
       wildcard/regex bypass; no ledger row names an absolute or promoted
       rule; every row's locator/hash binds to the *current* on-disk
       content of its declared field/path.
       "Promoted" is a CROSS-COMMIT property: a ratchetable rule becomes
       permanently un-ledgerable once the BASE (parent/merge-base) commit's
       ledger already had zero rows for it -- see --base-ledger/--base-ref
       and load_base_ledger_rule_ids(). If no base ledger is available (the
       commit that first introduces the ledger), nothing is treated as
       promoted yet, since nothing has ever been cleared.
    3. V == L as sets keyed by (path, field, locator_sha256) -- both
       V subset L (no new/unlisted debt) and L subset V (no stale debt).
    4. Every ledger row is unexpired (today <= expires).

Raw vs. semantic word values
-----------------------------
Every bash "word" this analyzer recovers (a source array element, a pkgver
value, a scalar variable assignment scanned for the quarantine rule) is
tokenized ONCE into a `Word` carrying TWO representations, computed together
in the same pass so there is never a second, separately-fallible re-scan:

* `Word.text`  -- the exact, verbatim, still-quoted source span. This is the
  ONLY thing ever stored as a ledger `locator` or hashed for binding. It is
  never modified, never "cleaned up", so `sha256(locator)` always matches
  what is physically on disk.
* `Word.value` -- the derived bash SEMANTIC value: syntactic single/double
  quote delimiters are removed, bash's double-quote backslash-escape rules
  (quote, backslash, backtick, dollar-sign, and backslash-newline
  continuation) and its
  unquoted backslash-escape rule (backslash removes the special meaning of
  the following character; backslash-newline is a line continuation and
  vanishes) are both applied, and ADJACENT fragments (whether quoted or not)
  are concatenated exactly as bash would -- e.g. `'git'"://x"'#tag='` and
  `git://x#tag=` are the SAME semantic value. `${...}` and `$(...)` are
  preserved OPAQUELY (copied through unresolved/unevaluated) in both `text`
  and `value` -- their surrounding literal characters are what matters and
  remain fully knowable; their own contents are never executed or expanded.
  ALL rule matching (quarantine, SRC_*, TOOLCHAIN_DEV_VER) is performed
  against `Word.value`, NEVER against `Word.text` -- this is what closes the
  class of evasions where a flagged substring or the quarantined commit hash
  is split across a quote boundary (single, double, or mixed; including an
  empty `''`/`""` used purely as filler) so that no single raw fragment
  contains it, even though bash's own concatenation would reassemble it.

This tokenizer is intentionally NOT permissive: every construct it accepts
is one whose semantic value it fully and precisely understands from the
grammar alone (no best-effort guessing). Anything it cannot understand
raises ParseError, which the caller turns into an absolute, non-ledgerable
PARSE_FAIL for that recipe -- fail-closed, not silently skipped.

Supported static forms
-----------------------
* `source=(...)`/`source_<arch>=(...)` bash arrays and `NAME=value` scalar
  assignments containing any mixture of single-quoted (`'...'`, no escapes
  at all -- 100% literal per bash), double-quoted (`"..."`, with the escapes
  described above), and bare/unquoted words, including adjacent-token
  concatenation, exactly as bash performs word splitting.
* `$(...)` command substitution is tokenized as an OPAQUE, balanced-paren
  literal span (quotes inside it are honored so embedded parens are not
  miscounted) -- it is never evaluated or executed, only kept verbatim in
  both `text` and `value` so the surrounding array/word can still be located
  and its true locator text captured exactly. This is required for real
  recipes (e.g. `bash`, `readline`) that conditionally append patch-level
  source entries via
  `source=(${source[@]} https://.../patch-$(printf "%03d" $p){,.sig})`.
  Because a `$(...)`'s real runtime output is fundamentally unknowable
  without executing it (which this analyzer must never do), a SEPARATE,
  narrow, fail-closed check (`_dynamic_boundary_risk`) flags -- as the
  absolute `DYNAMIC_SOURCE_UNVERIFIABLE` rule -- the specific case where a
  flagged marker (`git://`, `http://`, `#tag=`) could be assembled by
  combining a NON-EMPTY trailing fragment of the text immediately before a
  `$(...)` span with a NON-EMPTY leading fragment of the text immediately
  after it (i.e. an adversary using the substitution purely as a splitting
  gap, exactly mirroring the quote-splitting evasion). It deliberately does
  NOT flag the case where a marker could be produced ENTIRELY inside the
  substitution's own unknowable output with no contribution from either
  side -- that is an inherent, accepted limit of static analysis shared by
  ANY use of `$(...)` (including the legitimate patch-level idiom above),
  and flagging it would make ordinary supported `$(...)` usage fail closed
  unconditionally, which contradicts the requirement to keep it supported.
* A `source`/`source_<arch>` name may be assigned more than once (that same
  conditional-append idiom re-assigns it inside an `if`). Since control flow
  is not evaluated, every element from every such assignment in the file is
  unioned into that array's element set -- a conservative superset so a
  violation hidden behind an untaken branch is still caught.
* A scalar `pkgver=<word>` assignment (quoted or unquoted), read with the
  same tokenizer, first token wins; matched against its SEMANTIC value.
* The quarantine rule additionally scans every top-level SCALAR variable
  assignment in the file (`NAME=<word>`, not just `_commit=`) -- not merely
  a hardcoded set of spellings -- so a reference hidden behind ANY
  intermediate variable is caught, not only the specific `_commit` idiom
  used by today's baseline. Array assignments other than `source`/
  `source_<arch>` are intentionally NOT generically scanned (see
  `find_all_scalar_assignment_values` docstring for the scoping rationale).
* `#` starts a line comment only when it is the first character of an
  as-yet-unstarted word (real bash semantics) -- a `#` that appears after
  other unquoted characters of the *same* word (e.g. inside a URL) is kept
  literal.

Rejection behavior
------------------
Any of the following make a recipe's source/pkgver/scanned-assignment
fields "cannot be safely and unambiguously recovered", which raises
PARSE_FAIL (absolute, fails closed) for that path:
* unterminated single/double-quoted string, or unterminated `$(...)`,
  within the array/word region;
* a bare unquoted `(`/`)` that is not either the array's own delimiters or
  part of a `$(...)` span;
* a dangling backslash at end of input;
* a `source`/`source_<arch>=(` whose closing `)` cannot be located before
  end of file.
No network access, subprocess execution, or `source`/`bash -c` of any
PKGBUILD occurs anywhere in this file. The ONLY subprocess ever invoked is a
strictly read-only, local `git show <ref>:<path>` used solely to materialize
the BASE ledger for cross-commit rule-promotion detection (see
`resolve_default_base_ledger`) -- never for any PKGBUILD or package file.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_DIR = REPO_ROOT / ".ci"
CONE_FILE = CI_DIR / "arm64-cone.txt"
CONE_DIGEST_FILE = CI_DIR / "arm64-cone.sha256"
RULES_FILE = CI_DIR / "arm64-rules.toml"
LEDGER_FILE = CI_DIR / "arm64-debt-ledger.tsv"

QUARANTINE_COMMIT_FULL = "9bbaa7b7a36ae51328cbff6acb720dcfa472db37"
# Any hex prefix of at least this length is treated as an attempted reference
# to the quarantined commit -- long enough that it cannot collide with an
# unrelated short token, short enough to catch common abbreviated forms.
QUARANTINE_MIN_ABBREV = 7

# NOTE on case sensitivity: an audit against makepkg's real implementation
# (libmakepkg/util/source.sh.in get_downloadclient(), which compares
# `[[ $proto = "$handler" ]]` against lowercase DLAGENTS keys; and
# libmakepkg/source/git.sh.in extract_git(), whose `case ${fragment%%=*}`
# only recognizes lowercase keys) showed BOTH an uppercase protocol
# (`HTTP://`) and an uppercase fragment key (`#TAG=`) make makepkg itself
# ABORT the build ("Unknown download protocol" / "Unrecognized
# reference"). Those are broken recipes, not insecure fetches -- makepkg
# cannot reach that state successfully, so no case-folding rule is
# written for either; matching stays exactly case-sensitive throughout
# (see `_extract_protocol_span`/`_extract_fragment_key_span`, which
# compare the extracted tokens with plain `==`).

LEDGER_FIELDS = [
    "path", "field", "rule_id", "locator", "locator_sha256", "matched",
    "reason", "introduced_by", "removal_gate", "expires",
]
LEDGER_HEADER = "\t".join(LEDGER_FIELDS)

CONE_BYPASS_CHARS = set("*?[]{}()|\\")
# Locators/matched preserve literal PKGBUILD shell text verbatim, which
# legitimately and pervasively contains bash parameter expansion syntax
# (`${pkgname}`, `${_realname}`, ...). Braces are therefore NOT treated as
# a bypass/wildcard character here -- only real glob/regex metacharacters
# that could make a ledger row non-exactly bind to on-disk content are
# rejected.
LOCATOR_BYPASS_CHARS = set("*?[]()|\\")

TOOLCHAIN_DEV_VER_RE = re.compile(r"^[0-9]+(\.[0-9]+)*dev$")
# Matches an assignment to `source` or `source_<arch>` in ANY form makepkg
# actually honors: a bare assignment (`source=(`), an append (`source+=(`),
# or the same prefixed by `declare`/`typeset`/`export`/`readonly` and their
# common flags (`declare -a source=(`, `export source+=(`, ...). This is
# NOT a line-anchored "just the plain form" regex specifically because an
# enumerated list of prefixes is always missing one -- matching the
# assignment OPERATOR (`=`/`+=`) immediately after the name, regardless of
# what precedes it on the line, is what makes new omitted prefixes
# structurally impossible rather than another prefix to remember to add.
# `source =(` (a SPACE before `=`) is deliberately NOT matched: that is not
# valid bash assignment syntax at all (bash would parse it as the `source`
# built-in / `.` command given odd arguments, a syntax error, or invoke
# `source` as a command -- never an array assignment), so makepkg does not
# honor it as one either, and treating it as in-scope would be modelling a
# construct that cannot occur.
SOURCE_ARRAY_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:declare|typeset|export|readonly)\s+(?:-[A-Za-z]+\s+)*)?"
    r"(source(?:_[A-Za-z0-9_]+)?)(\+?=)\("
)
PKGVER_RE = re.compile(r"(?m)^[ \t]*pkgver=")
# Any top-level scalar assignment (`NAME=...`, NOT `NAME=(...)` -- arrays are
# excluded here; source/source_<arch> arrays are handled by SOURCE_ARRAY_RE).
SCALAR_ASSIGN_RE = re.compile(r"(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)=(?!\()")
HEX_RE = re.compile(r"[0-9a-fA-F]+")
FIELD_RE = re.compile(r"^(source(_[A-Za-z0-9_]+)?|pkgver)$")


class ParseError(Exception):
    """Raised when a field cannot be safely and unambiguously recovered."""


@dataclass
class Finding:
    path: str
    field: str
    locator: str
    rule_ids: tuple  # sorted tuple of rule_ids this single locator violates
    matched: str


@dataclass
class Word:
    text: str   # raw, verbatim source span -- the ONLY thing ever hashed/stored as a locator
    value: str  # derived bash semantic value -- the ONLY thing ever rule-matched
    start: int
    end: int


def _scan_double_quoted(s: str, pos: int) -> tuple[str, str, int]:
    """pos is the index of the opening '"'. Returns (raw_incl_quotes, value,
    end_pos). `value` has the quotes removed and ONLY the bash-defined
    double-quote escapes processed: backslash before `"` `\\` `$` `` ` `` is
    special (backslash consumed, that character kept literally); backslash
    before a newline is a line continuation (both vanish); backslash before
    any OTHER character retains NO special meaning inside double quotes and
    is kept completely literally (both characters), exactly as bash defines
    it -- this is deliberately NOT a permissive/best-effort transformation,
    it is the precise POSIX/bash double-quote grammar. Both `$(...)` command
    substitution AND legacy `` `...` `` backtick substitution are also
    permitted (and recognized as OPAQUE spans, never evaluated/executed)
    inside double quotes -- exactly as real bash allows -- since real
    recipes (e.g. `ca-certificates`) use backtick substitution inside
    double-quoted arguments.
    """
    start = pos
    i = pos + 1
    n = len(s)
    value_parts: list[str] = []
    while i < n:
        c = s[i]
        if c == "$" and i + 1 < n and s[i + 1] == "(":
            raw, i = _scan_command_subst(s, i)
            value_parts.append(raw)
            continue
        if c == "`":
            raw, i = _scan_backtick_subst(s, i)
            value_parts.append(raw)
            continue
        if c == "\\" and i + 1 < n and s[i + 1] in ('"', "\\", "$", "`"):
            value_parts.append(s[i + 1])
            i += 2
            continue
        if c == "\\" and i + 1 < n and s[i + 1] == "\n":
            i += 2  # line continuation: both characters vanish from value
            continue
        if c == "\\" and i + 1 < n:
            value_parts.append(s[i])
            value_parts.append(s[i + 1])
            i += 2
            continue
        if c == "\\" and i + 1 >= n:
            raise ParseError(f"dangling backslash inside double-quoted string at offset {i}")
        if c == '"':
            return s[start:i + 1], "".join(value_parts), i + 1
        value_parts.append(c)
        i += 1
    raise ParseError(f"unterminated double-quoted string starting at offset {start}")


def _scan_single_quoted(s: str, pos: int) -> tuple[str, str, int]:
    """Single quotes: bash performs NO escape processing at all inside them
    -- every character up to the next `'` is 100% literal, INCLUDING a
    literal backslash immediately followed by a newline (single quotes do
    NOT support line continuation -- unlike double-quoted or unquoted
    context, a `\\<newline>` sequence inside single quotes is two ordinary
    literal characters, not a continuation). Returns (raw_incl_quotes,
    value, end_pos)."""
    start = pos
    i = pos + 1
    n = len(s)
    idx = s.find("'", i)
    if idx == -1:
        raise ParseError(f"unterminated single-quoted string starting at offset {start}")
    return s[start:idx + 1], s[i:idx], idx + 1


def _scan_command_subst(s: str, pos: int) -> tuple[str, int]:
    """pos is the index of '$' in a '$(' command-substitution opener.
    Balances nested parens while skipping quoted content (so parens inside
    a quoted string, e.g. `$(printf "%03d" $p)`, are not miscounted). The
    substitution is treated as an OPAQUE literal span: it is never
    evaluated/executed, only captured verbatim -- identically in both `text`
    and `value` -- so the locator text and the array's true closing paren
    can still be located safely, and so the (narrow, documented) dynamic-
    boundary risk check can still reason about the KNOWN text immediately
    surrounding it."""
    assert s[pos:pos + 2] == "$("
    start = pos
    i = pos + 2
    depth = 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "'":
            _, _, i = _scan_single_quoted(s, i)
            continue
        if c == '"':
            _, _, i = _scan_double_quoted(s, i)
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "(":
            depth += 1
            i += 1
            continue
        if c == ")":
            depth -= 1
            i += 1
            if depth == 0:
                return s[start:i], i
            continue
        i += 1
    raise ParseError(f"unterminated command substitution $(...) starting at offset {start}")


def _scan_backtick_subst(s: str, pos: int) -> tuple[str, int]:
    """pos is the index of the opening legacy backtick '`'. Returns
    (raw_incl_backticks, end_pos). Treated as an OPAQUE literal span
    exactly like `$(...)` -- never evaluated/executed, only captured
    verbatim. Skips nested single/double-quoted content (so a quote's own
    characters, e.g. the pipeline-separated `sed` invocations real recipes
    use, don't prematurely end the substitution) and honors an escaped
    backtick or backslash (`\\``, `\\\\`) as literal, non-terminating. This
    is required for real recipes (e.g. `ca-certificates`, `gcc`,
    `python-flit-core`) that use legacy backtick command substitution in
    scalar variable assignments.
    """
    start = pos
    i = pos + 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            i = (j + 1) if j != -1 else n
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if s[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if s[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "`":
            return s[start:i + 1], i + 1
        i += 1
    raise ParseError(f"unterminated backtick command substitution starting at offset {start}")


def _tokenize_words(s: str, pos: int, end_limit: int, stop_at_paren: bool):
    """Tokenize whitespace-separated, quote-aware, concatenation-aware words
    from s[pos:end_limit], computing BOTH the raw verbatim text and the
    derived bash semantic value for each word IN THE SAME PASS (see the
    module docstring's "Raw vs. semantic word values" section). If
    stop_at_paren, an unquoted ')' ends the whole region (its index is
    returned as close_pos); otherwise the region simply runs to end_limit.
    Returns (words, close_pos_or_None). Raises ParseError for anything this
    narrow grammar cannot precisely and unambiguously resolve -- there is no
    permissive/best-effort fallback path.
    """
    words: list[Word] = []
    n = end_limit
    i = pos
    cur_raw: list[str] = []
    cur_value: list[str] = []
    cur_start = None
    close_pos = None

    def flush():
        nonlocal cur_raw, cur_value, cur_start
        if cur_raw:
            words.append(Word("".join(cur_raw), "".join(cur_value), cur_start, i))
            cur_raw = []
            cur_value = []
            cur_start = None

    while i < n:
        c = s[i]
        if c in " \t\r\n":
            flush()
            i += 1
            continue
        if c == "#" and not cur_raw:
            # Comment: only a bare '#' at the very start of a fresh word.
            nl = s.find("\n", i)
            i = n if nl == -1 or nl > n else nl
            continue
        if c == ")" and stop_at_paren:
            flush()
            close_pos = i
            break
        if c == "(":
            # A bare unquoted '(' that is not part of $(...) is an
            # unsupported nested construct -- fail closed.
            raise ParseError(f"unsupported unquoted '(' at offset {i}")
        if c == "$" and i + 1 < n and s[i + 1] == "(":
            if cur_start is None:
                cur_start = i
            raw, i = _scan_command_subst(s, i)
            cur_raw.append(raw)
            cur_value.append(raw)  # opaque passthrough: never evaluated
            continue
        if c == "$" and i + 1 < n and s[i + 1] == "'":
            # ANSI-C quoting ($'...'). Verified (see the module docstring)
            # that no in-cone recipe uses this construct -- rather than
            # implementing its full escape grammar, it is explicitly
            # rejected fail-closed: an unsupported construct must never be
            # silently passed through or guessed at.
            raise ParseError(f"unsupported ANSI-C-quoted string ($'...') at offset {i}")
        if c == "`":
            if cur_start is None:
                cur_start = i
            raw, i = _scan_backtick_subst(s, i)
            cur_raw.append(raw)
            cur_value.append(raw)  # opaque passthrough: never evaluated
            continue
        if c == '"':
            if cur_start is None:
                cur_start = i
            raw, val, i = _scan_double_quoted(s, i)
            cur_raw.append(raw)
            cur_value.append(val)
            continue
        if c == "'":
            if cur_start is None:
                cur_start = i
            raw, val, i = _scan_single_quoted(s, i)
            cur_raw.append(raw)
            cur_value.append(val)
            continue
        if c == "\\" and i + 1 < n and s[i + 1] == "\n":
            # Unquoted backslash-newline: a line continuation -- both
            # characters are kept in the raw locator text (so it still
            # binds to the exact on-disk bytes) but contribute NOTHING to
            # the semantic value.
            if cur_start is None:
                cur_start = i
            cur_raw.append(s[i:i + 2])
            i += 2
            continue
        if c == "\\" and i + 1 < n:
            # Unquoted backslash: escapes exactly the next character (its
            # special meaning, if any, is removed); the backslash itself is
            # consumed and does not appear in the semantic value.
            if cur_start is None:
                cur_start = i
            cur_raw.append(s[i:i + 2])
            cur_value.append(s[i + 1])
            i += 2
            continue
        if c == "\\" and i + 1 >= n:
            raise ParseError(f"dangling backslash at end of input at offset {i}")
        # Bare unquoted run: consume until a char that needs special
        # handling (whitespace, quote, paren, backtick, '$(' / $'...', or a
        # leading '#').
        if cur_start is None:
            cur_start = i
        j = i
        while j < n:
            cj = s[j]
            if cj in " \t\r\n\"'()":
                break
            if cj == "`":
                break
            if cj == "#" and j == i and not cur_raw:
                break
            if cj == "\\":
                break
            if cj == "$" and j + 1 < n and s[j + 1] in ("(", "'"):
                break
            j += 1
        if j == i:
            # Nothing consumed (shouldn't happen) -- avoid infinite loop.
            raise ParseError(f"unrecognized character {c!r} at offset {i}")
        chunk = s[i:j]
        cur_raw.append(chunk)
        cur_value.append(chunk)
        i = j
    else:
        if stop_at_paren:
            raise ParseError("array not terminated with ')' before end of file")
    flush()
    return words, close_pos


def _find_dynamic_spans(word_text: str) -> list[tuple[int, int]]:
    """Returns the (start, end) character offsets of every OPAQUE dynamic
    span -- `$(...)` command substitution OR legacy `` `...` `` backtick
    substitution -- within an already-tokenized word's raw text, INCLUDING
    ones nested inside a double-quoted segment (bash permits both forms of
    command substitution inside double quotes; earlier versions of this
    analyzer only looked for them at the top level, which meant
    `source=("htt$(echo t)p://...")`, `"git`echo :`//..."`, etc. went
    undetected by the dynamic-boundary-risk and quarantine-split checks --
    this closes that gap). Used only by `_dynamic_boundary_risk` and
    `_quarantine_dynamic_boundary_risk`; never executes anything.
    """
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(word_text)

    def _consume_dynamic(start: int) -> int:
        try:
            if word_text[start:start + 2] == "$(":
                _, end = _scan_command_subst(word_text, start)
            else:
                _, end = _scan_backtick_subst(word_text, start)
        except ParseError:
            end = n
        spans.append((start, end))
        return end

    while i < n:
        c = word_text[i]
        if c == "'":
            j = word_text.find("'", i + 1)
            i = (j + 1) if j != -1 else n
            continue
        if c == '"':
            i += 1
            while i < n:
                cj = word_text[i]
                if cj == "$" and i + 1 < n and word_text[i + 1] == "(":
                    i = _consume_dynamic(i)
                    continue
                if cj == "`":
                    i = _consume_dynamic(i)
                    continue
                if cj == "\\" and i + 1 < n:
                    i += 2
                    continue
                if cj == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "$" and i + 1 < n and word_text[i + 1] == "(":
            i = _consume_dynamic(i)
            continue
        if c == "`":
            i = _consume_dynamic(i)
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        i += 1
    return spans


def _boundary_straddle_possible(preceding: str, following: str, target: str, min_contribution: int = 1) -> bool:
    """True if `target` could be assembled as
    [some suffix of preceding] + [the dynamic span's unknowable output,
    of ANY length/content] + [some prefix of following], for SOME pair of
    split points (p1 <= p2, 0 <= p1,p2 <= len(target)) where preceding ends
    with target[:p1] and following starts with target[p2:]. The gap
    target[p1:p2] (possibly empty) is exactly what the dynamic span would
    need to contribute -- since its real output is never executed/known,
    ANY such gap is considered adversarially achievable.

    The EXCLUDED cases are every (p1, p2) pair where NEITHER side
    contributes at least `min_contribution` real characters (i.e. both
    p1 < min_contribution and length - p2 < min_contribution). With the
    default `min_contribution=1` (used for `$(...)`/backtick spans), this
    excludes only the single fully-trivial p1==0-and-p2==length case --
    neither side contributes anything and the entire target could only
    come from the dynamic span's own output, an inherent, accepted limit
    of static analysis true of literally ANY `$(...)`/backtick usage for
    literally any target string (flagging it would make every real,
    supported use, e.g. the bash/readline `$(printf ...)` patch-level
    idiom, fail closed unconditionally). Every OTHER combination -- where
    at least one side contributes a real, non-empty fragment, however
    short -- is flagged, catching a deliberate split even when an
    individual fragment is very short (e.g. a 5-character hash prefix,
    below the quarantine abbreviation threshold).

    A higher `min_contribution` (used for unresolved `${name}` parameter
    expansions, which -- unlike rare `$(...)` spans -- sit adjacent to
    single generic separator characters like `/` constantly in ordinary,
    compliant PKGBUILD source URLs such as `.../${pkgname}/${pkgname}-
    ${pkgver}.tar.gz`) additionally excludes degenerate single-character
    coincidental overlaps that carry no real signal, while still catching
    any genuine multi-character marker fragment straddling the boundary.
    """
    length = len(target)
    valid_p1 = [p for p in range(length + 1) if preceding.endswith(target[:p])]
    valid_p2 = [p for p in range(length + 1) if following.startswith(target[p:])]
    for p1 in valid_p1:
        for p2 in valid_p2:
            if p1 <= p2 and (p1 >= min_contribution or (length - p2) >= min_contribution):
                return True
    return False


def _quarantine_dynamic_boundary_risk(word: Word) -> bool:
    """Same reasoning as `_dynamic_boundary_risk`, but for the quarantined
    commit hash: flags a dynamic span positioned where the hash could be
    assembled straddling it, including fragments shorter than
    QUARANTINE_MIN_ABBREV on one side -- a deliberate split across an
    unexecuted substitution is inherently suspicious regardless of
    individual fragment length, e.g. `_c=9bbaa`echo x`7b7a36ae...` where
    "9bbaa" alone is only 5 hex characters. Case-insensitive, matching
    `contains_quarantine_reference`.
    """
    spans = _find_dynamic_spans(word.text)
    if not spans:
        return False
    full = QUARANTINE_COMMIT_FULL
    for start, end in spans:
        cs_text = word.text[start:end]
        idx = word.value.find(cs_text)
        if idx == -1:
            continue
        preceding = word.value[:idx].lower()
        following = word.value[idx + len(cs_text):].lower()
        if _boundary_straddle_possible(preceding, following, full):
            return True
    return False


def parse_source_arrays(text: str, path: str) -> tuple[dict[str, list[Word]], list[tuple[int, int]]]:
    """Returns ({array_name: [Word, ...]}, consumed_spans) for every
    source/source_<arch> array. `consumed_spans` is the list of (start, end)
    character ranges each array's full declaration occupies -- used by
    `find_all_scalar_assignment_values` so a continuation line that is
    semantically part of an ALREADY-parsed array (e.g. a backslash-newline
    inside a multi-line quoted array element) is never misinterpreted as an
    unrelated top-level scalar assignment.

    A name may be assigned more than once (a common PKGBUILD idiom is a
    conditional block that reassigns `source=(${source[@]} <extra>)` to
    append patch-level-specific entries). Since this static analyzer does
    not evaluate control flow, it conservatively takes the UNION of every
    element ever assigned to a given array name across the whole file --
    a superset over-approximation of what could reach the final array on
    any code path, so a violation hidden behind an untaken conditional
    branch is still caught (fail-closed), never silently dropped.
    """
    result: dict[str, list[Word]] = {}
    spans: list[tuple[int, int]] = []
    for m in SOURCE_ARRAY_RE.finditer(text):
        name = m.group(1)
        open_paren = m.end() - 1
        assert text[open_paren] == "("
        try:
            words, close_pos = _tokenize_words(text, open_paren + 1, len(text), stop_at_paren=True)
        except ParseError as e:
            raise ParseError(f"{path}: {name}=(...): {e}") from e
        result.setdefault(name, []).extend(words)
        spans.append((m.start(), close_pos if close_pos is not None else len(text)))
    return result, spans



def _find_logical_line_end(text: str, start: int) -> int:
    """Returns the index of the first UNESCAPED newline at/after `start`,
    treating a backslash immediately preceding a newline as a line
    continuation -- so a scalar assignment's value (e.g. a `./configure`
    argument like bash_cv_dev_stdin=present, continued with a trailing
    backslash onto the next physical line, as seen in real recipes) can legitimately span multiple
    physical lines without the boundary being cut mid-continuation."""
    i = start
    n = len(text)
    while i < n:
        if text[i] == "\n":
            if i > start and text[i - 1] == "\\":
                i += 1
                continue
            return i
        i += 1
    return n


def parse_pkgver(text: str, path: str) -> tuple[Word | None, tuple[int, int] | None]:
    matches = list(PKGVER_RE.finditer(text))
    if not matches:
        return None, None
    if len(matches) > 1:
        raise ParseError(f"{path}: multiple top-level pkgver= assignments")
    m = matches[0]
    val_start = m.end()
    line_end = _find_logical_line_end(text, val_start)
    try:
        words, _ = _tokenize_words(text, val_start, line_end, stop_at_paren=False)
    except ParseError as e:
        raise ParseError(f"{path}: pkgver=...: {e}") from e
    if not words:
        raise ParseError(f"{path}: pkgver= has no value")
    return words[0], (m.start(), words[0].end)


def find_all_scalar_assignment_values(text: str, path: str, exclude_spans: list[tuple[int, int]] = ()) -> list[Word]:
    """Returns the first-token Word of every top-level SCALAR variable
    assignment in the file (`NAME=value`, explicitly excluding `NAME=(...)`
    array assignments, which SOURCE_ARRAY_RE/parse_source_arrays already
    handle for `source`/`source_<arch>` specifically).

    This exists ONLY to widen the quarantine (TOOLCHAIN_QUARANTINE) scan so
    a reference to the forbidden commit hidden behind ANY intermediate
    scalar variable (not merely the `_commit` spelling used by today's
    baseline recipes) cannot evade detection -- e.g.
    `_commit="<hash>"` ... `source=(...#commit=${_commit})`.

    `exclude_spans` are character ranges ALREADY consumed by parsing the
    source arrays / pkgver (see parse_source_arrays / parse_pkgver). This
    matters because a value can legitimately span multiple physical lines
    via a backslash-newline continuation inside a quoted string; without
    excluding those already-consumed spans, a continuation line that
    happens to start with something matching `IDENTIFIER=` (e.g. the tail
    of a still-open double-quoted array element resuming on the next
    physical line) would be misinterpreted as an unrelated top-level scalar
    assignment. Matches inside `exclude_spans`, and inside the span of any
    scalar assignment already parsed earlier in this same scan, are
    skipped.

    Scoping note (deliberately NOT generic-array-aware): this analyzer does
    NOT attempt to generically tokenize arbitrary OTHER arrays
    (`depends=(...)`, `makedepends=(...)`, `groups=(...)`, etc.). Those
    fields are not plausible carriers for a VCS commit hash, commonly use
    bash constructs well outside this analyzer's narrow supported grammar,
    and attempting to parse them would materially raise the risk of a
    spurious PARSE_FAIL on real, otherwise-compliant recipes for a field
    this rule set has no reason to inspect. Scalar assignments are low-risk
    (a single tokenized word) and are exactly the shape real recipes use for
    commit-hash indirection, so the scan is scoped to them precisely.
    """
    def _excluded(pos: int, spans) -> bool:
        return any(s <= pos < e for s, e in spans)

    values: list[Word] = []
    consumed = list(exclude_spans)
    for m in SCALAR_ASSIGN_RE.finditer(text):
        if _excluded(m.start(), consumed):
            continue
        name = m.group(1)
        val_start = m.end()
        line_end = _find_logical_line_end(text, val_start)
        try:
            words, _ = _tokenize_words(text, val_start, line_end, stop_at_paren=False)
        except ParseError as e:
            raise ParseError(f"{path}: {name}=...: {e}") from e
        if words:
            values.append(words[0])
            consumed.append((m.start(), words[0].end))
    return values


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


BARE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# `${source[@]}`/`${source_x86_64[*]}` -- see resolve_effective_value for
# why this specific self-referential whole-array expansion is treated as
# contributing no new content, unlike any other `${name[...]}` array
# index/slice reference (which stays unresolved/opaque per the auditor's
# explicit instruction that array-element references must not be
# silently passed through).
SOURCE_ARRAY_SELF_REF_RE = re.compile(r"^source(?:_[A-Za-z0-9_]+)?\[[@*]\]$")
VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _find_param_expansion_spans(s: str) -> list[tuple[int, int]]:
    """Finds every `${...}` parameter-expansion span in `s`, respecting
    nesting (a `${` occurring INSIDE another `${...}` increases depth, and
    the matching `}` is the one that returns depth to zero, e.g.
    `${x:-${y}}`). Returns (start, end) offsets, `end` one past the closing
    `}`. Unlike the tokenizer's deliberate non-tracking of plain `{`/`}`
    (safe there because nothing depends on finding a matching `}`), THIS
    function's whole purpose is finding the exact extent of a `${...}`
    construct, because classifying whether its content is one we
    understand (a bare name we can resolve) or something else entirely
    (an operator, indirection, an array index -- anything we do not
    model) requires knowing precisely where it ends. An unterminated `${`
    (no matching `}` before the end of the string) fails closed by
    consuming to the end of the string as one opaque span.
    """
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "$" and i + 1 < n and s[i + 1] == "{":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if s[j] == "$" and j + 1 < n and s[j + 1] == "{":
                    depth += 1
                    j += 2
                    continue
                if s[j] == "}":
                    depth -= 1
                    j += 1
                    continue
                j += 1
            spans.append((i, j))
            i = j
        else:
            i += 1
    return spans


def build_resolved_variable_map(text: str) -> dict[str, str]:
    """Scans every top-level SCALAR assignment (`NAME=value`, a single
    tokenized word -- NOT arrays) and returns {name: fully-resolved literal
    value} for names that are BOTH:
      (a) assigned EXACTLY ONCE anywhere in the file -- a name assigned
          more than once (e.g. conditionally, or via any control flow this
          analyzer does not evaluate) is never resolved: rather than
          guessing which assignment "wins" (exploitable either way, since
          an attacker could target whichever one is NOT checked), it is
          conservatively left fully unresolved so every downstream check
          must fail closed at any position it could affect, and
      (b) whose value, after a bounded fixed-point substitution pass over
          bare `${other}` references that are themselves resolved this
          way, contains NO remaining `${...}` construct of ANY form and no
          `$(...)`/backtick dynamic span. This means an unmodeled operator
          (`${x:-y}`, `${x//a/b}`, `${!x}`, `${x[0]}`, ...) NEVER gets
          treated as resolved just because it happens to sit inside a
          scalar assignment -- unlike a plain bare-`${other}` chain, which
          IS resolved, since leaving that unresolved would be a needless
          false positive rather than a genuine limit of static analysis.
    A name failing either condition is simply ABSENT from the returned
    map. This is pure, safe, static string substitution of already-parsed
    literal text -- it never executes, sources, or evaluates anything.
    """
    raw_values: dict[str, list[str]] = {}
    for m in SCALAR_ASSIGN_RE.finditer(text):
        name = m.group(1)
        val_start = m.end()
        line_end = _find_logical_line_end(text, val_start)
        try:
            words, _ = _tokenize_words(text, val_start, line_end, stop_at_paren=False)
        except ParseError:
            raw_values.setdefault(name, []).append(None)
            continue
        raw_values.setdefault(name, []).append(words[0].value if words else None)

    candidates: dict[str, str] = {}
    permanently_unresolved: set[str] = set()
    for name, values in raw_values.items():
        if len(values) != 1 or values[0] is None:
            permanently_unresolved.add(name)
            continue
        candidates[name] = values[0]

    resolved: dict[str, str] = {}
    for _ in range(10):
        changed = False
        for name in list(candidates.keys()):
            value = candidates[name]
            if _find_dynamic_spans(value):
                permanently_unresolved.add(name)
                del candidates[name]
                changed = True
                continue
            spans = _find_param_expansion_spans(value)
            bare_refs: set[str] = set()
            has_unmodeled = False
            for start, end in spans:
                content = value[start + 2:end - 1]
                if BARE_NAME_RE.match(content):
                    bare_refs.add(content)
                else:
                    has_unmodeled = True
            if has_unmodeled:
                permanently_unresolved.add(name)
                del candidates[name]
                changed = True
                continue
            if not bare_refs:
                resolved[name] = value
                del candidates[name]
                changed = True
                continue
            if bare_refs & permanently_unresolved:
                permanently_unresolved.add(name)
                del candidates[name]
                changed = True
                continue
            if bare_refs <= resolved.keys():
                new_value = VAR_REF_RE.sub(lambda m: resolved[m.group(1)], value)
                candidates[name] = new_value
                changed = True
        if not changed:
            break
    return resolved


def resolve_effective_value(value: str, resolved_vars: dict[str, str]) -> tuple[str, list[tuple[int, int]]]:
    """Substitutes every STATICALLY-resolvable BARE `${name}` reference in
    `value` using `resolved_vars`, returning (effective_value,
    unresolved_spans) where `unresolved_spans` are the (start, end) offsets
    WITHIN effective_value of every `${...}` parameter-expansion construct
    that could NOT be resolved -- this includes not only a bare `${name}`
    whose name is absent from `resolved_vars`, but ALSO any `${...}` form
    this analyzer does not model at all (an operator such as `:-`, `//`,
    `#`, `%`, `^^`, `,,`, indirection `${!name}`, an array index
    `${name[0]}`, ...). Modeling only SOME operators and silently passing
    the rest through as inert literal text would be exactly the same
    "handle what we understand, silently allow what we don't" defect this
    analyzer exists to close elsewhere (raw-vs-semantic quoting, dynamic
    substitution boundaries): every unmodeled `${...}` construct is
    therefore treated identically to an unresolved bare name -- an opaque
    span whose real runtime value is unknown -- regardless of how
    "obviously safe" its literal spelling might look.

    An unresolved/unmodeled span is left as its literal on-disk text in
    the output (so its exact character length/position within
    effective_value is preserved) and its span is reported so the caller
    can determine whether it overlaps a security-decisive position (the
    scheme token, the VCS fragment key -- see `_extract_protocol_span`/
    `_extract_fragment_key_span`). Failing to substitute a genuinely
    resolvable bare reference here would be a fail-OPEN (the marker is
    present, just spelled with a variable name bash would expand at
    runtime), which is why resolution is attempted for that one narrow,
    provably-safe case.
    """
    spans = _find_param_expansion_spans(value)
    out: list[str] = []
    unresolved: list[tuple[int, int]] = []
    pos = 0
    for start, end in spans:
        out.append(value[pos:start])
        content = value[start + 2:end - 1]
        if BARE_NAME_RE.match(content) and content in resolved_vars:
            out.append(resolved_vars[content])
        elif SOURCE_ARRAY_SELF_REF_RE.match(content):
            # `${source[@]}`/`${source_x86_64[*]}` (self-referential
            # whole-array expansion, the standard "append another element
            # to the array I am currently (re-)declaring" idiom, e.g.
            # `source=(${source[@]} <new-entry>)`). This contributes
            # nothing NEW to verify: it expands to elements of a
            # source/source_<arch> array that is ALWAYS independently
            # scanned in full regardless of this reference (every
            # source=(...)/source_<arch>=(...) assignment's own tokenized
            # elements are unioned into `arrays[name]` by
            # parse_source_arrays and matched on their own), so treating
            # it as empty here neither hides nor duplicates a finding.
            pass
        else:
            span_start = sum(len(p) for p in out)
            out.append(value[start:end])
            unresolved.append((span_start, span_start + (end - start)))
        pos = end
    out.append(value[pos:])
    return "".join(out), unresolved


def _collect_opaque_spans(word: "Word", unresolved_expansion_spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Combines `$(...)`/backtick dynamic spans (mapped from `word.text`
    offsets into `word.value`/effective-value offsets) with unresolved
    `${...}` parameter-expansion spans into one list of opaque character
    ranges within the semantic value -- positions whose real runtime
    content this analyzer cannot know."""
    spans: list[tuple[int, int]] = []
    for start, end in _find_dynamic_spans(word.text):
        cs_text = word.text[start:end]
        idx = word.value.find(cs_text)
        if idx != -1:
            spans.append((idx, idx + len(cs_text)))
    spans.extend(unresolved_expansion_spans)
    return spans


def _split_filename_prefix(value: str) -> tuple[int, str]:
    """Mirrors makepkg's get_url()/get_protocol() (`${1#*::}`): strip up
    to and including the FIRST '::' if present (a `filename::url` source
    entry). Returns (url_start_offset_within_value, url_part)."""
    idx = value.find("::")
    if idx == -1:
        return 0, value
    return idx + 2, value[idx + 2:]


def _extract_vcs_type_span(value: str) -> tuple[int, int] | None:
    """Mirrors makepkg's get_protocol() exactly (`${proto%%+*}`): returns
    the (start, end) offset within `value` of the VCS-HANDLER-DISPATCH
    token -- what decides whether `extract_git()`'s fragment-key
    vocabulary (commit/tag/branch) applies at all. For `git+https://` this
    is `git` (get_protocol() truncates AT the first `+`), the SAME VCS
    type as bare `git://`, since both are handled by the git downloader.
    This is intentionally a DIFFERENT token from `_extract_protocol_span`
    (which decides transport security using the opposite truncation
    direction) -- makepkg itself uses two different substrings of the
    same prefix for two different purposes, and conflating them was an
    earlier defect in this analyzer (a `git+https://` source was
    incorrectly flagged as insecure `SRC_GIT_PROTO` before this split).
    """
    url_start, url_part = _split_filename_prefix(value)
    scheme_idx = url_part.find("://")
    if scheme_idx == -1:
        return None
    proto_full = url_part[:scheme_idx]
    plus_idx = proto_full.find("+")
    vcs_len = plus_idx if plus_idx != -1 else len(proto_full)
    return (url_start, url_start + vcs_len)


def _extract_protocol_span(value: str) -> tuple[int, int] | None:
    """Returns the (start, end) offset within `value` of the token that
    decides transport SECURITY, or None if there is no '://' at all after
    stripping any 'filename::' prefix (makepkg's "local" source case --
    no protocol to check).

    This is deliberately NOT the same truncation as makepkg's own
    get_protocol() (`${proto%%+*}`, which keeps only the part BEFORE a
    `+` for VCS-HANDLER DISPATCH purposes, e.g. both `git://` and
    `git+https://` report VCS type "git"). For OUR purposes -- is the
    actual data transport insecure/plaintext -- that truncation direction
    is wrong: `download_git()` does `url=${url#git+}` and hands the
    REMAINDER straight to `git clone`, so for a `vcstype+transport://`
    entry the transport that is actually fetched over is the part AFTER
    the `+` (`git+https://` fetches over HTTPS -- secure; `git+git://`
    explicitly requests the native insecure git:// transport). Only a
    bare scheme with no `+` (`git://`, `http://`, `https://`) uses the
    whole pre-`://` token directly as its own transport. See
    `_extract_vcs_type_span` for the OTHER truncation, used to decide
    whether the git fragment-key vocabulary applies.
    """
    url_start, url_part = _split_filename_prefix(value)
    scheme_idx = url_part.find("://")
    if scheme_idx == -1:
        return None
    proto_full = url_part[:scheme_idx]
    plus_idx = proto_full.find("+")
    if plus_idx != -1:
        transport_start = url_start + plus_idx + 1
        return (transport_start, url_start + len(proto_full))
    return (url_start, url_start + len(proto_full))



def _extract_fragment_key_span(value: str) -> tuple[int, int] | None:
    """Mirrors makepkg's get_uri_fragment() + extract_git()'s
    `${fragment%%=*}`: the fragment is everything after the FIRST '#' in
    the whole entry, truncated at the first '?'; the key is everything in
    the fragment before its first '='. Returns None if there is no '#' at
    all (no VCS fragment present)."""
    hash_idx = value.find("#")
    if hash_idx == -1:
        return None
    frag_start = hash_idx + 1
    frag = value[frag_start:]
    q_idx = frag.find("?")
    if q_idx != -1:
        frag = frag[:q_idx]
    eq_idx = frag.find("=")
    key_len = eq_idx if eq_idx != -1 else len(frag)
    return (frag_start, frag_start + key_len)


def _span_overlaps_any(span: tuple[int, int], opaque_spans: list[tuple[int, int]]) -> bool:
    s, e = span
    for os_, oe in opaque_spans:
        if s < oe and os_ < e:
            return True
    return False


def _delimiter_could_be_hidden(effective_value: str, opaque_spans: list[tuple[int, int]], delimiter: str) -> bool:
    """True if any opaque span (a `$(...)`/backtick dynamic substitution
    or an unresolved/unmodeled `${...}` expansion) sits where it could
    contribute part of `delimiter` (`"://"`) that the LITERAL text search
    `_extract_vcs_type_span`/`_extract_protocol_span`/
    `_extract_fragment_key_span` rely on (`str.find`) would otherwise
    simply miss -- e.g. `"git$(echo :)//example.org/x"` never contains
    the literal substring `"://"` at all (the `:` is produced by the
    substitution), so a plain `.find("://")` would incorrectly conclude
    there is no scheme here rather than failing closed.

    Uses `min_contribution=2`, NOT the dynamic-span default of 1: unlike a
    `$(...)`/backtick span (rare in this corpus), an unresolved `${...}`
    expansion sits immediately before a bare `/` constantly in ordinary,
    fully compliant source URLs (`.../${pkgver%.*}/name-${pkgver}.tar.xz`),
    and `://`'s own trailing single character (`/`) would otherwise
    coincidentally "straddle" on that ubiquitous `/` alone. Requiring at
    least a 2-character real contribution (verified to still catch the
    adversarial `git$(echo :)//...` case, where the following text's
    `"//"` overlap with `://`'s `[1:]` suffix is itself 2 characters)
    keeps this sensitive to genuine delimiter-splitting without flagging
    every ordinary unresolved expansion adjacent to a single path
    separator.

    NOTE, documented rather than silently accepted: this same technique
    is NOT applied to the single-character `#` fragment delimiter,
    because `min_contribution=2` can never be satisfied against a
    length-1 target (making the check permanently vacuous there) while
    `min_contribution=1` reproduces the exact same false-positive flood
    this function exists to avoid (`#` trivially "straddles" via the
    fully-trivial exemption on ANY opaque span with no real signal). An
    unresolved/opaque span positioned such that it alone could hide an
    ENTIRE `#key=value` fragment with no literal `#` anywhere else in the
    element is therefore a known, accepted residual limit -- the same
    class of "entirely inside the opaque span, zero contribution from
    static text" limit already accepted for `$(...)`/backtick spans
    elsewhere in this analyzer, not a new one.
    """
    for start, end in opaque_spans:
        preceding = effective_value[:start]
        following = effective_value[end:]
        if _boundary_straddle_possible(preceding, following, delimiter, min_contribution=2):
            return True
    return False


# The VCS-fragment-key vocabulary EACH of makepkg's VCS source handlers
# recognizes (msys2-pacman libmakepkg/source/{git,fossil,hg,svn,bzr}.sh.in
# -- every one of them `case ${fragment%%=*} in <keys>) ... *) error
# "Unrecognized reference"; exit 1`, so an unrecognized key aborts the
# real build there regardless of VCS type):
#   git:    commit (immutable) | tag, branch (mutable)
#   fossil: commit (immutable) | tag, branch (mutable)  -- identical to git
#   hg:     revision (immutable content hash) | tag, branch (mutable)
#   svn:    revision (immutable) | (no mutable key exists)
#   bzr:    revision (immutable) | (no mutable key exists)
# `branch` is the MORE mutable of the mutable keys where both exist: it
# resolves to origin/<name> and moves on every upstream push, with no
# forged-ref check equivalent to the one makepkg applies to tags.
VCS_FRAGMENT_VOCAB: dict[str, tuple[frozenset, frozenset]] = {
    "git": (frozenset({"commit"}), frozenset({"tag", "branch"})),
    "fossil": (frozenset({"commit"}), frozenset({"tag", "branch"})),
    "hg": (frozenset({"revision"}), frozenset({"tag", "branch"})),
    "svn": (frozenset({"revision"}), frozenset()),
    "bzr": (frozenset({"revision"}), frozenset()),
}
# Non-VCS schemes: any '#...' in the entry is an ordinary URI fragment
# with no makepkg-interpreted VCS-ref semantics at all (no extract_*()
# ever inspects it), so no fragment-key vocabulary check applies.
NON_VCS_SCHEMES = frozenset({"http", "https", "ftp", "ftps"})



def _unresolved_variable_boundary_risk(
    effective_value: str,
    unresolved_spans: list[tuple[int, int]],
    target: str,
    flag_entirely_bare: bool = True,
) -> bool:
    """Same boundary-straddle reasoning as `_boundary_straddle_possible`,
    with `min_contribution=2` -- an unresolved `${name}` reference sits
    adjacent to single generic separator characters (`/`, `:`, `.`)
    constantly in ordinary, fully compliant PKGBUILD source URLs (e.g.
    `.../${pkgname}/${pkgname}-${pkgver}.tar.gz`), so a 1-character
    coincidental overlap (e.g. the trailing `/` of `http://` matching the
    `/` that follows `${pkgname}` in that idiom) carries no real signal
    and must not be flagged; a genuine >=2-character marker fragment
    straddling the boundary still is.

    PLUS, when `flag_entirely_bare` is true, one case `_boundary_straddle_
    possible` intentionally never covers: a variable reference that is, by
    itself, the ENTIRE value with no static text on either side at all
    (e.g. `source=(${_u})`). That specific shape -- unlike a command
    substitution, which can never be assumed to equal a known marker
    without executing it -- IS exactly the real-world "hide a marker
    behind an ordinary variable" evasion (`_u=git://host/repo`), so it is
    flagged unconditionally there. `flag_entirely_bare` is disabled for
    the wide, file-wide quarantine scalar-assignment scan specifically
    (see `detect_findings_for_file`), where ordinary bare self-referential
    or makepkg-provided-variable copies (`DESTDIR="${pkgdir}"`,
    `CFLAGS="${CFLAGS}"`) are extremely common and are not a plausible
    carrier for a 40-character VCS commit hash; it stays enabled for
    source-array/pkgver candidates, which is the exact shape of the
    evasion this exists to catch.
    """
    for start, end in unresolved_spans:
        preceding = effective_value[:start]
        following = effective_value[end:]
        if flag_entirely_bare and preceding == "" and following == "":
            return True
        if _boundary_straddle_possible(preceding, following, target, min_contribution=2):
            return True
    return False


def contains_quarantine_reference(s: str) -> bool:
    """True if s contains the full quarantined commit or a long-enough hex
    abbreviation of it that is not itself a substring of an unrelated hex
    run of different length starting elsewhere (we simply check: any hex
    run in s of length >= QUARANTINE_MIN_ABBREV that is a prefix of the
    full quarantined sha, OR the full sha itself as a substring). Callers
    MUST pass a derived semantic `Word.value`, never a raw `Word.text` --
    see the module docstring."""
    if QUARANTINE_COMMIT_FULL in s:
        return True
    for hm in HEX_RE.finditer(s):
        token = hm.group(0).lower()
        if len(token) >= QUARANTINE_MIN_ABBREV and QUARANTINE_COMMIT_FULL.startswith(token):
            return True
    return False


TOOLCHAIN_DIR_RE = re.compile(r"^mingw-w64-cross-mingwarm64-[^/]+$")


def is_toolchain_path(pkgbuild_path: str) -> bool:
    directory = pkgbuild_path.split("/")[0]
    return bool(TOOLCHAIN_DIR_RE.match(directory))


# Matches a `pkgver()` FUNCTION DEFINITION (any of the common bash forms:
# `pkgver() {`, `pkgver ( ) {`, `function pkgver {`, `function pkgver() {`)
# -- NOT its body, which this analyzer never interprets or executes (doing
# so would be a step toward evaluation). makepkg calls this function AFTER
# fetching sources and REPLACES the static `pkgver=` this analyzer
# inspects with its output (idiomatic in this exact package family --
# `mingw-w64-cross-crt/PKGBUILD` and seven siblings already derive pkgver
# via `git describe --long ... | sed ...`), making the true runtime
# version statically undecidable the moment a toolchain recipe defines
# one, even though this analyzer's TOOLCHAIN_DEV_VER check only ever looks
# at the static value.
PKGVER_FUNCTION_RE = re.compile(r"(?m)^[ \t]*(?:function[ \t]+pkgver\b|pkgver[ \t]*\(\s*\))")
# A `source`/`.` bash COMMAND (built-in file inclusion, e.g. `source
# ./helpers.sh` or `. ./helpers.sh`) is deliberately distinguished from
# the `source=(`/`source_<arch>=(` ARRAY ASSIGNMENT syntax this analyzer
# does parse: the command form requires whitespace before its argument
# and is not immediately followed by `=`, whereas the assignment form
# never has a space before `=`. An in-cone recipe using the command form
# could define the source array or any scalar variable this analyzer
# resolves in an externally-included file it never reads, hiding content
# entirely out of view -- the identical "content defined somewhere this
# analyzer cannot see" risk as a hidden `pkgver()`, so it fails closed the
# same way.
SOURCE_INCLUDE_DIRECTIVE_RE = re.compile(r"(?m)^[ \t]*(?:source|\.)[ \t]+\S")


def _has_source_include_directive(text: str) -> bool:
    """True if `text` contains a genuine `source`/`.` file-inclusion
    COMMAND -- i.e. a `SOURCE_INCLUDE_DIRECTIVE_RE` match that begins a
    LOGICAL line, not merely a physical one. A match on a physical line
    that is itself a backslash-newline CONTINUATION of an earlier logical
    line is excluded: there the token is not the first word of a command
    at all, just one element of whatever multi-line construct the
    previous line started (a real, present example: `bash/PKGBUILD`'s
    `for f in bg bind ... source suspend ... ; do` builtin-name list,
    continued across several physical lines, where `source` is a bash
    KEYWORD NAME being enumerated, not a command being invoked).
    """
    for m in SOURCE_INCLUDE_DIRECTIVE_RE.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        if line_start == 0:
            return True  # first physical line of the file: cannot be a continuation
        # The newline at `line_start - 1` ends the PREVIOUS physical line;
        # this line is a continuation of it iff that previous line's last
        # non-whitespace-trimmed character is an unescaped backslash. We
        # walk back over any run of backslashes and treat an ODD count as
        # an active continuation (each backslash+newline pair escapes the
        # newline; a literal trailing backslash would itself need to be
        # escaped as `\\`, so consecutive continuations pair off).
        prev_line_end = line_start - 1
        j = prev_line_end
        backslash_run = 0
        while j > 0 and text[j - 1] == "\\":
            backslash_run += 1
            j -= 1
        if backslash_run % 2 == 1:
            continue  # continuation line -- not a fresh command
        return True
    return False


def detect_findings_for_file(path: str, text: str) -> tuple[list[Finding], list[str]]:
    """Returns (ratchetable_findings, absolute_hits) for one PKGBUILD's text.
    Raises ParseError (caller turns that into PARSE_FAIL) if unparseable.
    ALL rule matching below is performed against each Word's derived
    SEMANTIC `.value` after safe, static, non-executing variable
    substitution (`resolve_effective_value`) -- never against raw `.text`,
    which is used ONLY as the stored/hashed locator, and never against the
    unsubstituted `.value` alone (that would miss a marker hidden behind an
    ordinary variable, e.g. `_p=git` then `source=("${_p}://host/repo")`).
    """
    absolute_hits: list[str] = []
    findings: dict[tuple[str, str], set] = {}
    matched_text: dict[tuple[str, str], set] = {}

    if _has_source_include_directive(text):
        raise ParseError(
            f"{path}: uses a `source`/`.` file-inclusion COMMAND (not a source=() array assignment); an "
            f"externally-included file could define the source array or any resolved variable entirely out of "
            f"this analyzer's view and cannot be safely and unambiguously analyzed"
        )

    if is_toolchain_path(path) and PKGVER_FUNCTION_RE.search(text):
        raise ParseError(
            f"{path}: defines a pkgver() function; makepkg calls it after fetching sources and REPLACES the "
            f"static pkgver= this analyzer inspects with its output (this analyzer never interprets/executes "
            f"the function body, since doing so would be a step toward evaluation), so the true runtime "
            f"version is statically undecidable and cannot be safely analyzed for TOOLCHAIN_DEV_VER"
        )

    arrays, array_spans = parse_source_arrays(text, path)
    resolved_vars = build_resolved_variable_map(text)

    # Quarantine scan: every source/source_<arch> element, the pkgver value,
    # and every scalar variable assignment anywhere in the file (see
    # find_all_scalar_assignment_values for the generalization rationale).
    # Source-array/pkgver candidates are the exact shape of the "hide a
    # marker behind an ordinary variable" evasion, so an entirely-bare
    # unresolved reference (no static text on either side at all) is
    # flagged unconditionally there. The much WIDER file-wide scalar-
    # assignment scan additionally picks up ordinary, ubiquitous, and
    # entirely benign bare self-referential/makepkg-provided-variable
    # copies (`DESTDIR="${pkgdir}"`, `CFLAGS="${CFLAGS}"`) that are not a
    # plausible carrier for a 40-character VCS commit hash, so that scan
    # does not apply the entirely-bare exception.
    narrow_quarantine_candidates: list[Word] = []
    for words in arrays.values():
        narrow_quarantine_candidates.extend(words)
    pkgver_word, pkgver_span = parse_pkgver(text, path)
    if pkgver_word is not None:
        narrow_quarantine_candidates.append(pkgver_word)
    exclude_spans = list(array_spans)
    if pkgver_span is not None:
        exclude_spans.append(pkgver_span)
    wide_quarantine_candidates = find_all_scalar_assignment_values(text, path, exclude_spans)
    for w, flag_entirely_bare in itertools.chain(
        ((w, True) for w in narrow_quarantine_candidates),
        ((w, False) for w in wide_quarantine_candidates),
    ):
        effective, unresolved = resolve_effective_value(w.value, resolved_vars)
        if contains_quarantine_reference(effective):
            absolute_hits.append(f"{path}: quarantined commit reference found (semantic value {effective!r})")
        elif _quarantine_dynamic_boundary_risk(w) or _unresolved_variable_boundary_risk(
            effective, unresolved, QUARANTINE_COMMIT_FULL, flag_entirely_bare=flag_entirely_bare
        ):
            absolute_hits.append(
                f"{path}: a dynamic substitution or unresolved variable reference is positioned where its "
                f"unknowable runtime value could complete/hide a reference to the quarantined commit across "
                f"the boundary; cannot be safely verified (raw={w.text!r})"
            )

    for arrname, words in arrays.items():
        for w in words:
            effective, unresolved = resolve_effective_value(w.value, resolved_vars)
            opaque_spans = _collect_opaque_spans(w, unresolved)

            vcs_type_span = _extract_vcs_type_span(effective)
            proto_span = _extract_protocol_span(effective)
            frag_key_span = _extract_fragment_key_span(effective)
            vcs_type_unverifiable = vcs_type_span is not None and _span_overlaps_any(vcs_type_span, opaque_spans)
            proto_unverifiable = proto_span is not None and _span_overlaps_any(proto_span, opaque_spans)
            frag_key_unverifiable = frag_key_span is not None and _span_overlaps_any(frag_key_span, opaque_spans)
            delimiter_unverifiable = bool(opaque_spans) and _delimiter_could_be_hidden(effective, opaque_spans, "://")

            if vcs_type_unverifiable or proto_unverifiable or frag_key_unverifiable or delimiter_unverifiable:
                absolute_hits.append(
                    f"{path}:{arrname}: a dynamic substitution or an unresolved/unmodeled parameter expansion "
                    f"occupies -- or could hide -- the VCS-type, transport, delimiter, or VCS-fragment-key "
                    f"position of a source element (the exact positions makepkg's own get_protocol()/"
                    f"download_git()/extract_git() decompose the entry into); its real runtime value cannot be "
                    f"safely verified as rule-compliant (raw={w.text!r}, effective={effective!r})"
                )
                continue

            rules = set()
            matched = set()
            proto_text = effective[proto_span[0]:proto_span[1]] if proto_span is not None else None
            if proto_text == "git":
                rules.add("SRC_GIT_PROTO")
                matched.add("git://")
            elif proto_text == "http":
                rules.add("SRC_INSECURE_HTTP")
                matched.add("http://")
            vcs_type_text = effective[vcs_type_span[0]:vcs_type_span[1]] if vcs_type_span is not None else None
            if frag_key_span is not None:
                frag_key_text = effective[frag_key_span[0]:frag_key_span[1]]
                if vcs_type_text in VCS_FRAGMENT_VOCAB:
                    immutable_keys, mutable_keys = VCS_FRAGMENT_VOCAB[vcs_type_text]
                    if frag_key_text in mutable_keys:
                        rules.add("SRC_MUTABLE_REF")
                        matched.add(f"#{frag_key_text}=")
                    elif frag_key_text not in immutable_keys:
                        absolute_hits.append(
                            f"{path}:{arrname}: source element's {vcs_type_text} VCS fragment key {frag_key_text!r} "
                            f"is not one makepkg's extract_{vcs_type_text}() recognizes; an unrecognized key aborts "
                            f"the real build there, so it can neither be treated as compliant nor silently ignored "
                            f"(raw={w.text!r})"
                        )
                        continue
                elif vcs_type_text not in NON_VCS_SCHEMES:
                    absolute_hits.append(
                        f"{path}:{arrname}: source element has a VCS fragment (#{frag_key_text}=...) but its VCS "
                        f"type {vcs_type_text!r} is not one this analyzer recognizes (git/fossil/hg/svn/bzr) or a "
                        f"known non-VCS scheme with inert fragments (http/https/ftp); whether the fragment key is "
                        f"a legitimate/immutable reference cannot be safely verified (raw={w.text!r})"
                    )
                    continue
            if rules:
                key = (arrname, w.text)
                findings.setdefault(key, set()).update(rules)
                matched_text.setdefault(key, set()).update(matched)

    if pkgver_word is not None:
        pkgver_effective, _pkgver_unresolved = resolve_effective_value(pkgver_word.value, resolved_vars)
        if is_toolchain_path(path) and TOOLCHAIN_DEV_VER_RE.match(pkgver_effective):
            key = ("pkgver", pkgver_word.text)
            findings.setdefault(key, set()).add("TOOLCHAIN_DEV_VER")
            matched_text.setdefault(key, set()).add(pkgver_effective)

    out = []
    for (fld, locator), rules in findings.items():
        out.append(Finding(path, fld, locator, tuple(sorted(rules)), ",".join(sorted(matched_text[(fld, locator)]))))
    return out, absolute_hits


# ---------------------------------------------------------------------------
# Cone / rules / ledger loading and validation
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    rule_id: str
    severity: str  # "absolute" | "ratchetable"
    promote_when_clear: bool
    matched_marker: str | None = None  # authoritative fixed token for SRC_* rules
    reason: str | None = None          # authoritative reason text


def load_rules(rules_path: Path) -> dict[str, Rule]:
    try:
        raw = rules_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ParseError(f"cannot read rules file: {e}") from e
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as e:
        raise ParseError(f"malformed rules TOML: {e}") from e

    rules = {}
    rule_table = data.get("rule")
    if not isinstance(rule_table, dict) or not rule_table:
        raise ParseError("rules file has no [rule.<ID>] entries")
    for rule_id, spec in rule_table.items():
        if not isinstance(spec, dict):
            raise ParseError(f"rule {rule_id}: malformed entry")
        severity = spec.get("severity")
        if severity not in ("absolute", "ratchetable"):
            raise ParseError(f"rule {rule_id}: invalid severity {severity!r}")
        promote = spec.get("promote_when_clear", False)
        if not isinstance(promote, bool):
            raise ParseError(f"rule {rule_id}: promote_when_clear must be boolean")
        if severity == "absolute" and promote:
            raise ParseError(f"rule {rule_id}: absolute rule cannot set promote_when_clear")
        matched_marker = spec.get("matched_marker")
        if matched_marker is not None and not isinstance(matched_marker, str):
            raise ParseError(f"rule {rule_id}: matched_marker must be a string")
        reason = spec.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise ParseError(f"rule {rule_id}: reason must be a string")
        if severity == "ratchetable" and reason is None:
            raise ParseError(f"rule {rule_id}: ratchetable rules must declare an authoritative 'reason'")
        rules[rule_id] = Rule(rule_id, severity, promote, matched_marker, reason)
    return rules


def derive_canonical_matched(rule_ids: tuple, locator: str, rules: dict[str, "Rule"]) -> str | None:
    """Authoritatively re-derives the expected `matched` ledger value from a
    row's rule_id set and its (raw, verbatim) locator -- this is what makes
    `matched` a proof-bearing, validated column rather than free text: a
    forged value that doesn't equal this is SCHEMA_INVALID. For
    TOOLCHAIN_DEV_VER this is the locator's own re-derived semantic value
    (there is no fixed marker -- the whole point is the actual pinned
    version string). For SRC_MUTABLE_REF this is `#<key>=` where `<key>`
    is the locator's OWN re-derived VCS fragment key (`tag` or `branch` --
    there is no single fixed marker any more now the rule covers the full
    makepkg-recognized mutable vocabulary, not only `#tag=`). For the
    other SRC_* rules this is each rule's fixed `matched_marker`
    (rules.toml). Returns None if any rule_id lacks the information needed
    to derive a canonical value (caller must fail closed).
    """
    tokens = set()
    for rid in rule_ids:
        if rid == "TOOLCHAIN_DEV_VER":
            try:
                words, _ = _tokenize_words(locator, 0, len(locator), stop_at_paren=False)
            except ParseError:
                return None
            if not words:
                return None
            tokens.add(words[0].value)
        elif rid == "SRC_MUTABLE_REF":
            try:
                words, _ = _tokenize_words(locator, 0, len(locator), stop_at_paren=False)
            except ParseError:
                return None
            if not words:
                return None
            value = words[0].value
            vcs_type_span = _extract_vcs_type_span(value)
            frag_key_span = _extract_fragment_key_span(value)
            if vcs_type_span is None or frag_key_span is None:
                return None
            vcs_type_text = value[vcs_type_span[0]:vcs_type_span[1]]
            frag_key_text = value[frag_key_span[0]:frag_key_span[1]]
            vocab = VCS_FRAGMENT_VOCAB.get(vcs_type_text)
            if vocab is None or frag_key_text not in vocab[1]:
                return None
            tokens.add(f"#{frag_key_text}=")
        else:
            rule = rules.get(rid)
            marker = rule.matched_marker if rule else None
            if marker is None:
                return None
            tokens.add(marker)
    return ",".join(sorted(tokens))




def load_cone(cone_path: Path, digest_path: Path | None = None) -> list[str]:
    """Loads and validates the cone file, additionally enforcing (when
    `digest_path` is given) that the file's exact raw bytes hash to the
    pinned sha256 digest recorded there. This is what makes the 225-entry
    declared ARM64 BUILD closure cryptographically bound and monotonic: ANY
    change to the cone -- a removal, an addition, or a same-size
    substitution of one directory for another -- changes its digest, and is
    therefore rejected as SCHEMA_INVALID unless the pinned digest file is
    updated in the SAME reviewed change (and that file is itself
    CODEOWNERS-covered, see .github/CODEOWNERS). This is a structural
    superset of "reject every removal/substitution": it rejects ANY
    unaccompanied textual change whatsoever.
    """
    try:
        raw_bytes = cone_path.read_bytes()
    except OSError as e:
        raise ParseError(f"cannot read cone file: {e}") from e

    if digest_path is not None:
        try:
            pinned = digest_path.read_text(encoding="utf-8").strip()
        except OSError as e:
            raise ParseError(f"cannot read cone digest file: {e}") from e
        if not re.fullmatch(r"[0-9a-f]{64}", pinned):
            raise ParseError(f"cone digest file does not contain a bare 64-char lowercase sha256 hex digest: {pinned!r}")
        actual = hashlib.sha256(raw_bytes).hexdigest()
        if actual != pinned:
            raise ParseError(
                f"cone file content does not match its pinned digest (expected {pinned}, got {actual}) -- "
                f"any change to the declared 225-entry ARM64 build closure (add, remove, or same-size "
                f"substitution) must update {digest_path} in the same reviewed change"
            )

    raw = raw_bytes.decode("utf-8")
    if raw != "" and not raw.endswith("\n"):
        raise ParseError("cone file must end with a single trailing newline")
    lines = raw.splitlines()
    if any(line == "" for line in lines):
        raise ParseError("cone file contains a blank line")
    seen = set()
    for line in lines:
        if line != line.strip():
            raise ParseError(f"cone entry has leading/trailing whitespace: {line!r}")
        if any(ch in CONE_BYPASS_CHARS for ch in line):
            raise ParseError(f"cone entry contains disallowed metacharacter: {line!r}")
        if line.startswith("/") or line.startswith("..") or "/../" in line or line.endswith("/.."):
            raise ParseError(f"cone entry escapes repo scope: {line!r}")
        if "\\" in line:
            raise ParseError(f"cone entry contains backslash path separator: {line!r}")
        if line in seen:
            raise ParseError(f"cone file has duplicate entry: {line!r}")
        seen.add(line)
    sorted_lines = sorted(lines)
    if sorted_lines != lines:
        raise ParseError("cone file is not in canonical sorted order")
    return lines


def resolve_cone_path(directory: str, repo_root: Path = REPO_ROOT) -> Path:
    """Resolve a cone directory entry to its PKGBUILD, refusing any path
    that escapes the repository root or passes through a symlink."""
    candidate = (repo_root / directory).resolve()
    try:
        candidate.relative_to(repo_root.resolve())
    except ValueError:
        raise ParseError(f"cone entry resolves outside the repository: {directory!r}")
    # Reject symlink components anywhere from the repo root down to the file.
    node = repo_root
    for part in (*Path(directory).parts, "PKGBUILD"):
        node = node / part
        if node.is_symlink():
            raise ParseError(f"cone entry traverses a symlink: {node}")
    pkgbuild = repo_root / directory / "PKGBUILD"
    if not pkgbuild.is_file():
        raise ParseError(f"cone entry has no PKGBUILD: {directory!r}")
    return pkgbuild


def load_ledger(ledger_path: Path, rules: dict[str, Rule]) -> list[dict]:
    try:
        raw = ledger_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ParseError(f"cannot read ledger file: {e}") from e
    if raw == "":
        raise ParseError("ledger file is empty (missing header)")
    if not raw.endswith("\n"):
        raise ParseError("ledger file must end with a single trailing newline")
    lines = raw.splitlines()
    if lines[0] != LEDGER_HEADER:
        raise ParseError(f"ledger header mismatch: {lines[0]!r} != {LEDGER_HEADER!r}")
    body = lines[1:]
    if any(line == "" for line in body):
        raise ParseError("ledger file contains a blank line")

    rows = []
    for lineno, line in enumerate(body, start=2):
        cols = line.split("\t")
        if len(cols) != len(LEDGER_FIELDS):
            raise ParseError(f"ledger line {lineno}: expected {len(LEDGER_FIELDS)} tab-separated fields, got {len(cols)}")
        row = dict(zip(LEDGER_FIELDS, cols))
        for k, v in row.items():
            if v != v.strip():
                raise ParseError(f"ledger line {lineno}: field {k!r} has leading/trailing whitespace")
            if v == "":
                raise ParseError(f"ledger line {lineno}: field {k!r} is empty")
        if row["removal_gate"] not in ("PR-1", "T0-corrected-toolchain"):
            raise ParseError(f"ledger line {lineno}: removal_gate must be one of PR-1 | T0-corrected-toolchain, got {row['removal_gate']!r}")
        if any(ch in LOCATOR_BYPASS_CHARS for ch in row["locator"]):
            raise ParseError(f"ledger line {lineno}: locator contains disallowed metacharacter")
        if any(ch in LOCATOR_BYPASS_CHARS for ch in row["matched"]):
            raise ParseError(f"ledger line {lineno}: matched contains disallowed metacharacter")
        if row["path"].startswith("/") or ".." in row["path"].split("/") or "\\" in row["path"]:
            raise ParseError(f"ledger line {lineno}: path is not a safe repo-relative path: {row['path']!r}")
        if not FIELD_RE.match(row["field"]):
            raise ParseError(f"ledger line {lineno}: unknown field {row['field']!r}")
        rule_ids = row["rule_id"].split(",")
        if rule_ids != sorted(rule_ids) or len(rule_ids) != len(set(rule_ids)):
            raise ParseError(f"ledger line {lineno}: rule_id set must be sorted, comma-separated, unique: {row['rule_id']!r}")
        for rid in rule_ids:
            rule = rules.get(rid)
            if rule is None:
                raise ParseError(f"ledger line {lineno}: unknown rule_id {rid!r}")
            if rule.severity == "absolute":
                raise ParseError(f"ledger line {lineno}: rule_id {rid!r} is an absolute rule and can never be ledgered")
        # `matched` and `reason` are AUTHORITATIVE, proof-bearing columns,
        # not free text: both are independently re-derived from the row's
        # rule_id set (and, for TOOLCHAIN_DEV_VER, its own locator) and MUST
        # equal the stored value exactly, or the row is rejected. This is
        # what prevents a forged/inconsistent `matched` or `reason` from
        # ever passing review undetected.
        canonical_matched = derive_canonical_matched(tuple(rule_ids), row["locator"], rules)
        if canonical_matched is None or canonical_matched != row["matched"]:
            raise ParseError(
                f"ledger line {lineno}: matched {row['matched']!r} does not match the authoritative "
                f"recomputed value {canonical_matched!r} for rule_id(s) {row['rule_id']!r}"
            )
        canonical_reason_parts = [rules[rid].reason for rid in rule_ids]
        if any(part is None for part in canonical_reason_parts):
            raise ParseError(f"ledger line {lineno}: one or more rule_id(s) in {row['rule_id']!r} has no authoritative reason declared in rules.toml")
        canonical_reason = "; ".join(canonical_reason_parts)
        if canonical_reason != row["reason"]:
            raise ParseError(
                f"ledger line {lineno}: reason {row['reason']!r} does not match the authoritative "
                f"recomputed value {canonical_reason!r} for rule_id(s) {row['rule_id']!r}"
            )
        if sha256_hex(row["locator"]) != row["locator_sha256"].lower():
            raise ParseError(f"ledger line {lineno}: locator_sha256 does not match sha256(locator)")
        if not re.fullmatch(r"[0-9a-f]{64}", row["locator_sha256"]):
            raise ParseError(f"ledger line {lineno}: locator_sha256 must be 64 lowercase hex chars")
        if not re.fullmatch(r"[0-9a-f]{7,40}", row["introduced_by"]):
            raise ParseError(f"ledger line {lineno}: introduced_by must be a git commit sha (7-40 hex chars)")
        try:
            datetime.strptime(row["expires"], "%Y-%m-%d")
        except ValueError:
            raise ParseError(f"ledger line {lineno}: expires is not ISO-8601 (YYYY-MM-DD): {row['expires']!r}")
        rows.append(row)

    keys = [(r["path"], r["field"], r["locator_sha256"]) for r in rows]
    if len(keys) != len(set(keys)):
        raise ParseError("ledger has duplicate (path, field, locator_sha256) keys")
    sort_keys = [(r["path"], r["rule_id"], r["locator_sha256"], line) for r, line in zip(rows, body)]
    if sort_keys != sorted(sort_keys, key=lambda t: t[:3]):
        raise ParseError("ledger is not sorted by (path, rule_id, locator_sha256)")
    return rows


def verify_introduced_by_provenance(rows: list[dict], repo_root: Path) -> list[str]:
    """Best-effort, read-only: if repo_root is a real git repository, verify
    each ledger row's `introduced_by` names a commit that actually exists in
    it (i.e. real repository provenance, not an arbitrary hex-looking
    string). Uses only local `git cat-file -e <sha>^{commit}` -- no network,
    no writes. If repo_root is not a git repository (e.g. an isolated test
    fixture), this check is skipped entirely (returns no problems) rather
    than failing every fixture that has no git history of its own.
    """
    if not (repo_root / ".git").exists():
        return []
    import subprocess
    problems: list[str] = []
    seen_shas: set[str] = set()
    for row in rows:
        sha = row["introduced_by"]
        if sha in seen_shas:
            continue
        seen_shas.add(sha)
        try:
            result = subprocess.run(
                ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
                cwd=repo_root, capture_output=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as e:
            problems.append(f"SCHEMA_INVALID(ledger): could not verify introduced_by={sha!r} via git ({e})")
            continue
        if result.returncode != 0:
            problems.append(f"SCHEMA_INVALID(ledger): introduced_by={sha!r} does not name a real commit in this repository")
    return problems


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------

def load_base_ledger_rule_ids(base_ledger_path: Path | None) -> set[str] | None:
    """Returns the set of rule_ids that appear anywhere in the BASE (parent/
    merge-base) ledger, used only to decide which ratchetable rules are
    already promoted (zero rows at the base commit). Returns None if no
    base ledger is available (e.g. this is the commit that first introduces
    the ledger) -- in that case nothing can be treated as promoted yet,
    since nothing has ever been cleared. The base ledger is read leniently
    (best-effort tab-split) since it is historical reference data that was
    already validated when it was committed; if it cannot be parsed at all,
    we conservatively treat it as unavailable (no promotions inferred from
    it) rather than guessing.
    """
    if base_ledger_path is None or not Path(base_ledger_path).is_file():
        return None
    try:
        raw = Path(base_ledger_path).read_text(encoding="utf-8")
    except OSError:
        return None
    lines = raw.splitlines()
    if not lines or lines[0] != LEDGER_HEADER:
        return None
    rule_ids: set[str] = set()
    for line in lines[1:]:
        cols = line.split("\t")
        if len(cols) != len(LEDGER_FIELDS):
            return None
        rule_ids.update(cols[LEDGER_FIELDS.index("rule_id")].split(","))
    return rule_ids


def load_base_cone_entries(base_cone_path: Path | None) -> set[str] | None:
    """Returns the set of non-blank lines in the BASE (parent/merge-base)
    commit's cone file, used only for the cross-commit cone-monotonicity
    check (see `run`). Returns None if no base cone is available (this is
    the commit that first introduces the cone, or the base commit predates
    it, or it could not be read) -- in that case no monotonicity check is
    applied, matching the base-ledger pattern: there is nothing to have
    shrunk relative to. Read leniently (the base cone was already validated
    when it was committed); an unreadable base cone is conservatively
    treated as unavailable, never as an error.
    """
    if base_cone_path is None or not Path(base_cone_path).is_file():
        return None
    try:
        raw = Path(base_cone_path).read_text(encoding="utf-8")
    except OSError:
        return None
    return {line for line in raw.splitlines() if line.strip()}


def run(cone_path: Path = CONE_FILE, rules_path: Path = RULES_FILE, ledger_path: Path = LEDGER_FILE,
        today: date | None = None, repo_root: Path = REPO_ROOT,
        base_ledger_path: Path | None = None,
        cone_digest_path: Path | None = CONE_DIGEST_FILE,
        base_cone_path: Path | None = None) -> tuple[bool, list[str]]:
    problems: list[str] = []
    today = today or date.today()

    try:
        rules = load_rules(rules_path)
    except ParseError as e:
        return False, [f"SCHEMA_INVALID(rules): {e}"]

    try:
        cone = load_cone(cone_path, cone_digest_path)
    except ParseError as e:
        return False, [f"SCHEMA_INVALID(cone): {e}"]

    # Cross-commit cone monotonicity: the declared 225-entry ARM64 build
    # closure may only grow (a reviewed, digest-updated addition) -- it may
    # NEVER shrink, and a same-size substitution (swapping one directory for
    # another while keeping the digest internally self-consistent) is
    # exactly as forbidden as an outright removal. Digest pinning alone only
    # proves the CURRENT commit's cone+digest are mutually self-consistent;
    # it says nothing about whether the CHANGE from the base commit was
    # legitimate. This check closes that gap by comparing against the real
    # base commit's cone (via --base-ref/--base-cone, resolved the same way
    # as the base ledger). If no base cone is available (first commit that
    # introduces the cone, or the base predates it), nothing can have
    # shrunk relative to it, so no check is applied -- this must never
    # crash and must never silently disable the check when a base cone
    # genuinely IS available and readable.
    base_cone_entries = load_base_cone_entries(base_cone_path)
    if base_cone_entries is not None:
        missing = base_cone_entries - set(cone)
        if missing:
            problems.append(
                f"SCHEMA_INVALID(cone): {len(missing)} entrie(s) present in the base commit's cone are absent "
                f"from the current cone -- removal and same-size substitution of a declared build-closure "
                f"directory are never permitted, only reviewed additions: {sorted(missing)}"
            )

    try:
        ledger_rows = load_ledger(ledger_path, rules)
    except ParseError as e:
        return False, [f"SCHEMA_INVALID(ledger): {e}"]

    problems.extend(verify_introduced_by_provenance(ledger_rows, repo_root))

    # Promotion is a CROSS-COMMIT, monotonic property: a rule becomes
    # permanently un-ledgerable once the BASE (parent/merge-base) commit's
    # ledger already had zero rows for it. Checking only the ledger being
    # validated would be self-referentially useless -- a PR that smuggles in
    # a new row for an already-cleared rule always has >=1 row for it in its
    # OWN file, so "current file has zero rows" can never catch that PR. If
    # no base ledger is available (this is the introducing commit), nothing
    # is treated as promoted yet, since nothing has ever been cleared.
    base_rule_ids = load_base_ledger_rule_ids(base_ledger_path)
    if base_rule_ids is not None:
        promoted = {rid for rid, r in rules.items()
                    if r.severity == "ratchetable" and r.promote_when_clear
                    and rid not in base_rule_ids}
    else:
        promoted = set()
    for row in ledger_rows:
        for rid in row["rule_id"].split(","):
            if rid in promoted:
                problems.append(f"SCHEMA_INVALID(ledger): rule_id {rid!r} is promoted (zero rows in the base ledger) and cannot accept new entries; offending row path={row['path']}")

    for row in ledger_rows:
        if today > datetime.strptime(row["expires"], "%Y-%m-%d").date():
            problems.append(f"EXPIRED: ledger row for {row['path']} field={row['field']} rule_id={row['rule_id']} expired {row['expires']}")

    absolute_hits: list[str] = []
    v_keys: dict[tuple[str, str, str], Finding] = {}
    for directory in cone:
        try:
            pkgbuild = resolve_cone_path(directory, repo_root)
        except ParseError as e:
            return False, problems + [f"SCHEMA_INVALID(cone): {e}"]
        try:
            text = pkgbuild.read_text(encoding="utf-8")
        except OSError as e:
            return False, problems + [f"PARSE_FAIL: cannot read {pkgbuild}: {e}"]
        rel = directory + "/PKGBUILD"
        try:
            findings, hits = detect_findings_for_file(rel, text)
        except ParseError as e:
            return False, problems + [f"PARSE_FAIL: {e}"]
        absolute_hits.extend(hits)
        for f_ in findings:
            key = (f_.path, f_.field, sha256_hex(f_.locator))
            v_keys[key] = f_

    if absolute_hits:
        problems.extend(f"TOOLCHAIN_QUARANTINE: {h}" for h in absolute_hits)

    ledger_keys = {(r["path"], r["field"], r["locator_sha256"]): r for r in ledger_rows}
    for key, f_ in v_keys.items():
        if key not in ledger_keys:
            problems.append(f"NEW_DEBT (V\u2284L): {key[0]} field={key[1]} rules={','.join(f_.rule_ids)} locator={f_.locator!r} has no ledger entry")
        else:
            row = ledger_keys[key]
            ledger_rules = tuple(row["rule_id"].split(","))
            if ledger_rules != f_.rule_ids:
                problems.append(f"RULE_SET_MISMATCH: {key[0]} field={key[1]} on-disk rules={f_.rule_ids} != ledger rules={ledger_rules}")
    for key, row in ledger_keys.items():
        if key not in v_keys:
            problems.append(f"STALE_DEBT (L\u2284V): {key[0]} field={key[1]} rule_id={row['rule_id']} locator={row['locator']!r} no longer violates on current disk content")

    for row in ledger_rows:
        rel = row["path"]
        directory = rel.rsplit("/PKGBUILD", 1)[0] if rel.endswith("/PKGBUILD") else None
        if directory is None or directory not in cone:
            problems.append(f"SCHEMA_INVALID(ledger): path {rel!r} is not an in-cone PKGBUILD")

    ok = not problems
    return ok, problems


class BaseRefResolutionError(Exception):
    """Raised when an explicitly-supplied --base-ref cannot be safely
    resolved, for any reason OTHER than the one legitimate case: the ref
    itself is a valid, real commit, but the target file simply did not
    exist yet at that commit (first-run/bootstrap). This must NEVER be
    silently swallowed into "no base available" -- doing so would make the
    entire cross-commit monotonicity mechanism (rule promotion, cone
    shrink/substitution rejection) bypassable by the trivial path of simply
    not supplying a working --base-ref. Once --base-ref is given at all,
    resolution failure is a hard CLI error (see `main`), never a silent
    downgrade to same-commit-only checking.
    """


def derive_github_actions_base_ref(env: dict | None = None) -> str | None:
    """Returns the TRUSTED base commit SHA when running inside a GitHub
    Actions job, derived ENTIRELY from `GITHUB_EVENT_PATH` -- a JSON file
    GitHub's own servers write to disk before the job starts, populated
    from the event that triggered the run. This is deliberately NOT the
    same trust source as a `--base-ref` string a workflow YAML computes
    and passes on the command line: on a `pull_request` (non-`_target`)
    trigger, the workflow FILE that would compute and pass that string is
    itself part of the diff under review, so a pull request could rewrite
    it to supply any resolvable-but-wrong commit (an old tag, an unrelated
    branch, the repository's initial commit) and reach the "base lacks the
    ledger/cone yet" first-run carve-out on a base that predates the
    ledger, skipping the cross-commit monotonicity check entirely. The
    event JSON, by contrast, is written by the GitHub Actions runner
    BEFORE any repository code (including this workflow's own YAML) is
    read or executed, so nothing in the pull request's diff -- including
    the workflow file itself -- can influence its content.

    Returns None (not running in GitHub Actions, or the event doesn't
    carry a base commit at all -- e.g. a `workflow_dispatch` run) so the
    caller can fall back to ordinary local/manual `--base-ref` handling;
    returns the SHA string on success. Never returns a "maybe" value: any
    GitHub-Actions-environment condition that looks like it OUGHT to carry
    a base (a `pull_request`/`push` event whose JSON cannot be read or
    parsed, or whose expected field is absent/malformed) raises
    BaseRefResolutionError -- a corrupt or unreadable event file is exactly
    the kind of ambiguity this analyzer fails closed on everywhere else,
    never silently treated the same as "no base to check at all".
    """
    env = env if env is not None else os.environ
    if env.get("GITHUB_ACTIONS") != "true":
        return None
    event_path = env.get("GITHUB_EVENT_PATH")
    event_name = env.get("GITHUB_EVENT_NAME", "")
    if not event_path:
        return None
    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event = json.load(f)
    except (OSError, ValueError) as e:
        raise BaseRefResolutionError(f"GITHUB_EVENT_PATH={event_path!r} could not be read/parsed as JSON: {e}") from e
    if event_name in ("pull_request", "pull_request_target"):
        try:
            sha = event["pull_request"]["base"]["sha"]
        except (KeyError, TypeError) as e:
            raise BaseRefResolutionError(
                f"GitHub Actions event {event_name!r} JSON is missing pull_request.base.sha"
            ) from e
        if not isinstance(sha, str) or not sha:
            raise BaseRefResolutionError(f"GitHub Actions event {event_name!r} pull_request.base.sha is not a non-empty string")
        return sha
    if event_name == "push":
        sha = event.get("before")
        if not isinstance(sha, str) or not sha or set(sha) == {"0"}:
            # A `before` of all zeros is GitHub's sentinel for "no prior
            # commit" (e.g. a brand-new branch) -- legitimately no base to
            # compare against, NOT a malformed event.
            return None
        return sha
    # Any other trigger (workflow_dispatch, schedule, ...) legitimately
    # carries no PR/push base at all.
    return None


def _git_ref_is_valid_commit(base_ref: str, repo_root: Path) -> bool:
    import subprocess
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise BaseRefResolutionError(f"could not invoke git to verify base-ref {base_ref!r}: {e}") from e
    return result.returncode == 0


def _resolve_default_base_file(target_path: Path, base_ref: str | None, repo_root: Path, tmp_prefix: str, tmp_suffix: str) -> Path | None:
    """Shared helper: materialize `target_path` as it existed at `base_ref`
    (a trusted, GitHub-supplied commit -- see the workflow) into a temp
    file, using local `git show` only (no network, no writes to the
    repository). Returns None ONLY for the single legitimate case: base_ref
    is a real, resolvable commit but the target file did not exist there
    yet (this commit/PR is the one introducing it). Every OTHER failure
    mode -- base_ref missing/empty, base_ref not a real commit, git itself
    unavailable, or any other `git show` error -- raises
    BaseRefResolutionError, which callers must treat as fatal, not as "no
    base". Callers are responsible for deleting the returned temp file.
    """
    import subprocess
    import tempfile
    if not base_ref:
        raise BaseRefResolutionError("--base-ref was not provided (empty/missing) -- refusing to silently skip the cross-commit check")
    if not _git_ref_is_valid_commit(base_ref, repo_root):
        raise BaseRefResolutionError(f"--base-ref {base_ref!r} does not resolve to a real commit in this repository")
    try:
        rel = target_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as e:
        raise BaseRefResolutionError(f"target path {target_path} is not inside repo_root {repo_root}") from e
    try:
        result = subprocess.run(
            ["git", "show", f"{base_ref}:{rel}"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise BaseRefResolutionError(f"git show failed for {base_ref}:{rel}: {e}") from e
    if result.returncode != 0:
        # Distinguish "the path did not exist at this (already-verified-
        # valid) commit" -- the one legitimate first-run/bootstrap case --
        # from any OTHER git-show failure, which must hard-fail. Git's
        # stderr wording for a missing path is stable and specific.
        stderr = result.stderr or ""
        if "does not exist in" in stderr or "exists on disk, but not in" in stderr:
            return None
        raise BaseRefResolutionError(f"git show {base_ref}:{rel} failed unexpectedly: {stderr.strip()}")
    fd, tmp_path = tempfile.mkstemp(prefix=tmp_prefix, suffix=tmp_suffix)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(result.stdout)
    return Path(tmp_path)


def resolve_default_base_ledger(ledger_path: Path, base_ref: str | None, repo_root: Path = REPO_ROOT) -> Path | None:
    """Best-effort: materialize the ledger file as it existed at base_ref.
    See `_resolve_default_base_file`."""
    return _resolve_default_base_file(ledger_path, base_ref, repo_root, "arm64-base-ledger-", ".tsv")


def resolve_default_base_cone(cone_path: Path, base_ref: str | None, repo_root: Path = REPO_ROOT) -> Path | None:
    """Best-effort: materialize the cone file as it existed at base_ref, for
    the cross-commit cone-monotonicity check. See
    `_resolve_default_base_file`."""
    return _resolve_default_base_file(cone_path, base_ref, repo_root, "arm64-base-cone-", ".txt")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cone", type=Path, default=CONE_FILE)
    parser.add_argument("--cone-digest", type=Path, default=CONE_DIGEST_FILE, help="Path to the pinned sha256 digest of --cone. Pass an empty/nonexistent path override only for isolated fixture tests that intentionally don't pin a digest.")
    parser.add_argument("--no-cone-digest", action="store_true", help="Disable cone digest pinning entirely (fixture tests only -- never used by the shipped CI workflow).")
    parser.add_argument("--rules", type=Path, default=RULES_FILE)
    parser.add_argument("--ledger", type=Path, default=LEDGER_FILE)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help="Repository root cone paths are resolved against (for isolated fixture tests only).")
    parser.add_argument("--today", type=str, default=None, help="Override today's date (YYYY-MM-DD), for tests only.")
    parser.add_argument("--base-ledger", type=Path, default=None, help="Path to the ledger file as it existed at the PR's base/merge-base commit (used only to detect newly-promoted rules). Omit to auto-resolve via --base-ref.")
    parser.add_argument("--base-cone", type=Path, default=None, help="Path to the cone file as it existed at the PR's base/merge-base commit (used only for the cone-monotonicity check). Omit to auto-resolve via --base-ref.")
    parser.add_argument("--base-ref", type=str, default=None,
                         help="A trusted, GitHub-supplied commit (e.g. the pull_request base SHA) to auto-resolve --base-ledger/--base-cone from via 'git show'. "
                              "Once given, resolution failure is a HARD ERROR (exit 1), never a silent skip of the cross-commit check -- see BaseRefResolutionError. "
                              "Omit entirely (together with --base-ledger/--base-cone) only for ad hoc local runs that intentionally forgo the cross-commit check; "
                              "the shipped CI workflow does not pass this flag at all -- see derive_github_actions_base_ref, which supplies the trusted value "
                              "automatically from GITHUB_EVENT_PATH whenever running in GitHub Actions, precisely so that no workflow YAML (itself part of the "
                              "diff under review on a `pull_request` trigger) ever gets to choose the base. If BOTH this flag and a GitHub-Actions-derived base "
                              "are present, they must match exactly, or this is a HARD ERROR -- never a silent preference for one over the other. No network "
                              "access is performed.")
    args = parser.parse_args(argv)

    try:
        github_actions_base_ref = derive_github_actions_base_ref()
    except BaseRefResolutionError as e:
        print(f"FAIL: arm64-admission-guard: cannot derive the trusted GitHub Actions base ref: {e}", file=sys.stderr)
        print("  - refusing to silently proceed without the cross-commit monotonicity check", file=sys.stderr)
        return 1

    if github_actions_base_ref is not None:
        if args.base_ref is not None and args.base_ref != github_actions_base_ref:
            print(
                f"FAIL: arm64-admission-guard: --base-ref {args.base_ref!r} does not match the trusted "
                f"GitHub-Actions-event-derived base {github_actions_base_ref!r}", file=sys.stderr,
            )
            print("  - a workflow-supplied base ref may never override the GitHub-event-derived one", file=sys.stderr)
            return 1
        args.base_ref = github_actions_base_ref

    resolved_temp_base_ledger = None
    resolved_temp_base_cone = None
    try:
        try:
            base_ledger_path = args.base_ledger
            if base_ledger_path is None and args.base_ref is not None:
                base_ledger_path = resolve_default_base_ledger(args.ledger, args.base_ref, repo_root=args.repo_root)
                resolved_temp_base_ledger = base_ledger_path

            base_cone_path = args.base_cone
            if base_cone_path is None and args.base_ref is not None:
                base_cone_path = resolve_default_base_cone(args.cone, args.base_ref, repo_root=args.repo_root)
                resolved_temp_base_cone = base_cone_path
        except BaseRefResolutionError as e:
            print(f"FAIL: arm64-admission-guard: cannot resolve --base-ref {args.base_ref!r}: {e}", file=sys.stderr)
            print("  - refusing to silently proceed without the cross-commit monotonicity check", file=sys.stderr)
            return 1

        today = datetime.strptime(args.today, "%Y-%m-%d").date() if args.today else None
        cone_digest_path = None if args.no_cone_digest else args.cone_digest
        ok, problems = run(args.cone, args.rules, args.ledger, today=today, repo_root=args.repo_root,
                            base_ledger_path=base_ledger_path, cone_digest_path=cone_digest_path,
                            base_cone_path=base_cone_path)
    finally:
        for resolved_temp in (resolved_temp_base_ledger, resolved_temp_base_cone):
            if resolved_temp is not None:
                try:
                    resolved_temp.unlink(missing_ok=True)
                except OSError:
                    pass

    if ok:
        print("PASS: arm64-admission-guard (V == L, no absolute hits, ledger valid, unexpired)")
        return 0
    print("FAIL: arm64-admission-guard", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
