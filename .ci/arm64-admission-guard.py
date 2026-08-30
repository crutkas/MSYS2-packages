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

DYNAMIC_MARKERS = ("git://", "http://", "#tag=")

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
SOURCE_ARRAY_RE = re.compile(r"(?m)^[ \t]*(source(?:_[A-Za-z0-9_]+)?)=\(")
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


def _boundary_straddle_possible(preceding: str, following: str, target: str) -> bool:
    """True if `target` could be assembled as
    [some suffix of preceding] + [the dynamic span's unknowable output,
    of ANY length/content] + [some prefix of following], for SOME pair of
    split points (p1 <= p2, 0 <= p1,p2 <= len(target)) where preceding ends
    with target[:p1] and following starts with target[p2:]. The gap
    target[p1:p2] (possibly empty) is exactly what the dynamic span would
    need to contribute -- since its real output is never executed/known,
    ANY such gap is considered adversarially achievable.

    The single EXCLUDED case is p1 == 0 AND p2 == len(target) simultaneously
    -- i.e. NEITHER side contributes anything and the entire target could
    only come from the dynamic span's own output. That is an inherent,
    accepted limit of static analysis true of literally ANY `$(...)`/
    backtick usage for literally any target string, and flagging it would
    make every real, supported use (e.g. the bash/readline `$(printf ...)`
    patch-level idiom, or any file containing ANY command substitution at
    all) fail closed unconditionally. Every OTHER combination -- where at
    least one side contributes a real, non-empty fragment, however short --
    is flagged, which is what catches a deliberate split even when an
    individual fragment is very short (e.g. a 5-character hash prefix,
    below the quarantine abbreviation threshold).
    """
    length = len(target)
    valid_p1 = [p for p in range(length + 1) if preceding.endswith(target[:p])]
    valid_p2 = [p for p in range(length + 1) if following.startswith(target[p:])]
    for p1 in valid_p1:
        for p2 in valid_p2:
            if p1 <= p2 and not (p1 == 0 and p2 == length):
                return True
    return False


def _dynamic_boundary_risk(word: Word) -> bool:
    """Conservative, narrowly-scoped check for whether `word` contains a
    dynamic (`$(...)` or backtick) span positioned such that an adversarial
    choice of the substitution's real runtime output (NEVER executed here)
    could cause one of the ratchet marker substrings (git://, http://,
    #tag=) to be formed STRADDLING the substitution. See
    `_boundary_straddle_possible` for exactly which cases are (and are not)
    flagged, and why the case where a marker could be produced ENTIRELY
    inside the substitution's own output (no contribution from either
    side) is deliberately NOT flagged -- that would make the real,
    supported `bash`/`readline` `$(printf ...)` idiom fail closed
    unconditionally.
    """
    spans = _find_dynamic_spans(word.text)
    if not spans:
        return False
    for start, end in spans:
        cs_text = word.text[start:end]
        idx = word.value.find(cs_text)
        if idx == -1:
            continue  # should not happen (dynamic spans are opaque in both text and value)
        preceding = word.value[:idx]
        following = word.value[idx + len(cs_text):]
        for marker in DYNAMIC_MARKERS:
            if _boundary_straddle_possible(preceding, following, marker):
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


def detect_findings_for_file(path: str, text: str) -> tuple[list[Finding], list[str]]:
    """Returns (ratchetable_findings, absolute_hits) for one PKGBUILD's text.
    Raises ParseError (caller turns that into PARSE_FAIL) if unparseable.
    ALL rule matching below is performed against each Word's derived
    SEMANTIC `.value`, never its raw `.text` -- `.text` is used ONLY as the
    stored/hashed locator.
    """
    absolute_hits: list[str] = []
    findings: dict[tuple[str, str], set] = {}
    matched_text: dict[tuple[str, str], set] = {}

    arrays, array_spans = parse_source_arrays(text, path)

    # Quarantine scan: every source/source_<arch> element, the pkgver value,
    # and every scalar variable assignment anywhere in the file (see
    # find_all_scalar_assignment_values for the generalization rationale).
    quarantine_candidates: list[Word] = []
    for words in arrays.values():
        quarantine_candidates.extend(words)
    pkgver_word, pkgver_span = parse_pkgver(text, path)
    if pkgver_word is not None:
        quarantine_candidates.append(pkgver_word)
    exclude_spans = list(array_spans)
    if pkgver_span is not None:
        exclude_spans.append(pkgver_span)
    quarantine_candidates.extend(find_all_scalar_assignment_values(text, path, exclude_spans))
    for w in quarantine_candidates:
        if contains_quarantine_reference(w.value):
            absolute_hits.append(f"{path}: quarantined commit reference found (semantic value {w.value!r})")
        elif _quarantine_dynamic_boundary_risk(w):
            absolute_hits.append(
                f"{path}: a dynamic (command/backtick) substitution is positioned where its unknowable "
                f"runtime output could complete/hide a reference to the quarantined commit across the "
                f"substitution boundary; cannot be safely verified (raw={w.text!r})"
            )

    for arrname, words in arrays.items():
        for w in words:
            if _dynamic_boundary_risk(w):
                absolute_hits.append(
                    f"{path}:{arrname}: source element contains a dynamic (command/backtick) substitution "
                    f"positioned where its unknowable runtime output could complete/hide a flagged marker "
                    f"(git://, http://, #tag=) across the substitution boundary; cannot be safely verified (raw={w.text!r})"
                )
                continue
            rules = set()
            matched = set()
            if "git://" in w.value:
                rules.add("SRC_GIT_PROTO")
                matched.add("git://")
            if "#tag=" in w.value:
                rules.add("SRC_MUTABLE_REF")
                matched.add("#tag=")
            if "http://" in w.value:
                rules.add("SRC_INSECURE_HTTP")
                matched.add("http://")
            if rules:
                key = (arrname, w.text)
                findings.setdefault(key, set()).update(rules)
                matched_text.setdefault(key, set()).update(matched)

    if pkgver_word is not None:
        if is_toolchain_path(path) and TOOLCHAIN_DEV_VER_RE.match(pkgver_word.value):
            key = ("pkgver", pkgver_word.text)
            findings.setdefault(key, set()).add("TOOLCHAIN_DEV_VER")
            matched_text.setdefault(key, set()).add(pkgver_word.value)

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
    forged value that doesn't equal this is SCHEMA_INVALID. For SRC_* rules
    this is each rule's fixed `matched_marker` (rules.toml); for
    TOOLCHAIN_DEV_VER it is the locator's own re-derived semantic value
    (there is no fixed marker -- the whole point is the actual pinned
    version string). Returns None if any rule_id lacks the information
    needed to derive a canonical value (caller must fail closed).
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


def _resolve_default_base_file(target_path: Path, base_ref: str | None, repo_root: Path, tmp_prefix: str, tmp_suffix: str) -> Path | None:
    """Shared helper: materialize `target_path` as it existed at `base_ref`
    (typically the PR's merge-base / the default branch) into a temp file,
    using local `git show` only (no network, no writes to the repository).
    Returns None if unavailable for any reason (not a git repo, ref doesn't
    exist, the file didn't exist at that ref yet, git not installed) --
    callers must treat that as "no base file available", not as an error.
    Callers are responsible for deleting the returned temp file.
    """
    import subprocess
    import tempfile
    if not base_ref:
        return None
    try:
        rel = target_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return None
    try:
        result = subprocess.run(
            ["git", "show", f"{base_ref}:{rel}"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
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
    parser.add_argument("--base-ref", type=str, default=None, help="A local git ref (e.g. origin/master) to auto-resolve --base-ledger/--base-cone from via 'git show'. Ignored for either flag explicitly given. No network access is performed.")
    args = parser.parse_args(argv)

    resolved_temp_base_ledger = None
    resolved_temp_base_cone = None
    try:
        base_ledger_path = args.base_ledger
        if base_ledger_path is None and args.base_ref:
            base_ledger_path = resolve_default_base_ledger(args.ledger, args.base_ref, repo_root=args.repo_root)
            resolved_temp_base_ledger = base_ledger_path

        base_cone_path = args.base_cone
        if base_cone_path is None and args.base_ref:
            base_cone_path = resolve_default_base_cone(args.cone, args.base_ref, repo_root=args.repo_root)
            resolved_temp_base_cone = base_cone_path

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
