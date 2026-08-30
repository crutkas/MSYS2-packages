#!/usr/bin/env python3
"""ARM64 package-admission governance gate.

Deterministic, offline, pure static analyzer for PR-0 of the ARM64 bootstrap
ratchet. It never executes, sources, builds, fetches, or links any PKGBUILD
or toolchain artifact -- it only reads UTF-8 text and applies a narrow,
conservative bash-array tokenizer to the specific fields the rule set cares
about (`source`/`source_<arch>` arrays and the scalar `pkgver` assignment).

Fail-closed predicate (see .ci/arm64-cone.txt / arm64-rules.toml / the design
note carried in the PR description for the full rationale):

  PASS iff:
    1. A (current absolute-rule hits: TOOLCHAIN_QUARANTINE, PARSE_FAIL,
       SCHEMA_INVALID) is empty.
    2. The registry, cone and ledger are structurally valid, canonical,
       sorted, unique, and scope-safe; no wildcard/regex bypass; no ledger
       row names an absolute or promoted rule; every row's locator/hash
       binds to the *current* on-disk content of its declared field/path.
       "Promoted" is a CROSS-COMMIT property: a ratchetable rule becomes
       permanently un-ledgerable once the BASE (parent/merge-base) commit's
       ledger already had zero rows for it -- see --base-ledger/--base-ref
       and load_base_ledger_rule_ids(). If no base ledger is available (the
       commit that first introduces the ledger), nothing is treated as
       promoted yet, since nothing has ever been cleared.
    3. V == L as sets keyed by (path, field, locator_sha256) -- both
       V subset L (no new/unlisted debt) and L subset V (no stale debt).
    4. Every ledger row is unexpired (today <= expires).

Supported static forms
-----------------------
* `source=(...)`/`source_<arch>=(...)` bash arrays containing any mixture of
  single-quoted (`'...'`), double-quoted (`"..."`, with backslash escapes for
  a literal quote, backslash, backtick, or dollar sign), and bare/unquoted
  words, including adjacent-token concatenation
  (e.g. `'name'::git://host/x.git#tag=y`) exactly as bash performs word
  splitting -- no variable expansion is performed; `${...}` is preserved
  literally so the locator binds to the exact on-disk text.
* `$(...)` command substitution is tokenized as an OPAQUE, balanced-paren
  literal span (quotes inside it are honored so embedded parens are not
  miscounted) -- it is never evaluated or executed, only kept verbatim so
  the surrounding array can still be located and its true locator text
  captured exactly. This is required for real recipes (e.g. `bash`,
  `readline`) that conditionally append patch-level source entries via
  `source=(${source[@]} https://.../patch-$(printf "%03d" $p){,.sig})`.
* A `source`/`source_<arch>` name may be assigned more than once (that same
  conditional-append idiom re-assigns it inside an `if`). Since control flow
  is not evaluated, every element from every such assignment in the file is
  unioned into that array's element set -- a conservative superset so a
  violation hidden behind an untaken branch is still caught.
* A scalar `pkgver=<word>` assignment (quoted or unquoted), read with the
  same tokenizer, first token wins.
* `#` starts a line comment only when it is the first character of an
  as-yet-unstarted word (real bash semantics) -- a `#` that appears after
  other unquoted characters of the *same* word (e.g. inside a URL) is kept
  literal.

Rejection behavior
------------------
Any of the following make a recipe's source/pkgver fields "cannot be safely
and unambiguously recovered", which raises PARSE_FAIL (absolute, fails
closed) for that path:
* unterminated single/double-quoted string, or unterminated `$(...)`,
  within the array/word region;
* a bare unquoted `(`/`)` that is not either the array's own delimiters or
  part of a `$(...)` span;
* a `source`/`source_<arch>=(` whose closing `)` cannot be located before
  end of file.
No network access, subprocess execution, or `source`/`bash -c` of any
PKGBUILD occurs anywhere in this file.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_DIR = REPO_ROOT / ".ci"
CONE_FILE = CI_DIR / "arm64-cone.txt"
RULES_FILE = CI_DIR / "arm64-rules.toml"
LEDGER_FILE = CI_DIR / "arm64-debt-ledger.tsv"

QUARANTINE_COMMIT_FULL = "9bbaa7b7a36ae51328cbff6acb720dcfa472db37"
# Any hex prefix of at least this length is treated as an attempted reference
# to the quarantined commit -- long enough that it cannot collide with an
# unrelated short token, short enough to catch common abbreviated forms.
QUARANTINE_MIN_ABBREV = 7

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
HEX_RE = re.compile(r"[0-9a-fA-F]+")


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
    text: str
    start: int
    end: int


def _scan_double_quoted(s: str, pos: int) -> tuple[str, int]:
    """pos is the index of the opening '\"'. Returns (raw_text_incl_quotes, end_pos)."""
    start = pos
    i = pos + 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == '"':
            return s[start:i + 1], i + 1
        i += 1
    raise ParseError(f"unterminated double-quoted string starting at offset {start}")


def _scan_single_quoted(s: str, pos: int) -> tuple[str, int]:
    start = pos
    i = pos + 1
    n = len(s)
    idx = s.find("'", i)
    if idx == -1:
        raise ParseError(f"unterminated single-quoted string starting at offset {start}")
    return s[start:idx + 1], idx + 1


def _scan_command_subst(s: str, pos: int) -> tuple[str, int]:
    """pos is the index of '$' in a '$(' command-substitution opener.
    Balances nested parens while skipping quoted content (so parens inside
    a quoted string, e.g. `$(printf "%03d" $p)`, are not miscounted). The
    substitution is treated as an OPAQUE literal span: it is never
    evaluated/executed, only captured verbatim so the locator text and the
    array's true closing paren can still be located safely."""
    assert s[pos:pos + 2] == "$("
    start = pos
    i = pos + 2
    depth = 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "'":
            _, i = _scan_single_quoted(s, i)
            continue
        if c == '"':
            _, i = _scan_double_quoted(s, i)
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


def _tokenize_words(s: str, pos: int, end_limit: int, stop_at_paren: bool):
    """Tokenize whitespace-separated, quote-aware, concatenation-aware words
    from s[pos:end_limit]. If stop_at_paren, an unquoted ')' ends the whole
    region (its index is returned as close_pos); otherwise the region simply
    runs to end_limit. Returns (words, close_pos_or_None).
    """
    words: list[Word] = []
    n = end_limit
    i = pos
    cur_parts: list[str] = []
    cur_start = None
    close_pos = None

    def flush():
        nonlocal cur_parts, cur_start
        if cur_parts:
            text = "".join(cur_parts)
            words.append(Word(text, cur_start, i))
            cur_parts = []
            cur_start = None

    while i < n:
        c = s[i]
        if c in " \t\r\n":
            flush()
            i += 1
            continue
        if c == "#" and not cur_parts:
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
            cur_parts.append(raw)
            continue
        if c == '"':
            if cur_start is None:
                cur_start = i
            raw, i = _scan_double_quoted(s, i)
            cur_parts.append(raw)
            continue
        if c == "'":
            if cur_start is None:
                cur_start = i
            raw, i = _scan_single_quoted(s, i)
            cur_parts.append(raw)
            continue
        if c == "\\" and i + 1 < n:
            if cur_start is None:
                cur_start = i
            cur_parts.append(s[i:i + 2])
            i += 2
            continue
        # Bare unquoted run: consume until a char that needs special
        # handling (whitespace, quote, paren, '$(' , or a leading '#').
        if cur_start is None:
            cur_start = i
        j = i
        while j < n:
            cj = s[j]
            if cj in " \t\r\n\"'()":
                break
            if cj == "#" and j == i and not cur_parts:
                break
            if cj == "\\":
                break
            if cj == "$" and j + 1 < n and s[j + 1] == "(":
                break
            j += 1
        if j == i:
            # Nothing consumed (shouldn't happen) -- avoid infinite loop.
            raise ParseError(f"unrecognized character {c!r} at offset {i}")
        cur_parts.append(s[i:j])
        i = j
    else:
        if stop_at_paren:
            raise ParseError("array not terminated with ')' before end of file")
    flush()
    return words, close_pos


def parse_source_arrays(text: str, path: str) -> dict[str, list[Word]]:
    """Returns {array_name: [Word, ...]} for every source/source_<arch> array.

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
    for m in SOURCE_ARRAY_RE.finditer(text):
        name = m.group(1)
        open_paren = m.end() - 1
        assert text[open_paren] == "("
        try:
            words, close_pos = _tokenize_words(text, open_paren + 1, len(text), stop_at_paren=True)
        except ParseError as e:
            raise ParseError(f"{path}: {name}=(...): {e}") from e
        result.setdefault(name, []).extend(words)
    return result


def parse_pkgver(text: str, path: str) -> str | None:
    matches = list(PKGVER_RE.finditer(text))
    if not matches:
        return None
    if len(matches) > 1:
        raise ParseError(f"{path}: multiple top-level pkgver= assignments")
    m = matches[0]
    val_start = m.end()
    line_end = text.find("\n", val_start)
    if line_end == -1:
        line_end = len(text)
    try:
        words, _ = _tokenize_words(text, val_start, line_end, stop_at_paren=False)
    except ParseError as e:
        raise ParseError(f"{path}: pkgver=...: {e}") from e
    if not words:
        raise ParseError(f"{path}: pkgver= has no value")
    return words[0].text


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def contains_quarantine_reference(s: str) -> bool:
    """True if s contains the full quarantined commit or a long-enough hex
    abbreviation of it that is not itself a substring of an unrelated hex
    run of different length starting elsewhere (we simply check: any hex
    run in s of length >= QUARANTINE_MIN_ABBREV that is a prefix of the
    full quarantined sha, OR the full sha itself as a substring)."""
    if QUARANTINE_COMMIT_FULL in s:
        return True
    for hm in HEX_RE.finditer(s):
        token = hm.group(0).lower()
        if len(token) >= QUARANTINE_MIN_ABBREV and QUARANTINE_COMMIT_FULL.startswith(token):
            return True
    return False


def detect_findings_for_file(path: str, text: str) -> tuple[list[Finding], list[str]]:
    """Returns (ratchetable_findings, absolute_hits) for one PKGBUILD's text.
    Raises ParseError (caller turns that into PARSE_FAIL) if unparseable.
    """
    absolute_hits: list[str] = []
    findings: dict[tuple[str, str], set] = {}
    matched_text: dict[tuple[str, str], set] = {}

    # The quarantine check is scanned across the ENTIRE raw file text, not
    # just source/pkgver fields. Real recipes commonly reference a VCS
    # commit indirectly, e.g. `_commit="<hash>"` followed by
    # `source=(...#commit=${_commit})` -- since this analyzer performs no
    # variable expansion (by design), checking only the literal source
    # array text would miss the hash hiding in the `_commit=` assignment.
    # Scanning the whole file closes that evasion path.
    if contains_quarantine_reference(text):
        absolute_hits.append(f"{path}: quarantined commit reference found in file")

    arrays = parse_source_arrays(text, path)
    for arrname, words in arrays.items():
        for w in words:
            rules = set()
            matched = set()
            if "git://" in w.text:
                rules.add("SRC_GIT_PROTO")
                matched.add("git://")
            if "#tag=" in w.text:
                rules.add("SRC_MUTABLE_REF")
                matched.add("#tag=")
            if "http://" in w.text:
                rules.add("SRC_INSECURE_HTTP")
                matched.add("http://")
            if rules:
                key = ("source", w.text)
                findings.setdefault(key, set()).update(rules)
                matched_text.setdefault(key, set()).update(matched)

    pkgver = parse_pkgver(text, path)
    if pkgver is not None:
        if is_toolchain_path(path) and TOOLCHAIN_DEV_VER_RE.match(pkgver):
            key = ("pkgver", pkgver)
            findings.setdefault(key, set()).add("TOOLCHAIN_DEV_VER")
            matched_text.setdefault(key, set()).add(pkgver)

    out = []
    for (fld, locator), rules in findings.items():
        out.append(Finding(path, fld, locator, tuple(sorted(rules)), ",".join(sorted(matched_text[(fld, locator)]))))
    return out, absolute_hits


TOOLCHAIN_DIR_RE = re.compile(r"^mingw-w64-cross-mingwarm64-[^/]+$")


def is_toolchain_path(pkgbuild_path: str) -> bool:
    directory = pkgbuild_path.split("/")[0]
    return bool(TOOLCHAIN_DIR_RE.match(directory))


# ---------------------------------------------------------------------------
# Cone / rules / ledger loading and validation
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    rule_id: str
    severity: str  # "absolute" | "ratchetable"
    promote_when_clear: bool


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
        rules[rule_id] = Rule(rule_id, severity, promote)
    return rules


def load_cone(cone_path: Path) -> list[str]:
    try:
        raw = cone_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ParseError(f"cannot read cone file: {e}") from e
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
        if row["field"] not in ("source", "pkgver"):
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


def run(cone_path: Path = CONE_FILE, rules_path: Path = RULES_FILE, ledger_path: Path = LEDGER_FILE,
        today: date | None = None, repo_root: Path = REPO_ROOT,
        base_ledger_path: Path | None = None) -> tuple[bool, list[str]]:
    problems: list[str] = []
    today = today or date.today()

    try:
        rules = load_rules(rules_path)
    except ParseError as e:
        return False, [f"SCHEMA_INVALID(rules): {e}"]

    try:
        cone = load_cone(cone_path)
    except ParseError as e:
        return False, [f"SCHEMA_INVALID(cone): {e}"]

    try:
        ledger_rows = load_ledger(ledger_path, rules)
    except ParseError as e:
        return False, [f"SCHEMA_INVALID(ledger): {e}"]

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


def resolve_default_base_ledger(ledger_path: Path, base_ref: str | None) -> Path | None:
    """Best-effort: materialize the ledger file as it existed at base_ref
    (typically the PR's merge-base / the default branch) into a temp file,
    using local `git show` only (no network). Returns None if unavailable
    for any reason (not a git repo, ref doesn't exist, file didn't exist at
    that ref, git not installed) -- callers must treat that as "no base
    ledger", not as an error.
    """
    import subprocess
    import tempfile
    if not base_ref:
        return None
    try:
        rel = ledger_path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return None
    try:
        result = subprocess.run(
            ["git", "show", f"{base_ref}:{rel}"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    fd, tmp_path = tempfile.mkstemp(prefix="arm64-base-ledger-", suffix=".tsv")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(result.stdout)
    return Path(tmp_path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cone", type=Path, default=CONE_FILE)
    parser.add_argument("--rules", type=Path, default=RULES_FILE)
    parser.add_argument("--ledger", type=Path, default=LEDGER_FILE)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help="Repository root cone paths are resolved against (for isolated fixture tests only).")
    parser.add_argument("--today", type=str, default=None, help="Override today's date (YYYY-MM-DD), for tests only.")
    parser.add_argument("--base-ledger", type=Path, default=None, help="Path to the ledger file as it existed at the PR's base/merge-base commit (used only to detect newly-promoted rules). Omit to auto-resolve via --base-ref.")
    parser.add_argument("--base-ref", type=str, default=None, help="A local git ref (e.g. origin/master) to auto-resolve --base-ledger from via 'git show'. Ignored if --base-ledger is given. No network access is performed.")
    args = parser.parse_args(argv)

    base_ledger_path = args.base_ledger
    if base_ledger_path is None and args.base_ref:
        base_ledger_path = resolve_default_base_ledger(args.ledger, args.base_ref)

    today = datetime.strptime(args.today, "%Y-%m-%d").date() if args.today else None
    ok, problems = run(args.cone, args.rules, args.ledger, today=today, repo_root=args.repo_root,
                        base_ledger_path=base_ledger_path)
    if ok:
        print("PASS: arm64-admission-guard (V == L, no absolute hits, ledger valid, unexpired)")
        return 0
    print("FAIL: arm64-admission-guard", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
