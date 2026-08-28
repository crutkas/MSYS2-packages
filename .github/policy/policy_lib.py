from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime as dt
import hashlib
import json
import re
import unicodedata
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Protocol, Sequence


APPROVED_ACTIONS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
}
ALLOWED_EVENTS = {"pull_request_target"}
SUPPORTED_MSYSTEMS = {
    "MSYS",
    "MINGW32",
    "MINGW64",
    "UCRT64",
    "CLANG32",
    "CLANG64",
    "CLANGARM64",
}
FORBIDDEN_EVENTS = {
    "workflow_dispatch",
    "workflow_call",
    "schedule",
    "pages_build",
    "deployment",
    "deployment_status",
    "release",
}
FORBIDDEN_STEP_KEYS = {"if", "continue-on-error", "timeout-minutes"}
FORBIDDEN_JOB_KEYS = {
    "if",
    "continue-on-error",
    "timeout-minutes",
    "container",
    "services",
    "uses",
    "secrets",
    "environment",
}
SCRIPT_SUFFIXES = {
    ".awk",
    ".bash",
    ".bat",
    ".bzl",
    ".cjs",
    ".cmake",
    ".cmd",
    ".com",
    ".exe",
    ".groovy",
    ".hta",
    ".js",
    ".jse",
    ".kts",
    ".lua",
    ".mjs",
    ".mk",
    ".php",
    ".pl",
    ".ps1",
    ".ps1xml",
    ".psd1",
    ".psm1",
    ".psrc",
    ".pssc",
    ".py",
    ".pyw",
    ".rb",
    ".reg",
    ".scr",
    ".sh",
    ".tcl",
    ".vbe",
    ".vbs",
    ".wsf",
    ".wsh",
    ".zsh",
}
EXECUTABLE_FILENAMES = {
    "action.yaml",
    "action.yml",
    "build.bazel",
    "build.gradle",
    "build.gradle.kts",
    "cmakelists.txt",
    "configure",
    "configure.ac",
    "configure.in",
    "dockerfile",
    "gnumakefile",
    "gnumakefile.am",
    "gnumakefile.in",
    "justfile",
    "makefile",
    "makefile.am",
    "makefile.in",
    "meson.build",
    "meson_options.txt",
    "pkgbuild",
    "sconstruct",
    "sconscript",
    "wscript",
    "workspace.bazel",
}
NETWORK_COMMANDS = {
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
}
PACKAGE_COMMANDS = {
    "apt",
    "apt-get",
    "brew",
    "choco",
    "gem",
    "go",
    "npm",
    "npx",
    "pacman",
    "pip",
    "pip3",
    "pipx",
    "pnpm",
    "vcpkg",
    "winget",
    "yarn",
}
DANGEROUS_GIT_SUBCOMMANDS = {
    "archive",
    "bundle",
    "checkout",
    "clone",
    "fetch",
    "init",
    "merge",
    "pull",
    "push",
    "read-tree",
    "reset",
    "restore",
    "submodule",
    "switch",
    "worktree",
}
MODELED_GIT_SUBCOMMANDS = {"rev-parse", "status", "remote"}
NESTED_SHELL_COMMANDS = {
    "ash",
    "bash",
    "busybox",
    "cmd",
    "command",
    "csh",
    "dash",
    "env",
    "fish",
    "ksh",
    "powershell",
    "powershell_ise",
    "pwsh",
    "saps",
    "sh",
    "start",
    "start-process",
    "sudo",
    "wsl",
    "xargs",
    "zsh",
}
DYNAMIC_COMMANDS = {
    "add-type",
    "eval",
    "iex",
    "icm",
    "invoke-command",
    "invoke-expression",
    "invoke-item",
    "new-object",
    "source",
}
CONTAINER_COMMANDS = {"docker", "podman", "nerdctl"}
PERMITTED_COMMANDS = {"git", "python"}
# Case-sensitive: CPython's -B (no bytecode) and -b (bytes warning) differ.
PERMITTED_PYTHON_FLAGS = {"-B"}
COMMAND_SUFFIXES = (".exe", ".cmd", ".bat", ".com", ".ps1")
ACQUISITION_MARKERS = (
    "bitsadmin",
    "certutil",
    "downloaddata",
    "downloadfile",
    "downloadstring",
    "httpclient",
    "msxml2",
    "net.sockets",
    "reflection.assembly",
    "start-bitstransfer",
    "tcpclient",
    "webclient",
    "webrequest",
    "xmlhttp",
)
PERMITTED_INTERPOLATIONS = {
    "$env:github_workspace",
    "$env:github_event_path",
    "$env:policy_private_root",
}
# Declared helper capabilities. A helper may only exercise a surface it names,
# and it may not name a surface it does not exercise.
CAPABILITY_VOCABULARY = {
    "github-api-read",
    "git-read-local",
    "dotnet-filesystem",
    "dotnet-acl",
    "dotnet-reflection",
    "legacy-disabled",
}
# Python import/call surfaces used by the helper capability model.
NETWORK_PYTHON_MODULES = {"urllib", "http", "requests", "socket", "ssl", "ftplib"}
PROCESS_PYTHON_MODULES = {"subprocess"}
FORBIDDEN_PYTHON_MODULES = {
    "ctypes",
    "importlib",
    "multiprocessing",
    "pickle",
    "pty",
    "runpy",
    "shutil",
    "signal",
    "site",
    "telnetlib",
    "webbrowser",
    "xmlrpc",
}
FORBIDDEN_PYTHON_CALLS = {
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "builtins.__import__",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.spawnv",
    "os.posix_spawn",
    "importlib.import_module",
    "ctypes.CDLL",
    "pickle.loads",
    "runpy.run_path",
    "runpy.run_module",
}
SUBPROCESS_ENTRYPOINTS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
FORBIDDEN_PYTHON_BUILTINS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "memoryview",
}
# Undeclared-surface denial codes, most specific first.
SURFACE_ORDER = (
    "github-api-read",
    "git-read-local",
    "dotnet-reflection",
    "dotnet-acl",
    "dotnet-filesystem",
)
SURFACE_CODES = {
    "github-api-read": "HELPER_NETWORK_UNMODELED",
    "git-read-local": "HELPER_PROCESS_UNMODELED",
    "dotnet-reflection": "HELPER_CAPABILITY_UNMODELED",
    "dotnet-acl": "HELPER_CAPABILITY_UNMODELED",
    "dotnet-filesystem": "HELPER_CAPABILITY_UNMODELED",
}
EXPRESSION_SCAN_LIMIT = 8192
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
YAML_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):(.*)$")
LOCAL_HELPER_RE = re.compile(
    r"(?i)((?:\.github|\.ci)[\\/][A-Za-z0-9_.\\/-]+)"
)
YAML_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\ufeff]")
EXPRESSION_OPEN_RE = re.compile(r"\$\{\{")
# A reference to the `secrets` context in ANY position leaks secrets: the
# property forms (`secrets.X`, `secrets['X']`) and the whole-context forms that
# function indirection produces (`toJSON(secrets)`, `fromJSON(toJSON(secrets))`).
# The negative lookbehind for `.` keeps a property named `secrets` a near-miss.
SECRETS_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_.])secrets(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
# `github.token` directly, or any whole-context use of `github` -- serializing
# the context with toJSON(github) exposes the token just as surely.
GITHUB_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_.])github(?![A-Za-z0-9_])"
    r"(?:"
    r"[ \t\n]{0,64}\.[ \t\n]{0,64}token(?![A-Za-z0-9_])"
    r"|[ \t\n]{0,64}\[[ \t\n]{0,64}(?P<quote>['\"])[ \t\n]{0,64}token[ \t\n]{0,64}(?P=quote)"
    r"|(?![ \t\n]{0,64}[.\[])"
    r")",
    re.IGNORECASE,
)
SHELL_TOKEN_RE = re.compile(
    r"(?P<newline>\n)"
    r"|(?P<space>[ \t]+)"
    r"|(?P<operator>\|\||&&|[;|&(){}=])"
    r"|(?P<string>\"(?:[^\"`]|`.){0,4096}\"|'(?:[^']|'')" r"{0,4096}')"
    r"|(?P<word>[^\s;|&(){}=\"']+)"
)
INTERPOLATION_RE = re.compile(r"\$(?:\{[^}]{0,256}\}|[A-Za-z_:][A-Za-z0-9_:.]{0,256}|\()")
# A command target must be the whole, anchored, workspace-local helper path --
# not merely a string that happens to contain ".github" somewhere.
WORKSPACE_ANCHOR_RE = re.compile(
    r"\$env:GITHUB_WORKSPACE[\\/]protected-base(?P<rest>[\\/][^\\/].*)",
    re.IGNORECASE,
)
HELPER_ROOTS = {".github", ".ci"}
HELPER_COMPONENT_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")


class PolicyError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PolicyError(code, message)


def is_exact_int(value: Any) -> bool:
    """True only for a real JSON integer.

    ``is_exact_int(True)`` is True in Python, so every numeric identity
    check must use this instead or a JSON ``true`` would satisfy an ID.
    """
    return type(value) is int


def is_positive_id(value: Any) -> bool:
    return is_exact_int(value) and value > 0


def is_nonnegative_size(value: Any) -> bool:
    return is_exact_int(value) and value >= 0


def require_exact_keys(
    value: Mapping[str, Any], keys: Iterable[str], code: str, label: str
) -> None:
    expected = set(keys)
    actual = set(value)
    require(
        actual == expected,
        code,
        f"{label} keys are {sorted(actual)}, expected {sorted(expected)}",
    )


def parse_json_strict(text: str, label: str = "JSON") -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "JSON_DUPLICATE_KEY", f"{label} repeats {key!r}")
            result[key] = value
        return result

    def reject_constant(name: str) -> Any:
        # NaN, Infinity, and -Infinity are Python extensions, not JSON. Accepting
        # them would let a lock or graph carry a value that compares unequal to
        # itself or exceeds every bound.
        raise PolicyError(
            "JSON_CONSTANT", f"{label} contains the non-JSON constant {name}"
        )

    try:
        return json.loads(
            text, object_pairs_hook=no_duplicates, parse_constant=reject_constant
        )
    except PolicyError:
        raise
    except (TypeError, ValueError) as error:
        raise PolicyError("JSON_INVALID", f"{label} is invalid: {error}") from error


@dataclasses.dataclass(frozen=True)
class _YamlLine:
    number: int
    indent: int
    content: str


class StrictYamlParser:
    """Parser for the intentionally small YAML subset admitted by this policy."""

    def __init__(self, text: str):
        require("\0" not in text, "YAML_NUL", "YAML contains NUL")
        require(not text.startswith("\ufeff"), "YAML_BOM", "YAML BOM is unsupported")
        text = text.replace("\r\n", "\n")
        require("\r" not in text, "YAML_LINE_ENDING", "bare CR is unsupported")
        control = YAML_CONTROL_RE.search(text)
        if control is not None:
            raise PolicyError(
                "YAML_CONTROL",
                "YAML contains a control or line-separator character "
                f"U+{ord(control.group()):04X} at offset {control.start()}",
            )
        self.lines: list[_YamlLine] = []
        for number, raw in enumerate(text.split("\n"), 1):
            require("\t" not in raw, "YAML_TAB", f"line {number} contains a tab")
            require(
                raw.rstrip(" ") == raw,
                "YAML_TRAILING_SPACE",
                f"line {number} has trailing spaces",
            )
            stripped = raw.lstrip(" ")
            indent = len(raw) - len(stripped)
            if stripped:
                require(
                    not stripped.startswith(("%YAML", "%TAG", "---", "...")),
                    "YAML_DOCUMENT_FEATURE",
                    f"line {number} uses a document feature",
                )
                require(
                    not stripped.startswith("#"),
                    "YAML_COMMENT",
                    f"line {number} uses an unsupported comment",
                )
            self.lines.append(_YamlLine(number, indent, stripped))
        self.index = 0

    def parse(self) -> Any:
        self._skip_blank()
        require(self.index < len(self.lines), "YAML_EMPTY", "YAML is empty")
        require(
            self.lines[self.index].indent == 0,
            "YAML_ROOT_INDENT",
            "YAML root must start at column zero",
        )
        result = self._parse_node(0)
        self._skip_blank()
        if self.index != len(self.lines):
            raise PolicyError(
                "YAML_TRAILING_CONTENT",
                f"unexpected content on line {self.lines[self.index].number}",
            )
        return result

    def _skip_blank(self) -> None:
        while self.index < len(self.lines) and not self.lines[self.index].content:
            self.index += 1

    def _parse_node(self, indent: int) -> Any:
        self._skip_blank()
        require(self.index < len(self.lines), "YAML_MISSING_NODE", "missing YAML node")
        line = self.lines[self.index]
        require(
            line.indent == indent,
            "YAML_INDENT",
            f"line {line.number} has indentation {line.indent}, expected {indent}",
        )
        if line.content == "-" or line.content.startswith("- "):
            return self._parse_sequence(indent)
        return self._parse_mapping(indent)

    def _parse_mapping(self, indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while True:
            self._skip_blank()
            if self.index >= len(self.lines):
                break
            line = self.lines[self.index]
            if line.indent < indent:
                break
            require(
                line.indent == indent,
                "YAML_CONTINUATION",
                f"line {line.number} is an unsupported continuation or indentation",
            )
            require(
                not (line.content == "-" or line.content.startswith("- ")),
                "YAML_NODE_KIND",
                f"line {line.number} mixes sequence and mapping nodes",
            )
            key, value = self._parse_pair(line.content, line.number, indent)
            require(
                key not in result,
                "YAML_DUPLICATE_KEY",
                f"line {line.number} repeats key {key!r}",
            )
            result[key] = value
        return result

    def _parse_sequence(self, indent: int) -> list[Any]:
        result: list[Any] = []
        while True:
            self._skip_blank()
            if self.index >= len(self.lines):
                break
            line = self.lines[self.index]
            if line.indent < indent:
                break
            require(
                line.indent == indent,
                "YAML_CONTINUATION",
                f"line {line.number} is an unsupported continuation or indentation",
            )
            if not (line.content == "-" or line.content.startswith("- ")):
                break
            rest = line.content[1:].lstrip(" ")
            self.index += 1
            if not rest:
                result.append(self._parse_child(indent, line.number))
            elif YAML_KEY_RE.match(rest):
                result.append(self._parse_sequence_mapping(rest, line.number, indent + 2))
            else:
                result.append(self._parse_scalar(rest, line.number))
                self._reject_scalar_continuation(indent, line.number)
        return result

    def _parse_sequence_mapping(
        self, first: str, first_number: int, indent: int
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        key, value = self._parse_pair_after_header(first, first_number, indent)
        result[key] = value
        while True:
            self._skip_blank()
            if self.index >= len(self.lines):
                break
            line = self.lines[self.index]
            if line.indent < indent:
                break
            require(
                line.indent == indent,
                "YAML_CONTINUATION",
                f"line {line.number} is an unsupported continuation or indentation",
            )
            key, value = self._parse_pair(line.content, line.number, indent)
            require(
                key not in result,
                "YAML_DUPLICATE_KEY",
                f"line {line.number} repeats key {key!r}",
            )
            result[key] = value
        return result

    def _parse_pair(self, content: str, number: int, indent: int) -> tuple[str, Any]:
        self.index += 1
        return self._parse_pair_after_header(content, number, indent)

    def _parse_pair_after_header(
        self, content: str, number: int, indent: int
    ) -> tuple[str, Any]:
        match = YAML_KEY_RE.match(content)
        require(match is not None, "YAML_MAPPING", f"line {number} is not a mapping")
        key = match.group(1)
        suffix = match.group(2)
        require(
            suffix == "" or suffix.startswith(" "),
            "YAML_COLON",
            f"line {number} must separate a value from ':' with one space",
        )
        rest = suffix.lstrip(" ")
        if not rest:
            value = self._parse_optional_child(indent, number)
        elif rest == "|":
            value = self._parse_literal(indent, number)
        else:
            require(
                not rest.startswith(("|", ">")),
                "YAML_BLOCK_STYLE",
                f"line {number} uses an unsupported block scalar style",
            )
            value = self._parse_scalar(rest, number)
            self._reject_scalar_continuation(indent, number)
        return key, value

    def _parse_optional_child(self, indent: int, number: int) -> Any:
        saved = self.index
        self._skip_blank()
        if self.index >= len(self.lines) or self.lines[self.index].indent <= indent:
            return None
        line = self.lines[self.index]
        require(
            line.indent == indent + 2,
            "YAML_INDENT",
            f"line {line.number} must be indented exactly two spaces below line {number}",
        )
        return self._parse_node(indent + 2)

    def _parse_child(self, indent: int, number: int) -> Any:
        self._skip_blank()
        require(
            self.index < len(self.lines),
            "YAML_MISSING_NODE",
            f"line {number} has no sequence value",
        )
        line = self.lines[self.index]
        require(
            line.indent == indent + 2,
            "YAML_INDENT",
            f"line {line.number} must be indented exactly two spaces below line {number}",
        )
        return self._parse_node(indent + 2)

    def _parse_literal(self, indent: int, number: int) -> str:
        content_indent = indent + 2
        chunks: list[str] = []
        saw_content = False
        while self.index < len(self.lines):
            line = self.lines[self.index]
            if line.content and line.indent <= indent:
                break
            if not line.content:
                chunks.append("")
                self.index += 1
                continue
            require(
                line.indent >= content_indent,
                "YAML_LITERAL_INDENT",
                f"line {line.number} is not indented below literal on line {number}",
            )
            chunks.append(" " * (line.indent - content_indent) + line.content)
            saw_content = True
            self.index += 1
        require(saw_content, "YAML_EMPTY_LITERAL", f"line {number} has an empty literal")
        while chunks and chunks[-1] == "":
            chunks.pop()
        return "\n".join(chunks) + "\n"

    def _reject_scalar_continuation(self, indent: int, number: int) -> None:
        saved = self.index
        self._skip_blank()
        if self.index < len(self.lines) and self.lines[self.index].indent > indent:
            line = self.lines[self.index]
            raise PolicyError(
                "YAML_PLAIN_CONTINUATION",
                f"line {line.number} continues the plain scalar on line {number}",
            )
        self.index = saved

    @staticmethod
    def _parse_scalar(value: str, number: int) -> Any:
        require(
            value[0] not in "'\"[]{}&*!>|?@`",
            "YAML_SCALAR_STYLE",
            f"line {number} uses an unsupported scalar style",
        )
        require(" #" not in value, "YAML_COMMENT", f"line {number} has a comment")
        require(": " not in value, "YAML_COLON", f"line {number} has an ambiguous colon")
        require(
            not re.search(r"(?:^|\s)(?:&|\*)[A-Za-z0-9_-]+", value),
            "YAML_ALIAS",
            f"line {number} uses an anchor or alias",
        )
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if lowered in {"null", "~"}:
            return None
        if re.fullmatch(r"0|[1-9][0-9]*", value):
            return int(value)
        require(
            lowered not in {"yes", "no", "on", "off"},
            "YAML_AMBIGUOUS_BOOLEAN",
            f"line {number} uses an ambiguous YAML boolean",
        )
        return value


def parse_workflow_yaml(text: str) -> dict[str, Any]:
    document = StrictYamlParser(text).parse()
    require(isinstance(document, dict), "WORKFLOW_ROOT", "workflow root must be a map")
    return document


def normalize_policy_path(path: str) -> str:
    require(isinstance(path, str), "PATH_TYPE", "path must be a string")
    require(path == unicodedata.normalize("NFC", path), "PATH_NFC", f"{path!r} is not NFC")
    require("\\" not in path and "\0" not in path, "PATH_SEPARATOR", f"{path!r} is invalid")
    require(not path.startswith("/"), "PATH_ABSOLUTE", f"{path!r} is absolute")
    parts = path.split("/")
    require(
        all(part not in {"", ".", ".."} for part in parts),
        "PATH_TRAVERSAL",
        f"{path!r} contains an empty or dot component",
    )
    require(
        all(":" not in part for part in parts),
        "PATH_DEVICE",
        f"{path!r} contains a device-like component",
    )
    normalized = str(PurePosixPath(*parts))
    require(normalized == path, "PATH_CANONICAL", f"{path!r} is not canonical")
    return normalized


@dataclasses.dataclass(frozen=True)
class TreeEntry:
    path: str
    mode: str
    type: str
    sha: str
    size: int | None = None

    @property
    def fingerprint(self) -> tuple[str, str, str]:
        return self.type, self.mode, self.sha

    @property
    def is_symlink(self) -> bool:
        return self.mode == "120000"

    @property
    def is_submodule(self) -> bool:
        return self.mode == "160000" or self.type == "commit"

    @property
    def is_executable(self) -> bool:
        return self.mode == "100755"


class TreeManifest:
    def __init__(self, tree_sha: str, entries: Iterable[TreeEntry]):
        require(SHA1_RE.fullmatch(tree_sha) is not None, "TREE_SHA", "tree SHA is invalid")
        self.tree_sha = tree_sha
        self.entries: dict[str, TreeEntry] = {}
        folded: dict[str, str] = {}
        for entry in entries:
            path = normalize_policy_path(entry.path)
            require(path not in self.entries, "TREE_DUPLICATE", f"tree repeats {path}")
            fold = path.casefold()
            require(
                fold not in folded,
                "TREE_CASE_COLLISION",
                f"tree paths {folded.get(fold)!r} and {path!r} collide",
            )
            require(
                entry.mode in {"040000", "100644", "100755", "120000", "160000"},
                "TREE_MODE",
                f"{path} has unsupported mode {entry.mode}",
            )
            require(
                entry.type in {"blob", "tree", "commit"},
                "TREE_TYPE",
                f"{path} has unsupported type {entry.type}",
            )
            require(SHA1_RE.fullmatch(entry.sha) is not None, "TREE_ENTRY_SHA", path)
            self.entries[path] = dataclasses.replace(entry, path=path)
            folded[fold] = path

    @classmethod
    def from_api(cls, payload: Mapping[str, Any], expected_sha: str) -> "TreeManifest":
        require(payload.get("truncated") is False, "TREE_TRUNCATED", "tree API was truncated")
        require(payload.get("sha") == expected_sha, "TREE_IDENTITY", "tree SHA changed")
        raw_entries = payload.get("tree")
        require(isinstance(raw_entries, list), "TREE_SHAPE", "tree entries are missing")
        entries: list[TreeEntry] = []
        for raw in raw_entries:
            require(isinstance(raw, dict), "TREE_SHAPE", "tree entry is not a map")
            size = raw.get("size")
            require(
                size is None or is_nonnegative_size(size),
                "TREE_SHAPE",
                "tree entry size is not an exact non-negative integer",
            )
            entries.append(
                TreeEntry(
                    path=raw.get("path"),
                    mode=raw.get("mode"),
                    type=raw.get("type"),
                    sha=raw.get("sha"),
                    size=size,
                )
            )
        return cls(expected_sha, entries)

    def blobs(self) -> dict[str, TreeEntry]:
        return {path: entry for path, entry in self.entries.items() if entry.type == "blob"}

    def leaves(self) -> dict[str, TreeEntry]:
        return {path: entry for path, entry in self.entries.items() if entry.type != "tree"}

    def assert_symlink_free_path(self, path: str) -> TreeEntry:
        path = normalize_policy_path(path)
        components = path.split("/")
        for index in range(1, len(components)):
            prefix = "/".join(components[:index])
            entry = self.entries.get(prefix)
            if entry is not None:
                require(
                    entry.type == "tree" and entry.mode == "040000",
                    "LOCK_PATH_TRAVERSAL",
                    f"{path} traverses non-tree {prefix}",
                )
        entry = self.entries.get(path)
        require(entry is not None, "LOCK_PATH_MISSING", f"{path} is absent")
        require(
            entry.type == "blob" and entry.mode in {"100644", "100755"},
            "LOCK_PATH_TYPE",
            f"{path} is not a regular in-repository file",
        )
        return entry


@dataclasses.dataclass(frozen=True)
class NameStatus:
    status: str
    old_path: str | None
    new_path: str | None
    old_entry: TreeEntry | None
    new_entry: TreeEntry | None

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(path for path in (self.old_path, self.new_path) if path is not None)


def diff_manifests(base: TreeManifest, candidate: TreeManifest) -> list[NameStatus]:
    base_blobs = base.leaves()
    candidate_blobs = candidate.leaves()
    common = set(base_blobs) & set(candidate_blobs)
    result: list[NameStatus] = []
    for path in sorted(common):
        old = base_blobs[path]
        new = candidate_blobs[path]
        if old.fingerprint == new.fingerprint:
            continue
        status = "T" if (old.mode, old.type) != (new.mode, new.type) else "M"
        result.append(NameStatus(status, path, path, old, new))

    removed = {path: base_blobs[path] for path in set(base_blobs) - set(candidate_blobs)}
    added = {
        path: candidate_blobs[path] for path in set(candidate_blobs) - set(base_blobs)
    }
    removed_by_fingerprint: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    base_by_fingerprint: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for path, entry in removed.items():
        removed_by_fingerprint[entry.fingerprint].append(path)
    for path, entry in base_blobs.items():
        base_by_fingerprint[entry.fingerprint].append(path)

    consumed_removed: set[str] = set()
    consumed_added: set[str] = set()
    for new_path in sorted(added):
        new_entry = added[new_path]
        sources = sorted(
            path
            for path in removed_by_fingerprint[new_entry.fingerprint]
            if path not in consumed_removed
        )
        if sources:
            old_path = sources[0]
            consumed_removed.add(old_path)
            consumed_added.add(new_path)
            result.append(
                NameStatus(
                    "R100", old_path, new_path, removed[old_path], new_entry
                )
            )
            continue
        copy_sources = sorted(
            path
            for path in base_by_fingerprint[new_entry.fingerprint]
            if path in candidate_blobs
        )
        if copy_sources:
            old_path = copy_sources[0]
            consumed_added.add(new_path)
            result.append(
                NameStatus(
                    "C100", old_path, new_path, base_blobs[old_path], new_entry
                )
            )

    for path in sorted(set(removed) - consumed_removed):
        result.append(NameStatus("D", path, None, removed[path], None))
    for path in sorted(set(added) - consumed_added):
        result.append(NameStatus("A", None, path, None, added[path]))
    return sorted(result, key=lambda item: (item.paths, item.status))


def windows_effective_path(path: str) -> str:
    """Collapse every component to the name Windows would actually open.

    ``normalize_policy_path`` has already rejected backslashes, ``..``, and
    device/ADS colons, so this only has to fold the trailing dot and space
    forms: ``.github./workflows/x`` opens ``.github/workflows/x`` on Win32 and
    must therefore be treated as a controlled path.
    """
    parts = []
    for part in normalize_policy_path(path).split("/"):
        stripped = part.rstrip(". \t")
        parts.append((stripped or part).casefold())
    return "/".join(parts)


def path_is_controlled(path: str, lock_prefixes: Sequence[str]) -> bool:
    folded = windows_effective_path(path)
    prefixes = {
        ".github/workflows/",
        ".github/policy/",
        ".github/actions/",
        ".ci/",
    }
    if any(folded.startswith(prefix) for prefix in prefixes):
        return True
    if folded in {
        ".github/codeowners",
        ".github/github-app.yml",
        ".github/github-app.yaml",
    }:
        return True
    names = windows_effective_names(path)
    if names & {"action.yml", "action.yaml", ".gitattributes", ".gitmodules"}:
        return True
    return any(
        folded == prefix.casefold().rstrip("/")
        or folded.startswith(prefix.casefold().rstrip("/") + "/")
        for prefix in lock_prefixes
    )


def windows_effective_names(path: str) -> set[str]:
    """Every filename Windows could actually resolve this path component to.

    Win32 silently strips trailing dots and spaces, so ``evil.ps1.`` opens
    ``evil.ps1``. NTFS also resolves ``host.txt:evil.ps1`` to an alternate data
    stream. Both forms must be classified, not just the literal spelling.
    """
    name = PurePosixPath(path).name
    candidates = {name}
    queue = [name]
    while queue:
        current = queue.pop()
        stripped = current.rstrip(". \t")
        if stripped and stripped not in candidates:
            candidates.add(stripped)
            queue.append(stripped)
        if ":" in current:
            for part in current.split(":"):
                if part and part not in candidates:
                    candidates.add(part)
                    queue.append(part)
    return {candidate.casefold() for candidate in candidates if candidate}


def looks_like_shebang(prefix: bytes) -> bool:
    """Detect a shebang behind a UTF-8/UTF-16 BOM or leading blank bytes."""
    for bom in (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff"):
        if prefix.startswith(bom):
            prefix = prefix[len(bom) :]
            break
    compact = prefix.replace(b"\x00", b"")
    return compact.lstrip(b" \t").startswith(b"#!")


def path_looks_executable(path: str, entry: TreeEntry | None) -> bool:
    if entry is not None and (entry.is_executable or entry.is_submodule):
        return True
    for name in windows_effective_names(path):
        if name in EXECUTABLE_FILENAMES:
            return True
        suffix = PurePosixPath(name).suffix.casefold()
        if suffix in SCRIPT_SUFFIXES or suffix == ".install":
            return True
    return False


def exact_equal(left: Any, right: Any) -> bool:
    """Compare JSON values so that bool never equals int and types stay exact."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        if len(left) != len(right):
            return False
        for key, value in left.items():
            if key not in right or not exact_equal(value, right[key]):
                return False
        return True
    if isinstance(left, list):
        return len(left) == len(right) and all(
            exact_equal(item, other) for item, other in zip(left, right)
        )
    return left == right


def require_exact_equal(left: Any, right: Any, code: str, message: str) -> None:
    require(exact_equal(left, right), code, message)


def assert_safe_diff(
    changes: Sequence[NameStatus],
    lock_prefixes: Sequence[str],
    candidate_blob_prefix: callable,
) -> None:
    for change in changes:
        for path, entry in (
            (change.old_path, change.old_entry),
            (change.new_path, change.new_entry),
        ):
            if path is None:
                continue
            if path_is_controlled(path, lock_prefixes):
                raise PolicyError(
                    "SOURCE_ADMISSION_REQUIRED",
                    f"{change.status} involves controlled path {path}",
                )
            if entry is not None and (entry.is_symlink or entry.is_submodule):
                raise PolicyError(
                    "EXECUTABLE_SURFACE_CHANGE",
                    f"{change.status} involves link/submodule {path}",
                )
            if path_looks_executable(path, entry):
                raise PolicyError(
                    "EXECUTABLE_SURFACE_CHANGE",
                    f"{change.status} involves executable-like path {path}",
                )
        if change.new_path and change.new_entry and change.new_entry.type == "blob":
            prefix = candidate_blob_prefix(change.new_path, change.new_entry, 256)
            if looks_like_shebang(prefix):
                raise PolicyError(
                    "EXECUTABLE_SURFACE_CHANGE",
                    f"{change.status} introduces or changes shebang file {change.new_path}",
                )


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def expression_bodies(text: str) -> Iterable[str]:
    """Yield the bounded body of every ``${{ ... }}`` expression opened in *text*.

    An unterminated opener still yields a bounded window so truncation cannot
    hide a reference from the token model. The window is deliberately capped at
    ``EXPRESSION_SCAN_LIMIT``; every caller shares the same bound, so per-step
    and whole-document reference counts can never disagree.
    """
    for opener in EXPRESSION_OPEN_RE.finditer(text):
        start = opener.end()
        end = text.find("}}", start)
        if end == -1 or end - start > EXPRESSION_SCAN_LIMIT:
            yield text[start : start + EXPRESSION_SCAN_LIMIT]
        else:
            yield text[start:end]


def references_secret(value: Any) -> bool:
    return any(
        SECRETS_TOKEN_RE.search(body) is not None
        for text in _walk_strings(value)
        for body in expression_bodies(text)
    )


def references_github_token(value: Any) -> bool:
    return any(
        GITHUB_TOKEN_RE.search(body) is not None
        for text in _walk_strings(value)
        for body in expression_bodies(text)
    )


def count_github_token_references(value: Any) -> int:
    return sum(
        len(GITHUB_TOKEN_RE.findall(body))
        for text in _walk_strings(value)
        for body in expression_bodies(text)
    )


@dataclasses.dataclass(frozen=True)
class _ShellToken:
    kind: str
    value: str
    offset: int


def tokenize_shell(script: str) -> list[_ShellToken]:
    tokens: list[_ShellToken] = []
    index = 0
    while index < len(script):
        match = SHELL_TOKEN_RE.match(script, index)
        if match is None or match.end() == index:
            raise PolicyError(
                "SCRIPT_TOKEN",
                f"run script is not tokenizable at offset {index}",
            )
        tokens.append(_ShellToken(match.lastgroup or "", match.group(), index))
        index = match.end()
    return tokens


def _skip_space(tokens: Sequence[_ShellToken], index: int) -> int:
    while index < len(tokens) and tokens[index].kind == "space":
        index += 1
    return index


def command_name(value: str) -> str:
    name = value.strip("\"'")
    name = name.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for suffix in COMMAND_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


def canonical_workspace_helper(value: str) -> str | None:
    """Repo-relative helper path for a fully anchored literal, else ``None``.

    The entire token must be ``$env:GITHUB_WORKSPACE\\protected-base\\`` followed
    by a canonical ``.github``/``.ci`` path. Anything else -- a UNC or drive
    path, an absolute path, ``..`` traversal, an alternate data stream, an
    interpreter prefix such as ``cmd /c ...``, or a bare command name -- yields
    ``None`` and is refused by the caller.
    """
    match = WORKSPACE_ANCHOR_RE.fullmatch(value)
    if match is None:
        return None
    rest = match.group("rest")
    if "/" in rest and "\\" in rest:
        return None
    candidate = rest.replace("\\", "/").lstrip("/")
    parts = candidate.split("/")
    if len(parts) < 2 or parts[0] not in HELPER_ROOTS:
        return None
    for part in parts[1:]:
        if HELPER_COMPONENT_RE.fullmatch(part) is None:
            return None
        if part != part.rstrip(". \t"):
            return None
    try:
        normalized = normalize_policy_path(candidate)
    except PolicyError:
        return None
    if normalized != candidate:
        return None
    if windows_effective_path(normalized) != normalized.casefold():
        return None
    return normalized


def _assert_helper_reference(value: str) -> str | None:
    """Any token naming a local control path must be a canonical anchored one."""
    body = _string_body(value)
    if LOCAL_HELPER_RE.search(body) is None:
        return None
    helper = canonical_workspace_helper(body)
    require(
        helper is not None,
        "COMMAND_UNMODELED",
        f"run script references {value!r}, which is not a canonical "
        "workspace-local .github/.ci helper path",
    )
    return helper


def _assert_literal_interpolation(value: str) -> None:
    inner = _string_body(value)
    for match in INTERPOLATION_RE.finditer(inner):
        require(
            match.group().casefold() in PERMITTED_INTERPOLATIONS,
            "DYNAMIC_EXECUTION",
            f"run script interpolates {match.group()!r} outside the approved anchors",
        )


def _assert_not_denied_command(name: str, raw: str) -> None:
    require(name not in NETWORK_COMMANDS, "NETWORK_EXECUTION", f"run script invokes {raw}")
    require(name not in PACKAGE_COMMANDS, "PACKAGE_EXECUTION", f"run script invokes {raw}")
    require(
        name not in CONTAINER_COMMANDS,
        "CONTAINER_EXECUTION",
        f"run script invokes a container runtime {raw}",
    )
    require(
        name not in NESTED_SHELL_COMMANDS,
        "NESTED_SHELL_EXECUTION",
        f"run script launches a nested shell or process host {raw}",
    )
    require(
        name not in DYNAMIC_COMMANDS,
        "DYNAMIC_EXECUTION",
        f"run script uses dynamic execution {raw}",
    )


def _classify_command(name: str, raw: str) -> None:
    _assert_not_denied_command(name, raw)
    require(
        name in PERMITTED_COMMANDS,
        "COMMAND_UNMODELED",
        f"run script invokes unmodeled command {raw}",
    )


def _string_body(value: str) -> str:
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[1:-1]
    return value


def _validate_call_target(
    tokens: Sequence[_ShellToken], index: int, operator: str
) -> int:
    index = _skip_space(tokens, index)
    require(
        index < len(tokens),
        "DYNAMIC_EXECUTION",
        f"run script uses {operator!r} without a literal target",
    )
    target = tokens[index]
    require(
        target.kind == "string",
        "DYNAMIC_EXECUTION",
        f"run script uses {operator!r} with the non-literal target {target.value!r}",
    )
    _assert_literal_interpolation(target.value)
    body = _string_body(target.value)
    # The call operator is not an escape hatch around classification: the target
    # must clear the deny-lists and must be a canonical, fully anchored,
    # workspace-local helper path rather than "cmd", "pacman", a UNC or drive
    # path, a traversal, an ADS name, or an interpreter prefix.
    _assert_not_denied_command(command_name(body), target.value)
    helper = canonical_workspace_helper(body)
    require(
        helper is not None,
        "COMMAND_UNMODELED",
        f"run script calls {target.value!r}, which is not a canonical "
        "workspace-local .github/.ci helper path",
    )
    return index + 1, helper


def _validate_python(tokens: Sequence[_ShellToken], index: int) -> int:
    """Constrain python to running a literal helper file.

    This is an allow-list rather than a deny-list because ``-c`` and ``-m`` are
    single-character options: CPython accepts them bundled behind other flags
    (``-Bc``, ``-IBc``, ``-OOc``) and with their argument attached (``-mpip``),
    so enumerating the dangerous spellings cannot be made complete.
    """
    index = _skip_space(tokens, index)
    while index < len(tokens) and tokens[index].kind in {"word", "string"}:
        option = _string_body(tokens[index].value)
        if not option.startswith("-"):
            break
        require(
            option in PERMITTED_PYTHON_FLAGS,
            "DYNAMIC_EXECUTION",
            f"run script runs python with the unmodeled option {option!r}",
        )
        index = _skip_space(tokens, index + 1)
    return index


def _validate_git(tokens: Sequence[_ShellToken], index: int) -> int:
    index = _skip_space(tokens, index)
    require(
        index < len(tokens) and tokens[index].kind == "word",
        "GIT_UNMODELED",
        "run script invokes git without a literal subcommand",
    )
    subcommand = tokens[index].value.casefold()
    require(
        subcommand not in DANGEROUS_GIT_SUBCOMMANDS,
        "GIT_ACQUISITION",
        f"run script invokes git {subcommand}",
    )
    require(
        subcommand in MODELED_GIT_SUBCOMMANDS,
        "GIT_UNMODELED",
        f"run script invokes unmodeled git {subcommand}",
    )
    return index + 1


def scan_run_script(script: str) -> set[str]:
    lowered = script.casefold()
    require(
        not re.search(
            r"(?<![a-z0-9_-])(?:invoke-expression|iex|eval)(?![a-z0-9_-])", lowered
        ),
        "DYNAMIC_EXECUTION",
        "run script uses dynamic evaluation",
    )
    require(
        "http://" not in lowered and "https://" not in lowered,
        "NETWORK_EXECUTION",
        "run script embeds a network URL",
    )
    marker = next((item for item in ACQUISITION_MARKERS if item in lowered), None)
    require(
        marker is None,
        "NETWORK_EXECUTION",
        f"run script references the acquisition surface {marker!r}",
    )
    require(
        "$(" not in script,
        "DYNAMIC_EXECUTION",
        "run script uses subexpression or command substitution",
    )
    require(
        "`" not in script,
        "DYNAMIC_EXECUTION",
        "run script uses escape or substitution backticks",
    )

    tokens = tokenize_shell(script)
    helpers: set[str] = set()
    command_position = True
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "space":
            index += 1
            continue
        if token.kind == "newline":
            command_position = True
            index += 1
            continue
        if token.kind == "operator":
            if command_position and token.value in {"&", "(", "{"}:
                require(
                    token.value == "&",
                    "DYNAMIC_EXECUTION",
                    f"run script opens {token.value!r} at a command position",
                )
                index, helper = _validate_call_target(tokens, index + 1, "&")
                helpers.add(helper)
                command_position = False
                continue
            command_position = True
            index += 1
            continue
        if token.kind in {"string", "word"}:
            _assert_literal_interpolation(token.value)
            referenced = _assert_helper_reference(token.value)
            if referenced is not None:
                helpers.add(referenced)
        if command_position:
            if token.kind == "word" and token.value == ".":
                raise PolicyError(
                    "DYNAMIC_EXECUTION",
                    "run script dot-sources at a command position",
                )
            name = command_name(token.value)
            _classify_command(name, token.value)
            command_position = False
            if name == "git":
                index = _validate_git(tokens, index + 1)
                continue
            if name == "python":
                index = _validate_python(tokens, index + 1)
                continue
        else:
            command_position = False
        index += 1

    # Nothing outside a validated, anchored token may name a control path.
    for match in LOCAL_HELPER_RE.finditer(script):
        candidate = match.group(1).replace("\\", "/").rstrip(".,;:)")
        require(
            any(candidate.casefold().endswith(helper.casefold()) for helper in helpers),
            "COMMAND_UNMODELED",
            f"run script names the control path {candidate!r} outside a "
            "validated anchored helper reference",
        )
    return helpers


def validate_workflow_document(
    document: Mapping[str, Any],
    workflow_spec: Mapping[str, Any],
    approved_actions: Mapping[str, str],
) -> set[str]:
    require_exact_keys(
        workflow_spec,
        {
            "blob",
            "name",
            "events",
            "event_types",
            "event_branches",
            "protected_branch",
            "permissions",
            "fork_execution",
            "jobs",
            "helpers",
            "data",
        },
        "GRAPH_WORKFLOW",
        "workflow specification",
    )
    require(
        workflow_spec["fork_execution"] == "base-only-data-validation",
        "WORKFLOW_FORK_MODEL",
        "fork execution is not explicitly constrained to base-only data validation",
    )
    require_exact_keys(
        document,
        {"name", "on", "permissions", "jobs"},
        "WORKFLOW_KEYS",
        "workflow",
    )
    require(document["name"] == workflow_spec["name"], "WORKFLOW_NAME", "name changed")
    triggers = document["on"]
    require(isinstance(triggers, dict), "WORKFLOW_EVENTS", "on must be a map")
    require(
        not (set(triggers) & FORBIDDEN_EVENTS),
        "WORKFLOW_EVENT_FORBIDDEN",
        f"forbidden events: {sorted(set(triggers) & FORBIDDEN_EVENTS)}",
    )
    require(
        set(triggers) <= ALLOWED_EVENTS,
        "WORKFLOW_EVENT_UNMODELED",
        f"events outside the global allow-list: {sorted(set(triggers) - ALLOWED_EVENTS)}",
    )
    require(
        set(triggers) == set(workflow_spec["events"]),
        "WORKFLOW_EVENTS",
        "event allow-list changed",
    )
    for event, config in triggers.items():
        expected_types = workflow_spec["event_types"].get(event)
        require(isinstance(config, dict), "WORKFLOW_EVENT_CONFIG", event)
        require_exact_keys(config, {"types", "branches"}, "WORKFLOW_EVENT_CONFIG", event)
        require(isinstance(config["types"], list), "WORKFLOW_EVENT_TYPES", event)
        require_exact_equal(
            config["types"],
            expected_types,
            "WORKFLOW_EVENT_TYPES",
            f"{event} activity types changed",
        )
        require_exact_equal(
            config["branches"],
            workflow_spec["event_branches"].get(event),
            "WORKFLOW_EVENT_BRANCHES",
            f"{event} base branch allow-list changed",
        )
        require_exact_equal(
            config["branches"],
            [workflow_spec["protected_branch"]],
            "WORKFLOW_EVENT_BRANCHES",
            f"{event} must only run for the protected base branch",
        )

    permissions = document["permissions"]
    require(isinstance(permissions, dict), "WORKFLOW_PERMISSIONS", "permissions must map")
    require_exact_equal(
        permissions,
        workflow_spec["permissions"],
        "WORKFLOW_PERMISSIONS",
        "permissions differ from the read-only allow-list",
    )
    for permission, level in permissions.items():
        require(level == "read", "WORKFLOW_WRITE_PERMISSION", f"{permission}: {level}")

    require(
        not references_secret(document),
        "WORKFLOW_SECRET",
        "workflow references secrets",
    )

    jobs = document["jobs"]
    require(isinstance(jobs, dict) and jobs, "WORKFLOW_JOBS", "jobs must be a map")
    require(
        set(jobs) == set(workflow_spec["jobs"]),
        "WORKFLOW_JOBS",
        "job allow-list changed",
    )
    referenced_helpers: set[str] = set()
    declared_token_uses = 0
    for job_id, job in jobs.items():
        require(isinstance(job, dict), "WORKFLOW_JOB", f"{job_id} must be a map")
        forbidden = set(job) & FORBIDDEN_JOB_KEYS
        require(not forbidden, "WORKFLOW_JOB_FORBIDDEN", f"{job_id}: {sorted(forbidden)}")
        require_exact_keys(
            job, {"name", "runs-on", "steps"}, "WORKFLOW_JOB_KEYS", job_id
        )
        job_spec = workflow_spec["jobs"][job_id]
        require_exact_equal(
            job["name"], job_spec["name"], "WORKFLOW_JOB_NAME", job_id
        )
        require_exact_equal(
            job["runs-on"], job_spec["runs_on"], "WORKFLOW_RUNNER", job_id
        )
        steps = job["steps"]
        require(isinstance(steps, list) and steps, "WORKFLOW_STEPS", job_id)
        require(
            len(steps) == len(job_spec["steps"]),
            "WORKFLOW_STEPS",
            f"{job_id} step count changed",
        )
        for index, (step, step_spec) in enumerate(zip(steps, job_spec["steps"])):
            require(isinstance(step, dict), "WORKFLOW_STEP", f"{job_id}[{index}]")
            forbidden = set(step) & FORBIDDEN_STEP_KEYS
            require(
                not forbidden,
                "WORKFLOW_STEP_FORBIDDEN",
                f"{job_id}[{index}]: {sorted(forbidden)}",
            )
            require(step.get("name") == step_spec["name"], "WORKFLOW_STEP_NAME", str(index))
            kind = step_spec["kind"]
            if kind == "action":
                require_exact_keys(
                    step_spec,
                    {"name", "kind", "action", "with"},
                    "GRAPH_WORKFLOW_STEP",
                    step["name"],
                )
                require_exact_keys(
                    step,
                    {"name", "uses", "with"},
                    "WORKFLOW_ACTION_KEYS",
                    step["name"],
                )
                uses = step["uses"]
                require(isinstance(uses, str), "WORKFLOW_USES", step["name"])
                require(
                    not uses.startswith(("./", "docker://")),
                    "WORKFLOW_DELEGATION",
                    f"{step['name']} delegates locally or to Docker",
                )
                require("@" in uses, "ACTION_PIN", f"{uses} is not pinned")
                action, pin = uses.rsplit("@", 1)
                require(
                    action == step_spec["action"],
                    "ACTION_GRAPH",
                    f"{step['name']} action differs from the approval graph",
                )
                require(action in approved_actions, "ACTION_UNAPPROVED", action)
                require(
                    pin == approved_actions[action] and SHA1_RE.fullmatch(pin) is not None,
                    "ACTION_PIN",
                    f"{action} pin is not the approved lowercase SHA",
                )
                require_exact_equal(
                    step["with"],
                    step_spec["with"],
                    "ACTION_INPUT",
                    f"{step['name']} inputs changed",
                )
                if action == "msys2/setup-msys2":
                    msystem = step["with"].get("msystem")
                    require(msystem != "MINGWARM64", "MSYSTEM_UNSUPPORTED", msystem)
                    require(msystem in SUPPORTED_MSYSTEMS, "MSYSTEM_UNSUPPORTED", str(msystem))
                if action == "actions/checkout":
                    require(index == 0, "CHECKOUT_ORDER", "checkout must be first")
                    require(
                        step["with"].get("persist-credentials") is False,
                        "CHECKOUT_CREDENTIALS",
                        "checkout credentials must not persist",
                    )
                    require(
                        step["with"].get("ref")
                        == "${{ github.event.pull_request.base.sha }}",
                        "CHECKOUT_REF",
                        "checkout must use the protected event base",
                    )
            elif kind == "run":
                expected_spec_keys = {"name", "kind", "env", "run_sha256"}
                if step_spec.get("github_token") is True:
                    expected_spec_keys.add("github_token")
                require_exact_keys(
                    step_spec,
                    expected_spec_keys,
                    "GRAPH_WORKFLOW_STEP",
                    step["name"],
                )
                require_exact_keys(
                    step,
                    {"name", "shell", "env", "run"},
                    "WORKFLOW_RUN_KEYS",
                    step["name"],
                )
                require(step["shell"] == "pwsh", "WORKFLOW_SHELL", step["name"])
                require_exact_equal(
                    step["env"], step_spec["env"], "WORKFLOW_ENV", step["name"]
                )
                require(isinstance(step["run"], str), "WORKFLOW_RUN", step["name"])
                require(
                    hashlib.sha256(step["run"].encode("utf-8")).hexdigest()
                    == step_spec["run_sha256"],
                    "WORKFLOW_RUN_DIGEST",
                    f"{step['name']} command block differs from the approval graph",
                )
                referenced_helpers.update(scan_run_script(step["run"]))
                declared_token = step_spec.get("github_token") is True
                token_uses = count_github_token_references(step["env"])
                require(
                    token_uses == 0 or declared_token,
                    "WORKFLOW_TOKEN",
                    f"{step['name']} has an unmodeled token",
                )
                require(
                    token_uses > 0 or not declared_token,
                    "WORKFLOW_TOKEN",
                    f"{step['name']} declares dormant token authority it never uses",
                )
                declared_token_uses += token_uses
            else:
                raise PolicyError("WORKFLOW_STEP_KIND", f"unknown graph kind {kind}")

    require(
        count_github_token_references(document) == declared_token_uses,
        "WORKFLOW_TOKEN",
        "workflow references github.token outside a declared run step environment",
    )

    expected_helpers = set(workflow_spec["helpers"])
    expected_references = expected_helpers | set(workflow_spec.get("data", []))
    require(
        referenced_helpers == expected_references,
        "WORKFLOW_HELPERS",
        f"local references {sorted(referenced_helpers)} != {sorted(expected_references)}",
    )
    return referenced_helpers & expected_helpers


def git_blob_sha(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def decode_base64_strict(value: str, label: str, allow_wrapping: bool) -> bytes:
    require(isinstance(value, str), "BASE64_VALUE", f"{label} is missing")
    if allow_wrapping:
        require(
            re.fullmatch(r"[A-Za-z0-9+/=\r\n]*", value) is not None,
            "BASE64_VALUE",
            f"{label} contains non-base64 characters",
        )
        value = value.replace("\r", "").replace("\n", "")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PolicyError("BASE64_VALUE", f"{label} is invalid") from error


def decode_github_blob(payload: Mapping[str, Any], expected_sha: str) -> bytes:
    require(payload.get("sha") == expected_sha, "BLOB_IDENTITY", "blob SHA changed")
    require(payload.get("encoding") == "base64", "BLOB_ENCODING", "blob is not base64")
    content = payload.get("content")
    require(isinstance(content, str), "BLOB_CONTENT", "blob content is missing")
    try:
        decoded = decode_base64_strict(content, "GitHub blob", allow_wrapping=True)
    except PolicyError as error:
        raise PolicyError("BLOB_ENCODING", error.message) from error
    require(payload.get("size") == len(decoded), "BLOB_SIZE", "blob size changed")
    require(git_blob_sha(decoded) == expected_sha, "BLOB_DIGEST", "blob digest changed")
    return decoded


def validate_approval_graph(graph: Mapping[str, Any]) -> None:
    require_exact_keys(
        graph,
        {
            "version",
            "repository",
            "bootstrap",
            "approved_actions",
            "workflows",
            "helpers",
            "locks",
        },
        "GRAPH_KEYS",
        "approval graph",
    )
    require(
        graph["version"] == 3 and type(graph["version"]) is int,
        "GRAPH_VERSION",
        "approval graph version must be 3",
    )
    repository = graph["repository"]
    require(isinstance(repository, dict), "GRAPH_REPOSITORY", "repository must map")
    require_exact_keys(
        repository,
        {
            "full_name",
            "id",
            "api_url",
            "html_url",
            "default_branch",
            "required_check",
            "required_workflow",
            "required_workflow_ref",
            "required_workflow_ruleset",
            "github_actions_integration_id",
            "dedicated_check",
        },
        "GRAPH_REPOSITORY",
        "repository",
    )
    require(
        REPOSITORY_RE.fullmatch(repository["full_name"]) is not None,
        "GRAPH_REPOSITORY",
        "repository name is invalid",
    )
    require(
        is_positive_id(repository["id"]),
        "GRAPH_REPOSITORY",
        "repository id is invalid",
    )
    require(repository["api_url"] == "https://api.github.com", "GRAPH_HOST", "API host")
    require(
        repository["html_url"] == f"https://github.com/{repository['full_name']}",
        "GRAPH_HOST",
        "HTML host",
    )
    require(
        repository["default_branch"] == "master",
        "GRAPH_BRANCH",
        "default branch must be master",
    )
    require(
        repository["required_check"] == "workflow-policy / verify",
        "GRAPH_CHECK",
        "required check changed",
    )
    require(
        repository["required_workflow"]
        == ".github/workflows/workflow-policy.yml",
        "GRAPH_CHECK",
        "required workflow changed",
    )
    require(
        repository["required_workflow_ref"] == "refs/heads/master",
        "GRAPH_CHECK",
        "required workflow ref changed",
    )
    ruleset_model = repository["required_workflow_ruleset"]
    require_exact_keys(
        ruleset_model,
        {"source_type", "target", "enforcement", "ref", "required_rule_types"},
        "GRAPH_RULESET",
        "required workflow ruleset",
    )
    require(
        ruleset_model["source_type"] == "Repository",
        "GRAPH_RULESET",
        "only a repository-sourced ruleset is modelled as authority",
    )
    require(
        ruleset_model["target"] == "branch",
        "GRAPH_RULESET",
        "ruleset target must be branch",
    )
    require(
        ruleset_model["enforcement"] == "active",
        "GRAPH_RULESET",
        "only an active ruleset is modelled as authority",
    )
    require(
        ruleset_model["ref"] == f"refs/heads/{repository['default_branch']}",
        "GRAPH_RULESET",
        "ruleset ref must be exactly the protected default branch",
    )
    require_exact_equal(
        ruleset_model["required_rule_types"],
        [
            "workflows",
            "pull_request",
            "required_status_checks",
            "non_fast_forward",
            "deletion",
        ],
        "GRAPH_RULESET",
        "required ruleset rule types changed",
    )
    require(
        repository["github_actions_integration_id"] == 15368,
        "GRAPH_CHECK",
        "GitHub Actions integration id changed",
    )
    dedicated_check = repository["dedicated_check"]
    require_exact_keys(
        dedicated_check,
        {"context", "integration_id"},
        "GRAPH_CHECK",
        "dedicated check",
    )
    require(
        dedicated_check["context"] == "workflow-policy / anchored-admission",
        "GRAPH_CHECK",
        "dedicated check context changed",
    )
    require(
        dedicated_check["integration_id"] is None
        or (
            is_positive_id(dedicated_check["integration_id"])
            and dedicated_check["integration_id"]
            != repository["github_actions_integration_id"]
        ),
        "GRAPH_CHECK",
        "dedicated check must use a unique non-Actions app identity",
    )
    bootstrap = graph["bootstrap"]
    require_exact_keys(
        bootstrap,
        {
            "base_policy_absent",
            "self_admission",
            "source_admission",
            "rules_activation",
        },
        "GRAPH_BOOTSTRAP",
        "bootstrap",
    )
    require(bootstrap["base_policy_absent"] is True, "GRAPH_BOOTSTRAP", "base marker")
    require(bootstrap["self_admission"] == "denied", "GRAPH_BOOTSTRAP", "self admission")
    require(
        bootstrap["source_admission"] == "required",
        "GRAPH_BOOTSTRAP",
        "source admission",
    )
    require(
        bootstrap["rules_activation"] == "required-after-landing",
        "GRAPH_BOOTSTRAP",
        "rules activation",
    )
    require_exact_equal(
        graph["approved_actions"], APPROVED_ACTIONS, "GRAPH_ACTIONS", "action pins"
    )
    require(isinstance(graph["workflows"], dict) and graph["workflows"], "GRAPH_WORKFLOWS", "")
    require(isinstance(graph["helpers"], dict) and graph["helpers"], "GRAPH_HELPERS", "")
    for path, spec in graph["workflows"].items():
        normalize_policy_path(path)
        require(path.endswith((".yml", ".yaml")), "GRAPH_WORKFLOW_PATH", path)
        require(isinstance(spec, dict), "GRAPH_WORKFLOW", path)
        require(SHA1_RE.fullmatch(spec["blob"]) is not None, "GRAPH_WORKFLOW_BLOB", path)
        require(
            spec.get("protected_branch") == repository["default_branch"],
            "GRAPH_WORKFLOW_BRANCH",
            f"{path} is not pinned to the protected default branch",
        )
        branches = spec.get("event_branches")
        require(isinstance(branches, dict), "GRAPH_WORKFLOW_BRANCH", path)
        require(
            set(branches) == set(spec["events"]),
            "GRAPH_WORKFLOW_BRANCH",
            f"{path} base branch allow-list does not cover every event",
        )
        for event, allowed in branches.items():
            require_exact_equal(
                allowed,
                [repository["default_branch"]],
                "GRAPH_WORKFLOW_BRANCH",
                f"{path} event {event} admits a non-protected base branch",
            )
    for path, spec in graph["helpers"].items():
        normalize_policy_path(path)
        require(isinstance(spec, dict), "GRAPH_HELPER", path)
        require_exact_keys(
            spec,
            {"blob", "mode", "interpreter", "capabilities", "dependencies", "consumers"},
            "GRAPH_HELPER",
            path,
        )
        require(SHA1_RE.fullmatch(spec["blob"]) is not None, "GRAPH_HELPER_BLOB", path)
        require(spec["mode"] in {"100644", "100755"}, "GRAPH_HELPER_MODE", path)
        require(
            isinstance(spec["capabilities"], list),
            "GRAPH_HELPER_CAPABILITY",
            path,
        )
        unknown = set(spec["capabilities"]) - CAPABILITY_VOCABULARY
        require(
            not unknown,
            "GRAPH_HELPER_CAPABILITY",
            f"{path} declares capabilities outside the vocabulary: {sorted(unknown)}",
        )
        require(
            len(set(spec["capabilities"])) == len(spec["capabilities"]),
            "GRAPH_HELPER_CAPABILITY",
            f"{path} repeats a capability",
        )
        for dependency in spec["dependencies"]:
            require(dependency in graph["helpers"], "GRAPH_HELPER_DEPENDENCY", dependency)
    locks = graph["locks"]
    require_exact_keys(
        locks,
        {"prefixes", "artifact", "release"},
        "GRAPH_LOCKS",
        "locks",
    )
    for prefix in locks["prefixes"]:
        normalize_policy_path(prefix.rstrip("/"))
        require(prefix.endswith("/"), "GRAPH_LOCK_PREFIX", prefix)
    for kind in ("artifact", "release"):
        require(isinstance(locks[kind], list), "GRAPH_LOCKS", kind)
        for path in locks[kind]:
            normalize_policy_path(path)
            require(
                any(path.startswith(prefix) for prefix in locks["prefixes"]),
                "GRAPH_LOCK_PATH",
                path,
            )


class GitHubApi(Protocol):
    trusted_now: dt.datetime

    def get(self, path: str) -> Mapping[str, Any]:
        ...

    def get_paginated(self, path: str) -> list[Mapping[str, Any]]:
        ...


def parse_github_time(value: Any, label: str) -> dt.datetime:
    require(isinstance(value, str), "TIME_VALUE", f"{label} is not a string")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PolicyError("TIME_VALUE", f"{label} is invalid") from error
    require(parsed.tzinfo is not None, "TIME_VALUE", f"{label} lacks timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_validity_window(
    validity: Mapping[str, Any], trusted_now: dt.datetime
) -> tuple[dt.datetime, dt.datetime]:
    require_exact_keys(
        validity, {"not_before", "not_after"}, "LOCK_VALIDITY", "validity"
    )
    not_before = parse_github_time(validity["not_before"], "not_before")
    not_after = parse_github_time(validity["not_after"], "not_after")
    require(not_before < not_after, "LOCK_VALIDITY", "window is reversed")
    require(not_before <= trusted_now < not_after, "LOCK_EXPIRED", "lock is not current")
    return not_before, not_after


def assert_bound_url(url: Any, expected: str, label: str) -> None:
    require(url == expected, "LOCK_URL", f"{label} is not {expected}")


def verify_trusted_topology(
    api: GitHubApi, repository: str, ancestor: str, protected_base: str
) -> None:
    require(SHA1_RE.fullmatch(ancestor) is not None, "LOCK_COMMIT", "ancestor SHA")
    require(
        SHA1_RE.fullmatch(protected_base) is not None,
        "LOCK_COMMIT",
        "protected base SHA",
    )
    comparison = api.get(
        f"/repos/{repository}/compare/{ancestor}...{protected_base}"
    )
    require(
        comparison.get("status") in {"ahead", "identical"},
        "LOCK_TOPOLOGY",
        "locked commit is not an ancestor of protected base",
    )
    merge_base = comparison.get("merge_base_commit")
    require(
        isinstance(merge_base, dict) and merge_base.get("sha") == ancestor,
        "LOCK_TOPOLOGY",
        "merge base does not equal locked commit",
    )


def verify_attestation(
    api: GitHubApi,
    repository: Mapping[str, Any],
    artifact_name: str,
    digest: str,
    workflow_ref: str,
    workflow_sha: str,
    workflow_path: str,
    event_name: str,
    run_id: int,
    run_attempt: int,
) -> None:
    payload = api.get(
        f"/repos/{repository['full_name']}/attestations/{digest}"
    )
    attestations = payload.get("attestations")
    require(isinstance(attestations, list) and attestations, "ATTESTATION_MISSING", digest)
    matched = False
    for attestation in attestations:
        bundle = attestation.get("bundle", {})
        envelope = bundle.get("dsseEnvelope", {})
        encoded = envelope.get("payload")
        if not isinstance(encoded, str):
            continue
        try:
            statement = parse_json_strict(
                decode_base64_strict(
                    encoded, "attestation payload", allow_wrapping=True
                ).decode("utf-8"),
                "attestation statement",
            )
        except (UnicodeDecodeError, PolicyError):
            continue
        subjects = statement.get("subject", [])
        subject_matches = any(
            subject.get("name") == artifact_name
            and subject.get("digest", {}).get("sha256") == digest.removeprefix("sha256:")
            for subject in subjects
            if isinstance(subject, dict)
        )
        predicate = statement.get("predicate", {})
        build = predicate.get("buildDefinition", {})
        external = build.get("externalParameters", {})
        workflow = external.get("workflow", {})
        internal = build.get("internalParameters", {})
        github_internal = internal.get("github", {})
        dependencies = build.get("resolvedDependencies", [])
        dependency_matches = any(
            dependency.get("uri")
            == f"git+https://github.com/{repository['full_name']}@{workflow_ref}"
            and dependency.get("digest", {}).get("gitCommit") == workflow_sha
            for dependency in dependencies
            if isinstance(dependency, dict)
        )
        invocation = predicate.get("runDetails", {}).get("metadata", {}).get("invocationId")
        builder = predicate.get("runDetails", {}).get("builder", {}).get("id")
        if (
            statement.get("_type") == "https://in-toto.io/Statement/v1"
            and statement.get("predicateType") == "https://slsa.dev/provenance/v1"
            and subject_matches
            and build.get("buildType")
            == "https://actions.github.io/buildtypes/workflow/v1"
            and workflow.get("repository") == repository["html_url"]
            and workflow.get("ref") == workflow_ref
            and workflow.get("path") == workflow_path
            and github_internal.get("repository_id") == str(repository["id"])
            and github_internal.get("event_name") == event_name
            and github_internal.get("runner_environment") == "github-hosted"
            and dependency_matches
            and isinstance(builder, str)
            and builder.startswith("https://github.com/")
            and invocation
            == f"https://github.com/{repository['full_name']}/actions/runs/{run_id}/attempts/{run_attempt}"
        ):
            matched = True
            break
    require(matched, "ATTESTATION_MISMATCH", f"no independent evidence for {digest}")


def verify_artifact_lock(
    lock: Mapping[str, Any],
    api: GitHubApi,
    protected_base_sha: str,
) -> None:
    require_exact_keys(
        lock,
        {"kind", "repository", "workflow", "run", "job", "artifact", "validity"},
        "ARTIFACT_LOCK_KEYS",
        "artifact lock",
    )
    require(lock["kind"] == "github-actions-artifact-v2", "ARTIFACT_LOCK_KIND", "")
    repository = lock["repository"]
    require_exact_keys(
        repository,
        {"full_name", "id", "api_url", "html_url"},
        "LOCK_REPOSITORY",
        "repository",
    )
    require(REPOSITORY_RE.fullmatch(repository["full_name"]) is not None, "LOCK_REPOSITORY", "")
    require(is_positive_id(repository["id"]), "LOCK_REPOSITORY", "")
    assert_bound_url(repository["api_url"], f"https://api.github.com/repos/{repository['full_name']}", "repository API URL")
    assert_bound_url(repository["html_url"], f"https://github.com/{repository['full_name']}", "repository HTML URL")
    live_repository = api.get(f"/repos/{repository['full_name']}")
    require(live_repository.get("id") == repository["id"], "LOCK_REPOSITORY", "id")
    require(live_repository.get("full_name") == repository["full_name"], "LOCK_REPOSITORY", "name")
    require(
        live_repository.get("url") == repository["api_url"]
        and live_repository.get("html_url") == repository["html_url"],
        "LOCK_REPOSITORY",
        "live host binding",
    )

    workflow = lock["workflow"]
    require_exact_keys(
        workflow, {"id", "path", "ref", "sha"}, "ARTIFACT_WORKFLOW", "workflow"
    )
    require(is_positive_id(workflow["id"]), "ARTIFACT_WORKFLOW", "id")
    normalize_policy_path(workflow["path"])
    require(workflow["ref"].startswith("refs/heads/"), "ARTIFACT_WORKFLOW", "ref")
    require(SHA1_RE.fullmatch(workflow["sha"]) is not None, "ARTIFACT_WORKFLOW", "sha")

    run_lock = lock["run"]
    require_exact_keys(
        run_lock,
        {
            "id",
            "attempt",
            "event",
            "head_sha",
            "head_tree",
            "created_at",
            "updated_at",
            "api_url",
        },
        "ARTIFACT_RUN",
        "run",
    )
    require(is_positive_id(run_lock["id"]), "ARTIFACT_RUN", "id")
    require(
        is_positive_id(run_lock["attempt"]),
        "ARTIFACT_RUN",
        "attempt",
    )
    require(SHA1_RE.fullmatch(run_lock["head_sha"]) is not None, "ARTIFACT_RUN", "head")
    require(SHA1_RE.fullmatch(run_lock["head_tree"]) is not None, "ARTIFACT_RUN", "tree")
    run_path = (
        f"/repos/{repository['full_name']}/actions/runs/{run_lock['id']}"
        f"/attempts/{run_lock['attempt']}"
    )
    run = api.get(run_path)
    assert_bound_url(
        run_lock["api_url"],
        f"https://api.github.com/repos/{repository['full_name']}/actions/runs/{run_lock['id']}",
        "run API URL",
    )
    expected_run_fields = {
        "id": run_lock["id"],
        "run_attempt": run_lock["attempt"],
        "event": run_lock["event"],
        "head_sha": run_lock["head_sha"],
        "workflow_id": workflow["id"],
        "path": workflow["path"],
        "status": "completed",
        "conclusion": "success",
        "created_at": run_lock["created_at"],
        "updated_at": run_lock["updated_at"],
    }
    for key, expected in expected_run_fields.items():
        require(run.get(key) == expected, "ARTIFACT_RUN", f"{key} changed")
    require(run.get("url") == run_lock["api_url"], "ARTIFACT_RUN", "API URL")
    require(run.get("repository", {}).get("id") == repository["id"], "ARTIFACT_RUN", "repository")
    require(run.get("head_repository", {}).get("id") == repository["id"], "ARTIFACT_RUN", "head repository")
    require(run.get("head_branch") == workflow["ref"].removeprefix("refs/heads/"), "ARTIFACT_RUN", "branch")
    created = parse_github_time(run_lock["created_at"], "run created_at")
    updated = parse_github_time(run_lock["updated_at"], "run updated_at")
    require(created <= updated <= api.trusted_now, "ARTIFACT_RUN_TIME", "run times")

    commit = api.get(
        f"/repos/{repository['full_name']}/git/commits/{run_lock['head_sha']}"
    )
    require(commit.get("tree", {}).get("sha") == run_lock["head_tree"], "ARTIFACT_TREE", "tree")
    verify_trusted_topology(
        api, repository["full_name"], run_lock["head_sha"], protected_base_sha
    )
    require(workflow["sha"] == run_lock["head_sha"], "ARTIFACT_WORKFLOW", "workflow SHA")

    job_lock = lock["job"]
    require_exact_keys(
        job_lock, {"id", "name", "run_attempt", "api_url"}, "ARTIFACT_JOB", "job"
    )
    require(is_positive_id(job_lock["id"]), "ARTIFACT_JOB", "id")
    require(job_lock["run_attempt"] == run_lock["attempt"], "ARTIFACT_JOB", "attempt")
    jobs = api.get_paginated(
        f"/repos/{repository['full_name']}/actions/runs/{run_lock['id']}"
        f"/attempts/{run_lock['attempt']}/jobs"
    )
    matches = [job for job in jobs if job.get("id") == job_lock["id"]]
    require(len(matches) == 1, "ARTIFACT_JOB", "job id is not unique")
    job = matches[0]
    require(job.get("name") == job_lock["name"], "ARTIFACT_JOB", "name")
    require(job.get("run_attempt") == run_lock["attempt"], "ARTIFACT_JOB", "run attempt")
    require(job.get("head_sha") == run_lock["head_sha"], "ARTIFACT_JOB", "head SHA")
    require(job.get("status") == "completed" and job.get("conclusion") == "success", "ARTIFACT_JOB", "result")
    assert_bound_url(
        job_lock["api_url"],
        f"https://api.github.com/repos/{repository['full_name']}/actions/jobs/{job_lock['id']}",
        "job API URL",
    )
    require(job.get("url") == job_lock["api_url"], "ARTIFACT_JOB", "API URL")

    artifact_lock = lock["artifact"]
    require_exact_keys(
        artifact_lock,
        {
            "id",
            "name",
            "digest",
            "size",
            "api_url",
            "archive_download_url",
            "created_at",
            "expires_at",
        },
        "ARTIFACT_FIELDS",
        "artifact",
    )
    require(is_positive_id(artifact_lock["id"]), "ARTIFACT_ID", "")
    require(SHA256_RE.fullmatch(artifact_lock["digest"]) is not None, "ARTIFACT_DIGEST", "")
    require(is_nonnegative_size(artifact_lock["size"]), "ARTIFACT_SIZE", "")
    artifact = api.get(
        f"/repos/{repository['full_name']}/actions/artifacts/{artifact_lock['id']}"
    )
    expected_artifact_fields = {
        "id": artifact_lock["id"],
        "name": artifact_lock["name"],
        "digest": artifact_lock["digest"],
        "size_in_bytes": artifact_lock["size"],
        "url": artifact_lock["api_url"],
        "archive_download_url": artifact_lock["archive_download_url"],
        "created_at": artifact_lock["created_at"],
        "expires_at": artifact_lock["expires_at"],
        "expired": False,
    }
    for key, expected in expected_artifact_fields.items():
        require(artifact.get(key) == expected, "ARTIFACT_FIELDS", f"{key} changed")
    require(artifact.get("workflow_run", {}).get("id") == run_lock["id"], "ARTIFACT_RUN_BINDING", "run")
    require(artifact.get("workflow_run", {}).get("head_sha") == run_lock["head_sha"], "ARTIFACT_RUN_BINDING", "head")
    require(artifact.get("workflow_run", {}).get("repository_id") == repository["id"], "ARTIFACT_RUN_BINDING", "repository")
    assert_bound_url(
        artifact_lock["api_url"],
        f"https://api.github.com/repos/{repository['full_name']}/actions/artifacts/{artifact_lock['id']}",
        "artifact API URL",
    )
    assert_bound_url(
        artifact_lock["archive_download_url"],
        f"https://api.github.com/repos/{repository['full_name']}/actions/artifacts/{artifact_lock['id']}/zip",
        "artifact archive URL",
    )
    artifact_created = parse_github_time(artifact_lock["created_at"], "artifact created_at")
    artifact_expires = parse_github_time(artifact_lock["expires_at"], "artifact expires_at")
    require(created <= artifact_created <= updated, "ARTIFACT_TIME", "artifact creation")
    require(api.trusted_now < artifact_expires, "ARTIFACT_EXPIRED", "artifact expired")
    validate_validity_window(lock["validity"], api.trusted_now)
    verify_attestation(
        api,
        repository,
        artifact_lock["name"],
        artifact_lock["digest"],
        workflow["ref"],
        workflow["sha"],
        workflow["path"],
        run_lock["event"],
        run_lock["id"],
        run_lock["attempt"],
    )


def verify_release_lock(
    lock: Mapping[str, Any],
    api: GitHubApi,
    protected_base_sha: str,
) -> None:
    require_exact_keys(
        lock,
        {
            "kind",
            "repository",
            "tag",
            "provenance",
            "release",
            "assets",
            "validity",
        },
        "RELEASE_LOCK_KEYS",
        "release lock",
    )
    require(lock["kind"] == "github-release-v2", "RELEASE_LOCK_KIND", "")
    repository = lock["repository"]
    require_exact_keys(
        repository,
        {"full_name", "id", "api_url", "html_url"},
        "LOCK_REPOSITORY",
        "repository",
    )
    require(
        REPOSITORY_RE.fullmatch(repository["full_name"]) is not None,
        "LOCK_REPOSITORY",
        "repository name",
    )
    require(
        is_positive_id(repository["id"]),
        "LOCK_REPOSITORY",
        "repository id",
    )
    live_repository = api.get(f"/repos/{repository['full_name']}")
    require(live_repository.get("id") == repository["id"], "LOCK_REPOSITORY", "id")
    require(live_repository.get("full_name") == repository["full_name"], "LOCK_REPOSITORY", "name")
    assert_bound_url(repository["api_url"], f"https://api.github.com/repos/{repository['full_name']}", "repository API URL")
    assert_bound_url(repository["html_url"], f"https://github.com/{repository['full_name']}", "repository HTML URL")
    require(
        live_repository.get("url") == repository["api_url"]
        and live_repository.get("html_url") == repository["html_url"],
        "LOCK_REPOSITORY",
        "live host binding",
    )

    tag_lock = lock["tag"]
    require_exact_keys(
        tag_lock,
        {
            "name",
            "object_id",
            "object_api_url",
            "tagger_date",
            "peeled_commit",
            "peeled_tree",
        },
        "RELEASE_TAG",
        "tag",
    )
    require(SHA1_RE.fullmatch(tag_lock["object_id"]) is not None, "RELEASE_TAG", "object")
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag_lock["name"])
        is not None,
        "RELEASE_TAG",
        "tag name",
    )
    require(SHA1_RE.fullmatch(tag_lock["peeled_commit"]) is not None, "RELEASE_TAG", "commit")
    require(SHA1_RE.fullmatch(tag_lock["peeled_tree"]) is not None, "RELEASE_TAG", "tree")
    tag_ref = api.get(
        f"/repos/{repository['full_name']}/git/ref/tags/{tag_lock['name']}"
    )
    require(tag_ref.get("object", {}).get("type") == "tag", "RELEASE_TAG_LIGHTWEIGHT", "tag must be annotated")
    require(tag_ref.get("object", {}).get("sha") == tag_lock["object_id"], "RELEASE_TAG", "ref moved")
    tag_object = api.get(
        f"/repos/{repository['full_name']}/git/tags/{tag_lock['object_id']}"
    )
    require(tag_object.get("tag") == tag_lock["name"], "RELEASE_TAG", "name")
    require(tag_object.get("sha") == tag_lock["object_id"], "RELEASE_TAG", "object id")
    require(tag_object.get("object", {}).get("type") == "commit", "RELEASE_TAG", "peeled type")
    require(tag_object.get("object", {}).get("sha") == tag_lock["peeled_commit"], "RELEASE_TAG", "peeled commit")
    require(tag_object.get("tagger", {}).get("date") == tag_lock["tagger_date"], "RELEASE_TAG", "tagger date")
    assert_bound_url(
        tag_lock["object_api_url"],
        f"https://api.github.com/repos/{repository['full_name']}/git/tags/{tag_lock['object_id']}",
        "tag API URL",
    )
    require(tag_object.get("url") == tag_lock["object_api_url"], "RELEASE_TAG", "API URL")
    tag_time = parse_github_time(tag_lock["tagger_date"], "tagger date")
    require(tag_time <= api.trusted_now, "RELEASE_TAG_TIME", "tag is from the future")
    commit = api.get(
        f"/repos/{repository['full_name']}/git/commits/{tag_lock['peeled_commit']}"
    )
    require(commit.get("tree", {}).get("sha") == tag_lock["peeled_tree"], "RELEASE_TREE", "tree")
    verify_trusted_topology(
        api, repository["full_name"], tag_lock["peeled_commit"], protected_base_sha
    )

    provenance = lock["provenance"]
    require_exact_keys(
        provenance,
        {"workflow", "run", "job"},
        "RELEASE_PROVENANCE",
        "provenance",
    )
    workflow = provenance["workflow"]
    require_exact_keys(
        workflow,
        {"id", "path", "ref", "sha"},
        "RELEASE_PROVENANCE_WORKFLOW",
        "workflow",
    )
    require(
        is_positive_id(workflow["id"]),
        "RELEASE_PROVENANCE_WORKFLOW",
        "workflow id",
    )
    normalize_policy_path(workflow["path"])
    require(
        workflow["ref"] == f"refs/tags/{tag_lock['name']}"
        and workflow["sha"] == tag_lock["peeled_commit"],
        "RELEASE_PROVENANCE_WORKFLOW",
        "workflow ref or SHA does not match the annotated tag",
    )
    run_lock = provenance["run"]
    require_exact_keys(
        run_lock,
        {
            "id",
            "attempt",
            "event",
            "head_sha",
            "head_tree",
            "created_at",
            "updated_at",
            "api_url",
        },
        "RELEASE_PROVENANCE_RUN",
        "run",
    )
    require(
        is_positive_id(run_lock["id"]),
        "RELEASE_PROVENANCE_RUN",
        "run id",
    )
    require(
        is_positive_id(run_lock["attempt"]),
        "RELEASE_PROVENANCE_RUN",
        "run attempt",
    )
    require(run_lock["event"] == "push", "RELEASE_PROVENANCE_RUN", "event")
    require(
        run_lock["head_sha"] == tag_lock["peeled_commit"]
        and run_lock["head_tree"] == tag_lock["peeled_tree"],
        "RELEASE_PROVENANCE_RUN",
        "head commit or tree",
    )
    run = api.get(
        f"/repos/{repository['full_name']}/actions/runs/{run_lock['id']}"
        f"/attempts/{run_lock['attempt']}"
    )
    expected_run = {
        "id": run_lock["id"],
        "run_attempt": run_lock["attempt"],
        "event": run_lock["event"],
        "head_sha": run_lock["head_sha"],
        "workflow_id": workflow["id"],
        "path": workflow["path"],
        "status": "completed",
        "conclusion": "success",
        "created_at": run_lock["created_at"],
        "updated_at": run_lock["updated_at"],
    }
    for key, expected in expected_run.items():
        require(
            run.get(key) == expected,
            "RELEASE_PROVENANCE_RUN",
            f"{key} changed",
        )
    require(
        run.get("repository", {}).get("id") == repository["id"]
        and run.get("head_repository", {}).get("id") == repository["id"],
        "RELEASE_PROVENANCE_RUN",
        "repository",
    )
    assert_bound_url(
        run_lock["api_url"],
        f"https://api.github.com/repos/{repository['full_name']}/actions/runs/{run_lock['id']}",
        "release producer run API URL",
    )
    require(
        run.get("url") == run_lock["api_url"],
        "RELEASE_PROVENANCE_RUN",
        "run API URL",
    )
    run_created = parse_github_time(run_lock["created_at"], "producer run created_at")
    run_updated = parse_github_time(run_lock["updated_at"], "producer run updated_at")
    require(
        tag_time <= run_created <= run_updated <= api.trusted_now,
        "RELEASE_PROVENANCE_TIME",
        "producer run times",
    )

    job_lock = provenance["job"]
    require_exact_keys(
        job_lock,
        {"id", "name", "run_attempt", "api_url"},
        "RELEASE_PROVENANCE_JOB",
        "job",
    )
    require(
        is_positive_id(job_lock["id"]),
        "RELEASE_PROVENANCE_JOB",
        "job id",
    )
    require(
        job_lock["run_attempt"] == run_lock["attempt"],
        "RELEASE_PROVENANCE_JOB",
        "run attempt",
    )
    jobs = api.get_paginated(
        f"/repos/{repository['full_name']}/actions/runs/{run_lock['id']}"
        f"/attempts/{run_lock['attempt']}/jobs"
    )
    matching_jobs = [job for job in jobs if job.get("id") == job_lock["id"]]
    require(
        len(matching_jobs) == 1,
        "RELEASE_PROVENANCE_JOB",
        "job id is not unique",
    )
    job = matching_jobs[0]
    require(
        job.get("name") == job_lock["name"]
        and job.get("run_attempt") == run_lock["attempt"]
        and job.get("head_sha") == run_lock["head_sha"]
        and job.get("status") == "completed"
        and job.get("conclusion") == "success",
        "RELEASE_PROVENANCE_JOB",
        "job identity or result",
    )
    assert_bound_url(
        job_lock["api_url"],
        f"https://api.github.com/repos/{repository['full_name']}/actions/jobs/{job_lock['id']}",
        "release producer job API URL",
    )
    require(
        job.get("url") == job_lock["api_url"],
        "RELEASE_PROVENANCE_JOB",
        "job API URL",
    )

    release_lock = lock["release"]
    require_exact_keys(
        release_lock,
        {
            "id",
            "tag_name",
            "name",
            "api_url",
            "html_url",
            "published_at",
        },
        "RELEASE_FIELDS",
        "release",
    )
    require(is_positive_id(release_lock["id"]), "RELEASE_ID", "")
    release = api.get(
        f"/repos/{repository['full_name']}/releases/{release_lock['id']}"
    )
    expected_release = {
        "id": release_lock["id"],
        "tag_name": release_lock["tag_name"],
        "name": release_lock["name"],
        "url": release_lock["api_url"],
        "html_url": release_lock["html_url"],
        "published_at": release_lock["published_at"],
        "draft": False,
        "prerelease": False,
    }
    for key, expected in expected_release.items():
        require(release.get(key) == expected, "RELEASE_FIELDS", f"{key} changed")
    require(release_lock["tag_name"] == tag_lock["name"], "RELEASE_TAG_BINDING", "")
    assert_bound_url(
        release_lock["api_url"],
        f"https://api.github.com/repos/{repository['full_name']}/releases/{release_lock['id']}",
        "release API URL",
    )
    assert_bound_url(
        release_lock["html_url"],
        f"https://github.com/{repository['full_name']}/releases/tag/{tag_lock['name']}",
        "release HTML URL",
    )
    published = parse_github_time(release_lock["published_at"], "release published_at")
    require(
        run_updated <= published <= api.trusted_now,
        "RELEASE_TIME",
        "publish time",
    )
    validate_validity_window(lock["validity"], api.trusted_now)

    locked_assets = lock["assets"]
    require(isinstance(locked_assets, list) and locked_assets, "RELEASE_ASSETS", "assets")
    live_assets = api.get_paginated(
        f"/repos/{repository['full_name']}/releases/{release_lock['id']}/assets"
    )
    require(len(live_assets) == len(locked_assets), "RELEASE_ASSET_MANIFEST", "asset count")
    live_by_id = {asset.get("id"): asset for asset in live_assets}
    require(len(live_by_id) == len(live_assets), "RELEASE_ASSET_MANIFEST", "duplicate ids")
    locked_ids: set[int] = set()
    for asset_lock in locked_assets:
        require_exact_keys(
            asset_lock,
            {
                "id",
                "name",
                "size",
                "digest",
                "content_type",
                "api_url",
                "browser_download_url",
                "created_at",
                "updated_at",
            },
            "RELEASE_ASSET_FIELDS",
            "asset",
        )
        asset_id = asset_lock["id"]
        require(is_positive_id(asset_id), "RELEASE_ASSET_ID", "")
        require(asset_id not in locked_ids, "RELEASE_ASSET_MANIFEST", "duplicate lock id")
        locked_ids.add(asset_id)
        require(SHA256_RE.fullmatch(asset_lock["digest"]) is not None, "RELEASE_ASSET_DIGEST", "")
        require(
            re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", asset_lock["name"]
            )
            is not None,
            "RELEASE_ASSET_NAME",
            "asset name",
        )
        require(is_nonnegative_size(asset_lock["size"]), "RELEASE_ASSET_SIZE", "")
        asset = live_by_id.get(asset_id)
        require(asset is not None, "RELEASE_ASSET_MANIFEST", f"missing {asset_id}")
        expected_asset = {
            "id": asset_id,
            "name": asset_lock["name"],
            "size": asset_lock["size"],
            "digest": asset_lock["digest"],
            "content_type": asset_lock["content_type"],
            "url": asset_lock["api_url"],
            "browser_download_url": asset_lock["browser_download_url"],
            "created_at": asset_lock["created_at"],
            "updated_at": asset_lock["updated_at"],
            "state": "uploaded",
        }
        for key, expected in expected_asset.items():
            require(asset.get(key) == expected, "RELEASE_ASSET_FIELDS", f"{key} changed")
        assert_bound_url(
            asset_lock["api_url"],
            f"https://api.github.com/repos/{repository['full_name']}/releases/assets/{asset_id}",
            "asset API URL",
        )
        assert_bound_url(
            asset_lock["browser_download_url"],
            f"https://github.com/{repository['full_name']}/releases/download/{tag_lock['name']}/{asset_lock['name']}",
            "asset download URL",
        )
        asset_created = parse_github_time(asset_lock["created_at"], "asset created_at")
        asset_updated = parse_github_time(asset_lock["updated_at"], "asset updated_at")
        require(published <= asset_created <= asset_updated <= api.trusted_now, "RELEASE_ASSET_TIME", asset_lock["name"])
        verify_attestation(
            api,
            repository,
            asset_lock["name"],
            asset_lock["digest"],
            workflow["ref"],
            workflow["sha"],
            workflow["path"],
            run_lock["event"],
            run_lock["id"],
            run_lock["attempt"],
        )
