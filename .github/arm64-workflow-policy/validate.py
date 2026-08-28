#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
POLICY_PATH = SCRIPT_DIR / "policy.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ACTION_RE = re.compile(
    r"^(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?)@"
    r"(?P<ref>[^@\s]+)$"
)
KEY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_-]+):(?:\s*(?P<value>.*))?$")
LIST_KEY_RE = re.compile(
    r"^-\s+(?P<key>[A-Za-z0-9_-]+):(?:\s*(?P<value>.*))?$"
)
SHARED_ROOT_RE = re.compile(r"(?i)(?:c:[\\/]+|/c/)msys64(?![A-Za-z0-9_-])")
PACKAGE_TRANSACTION_RE = re.compile(
    r"(?i)(?:\bpacman\b|\bpacboy\b|\bmakepkg(?:-mingw)?\b|[./\\]ci-build\.sh\b)"
)
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
HEAD_VERIFY_RE = re.compile(
    r'^(?:python3?|py(?: -3)?) '
    r'\.github/arm64-workflow-policy/verify_head\.py '
    r'(?:"?\$env:EXPECTED_HEAD"?|"?\$EXPECTED_HEAD"?)$'
)
EVIDENCE_VERIFY_RE = re.compile(
    r'^(?:python3?|py(?: -3)?) '
    r'\.github/arm64-workflow-policy/validate\.py evidence '
    r'(?:"?\$env:ARM64_CONSUMER_LOCK"?|"?\$ARM64_CONSUMER_LOCK"?)$'
)
BASIC_BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?$")
EXPLICIT_BLOCK_SCALAR_RE = re.compile(r"^[|>](?:[1-9][+-]?|[+-][1-9])$")


@dataclass(order=True, frozen=True)
class Violation:
    path: str
    line: int
    code: str
    message: str

    def render(self) -> str:
        location = self.path if self.line == 0 else f"{self.path}:{self.line}"
        return f"{location}: {self.code}: {self.message}"


@dataclass(frozen=True)
class SourceLine:
    number: int
    raw: str
    indent: int
    content: str


@dataclass
class Step:
    line: int
    job: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    field_lines: dict[str, int] = field(default_factory=dict)
    with_values: dict[str, str] = field(default_factory=dict)
    with_lines: dict[str, int] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    env_lines: dict[str, int] = field(default_factory=dict)
    run: str = ""

    @property
    def uses(self) -> str:
        return unquote(self.fields.get("uses", ""))


@dataclass
class Workflow:
    path: Path
    display_path: str
    text: str
    lines: list[SourceLine]
    steps: list[Step]
    triggers: set[str]
    job_conditions: dict[str, str]
    scalar_lines: set[int]
    parse_violations: list[Violation]


@dataclass
class Evidence:
    data: dict[str, Any] | None
    violations: list[Violation]


def strip_comment(value: str) -> str:
    single = False
    double = False
    for index, character in enumerate(value):
        if character == "'" and not double:
            single = not single
        elif character == '"' and not single:
            double = not double
        elif character == "#" and not single and not double:
            if index == 0 or value[index - 1].isspace():
                return value[:index].rstrip()
    return value.rstrip()


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def compact(value: str) -> str:
    return re.sub(r"\s+", "", unquote(value)).lower()


def display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def add_unique(
    target: dict[str, str],
    line_map: dict[str, int],
    key: str,
    value: str,
    line: int,
    path: str,
    violations: list[Violation],
) -> None:
    if key in target:
        violations.append(
            Violation(path, line, "DUPLICATE_KEY", f"duplicate '{key}' key")
        )
        return
    target[key] = unquote(value)
    line_map[key] = line


def block_scalar_lines(lines: list[SourceLine]) -> set[int]:
    result: set[int] = set()
    for index, line in enumerate(lines):
        match = LIST_KEY_RE.match(line.content) or KEY_RE.match(line.content)
        if not match or not BASIC_BLOCK_SCALAR_RE.fullmatch(
            match.group("value") or ""
        ):
            continue
        cursor = index + 1
        while cursor < len(lines):
            candidate = lines[cursor]
            if candidate.content and candidate.indent <= line.indent:
                break
            result.add(candidate.number)
            cursor += 1
    return result


def step_jobs(lines: list[SourceLine]) -> dict[int, str]:
    result: dict[int, str] = {}
    in_jobs = False
    current_job = ""
    steps_indent: int | None = None
    for index, line in enumerate(lines):
        if line.content and line.indent == 0:
            in_jobs = line.content == "jobs:"
            current_job = ""
            steps_indent = None
            continue
        if not in_jobs or not line.content:
            continue
        if line.indent == 2:
            match = KEY_RE.match(line.content)
            current_job = match.group("key") if match else ""
            steps_indent = None
            continue
        if current_job and line.indent == 4:
            if line.content == "steps:":
                steps_indent = line.indent
            elif steps_indent is not None:
                steps_indent = None
        if current_job and steps_indent is not None and line.indent > steps_indent:
            result[index] = current_job
    return result


def validate_job_structure(
    lines: list[SourceLine], scalar_lines: set[int], path: str
) -> list[Violation]:
    violations: list[Violation] = []
    jobs_headers = [
        index
        for index, line in enumerate(lines)
        if line.indent == 0 and line.content == "jobs:"
    ]
    if len(jobs_headers) != 1:
        return [
            Violation(
                path,
                0,
                "JOB_STRUCTURE",
                "workflow must have one canonical jobs map",
            )
        ]

    start = jobs_headers[0] + 1
    end = start
    while end < len(lines):
        if lines[end].content and lines[end].indent == 0:
            break
        end += 1

    job_starts: list[tuple[int, str]] = []
    seen_jobs: set[str] = set()
    for index in range(start, end):
        line = lines[index]
        if not line.content or line.number in scalar_lines:
            continue
        if line.indent == 2:
            match = KEY_RE.match(line.content)
            if not match:
                violations.append(
                    Violation(
                        path,
                        line.number,
                        "JOB_STRUCTURE",
                        "job entries must use an unquoted block key at indent 2",
                    )
                )
                continue
            job = match.group("key")
            if job in seen_jobs:
                violations.append(
                    Violation(
                        path,
                        line.number,
                        "DUPLICATE_KEY",
                        f"duplicate job '{job}'",
                    )
                )
            seen_jobs.add(job)
            job_starts.append((index, job))
        elif not job_starts:
            violations.append(
                Violation(
                    path,
                    line.number,
                    "JOB_STRUCTURE",
                    "the first jobs child must be a job key at indent 2",
                )
            )
            break

    if not job_starts:
        violations.append(
            Violation(path, 0, "JOB_STRUCTURE", "jobs map must contain a job")
        )
        return violations

    for position, (job_start, job) in enumerate(job_starts):
        job_end = job_starts[position + 1][0] if position + 1 < len(job_starts) else end
        steps_headers = [
            index
            for index in range(job_start + 1, job_end)
            if lines[index].indent == 4 and lines[index].content == "steps:"
        ]
        if len(steps_headers) != 1:
            violations.append(
                Violation(
                    path,
                    lines[job_start].number,
                    "JOB_STRUCTURE",
                    f"job '{job}' must have one steps key at indent 4",
                )
            )
            continue

        steps_header = steps_headers[0]
        saw_step = False
        for index in range(steps_header + 1, job_end):
            line = lines[index]
            if not line.content or line.number in scalar_lines:
                continue
            if line.content.startswith("-") and line.indent < 6:
                violations.append(
                    Violation(
                        path,
                        line.number,
                        "JOB_STRUCTURE",
                        f"job '{job}' step entries must start at indent 6",
                    )
                )
                break
            if line.indent <= 4:
                break
            if line.indent == 6:
                if not LIST_KEY_RE.match(line.content):
                    violations.append(
                        Violation(
                            path,
                            line.number,
                            "JOB_STRUCTURE",
                            f"job '{job}' steps must use '- key: value' block syntax",
                        )
                    )
                saw_step = True
        if not saw_step:
            violations.append(
                Violation(
                    path,
                    lines[steps_header].number,
                    "JOB_STRUCTURE",
                    f"job '{job}' has no canonical step entries",
                )
            )
    return violations


def parse_job_conditions(
    lines: list[SourceLine], path: str, violations: list[Violation]
) -> dict[str, str]:
    result: dict[str, str] = {}
    in_jobs = False
    current_job = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.content and line.indent == 0:
            in_jobs = line.content == "jobs:"
            current_job = ""
            index += 1
            continue
        if not in_jobs:
            index += 1
            continue
        if line.content and line.indent == 2:
            match = KEY_RE.match(line.content)
            current_job = match.group("key") if match else ""
            index += 1
            continue
        if current_job and line.indent == 4:
            match = KEY_RE.match(line.content)
            if match and match.group("key") == "if":
                if current_job in result:
                    violations.append(
                        Violation(
                            path,
                            line.number,
                            "DUPLICATE_KEY",
                            f"job '{current_job}' has duplicate if keys",
                        )
                    )
                value = match.group("value") or ""
                if BASIC_BLOCK_SCALAR_RE.fullmatch(value):
                    block: list[str] = []
                    cursor = index + 1
                    while cursor < len(lines):
                        candidate = lines[cursor]
                        if candidate.content and candidate.indent <= line.indent:
                            break
                        if candidate.content:
                            block.append(candidate.content)
                        cursor += 1
                    result[current_job] = " ".join(block)
                    index = cursor
                    continue
                result[current_job] = unquote(value)
        index += 1
    return result


def parse_steps(
    lines: list[SourceLine], path: str, violations: list[Violation]
) -> list[Step]:
    steps: list[Step] = []
    jobs = step_jobs(lines)
    index = 0
    while index < len(lines):
        line = lines[index]
        match = LIST_KEY_RE.match(line.content)
        if not match or index not in jobs:
            index += 1
            continue

        sequence_indent = line.indent
        direct_indent = sequence_indent + 2
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.content and candidate.indent <= sequence_indent:
                break
            end += 1

        step = Step(line=line.number, job=jobs[index])
        first_key = match.group("key")
        first_value = match.group("value") or ""
        add_unique(
            step.fields,
            step.field_lines,
            first_key,
            first_value,
            line.number,
            path,
            violations,
        )

        section = ""
        cursor = index + 1
        if first_key == "run":
            if BASIC_BLOCK_SCALAR_RE.fullmatch(first_value):
                block: list[str] = []
                block_cursor = cursor
                while (
                    block_cursor < end
                    and (
                        not lines[block_cursor].content
                        or lines[block_cursor].indent > direct_indent
                    )
                ):
                    block.append(lines[block_cursor].raw.strip())
                    block_cursor += 1
                step.run = "\n".join(block)
                cursor = block_cursor
            else:
                step.run = unquote(first_value)
        while cursor < end:
            current = lines[cursor]
            if not current.content:
                cursor += 1
                continue

            if current.indent == direct_indent:
                key_match = KEY_RE.match(current.content)
                if not key_match:
                    violations.append(
                        Violation(
                            path,
                            current.number,
                            "UNSUPPORTED_YAML",
                            "step entries must use block key/value syntax",
                        )
                    )
                    cursor += 1
                    continue
                key = key_match.group("key")
                value = key_match.group("value") or ""
                section = key if key in ("with", "env") and not value else ""
                add_unique(
                    step.fields,
                    step.field_lines,
                    key,
                    value,
                    current.number,
                    path,
                    violations,
                )
                if key == "run":
                    if BASIC_BLOCK_SCALAR_RE.fullmatch(value):
                        block: list[str] = []
                        block_cursor = cursor + 1
                        while (
                            block_cursor < end
                            and (
                                not lines[block_cursor].content
                                or lines[block_cursor].indent > direct_indent
                            )
                        ):
                            block.append(lines[block_cursor].raw.strip())
                            block_cursor += 1
                        step.run = "\n".join(block)
                        cursor = block_cursor
                        continue
                    step.run = unquote(value)
            elif current.indent > direct_indent and section in ("with", "env"):
                key_match = KEY_RE.match(current.content)
                if key_match:
                    key = key_match.group("key")
                    value = key_match.group("value") or ""
                    if section == "with":
                        add_unique(
                            step.with_values,
                            step.with_lines,
                            key,
                            value,
                            current.number,
                            path,
                            violations,
                        )
                    else:
                        add_unique(
                            step.env,
                            step.env_lines,
                            key,
                            value,
                            current.number,
                            path,
                            violations,
                        )
            cursor += 1

        if "uses" in step.fields or "run" in step.fields:
            steps.append(step)
        index = end
    return steps


def parse_triggers(
    lines: list[SourceLine], path: str, violations: list[Violation]
) -> set[str]:
    on_lines = [
        line
        for line in lines
        if line.indent == 0 and re.match(r"^on:(?:\s|$)", line.content)
    ]
    if len(on_lines) != 1:
        violations.append(
            Violation(path, 0, "TRIGGER_MAP", "workflow must have one block-style on map")
        )
        return set()

    on_line = on_lines[0]
    inline = on_line.content[3:].strip()
    if inline:
        values = inline.strip("[]").split(",")
        return {unquote(value.strip()) for value in values if value.strip()}

    index = lines.index(on_line) + 1
    child_indent: int | None = None
    triggers: set[str] = set()
    while index < len(lines):
        line = lines[index]
        if line.content and line.indent == 0:
            break
        if line.content:
            if child_indent is None:
                child_indent = line.indent
            if line.indent == child_indent:
                match = KEY_RE.match(line.content)
                if match:
                    trigger = match.group("key")
                    if trigger in triggers:
                        violations.append(
                            Violation(
                                path,
                                line.number,
                                "DUPLICATE_KEY",
                                f"duplicate '{trigger}' trigger",
                            )
                        )
                    triggers.add(trigger)
        index += 1
    return triggers


def load_workflow(path: Path, root: Path) -> Workflow:
    relative = display_path(path, root)
    violations: list[Violation] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return Workflow(
            path,
            relative,
            "",
            [],
            [],
            set(),
            {},
            set(),
            [Violation(relative, 0, "WORKFLOW_READ", str(error))],
        )

    source_lines: list[SourceLine] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            violations.append(
                Violation(relative, number, "TAB_INDENT", "tabs are not valid indentation")
            )
        content = strip_comment(raw.lstrip(" "))
        source_lines.append(
            SourceLine(number, raw, len(raw) - len(raw.lstrip(" ")), content)
        )
        if content in ("---", "...") or content.startswith("<<:"):
            violations.append(
                Violation(
                    relative,
                    number,
                    "UNSUPPORTED_YAML",
                    "multi-document and merge-key YAML is not accepted",
                )
            )

    scalar_line_numbers = block_scalar_lines(source_lines)
    for line in source_lines:
        if not line.content or line.number in scalar_line_numbers:
            continue
        content = line.content
        mapping = KEY_RE.match(content)
        list_mapping = LIST_KEY_RE.match(content)
        value = ""
        if mapping:
            value = (mapping.group("value") or "").lstrip()
        elif list_mapping:
            value = (list_mapping.group("value") or "").lstrip()
        if (
            content == "-"
            or content.startswith(("- {", "- [", "{", "["))
            or re.match(r"^(?:-\s+)?['\"][^'\"]+['\"]\s*:", content)
            or value.startswith(("{", "[", "&", "*", "!"))
            or re.match(r"^-\s+[*&!]", content)
        ):
            violations.append(
                Violation(
                    relative,
                    line.number,
                    "UNSUPPORTED_YAML",
                    "flow collections, quoted keys, anchors, aliases, and tags are not accepted",
                )
            )
        if EXPLICIT_BLOCK_SCALAR_RE.fullmatch(value):
            violations.append(
                Violation(
                    relative,
                    line.number,
                    "UNSUPPORTED_YAML",
                    "explicit block-scalar indentation indicators are not accepted",
                )
            )

    violations.extend(
        validate_job_structure(source_lines, scalar_line_numbers, relative)
    )
    steps = parse_steps(source_lines, relative, violations)
    triggers = parse_triggers(source_lines, relative, violations)
    conditions = parse_job_conditions(source_lines, relative, violations)
    return Workflow(
        path,
        relative,
        text,
        source_lines,
        steps,
        triggers,
        conditions,
        scalar_line_numbers,
        violations,
    )


def load_json_unique(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key '{key}'")
            result[key] = value
        return result

    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=reject_duplicates)


def load_policy() -> dict[str, Any]:
    policy = load_json_unique(POLICY_PATH)
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ValueError("unsupported policy schema")
    return policy


def action_parts(uses: str) -> tuple[str, str] | None:
    match = ACTION_RE.fullmatch(uses)
    if not match:
        return None
    return match.group("action").lower(), match.group("ref")


def validate_action(
    workflow: Workflow, step: Step, policy: dict[str, Any]
) -> list[Violation]:
    uses = step.uses
    if uses.startswith("./"):
        return [
            Violation(
                workflow.display_path,
                step.field_lines.get("uses", step.line),
                "LOCAL_ACTION",
                "local Actions and reusable workflows are not accepted by v1",
            )
        ]
    parts = action_parts(uses)
    if not parts:
        return [
            Violation(
                workflow.display_path,
                step.field_lines.get("uses", step.line),
                "ACTION_REFERENCE",
                f"external Action '{uses}' must use owner/repository[/path]@40-hex",
            )
        ]

    action, reference = parts
    required = policy["required_action_pins"]
    reviewed = policy["reviewed_external_actions"]
    if action in required:
        expected = required[action]
        if reference != expected:
            return [
                Violation(
                    workflow.display_path,
                    step.field_lines.get("uses", step.line),
                    "ACTION_PIN",
                    f"{action} must be pinned to {expected}",
                )
            ]
        return []

    if not SHA_RE.fullmatch(reference):
        return [
            Violation(
                workflow.display_path,
                step.field_lines.get("uses", step.line),
                "ACTION_PIN",
                f"{action} must use a full lowercase 40-hex commit",
            )
        ]
    if reviewed.get(action) != reference:
        return [
            Violation(
                workflow.display_path,
                step.field_lines.get("uses", step.line),
                "UNREVIEWED_ACTION",
                f"{action}@{reference} has no independent review approval",
            )
        ]
    return []


def all_action_steps(workflow: Workflow) -> list[Step]:
    result = list(workflow.steps)
    represented = {
        step.field_lines["uses"]
        for step in workflow.steps
        if "uses" in step.field_lines
    }
    for line in workflow.lines:
        if line.number in workflow.scalar_lines:
            continue
        content = line.content
        if content.startswith("- "):
            content = content[2:]
        match = KEY_RE.match(content)
        if (
            match
            and match.group("key") == "uses"
            and line.number not in represented
        ):
            result.append(
                Step(
                    line=line.number,
                    fields={"uses": unquote(match.group("value") or "")},
                    field_lines={"uses": line.number},
                )
            )
    return result


def step_for_action(workflow: Workflow, action: str) -> list[Step]:
    action = action.lower()
    result = []
    for step in workflow.steps:
        parts = action_parts(step.uses)
        if parts and parts[0] == action:
            result.append(step)
    return result


def verify_head_binding(
    workflow: Workflow,
    checkout_steps: list[Step],
    expression: str,
    label: str,
    required_jobs: set[str],
) -> list[Violation]:
    violations: list[Violation] = []
    for job in sorted(required_jobs):
        matching = [
            step
            for step in checkout_steps
            if step.job == job
            and compact(step.with_values.get("ref", "")) == compact(expression)
            and compact(step.with_values.get("persist-credentials", "")) == "false"
        ]
        if not matching:
            violations.append(
                Violation(
                    workflow.display_path,
                    0,
                    f"MISSING_{label}_HEAD_CHECKOUT",
                    f"job '{job}' must checkout {expression} with persist-credentials false",
                )
            )
            verification = [
                step
                for step in workflow.steps
                if step.job == job
                and compact(step.env.get("EXPECTED_HEAD", "")) == compact(expression)
                and HEAD_VERIFY_RE.fullmatch(" ".join(step.run.strip().split()))
                and compact(step.fields.get("continue-on-error", "")) != "true"
            ]
            if not verification:
                violations.append(
                    Violation(
                        workflow.display_path,
                        0,
                        f"MISSING_{label}_HEAD_VERIFY",
                        f"job '{job}' must verify {expression} with verify_head.py",
                    )
                )
            continue

        for checkout in matching:
            verification = [
                step
                for step in workflow.steps
                if step.job == checkout.job
                and step.line > checkout.line
                and compact(step.env.get("EXPECTED_HEAD", "")) == compact(expression)
                and HEAD_VERIFY_RE.fullmatch(" ".join(step.run.strip().split()))
                and compact(step.fields.get("continue-on-error", "")) != "true"
            ]
            if not verification:
                violations.append(
                    Violation(
                        workflow.display_path,
                        checkout.line,
                        f"MISSING_{label}_HEAD_VERIFY",
                        f"checkout in job '{checkout.job}' needs a later exact verify_head.py step for {expression}",
                    )
                )
    return violations


def validate_private_roots(workflow: Workflow) -> list[Violation]:
    violations: list[Violation] = []
    if SHARED_ROOT_RE.search(workflow.text):
        violations.append(
            Violation(
                workflow.display_path,
                0,
                "SHARED_MSYS_ROOT",
                r"shared C:\msys64 roots are forbidden",
            )
        )

    setup_steps = step_for_action(workflow, "msys2/setup-msys2")
    has_matrix = any(
        re.match(r"^\s*matrix:", line.raw) for line in workflow.lines
    )
    for step in setup_steps:
        location = step.with_values.get("location", "")
        normalized = compact(location)
        required_tokens = (
            "${{runner.temp}}",
            "${{github.run_id}}",
            "${{github.run_attempt}}",
            "${{github.job}}",
        )
        if not all(token in normalized for token in required_tokens):
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("location", step.line),
                    "PRIVATE_MSYS_ROOT",
                    "setup-msys2 location must bind runner.temp, run_id, run_attempt, and job",
                )
            )
        if has_matrix and not (
            "${{strategy.job-index}}" in normalized or "${{matrix." in normalized
        ):
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("location", step.line),
                    "MATRIX_PRIVATE_MSYS_ROOT",
                    "matrix jobs need a matrix or strategy.job-index root discriminator",
                )
            )
        if compact(step.with_values.get("cache", "")) != "false":
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("cache", step.line),
                    "MSYS_CACHE",
                    "private MSYS2 roots must set cache to false",
                )
            )
        if compact(step.with_values.get("release", "")) != "true":
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("release", step.line),
                    "MSYS_RELEASE",
                    "private MSYS2 roots must set release to true",
                )
            )

    for transaction in (
        step for step in workflow.steps if PACKAGE_TRANSACTION_RE.search(step.run)
    ):
        prior_setup = any(
            setup.job == transaction.job and setup.line < transaction.line
            for setup in setup_steps
        )
        if not prior_setup:
            violations.append(
                Violation(
                    workflow.display_path,
                    transaction.line,
                    "PACKAGE_TRANSACTION_ROOT",
                    f"job '{transaction.job}' needs a prior pinned setup-msys2 private root",
                )
            )
    return violations


def parse_timestamp(
    value: Any, path: str, field_name: str, violations: list[Violation]
) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        violations.append(
            Violation(path, 0, "EVIDENCE_TIMESTAMP", f"{field_name} must be RFC3339 UTC")
        )
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        violations.append(
            Violation(path, 0, "EVIDENCE_TIMESTAMP", f"{field_name} must be RFC3339 UTC")
        )
        return None
    if parsed.tzinfo != timezone.utc:
        violations.append(
            Violation(path, 0, "EVIDENCE_TIMESTAMP", f"{field_name} must use UTC")
        )
        return None
    return parsed


def check_exact_keys(
    value: Any,
    expected: set[str],
    path: str,
    field_name: str,
    violations: list[Violation],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        violations.append(
            Violation(path, 0, "EVIDENCE_SHAPE", f"{field_name} must be an object")
        )
        return None
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unknown {', '.join(extra)}")
        violations.append(
            Violation(
                path,
                0,
                "EVIDENCE_FIELDS",
                f"{field_name} fields are incomplete ({'; '.join(details)})",
            )
        )
    return value


def positive_integer(
    value: Any, path: str, field_name: str, violations: list[Violation]
) -> bool:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        violations.append(
            Violation(
                path,
                0,
                "EVIDENCE_INTEGER",
                f"{field_name} must be a positive integer",
            )
        )
        return False
    return True


def digest_is_valid(value: Any) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(r"sha256:[0-9a-f]{64}", value)
    )


def validate_evidence(path: Path, root: Path, now: datetime) -> Evidence:
    relative = display_path(path, root)
    violations: list[Violation] = []
    try:
        data = load_json_unique(path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        return Evidence(
            None, [Violation(relative, 0, "EVIDENCE_READ", str(error))]
        )

    top = check_exact_keys(
        data,
        {"schema_version", "verified_at", "artifact", "release"},
        relative,
        "consumer lock",
        violations,
    )
    if top is None:
        return Evidence(None, violations)
    if top.get("schema_version") != 1:
        violations.append(
            Violation(relative, 0, "EVIDENCE_SCHEMA", "schema_version must be 1")
        )

    artifact_keys = {
        "repository",
        "workflow_run_id",
        "workflow_run_attempt",
        "workflow_head_sha",
        "artifact_id",
        "artifact_name",
        "artifact_digest",
        "size_in_bytes",
        "created_at",
        "expires_at",
        "expired",
        "api_url",
    }
    release_keys = {
        "repository",
        "release_id",
        "release_api_url",
        "tag",
        "tag_target_sha",
        "published_at",
        "asset_id",
        "asset_name",
        "asset_digest",
        "asset_size_in_bytes",
        "asset_api_url",
    }
    artifact = check_exact_keys(
        top.get("artifact"), artifact_keys, relative, "artifact", violations
    )
    release = check_exact_keys(
        top.get("release"), release_keys, relative, "release", violations
    )
    verified_at = parse_timestamp(
        top.get("verified_at"), relative, "verified_at", violations
    )

    if artifact:
        repository = artifact.get("repository")
        artifact_id = artifact.get("artifact_id")
        if not isinstance(repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
        ):
            violations.append(
                Violation(
                    relative,
                    0,
                    "EVIDENCE_REPOSITORY",
                    "artifact.repository must be owner/repository",
                )
            )
        for name in (
            "workflow_run_id",
            "workflow_run_attempt",
            "artifact_id",
            "size_in_bytes",
        ):
            positive_integer(artifact.get(name), relative, f"artifact.{name}", violations)
        if not SHA_RE.fullmatch(str(artifact.get("workflow_head_sha", ""))):
            violations.append(
                Violation(
                    relative,
                    0,
                    "ARTIFACT_HEAD_SHA",
                    "artifact.workflow_head_sha must be full lowercase 40-hex",
                )
            )
        if not SAFE_NAME_RE.fullmatch(str(artifact.get("artifact_name", ""))):
            violations.append(
                Violation(
                    relative,
                    0,
                    "ARTIFACT_NAME",
                    "artifact.artifact_name must be literal and wildcard-free",
                )
            )
        if not digest_is_valid(artifact.get("artifact_digest")):
            violations.append(
                Violation(
                    relative,
                    0,
                    "ARTIFACT_DIGEST",
                    "artifact.artifact_digest must be a SHA-256 digest",
                )
            )
        if artifact.get("expired") is not False:
            violations.append(
                Violation(
                    relative, 0, "ARTIFACT_EXPIRED", "artifact.expired must be false"
                )
            )
        expected_url = (
            f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}"
        )
        if artifact.get("api_url") != expected_url:
            violations.append(
                Violation(
                    relative,
                    0,
                    "ARTIFACT_URL",
                    "artifact.api_url must bind repository and numeric artifact_id",
                )
            )

        created_at = parse_timestamp(
            artifact.get("created_at"), relative, "artifact.created_at", violations
        )
        expires_at = parse_timestamp(
            artifact.get("expires_at"), relative, "artifact.expires_at", violations
        )
        if expires_at and expires_at <= now:
            violations.append(
                Violation(
                    relative,
                    0,
                    "EVIDENCE_EXPIRED",
                    f"artifact evidence expired at {artifact.get('expires_at')}",
                )
            )
        if created_at and expires_at and created_at >= expires_at:
            violations.append(
                Violation(
                    relative,
                    0,
                    "EVIDENCE_TIME_ORDER",
                    "artifact.created_at must precede artifact.expires_at",
                )
            )
        if verified_at and created_at and verified_at < created_at:
            violations.append(
                Violation(
                    relative,
                    0,
                    "EVIDENCE_TIME_ORDER",
                    "verified_at cannot precede artifact.created_at",
                )
            )
        if verified_at and expires_at and verified_at >= expires_at:
            violations.append(
                Violation(
                    relative,
                    0,
                    "EVIDENCE_TIME_ORDER",
                    "verified_at must precede artifact.expires_at",
                )
            )

    if verified_at and verified_at > now:
        violations.append(
            Violation(relative, 0, "EVIDENCE_FUTURE", "verified_at cannot be in the future")
        )

    if release:
        repository = release.get("repository")
        release_id = release.get("release_id")
        asset_id = release.get("asset_id")
        if not isinstance(repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
        ):
            violations.append(
                Violation(
                    relative,
                    0,
                    "EVIDENCE_REPOSITORY",
                    "release.repository must be owner/repository",
                )
            )
        for name in ("release_id", "asset_id", "asset_size_in_bytes"):
            positive_integer(release.get(name), relative, f"release.{name}", violations)
        if not SAFE_NAME_RE.fullmatch(str(release.get("tag", ""))):
            violations.append(
                Violation(
                    relative,
                    0,
                    "RELEASE_TAG",
                    "release.tag must be literal and wildcard-free",
                )
            )
        if not SHA_RE.fullmatch(str(release.get("tag_target_sha", ""))):
            violations.append(
                Violation(
                    relative,
                    0,
                    "RELEASE_TAG_SHA",
                    "release.tag_target_sha must be full lowercase 40-hex",
                )
            )
        if not SAFE_NAME_RE.fullmatch(str(release.get("asset_name", ""))):
            violations.append(
                Violation(
                    relative,
                    0,
                    "RELEASE_ASSET_NAME",
                    "release.asset_name must be literal and wildcard-free",
                )
            )
        if not digest_is_valid(release.get("asset_digest")):
            violations.append(
                Violation(
                    relative,
                    0,
                    "RELEASE_ASSET_DIGEST",
                    "release.asset_digest must be a SHA-256 digest",
                )
            )
        expected_release_url = (
            f"https://api.github.com/repos/{repository}/releases/{release_id}"
        )
        expected_asset_url = (
            f"https://api.github.com/repos/{repository}/releases/assets/{asset_id}"
        )
        if release.get("release_api_url") != expected_release_url:
            violations.append(
                Violation(
                    relative,
                    0,
                    "RELEASE_URL",
                    "release.release_api_url must bind repository and numeric release_id",
                )
            )
        if release.get("asset_api_url") != expected_asset_url:
            violations.append(
                Violation(
                    relative,
                    0,
                    "RELEASE_ASSET_URL",
                    "release.asset_api_url must bind repository and numeric asset_id",
                )
            )
        published_at = parse_timestamp(
            release.get("published_at"), relative, "release.published_at", violations
        )
        if verified_at and published_at and published_at > verified_at:
            violations.append(
                Violation(
                    relative,
                    0,
                    "EVIDENCE_TIME_ORDER",
                    "release.published_at cannot follow verified_at",
                )
            )

    if artifact and release and artifact.get("repository") != release.get("repository"):
        violations.append(
            Violation(
                relative,
                0,
                "EVIDENCE_REPOSITORY",
                "artifact and release repositories must match",
            )
        )
    return Evidence(data if isinstance(data, dict) else None, violations)


def consumer_lock_path(
    workflow: Workflow, root: Path, lock_prefix: str
) -> tuple[Path | None, list[Violation]]:
    values = []
    for line in workflow.lines:
        match = re.match(r"^ARM64_CONSUMER_LOCK:\s*(.+)$", line.content)
        if match:
            values.append((line.number, unquote(match.group(1))))
    violations: list[Violation] = []
    unique = {value for _, value in values}
    if not values:
        return None, [
            Violation(
                workflow.display_path,
                0,
                "MISSING_CONSUMER_LOCK",
                "artifact downloads require ARM64_CONSUMER_LOCK",
            )
        ]
    if len(values) != 1 or len(unique) != 1:
        return None, [
            Violation(
                workflow.display_path,
                values[-1][0],
                "CONSUMER_LOCK_PATH",
                "ARM64_CONSUMER_LOCK must have one literal value",
            )
        ]

    raw = unique.pop()
    posix = PurePosixPath(raw.replace("\\", "/"))
    normalized_path = posix.as_posix()
    if (
        posix.is_absolute()
        or ".." in posix.parts
        or posix.suffix != ".json"
        or not normalized_path.startswith(lock_prefix)
    ):
        return None, [
            Violation(
                workflow.display_path,
                values[0][0],
                "CONSUMER_LOCK_PATH",
                f"consumer lock must be a JSON file under {lock_prefix}",
            )
        ]
    resolved = (root / Path(*posix.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        violations.append(
            Violation(
                workflow.display_path,
                values[0][0],
                "CONSUMER_LOCK_PATH",
                "consumer lock resolves outside the repository",
            )
        )
        return None, violations
    return resolved, violations


def validate_artifacts(
    workflow: Workflow, root: Path, policy: dict[str, Any], now: datetime
) -> list[Violation]:
    violations: list[Violation] = []
    upload_steps = step_for_action(workflow, "actions/upload-artifact")
    for step in upload_steps:
        name = compact(step.with_values.get("name", ""))
        if not all(
            token in name
            for token in ("${{github.run_id}}", "${{github.run_attempt}}")
        ) or not (
            "${{github.event.after}}" in name
            or "${{github.event.pull_request.head.sha}}" in name
        ):
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("name", step.line),
                    "ARTIFACT_NAME_BINDING",
                    "artifact name must bind run_id, run_attempt, and exact event head",
                )
            )
        if compact(step.with_values.get("if-no-files-found", "")) != "error":
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("if-no-files-found", step.line),
                    "ARTIFACT_MISSING_FILES",
                    "artifact upload must set if-no-files-found to error",
                )
            )
        if compact(step.with_values.get("overwrite", "")) != "false":
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("overwrite", step.line),
                    "ARTIFACT_OVERWRITE",
                    "artifact upload must set overwrite to false",
                )
            )
        try:
            retention = int(unquote(step.with_values.get("retention-days", "")))
        except ValueError:
            retention = 0
        if not 1 <= retention <= 90:
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("retention-days", step.line),
                    "ARTIFACT_RETENTION",
                    "artifact upload needs explicit retention-days from 1 through 90",
                )
            )

    download_steps = step_for_action(workflow, "actions/download-artifact")
    if not download_steps:
        return violations

    lock_path, lock_path_violations = consumer_lock_path(
        workflow, root, policy["consumer_lock_prefix"]
    )
    violations.extend(lock_path_violations)
    if lock_path is None:
        return violations
    evidence = validate_evidence(lock_path, root, now)
    violations.extend(evidence.violations)
    if not evidence.data:
        return violations

    for download in download_steps:
        validation_steps = [
            step
            for step in workflow.steps
            if step.job == download.job
            and step.line < download.line
            and EVIDENCE_VERIFY_RE.fullmatch(" ".join(step.run.strip().split()))
            and compact(step.fields.get("continue-on-error", "")) != "true"
            and "if" not in step.fields
        ]
        if not validation_steps:
            violations.append(
                Violation(
                    workflow.display_path,
                    download.line,
                    "EVIDENCE_RUNTIME_CHECK",
                    f"job '{download.job}' must validate its consumer lock before download",
                )
            )

    artifact = evidence.data.get("artifact", {})
    for step in download_steps:
        expected = {
            "artifact-ids": str(artifact.get("artifact_id", "")),
            "repository": str(artifact.get("repository", "")),
            "run-id": str(artifact.get("workflow_run_id", "")),
            "github-token": "${{ github.token }}",
        }
        for key, value in expected.items():
            if compact(step.with_values.get(key, "")) != compact(value):
                violations.append(
                    Violation(
                        workflow.display_path,
                        step.with_lines.get(key, step.line),
                        "ARTIFACT_EVIDENCE_BINDING",
                        f"download {key} must equal immutable consumer lock evidence",
                    )
                )
        for forbidden in ("name", "pattern", "merge-multiple"):
            if forbidden in step.with_values:
                violations.append(
                    Violation(
                        workflow.display_path,
                        step.with_lines[forbidden],
                        "ARTIFACT_AMBIGUOUS_DOWNLOAD",
                        f"download must not use {forbidden} with artifact-ids",
                    )
                )
        if compact(step.fields.get("continue-on-error", "")) == "true":
            violations.append(
                Violation(
                    workflow.display_path,
                    step.field_lines.get("continue-on-error", step.line),
                    "ARTIFACT_DOWNLOAD_FAILURE",
                    "artifact evidence failures must not continue on error",
                )
            )
    return violations


def validate_workflow(
    path: Path, root: Path, policy: dict[str, Any], now: datetime
) -> list[Violation]:
    workflow = load_workflow(path, root)
    violations = list(workflow.parse_violations)

    for step in all_action_steps(workflow):
        if step.uses:
            violations.extend(validate_action(workflow, step, policy))
            if not step.job:
                violations.append(
                    Violation(
                        workflow.display_path,
                        step.field_lines.get("uses", step.line),
                        "JOB_USES",
                        "v1 does not accept job-level reusable workflow calls",
                    )
                )

    if "push" not in workflow.triggers:
        violations.append(
            Violation(
                workflow.display_path,
                0,
                "PUSH_TRIGGER",
                "campaign workflows must include a canonical push trigger",
            )
        )

    checkout_steps = step_for_action(workflow, "actions/checkout")
    required_jobs = {step.job for step in workflow.steps if step.job}
    allowed_refs = {"${{github.event.after}}"}
    if "push" in workflow.triggers:
        violations.extend(
            verify_head_binding(
                workflow,
                checkout_steps,
                "${{ github.event.after }}",
                "PUSH",
                required_jobs,
            )
        )

    pr_triggers = workflow.triggers & {"pull_request", "pull_request_target"}
    if pr_triggers:
        allowed_refs.add("${{github.event.pull_request.head.sha}}")
        canonical_condition = (
            "github.event_name=='push'||"
            "github.event.pull_request.head.repo.full_name==github.repository"
        )
        for job in sorted(required_jobs):
            condition = compact(workflow.job_conditions.get(job, ""))
            if condition.startswith("${{") and condition.endswith("}}"):
                condition = condition[3:-2]
            if condition != canonical_condition:
                violations.append(
                    Violation(
                        workflow.display_path,
                        0,
                        "PR_REPOSITORY_GUARD",
                        f"job '{job}' must permit push or an exact same-repository PR head",
                    )
                )
        violations.extend(
            verify_head_binding(
                workflow,
                checkout_steps,
                "${{ github.event.pull_request.head.sha }}",
                "PR",
                required_jobs,
            )
        )

    for step in checkout_steps:
        reference = compact(step.with_values.get("ref", ""))
        if reference not in allowed_refs:
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("ref", step.line),
                    "CHECKOUT_REF",
                    "checkout ref must be the exact push or same-repository PR head",
                )
            )
        if compact(step.with_values.get("persist-credentials", "")) != "false":
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("persist-credentials", step.line),
                    "CHECKOUT_CREDENTIALS",
                    "campaign checkout must set persist-credentials to false",
                )
            )
        if "path" in step.with_values:
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines["path"],
                    "CHECKOUT_PATH",
                    "campaign checkout must occupy the default workspace",
                )
            )
        if compact(step.fields.get("continue-on-error", "")) == "true":
            violations.append(
                Violation(
                    workflow.display_path,
                    step.field_lines.get("continue-on-error", step.line),
                    "CHECKOUT_FAILURE",
                    "campaign checkout failures must stop the job",
                )
            )
        repository = compact(step.with_values.get("repository", ""))
        if repository and repository not in {
            "${{github.repository}}",
            "${{github.event.pull_request.head.repo.full_name}}",
        }:
            violations.append(
                Violation(
                    workflow.display_path,
                    step.with_lines.get("repository", step.line),
                    "CHECKOUT_REPOSITORY",
                    "campaign checkout must remain in the event repository",
                )
            )

    violations.extend(validate_private_roots(workflow))
    violations.extend(validate_artifacts(workflow, root, policy, now))
    return sorted(set(violations))


def run_git(repository: Path, arguments: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def parse_now(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not value.endswith("Z"):
        raise ValueError("--now must be RFC3339 UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != timezone.utc:
        raise ValueError("--now must use UTC")
    return parsed


def is_control_path(path: str, policy: dict[str, Any]) -> bool:
    return path == policy["control_workflow"] or path.startswith(
        policy["control_prefix"]
    )


def is_workflow_path(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


def base_has_policy(repository: Path, base_sha: str) -> bool:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "cat-file",
            "-e",
            f"{base_sha}:.github/arm64-workflow-policy/policy.json",
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def validate_changes(
    repository: Path,
    base_sha: str,
    head_sha: str,
    policy: dict[str, Any],
    now: datetime,
) -> tuple[list[Violation], int, int, str]:
    for label, value in (("base", base_sha), ("head", head_sha)):
        if not SHA_RE.fullmatch(value):
            raise ValueError(f"{label} SHA must be full lowercase 40-hex")
        resolved = run_git(repository, ["rev-parse", f"{value}^{{commit}}"])
        if resolved != value:
            raise ValueError(f"{label} SHA did not resolve exactly")

    merge_base = run_git(repository, ["merge-base", base_sha, head_sha])
    changed_output = run_git(
        repository,
        [
            "diff",
            "--name-only",
            "--diff-filter=ACMRTUXB",
            merge_base,
            head_sha,
            "--",
            ".github/workflows",
            ".github/arm64-workflow-policy",
            ".github/arm64-workflow-locks",
        ],
    )
    deleted_output = run_git(
        repository,
        [
            "diff",
            "--name-only",
            "--diff-filter=D",
            merge_base,
            head_sha,
            "--",
            ".github/workflows",
            ".github/arm64-workflow-policy",
            ".github/arm64-workflow-locks",
        ],
    )
    changed = sorted(filter(None, changed_output.splitlines()))
    deleted = sorted(filter(None, deleted_output.splitlines()))
    violations: list[Violation] = []
    bootstrap = not base_has_policy(repository, base_sha)

    control_changes = [path for path in changed + deleted if is_control_path(path, policy)]
    if control_changes and not bootstrap:
        for path in control_changes:
            violations.append(
                Violation(
                    path,
                    0,
                    "POLICY_SOURCE_CHANGED",
                    "v1 policy/control changes require an explicit policy-version review",
                )
            )

    for path in deleted:
        if path.startswith(policy["consumer_lock_prefix"]):
            violations.append(
                Violation(
                    path,
                    0,
                    "CONSUMER_LOCK_DELETED",
                    "consumer locks cannot be deleted while v1 is active",
                )
            )

    workflow_count = 0
    lock_count = 0
    for relative in changed:
        candidate = repository / Path(*PurePosixPath(relative).parts)
        if is_workflow_path(relative):
            if relative == policy["control_workflow"]:
                continue
            if relative in policy["excluded_workflows"]:
                continue
            workflow_count += 1
            violations.extend(validate_workflow(candidate, repository, policy, now))
        elif relative.startswith(policy["consumer_lock_prefix"]) and relative.endswith(
            ".json"
        ):
            lock_count += 1
            violations.extend(validate_evidence(candidate, repository, now).violations)

    return sorted(set(violations)), workflow_count, lock_count, merge_base


def emit(violations: list[Violation], summary: str) -> int:
    for violation in sorted(set(violations)):
        print(violation.render())
    if violations:
        print(f"policy-result=failed violations={len(set(violations))}")
        return 1
    print(summary)
    print("policy-result=passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate ARM64 campaign workflow policy")
    subparsers = parser.add_subparsers(dest="command", required=True)

    workflows = subparsers.add_parser("workflows")
    workflows.add_argument("paths", nargs="+")
    workflows.add_argument("--repository", type=Path, default=Path("."))
    workflows.add_argument("--now")

    evidence = subparsers.add_parser("evidence")
    evidence.add_argument("lock")
    evidence.add_argument("--repository", type=Path, default=Path("."))
    evidence.add_argument("--now")

    changes = subparsers.add_parser("changes")
    changes.add_argument("--repository", type=Path, default=Path("."))
    changes.add_argument("--base-sha", required=True)
    changes.add_argument("--head-sha", required=True)
    changes.add_argument("--now")

    args = parser.parse_args()
    try:
        policy = load_policy()
        now = parse_now(args.now)
        repository = args.repository.resolve()
        if args.command == "workflows":
            violations: list[Violation] = []
            for raw_path in args.paths:
                path = Path(raw_path)
                if not path.is_absolute():
                    path = repository / path
                violations.extend(validate_workflow(path, repository, policy, now))
            return emit(
                violations,
                f"validated-workflows={len(args.paths)} as-of={now.isoformat()}",
            )
        if args.command == "evidence":
            path = Path(args.lock)
            if not path.is_absolute():
                path = repository / path
            result = validate_evidence(path, repository, now)
            return emit(
                result.violations,
                f"validated-consumer-lock={display_path(path, repository)} "
                f"as-of={now.isoformat()}",
            )

        violations, workflows_checked, locks_checked, merge_base = validate_changes(
            repository,
            args.base_sha,
            args.head_sha,
            policy,
            now,
        )
        return emit(
            violations,
            f"validated-changes workflows={workflows_checked} locks={locks_checked} "
            f"merge-base={merge_base} as-of={now.isoformat()}",
        )
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"policy-error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
