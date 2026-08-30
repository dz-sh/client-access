#!/usr/bin/env python3
import json
import pathlib
import re
import sys

import yaml


SHA_ACTION = re.compile(r"^[^@]+@[0-9a-f]{40}$")
IMPORT = re.compile(r"^\s*import\b.*?\bfrom\s+(['\"])([^'\"]+)\1\s*;", re.MULTILINE)
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ContractError(Exception):
    pass


def read_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def workflow_triggers(document):
    value = document.get("on")
    if value is None and True in document:
        value = document[True]
    if isinstance(value, str):
        return {value: None}
    return value or {}


def strip_c_comments_and_literals(source: str) -> str:
    output = []
    index = 0
    state = "code"
    quote = ""

    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                state = "line_comment"
                output.extend("  ")
                index += 2
                continue
            if char == "/" and next_char == "*":
                state = "block_comment"
                output.extend("  ")
                index += 2
                continue
            if char in {'"', "'"}:
                state = "literal"
                quote = char
                output.append(" ")
                index += 1
                continue
            output.append(char)
            index += 1
            continue

        if state == "line_comment":
            if char == "\n":
                state = "code"
                output.append("\n")
            else:
                output.append(" ")
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                output.extend("  ")
                index += 2
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue

        if state == "literal":
            if char == "\\":
                output.append(" ")
                if next_char:
                    output.append(" ")
                    index += 2
                else:
                    index += 1
                continue
            if char == quote:
                state = "code"
            output.append("\n" if char == "\n" else " ")
            index += 1

    return "".join(output)


def extract_make_block(source: str, name: str) -> str:
    pattern = re.compile(
        rf"^define\s+{re.escape(name)}\s*$\n(.*?)^endef\s*$",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(source)
    if not match:
        raise ContractError(f"missing Make block: {name}")
    return match.group(1)


def make_field(block: str, field: str) -> str:
    lines = block.splitlines()
    for index, line in enumerate(lines):
        match = re.match(rf"\s*{re.escape(field)}\s*:?=\s*(.*)$", line)
        if not match:
            continue
        pieces = [match.group(1)]
        while pieces[-1].rstrip().endswith("\\") and index + 1 < len(lines):
            pieces[-1] = pieces[-1].rstrip()[:-1]
            index += 1
            pieces.append(lines[index].strip())
        return " ".join(pieces)
    raise ContractError(f"missing Make field: {field}")


def validate_paths(repo: pathlib.Path, contracts, errors):
    for relative in contracts["required_paths"]:
        if not (repo / relative).is_file():
            errors.append(f"paths: required file missing: {relative}")
    for relative in contracts["forbidden_paths"]:
        if (repo / relative).exists():
            errors.append(f"paths: forbidden path exists: {relative}")


def validate_ucode_imports(repo: pathlib.Path, contracts, errors):
    for relative, rules in contracts["ucode_imports"].items():
        source = (repo / relative).read_text(encoding="utf-8")
        imports = {match.group(2) for match in IMPORT.finditer(source)}
        for module in rules.get("required", []):
            if module not in imports:
                errors.append(f"ucode-imports: {relative} must import {module}")
        for module in rules.get("forbidden", []):
            if module in imports:
                errors.append(f"ucode-imports: {relative} must not import {module}")


def validate_c_lexical_boundaries(repo: pathlib.Path, contracts, errors):
    for boundary in contracts["c_lexical_boundaries"]:
        exact = set(boundary.get("forbidden_identifiers", []))
        fragments = tuple(item.casefold() for item in boundary.get("forbidden_identifier_fragments", []))
        for relative in boundary["paths"]:
            source = (repo / relative).read_text(encoding="utf-8")
            tokens = IDENTIFIER.findall(strip_c_comments_and_literals(source))
            for token in tokens:
                if token in exact or any(fragment in token.casefold() for fragment in fragments):
                    errors.append(
                        f"{boundary['id']}: forbidden identifier {token!r} in {relative}"
                    )


def validate_packages(repo: pathlib.Path, contracts, errors):
    for package, rules in contracts["packages"].items():
        relative = rules["makefile"]
        source = (repo / relative).read_text(encoding="utf-8")
        try:
            package_block = extract_make_block(source, f"Package/{package}")
            dependencies = set(re.findall(r"\+([A-Za-z0-9_.+-]+)", make_field(package_block, "DEPENDS")))
            install_block = extract_make_block(source, f"Package/{package}/install")
        except ContractError as error:
            errors.append(f"packages: {relative}: {error}")
            continue

        for dependency in rules["required_dependencies"]:
            if dependency not in dependencies:
                errors.append(f"packages: {package} missing dependency {dependency}")
        for dependency in rules["forbidden_dependencies"]:
            if dependency in dependencies:
                errors.append(f"packages: {package} has forbidden dependency {dependency}")
        for fragment in rules["forbidden_install_fragments"]:
            if fragment in install_block:
                errors.append(f"packages: {package} install owns forbidden fragment {fragment!r}")


def validate_workflows(repo: pathlib.Path, errors):
    workflow_dir = repo / ".github/workflows"
    workflows = sorted(workflow_dir.glob("*.yml"))
    expected = {
        "ci.yml",
        "_ci-quality.yml",
        "_ci-linux-runtime.yml",
        "_ci-openwrt-sdk.yml",
        "_ci-immortalwrt-sdk.yml",
    }
    observed = {path.name for path in workflows}
    if observed != expected:
        errors.append(f"workflows: expected {sorted(expected)}, observed {sorted(observed)}")

    documents = {}
    for path in workflows:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        limit = 150 if path.name == "ci.yml" else 300
        if line_count > limit:
            errors.append(
                f"workflows: {path.name} has {line_count} lines; maintainability limit is {limit}"
            )
        with path.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        documents[path.name] = document

        permissions = document.get("permissions", {})
        if permissions != {"contents": "read"}:
            errors.append(f"workflows: {path.name} permissions must be contents: read")

        triggers = workflow_triggers(document)
        if path.name == "ci.yml":
            if set(triggers) != {"push"}:
                errors.append(f"workflows: ci.yml must have only push trigger")
            branches = (triggers.get("push") or {}).get("branches", [])
            if branches != ["main"]:
                errors.append(f"workflows: ci.yml push branches must be [main]")
        elif set(triggers) != {"workflow_call"}:
            errors.append(f"workflows: {path.name} must have only workflow_call trigger")

        for job_name, job in (document.get("jobs") or {}).items():
            if "uses" not in job and "timeout-minutes" not in job:
                errors.append(f"workflows: {path.name}:{job_name} missing timeout-minutes")
            for step in job.get("steps", []):
                action = step.get("uses")
                if action and not action.startswith("./") and not SHA_ACTION.fullmatch(action):
                    errors.append(
                        f"workflows: {path.name}:{job_name} action is not SHA-pinned: {action}"
                    )
                run = step.get("run", "")
                if re.search(r"(^|[|;&()\s])grep([\s]|$)", run):
                    errors.append(
                        f"workflows: {path.name}:{job_name} embeds grep instead of a named checker"
                    )

    entry = documents.get("ci.yml", {})
    jobs = entry.get("jobs") or {}
    expected_jobs = {"quality", "linux-runtime", "openwrt-sdk", "immortalwrt-sdk", "ci-gate"}
    if set(jobs) != expected_jobs:
        errors.append(f"workflows: ci.yml jobs must be {sorted(expected_jobs)}")
        return

    for name in ("linux-runtime", "openwrt-sdk", "immortalwrt-sdk"):
        if jobs[name].get("needs") != "quality":
            errors.append(f"workflows: ci.yml:{name} must depend on quality")

    gate = jobs["ci-gate"]
    if gate.get("name") != "CI Gate":
        errors.append("workflows: aggregate job must be named CI Gate")
    gate_needs = gate.get("needs", [])
    if set(gate_needs) != expected_jobs - {"ci-gate"}:
        errors.append("workflows: CI Gate must depend on every validation lane")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: check-architecture.py REPOSITORY CONTRACTS_JSON")

    repo = pathlib.Path(sys.argv[1]).resolve()
    contracts = read_json(pathlib.Path(sys.argv[2]))
    errors = []

    validate_paths(repo, contracts, errors)
    validate_ucode_imports(repo, contracts, errors)
    validate_c_lexical_boundaries(repo, contracts, errors)
    validate_packages(repo, contracts, errors)
    validate_workflows(repo, errors)

    if errors:
        for error in errors:
            print(f"architecture contract failed: {error}", file=sys.stderr)
        return 1

    print("all named architecture contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
