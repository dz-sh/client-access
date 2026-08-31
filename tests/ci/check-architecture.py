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


def validate_ucode_boundaries(repo: pathlib.Path, contracts, errors):
    for relative, rules in contracts.get("ucode_boundaries", {}).items():
        source = (repo / relative).read_text(encoding="utf-8")
        lexical = strip_c_comments_and_literals(source)
        tokens = set(IDENTIFIER.findall(lexical))
        for identifier in rules.get("forbidden_identifiers", []):
            if identifier in tokens:
                errors.append(
                    f"ucode-boundaries: {relative} contains forbidden identifier {identifier}"
                )
        for call in rules.get("forbidden_calls", []):
            owner, member = call.split(".", 1)
            pattern = re.compile(
                rf"\b{re.escape(owner)}\s*\.\s*{re.escape(member)}\s*\("
            )
            if pattern.search(lexical):
                errors.append(
                    f"ucode-boundaries: {relative} must not call {call}"
                )


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


def validate_release_versioning(repo: pathlib.Path, contracts, errors):
    rules = contracts["release_versioning"]
    version_file = rules["version_file"]
    source = (repo / version_file).read_text(encoding="utf-8")
    assignments = dict(
        re.findall(r"^([A-Z][A-Z0-9_]*)\s*:=\s*([^\s]+)\s*$", source, re.MULTILINE)
    )
    version = assignments.get("CLIENT_ACCESS_VERSION", "")
    package_release = assignments.get("CLIENT_ACCESS_RELEASE", "")
    if not re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version
    ):
        errors.append(f"release-versioning: invalid source version {version!r}")
    if not re.fullmatch(r"[1-9][0-9]*", package_release):
        errors.append(f"release-versioning: invalid package release {package_release!r}")

    for relative in rules["package_makefiles"]:
        makefile = (repo / relative).read_text(encoding="utf-8")
        required = [
            "include $(CLIENT_ACCESS_REPO_DIR)/version.mk",
            "PKG_VERSION:=$(CLIENT_ACCESS_VERSION)",
            "PKG_RELEASE:=$(CLIENT_ACCESS_RELEASE)",
        ]
        for declaration in required:
            if makefile.count(declaration) != 1:
                errors.append(
                    f"release-versioning: {relative} must contain exactly one "
                    f"{declaration!r}"
                )


def validate_workflows(repo: pathlib.Path, errors):
    workflow_dir = repo / ".github/workflows"
    workflows = sorted(workflow_dir.glob("*.yml"))
    expected = {
        "ci.yml",
        "_ci-quality.yml",
        "_ci-linux-runtime.yml",
        "_ci-openwrt-sdk.yml",
        "_ci-immortalwrt-sdk.yml",
        "release.yml",
    }
    observed = {path.name for path in workflows}
    if observed != expected:
        errors.append(f"workflows: expected {sorted(expected)}, observed {sorted(observed)}")

    documents = {}
    for path in workflows:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        if path.name == "ci.yml":
            limit = 150
        elif path.name == "release.yml":
            limit = 180
        else:
            limit = 300
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
            if set(triggers) != {"push", "workflow_call"}:
                errors.append("workflows: ci.yml must have push and workflow_call triggers")
            branches = (triggers.get("push") or {}).get("branches", [])
            if branches != ["main"]:
                errors.append(f"workflows: ci.yml push branches must be [main]")
        elif path.name == "release.yml":
            if set(triggers) != {"push", "workflow_dispatch"}:
                errors.append(
                    "workflows: release.yml must have tag-push and workflow_dispatch triggers"
                )
            tags = (triggers.get("push") or {}).get("tags", [])
            if tags != ["v*"]:
                errors.append("workflows: release.yml push tags must be [v*]")
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

    release = documents.get("release.yml", {})
    release_jobs = release.get("jobs") or {}
    expected_release_jobs = {"validate", "verification", "assemble-release", "publish"}
    if set(release_jobs) != expected_release_jobs:
        errors.append(
            f"workflows: release.yml jobs must be {sorted(expected_release_jobs)}"
        )
        return

    verification = release_jobs["verification"]
    if verification.get("uses") != "./.github/workflows/ci.yml":
        errors.append("workflows: release verification must reuse ci.yml")
    if verification.get("needs") != "validate":
        errors.append("workflows: release verification must depend on validation")

    assemble_needs = set(release_jobs["assemble-release"].get("needs", []))
    if assemble_needs != {"validate", "verification"}:
        errors.append("workflows: release assembly must depend on validation and verification")

    publish = release_jobs["publish"]
    if set(publish.get("needs", [])) != {"validate", "assemble-release"}:
        errors.append("workflows: release publication must depend on verified assembly")
    if publish.get("permissions") != {"contents": "write"}:
        errors.append("workflows: only release publication receives contents: write")
    if publish.get("if") != "github.event_name == 'push'":
        errors.append("workflows: release publication must be limited to tag push events")
    for name, job in release_jobs.items():
        if name != "publish" and "permissions" in job:
            errors.append(f"workflows: release job {name} must inherit read-only permissions")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: check-architecture.py REPOSITORY CONTRACTS_JSON")

    repo = pathlib.Path(sys.argv[1]).resolve()
    contracts = read_json(pathlib.Path(sys.argv[2]))
    errors = []

    validate_paths(repo, contracts, errors)
    validate_ucode_imports(repo, contracts, errors)
    validate_ucode_boundaries(repo, contracts, errors)
    validate_c_lexical_boundaries(repo, contracts, errors)
    validate_packages(repo, contracts, errors)
    validate_release_versioning(repo, contracts, errors)
    validate_workflows(repo, errors)

    if errors:
        for error in errors:
            print(f"architecture contract failed: {error}", file=sys.stderr)
        return 1

    print("all named architecture contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
