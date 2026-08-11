#!/usr/bin/env python3
"""Validate exact-main evidence and an immutable annotated stable-tag handoff."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


SCHEMA = "elevenid.stable-tag-preparation/v1"
TAG_PATTERN = re.compile(r"^v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PREPARATION_WORKFLOW = ".github/workflows/prepare-stable-tag.yml"
OWNED_WORKSPACE_PACKAGES = (
    "marty-verifier",
    "marty-app-storage",
    "marty-sync",
    "marty-entitlements",
    "marty-reporting",
)


class StableTagGateError(ValueError):
    """Raised when stable-tag evidence is incomplete or inconsistent."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StableTagGateError(f"{label} must be a JSON object")
    return value


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise StableTagGateError(f"cannot load {label}: {error}") from error


def version_from_tag(tag: str) -> str:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise StableTagGateError(f"invalid stable tag: {tag}")
    return match.group("version")


def application_versions(repository: Path) -> dict[str, str]:
    try:
        cargo = tomllib.loads((repository / "Cargo.toml").read_text(encoding="utf-8"))
        workspace_version = cargo["workspace"]["package"]["version"]
        sync_dependency_version = cargo["workspace"]["dependencies"]["marty-sync"]["version"]
        cargo_lock = tomllib.loads((repository / "Cargo.lock").read_text(encoding="utf-8"))
        tauri = _object(
            json.loads((repository / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8")),
            "Tauri configuration",
        )
        package = _object(
            json.loads((repository / "ui" / "package.json").read_text(encoding="utf-8")),
            "UI package",
        )
        package_lock = _object(
            json.loads((repository / "ui" / "package-lock.json").read_text(encoding="utf-8")),
            "UI package lock",
        )
        lock_packages = _object(package_lock.get("packages"), "UI lock packages")
        lock_root = _object(lock_packages.get(""), "UI lock root package")
    except (OSError, KeyError, TypeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise StableTagGateError(f"cannot resolve application versions: {error}") from error

    versions = {
        "Cargo.toml": workspace_version,
        "Cargo.toml#workspace.dependencies.marty-sync": sync_dependency_version,
        "src-tauri/tauri.conf.json": tauri.get("version"),
        "ui/package.json": package.get("version"),
        "ui/package-lock.json": package_lock.get("version"),
        "ui/package-lock.json#packages-root": lock_root.get("version"),
    }
    locked_packages = cargo_lock.get("package")
    if not isinstance(locked_packages, list):
        raise StableTagGateError("Cargo.lock has no package records")
    for name in OWNED_WORKSPACE_PACKAGES:
        matches = [
            package
            for package in locked_packages
            if isinstance(package, dict) and package.get("name") == name
        ]
        if len(matches) != 1 or matches[0].get("source") is not None:
            raise StableTagGateError(f"Cargo.lock must contain exactly one local {name} package")
        versions[f"Cargo.lock#{name}"] = matches[0].get("version")
    if not all(isinstance(value, str) and value for value in versions.values()):
        raise StableTagGateError("application version metadata is missing or invalid")
    return {path: str(value) for path, value in versions.items()}


def _git(repository: Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        raise StableTagGateError(
            f"git {' '.join(arguments)} failed: {error.stderr.strip()}"
        ) from error


def validate_application_version(repository: Path, tag: str) -> None:
    expected_version = version_from_tag(tag)
    versions = application_versions(repository)
    mismatches = [path for path, value in versions.items() if value != expected_version]
    if mismatches:
        raise StableTagGateError(
            "stable tag does not match complete application version state: " + ", ".join(mismatches)
        )


def validate_source(repository: Path, tag: str, expected_commit: str) -> None:
    if not SHA_PATTERN.fullmatch(expected_commit):
        raise StableTagGateError("source commit must be a full lowercase SHA")
    validate_application_version(repository, tag)
    head = _git(repository, "rev-parse", "HEAD^{commit}")
    main = _git(repository, "rev-parse", "refs/remotes/origin/main^{commit}")
    if head != expected_commit or main != expected_commit:
        raise StableTagGateError(
            f"source mismatch: HEAD={head}, origin/main={main}, expected={expected_commit}"
        )


def _workflow_runs(payload: Any) -> list[dict[str, Any]]:
    pages = payload if isinstance(payload, list) else [payload]
    runs: list[dict[str, Any]] = []
    for page_index, page_value in enumerate(pages):
        page = _object(page_value, f"workflow-runs page {page_index}")
        page_runs = page.get("workflow_runs")
        if not isinstance(page_runs, list):
            raise StableTagGateError(f"workflow-runs page {page_index} has no workflow_runs array")
        runs.extend(_object(value, "workflow run") for value in page_runs)
    return runs


def _run_id(run: dict[str, Any]) -> int:
    value = run.get("id")
    if not isinstance(value, int) or value < 1:
        raise StableTagGateError("workflow run has an invalid id")
    return value


def validate_workflow_runs(
    payload: Any,
    policy: Any,
    expected_commit: str,
    current_run_id: int,
) -> list[dict[str, Any]]:
    if not SHA_PATTERN.fullmatch(expected_commit):
        raise StableTagGateError("workflow evidence commit must be a full lowercase SHA")
    document = _object(policy, "stable-tag policy")
    if document.get("schema") != SCHEMA:
        raise StableTagGateError("stable-tag policy schema is invalid")
    required = document.get("required_workflows")
    if not isinstance(required, list) or not required:
        raise StableTagGateError("stable-tag policy requires at least one workflow")

    runs = _workflow_runs(payload)
    accepted: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw_item in enumerate(required):
        item = _object(raw_item, f"required_workflows[{index}]")
        path, event = item.get("path"), item.get("event")
        if not isinstance(path, str) or not path or not isinstance(event, str) or not event:
            raise StableTagGateError(f"required_workflows[{index}] is invalid")
        key = (path, event)
        if key in seen:
            raise StableTagGateError(f"duplicate required workflow: {path} ({event})")
        seen.add(key)
        matches = [
            run
            for run in runs
            if run.get("path") == path
            and run.get("event") == event
            and run.get("head_sha") == expected_commit
            and run.get("id") != current_run_id
        ]
        if not matches:
            raise StableTagGateError(f"required exact-main workflow is missing: {path}")
        latest = max(matches, key=_run_id)
        if latest.get("status") != "completed":
            raise StableTagGateError(f"required workflow is still pending: {path}")
        if latest.get("conclusion") != "success":
            raise StableTagGateError(
                f"required workflow did not succeed: {path} ({latest.get('conclusion')})"
            )
        accepted.append(
            {"path": path, "event": event, "run_id": _run_id(latest), "conclusion": "success"}
        )
    return accepted


def preparation_evidence(
    repository_name: str,
    tag: str,
    commit: str,
    run_id: int,
    workflows: list[dict[str, Any]],
) -> dict[str, Any]:
    if not repository_name or "/" not in repository_name:
        raise StableTagGateError("repository name must use owner/name form")
    version_from_tag(tag)
    if not SHA_PATTERN.fullmatch(commit) or run_id < 1 or not workflows:
        raise StableTagGateError("preparation identity or workflow evidence is invalid")
    return {
        "schema": SCHEMA,
        "repository": repository_name,
        "tag": tag,
        "source_sha": commit,
        "preparation_run_id": run_id,
        "required_workflows": workflows,
    }


def record_tag(evidence: Any, tag_object: str, peeled_commit: str) -> dict[str, Any]:
    document = _object(evidence, "preparation evidence").copy()
    if document.get("schema") != SCHEMA:
        raise StableTagGateError("preparation evidence schema is invalid")
    if not SHA_PATTERN.fullmatch(tag_object):
        raise StableTagGateError("annotated tag object must be a full lowercase SHA")
    if peeled_commit != document.get("source_sha"):
        raise StableTagGateError("annotated tag does not peel to the prepared source")
    document["tag_object_sha"] = tag_object
    document["peeled_source_sha"] = peeled_commit
    return document


def parse_tag_message(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in message.splitlines():
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in {"Stable-Tag-Gate", "Preparation-Run", "Source-SHA"}:
            if key in fields:
                raise StableTagGateError(f"duplicate annotated-tag field: {key}")
            fields[key] = value.strip()
    if fields.get("Stable-Tag-Gate") != SCHEMA:
        raise StableTagGateError("annotated tag has no valid stable-tag gate marker")
    return fields


def validate_release_proof(
    repository_name: str,
    tag: str,
    commit: str,
    tag_type: str,
    tag_object: str,
    tag_message: str,
    run_payload: Any,
    evidence: Any,
) -> None:
    version_from_tag(tag)
    if tag_type != "tag":
        raise StableTagGateError("stable release ref must be an annotated tag object")
    if not SHA_PATTERN.fullmatch(commit) or not SHA_PATTERN.fullmatch(tag_object):
        raise StableTagGateError("release tag identity contains an invalid SHA")
    fields = parse_tag_message(tag_message)
    if fields.get("Source-SHA") != commit:
        raise StableTagGateError("annotated tag source marker does not match its peel")
    try:
        preparation_run_id = int(fields.get("Preparation-Run", ""))
    except ValueError as error:
        raise StableTagGateError("annotated tag preparation run is invalid") from error

    run = _object(run_payload, "preparation run")
    if (
        run.get("id") != preparation_run_id
        or run.get("path") != PREPARATION_WORKFLOW
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != commit
        or run.get("head_branch") != "main"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise StableTagGateError("preparation workflow run is not an exact successful main run")

    document = _object(evidence, "preparation evidence")
    expected = {
        "schema": SCHEMA,
        "repository": repository_name,
        "tag": tag,
        "source_sha": commit,
        "preparation_run_id": preparation_run_id,
        "tag_object_sha": tag_object,
        "peeled_source_sha": commit,
    }
    mismatches = [key for key, value in expected.items() if document.get(key) != value]
    if mismatches:
        raise StableTagGateError(
            "preparation evidence does not match release identity: " + ", ".join(mismatches)
        )
    workflows = document.get("required_workflows")
    if not isinstance(workflows, list) or not workflows:
        raise StableTagGateError("preparation evidence has no required workflow results")
    for item in workflows:
        record = _object(item, "required workflow evidence")
        if record.get("conclusion") != "success" or not isinstance(record.get("run_id"), int):
            raise StableTagGateError("preparation evidence contains an invalid workflow result")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("validate-source")
    source.add_argument("--repository", type=Path, required=True)
    source.add_argument("--tag", required=True)
    source.add_argument("--commit", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--repository", type=Path, required=True)
    prepare.add_argument("--repository-name", required=True)
    prepare.add_argument("--tag", required=True)
    prepare.add_argument("--commit", required=True)
    prepare.add_argument("--run-id", type=int, required=True)
    prepare.add_argument("--runs-json", type=Path, required=True)
    prepare.add_argument("--policy", type=Path, required=True)
    prepare.add_argument("--evidence", type=Path, required=True)
    record = commands.add_parser("record-tag")
    record.add_argument("--evidence", type=Path, required=True)
    record.add_argument("--tag-object", required=True)
    record.add_argument("--peeled-commit", required=True)
    release = commands.add_parser("validate-release")
    release.add_argument("--repository-name", required=True)
    release.add_argument("--tag", required=True)
    release.add_argument("--commit", required=True)
    release.add_argument("--tag-type", required=True)
    release.add_argument("--tag-object", required=True)
    release.add_argument("--tag-message", type=Path, required=True)
    release.add_argument("--run-json", type=Path, required=True)
    release.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate-source":
            validate_source(args.repository, args.tag, args.commit)
        elif args.command == "prepare":
            validate_source(args.repository, args.tag, args.commit)
            workflows = validate_workflow_runs(
                _load_json(args.runs_json, "workflow runs"),
                _load_json(args.policy, "stable-tag policy"),
                args.commit,
                args.run_id,
            )
            evidence = preparation_evidence(
                args.repository_name, args.tag, args.commit, args.run_id, workflows
            )
            args.evidence.write_text(
                json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        elif args.command == "record-tag":
            evidence = record_tag(
                _load_json(args.evidence, "preparation evidence"),
                args.tag_object,
                args.peeled_commit,
            )
            args.evidence.write_text(
                json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            validate_release_proof(
                args.repository_name,
                args.tag,
                args.commit,
                args.tag_type,
                args.tag_object,
                args.tag_message.read_text(encoding="utf-8"),
                _load_json(args.run_json, "preparation run"),
                _load_json(args.evidence, "preparation evidence"),
            )
    except (OSError, StableTagGateError) as error:
        print(f"stable-tag-gate: {error}", file=sys.stderr)
        return 1
    print("stable-tag-gate: exact-main preparation evidence is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
