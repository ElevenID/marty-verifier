#!/usr/bin/env python3
"""Update or validate the exact Marty Core revision consumed by Verifier."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


CORE_REPOSITORY = "https://github.com/ElevenID/marty-core"
CORE_CRATES = (
    "marty-crypto",
    "marty-verification",
    "marty-biometrics",
    "marty-secure-storage",
    "marty-types",
    "marty-oid4vci",
)
OWNED_WORKSPACE_PACKAGES = (
    "marty-verifier",
    "marty-app-storage",
    "marty-sync",
    "marty-entitlements",
    "marty-reporting",
)
STABLE_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
DEPENDENCY_LINE = re.compile(
    r"^(?P<indent>\s*)(?P<name>marty-[a-z0-9-]+)(?P<separator>\s*=\s*\{)(?P<body>.*)(?P<close>\}\s*)$"
)
REVISION = re.compile(r'(?P<prefix>\brev\s*=\s*")(?P<sha>[0-9a-f]{40})(?P<suffix>")')
WORKSPACE_VERSION = re.compile(r'(?m)^version\s*=\s*"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"\s*$')


class ContractError(ValueError):
    """Raised when dependency or release metadata is not exact and consistent."""


def validate_inputs(core_tag: str, core_sha: str) -> None:
    if not STABLE_TAG.fullmatch(core_tag):
        raise ContractError(f"Core tag must be an exact stable semantic version: {core_tag!r}")
    if not COMMIT_SHA.fullmatch(core_sha):
        raise ContractError("Core commit must be a lowercase 40-character hexadecimal SHA")


def _dependency_records(cargo_toml: str) -> dict[str, tuple[int, str, str]]:
    records: dict[str, tuple[int, str, str]] = {}
    for index, line in enumerate(cargo_toml.splitlines(keepends=True)):
        content = line.rstrip("\r\n")
        match = DEPENDENCY_LINE.fullmatch(content)
        if match is None or match.group("name") not in CORE_CRATES:
            continue

        name = match.group("name")
        if name in records:
            raise ContractError(f"Core dependency {name} is declared more than once")
        body = match.group("body")
        expected_git = f'git = "{CORE_REPOSITORY}"'
        if expected_git not in body:
            raise ContractError(f"Core dependency {name} does not use the governed repository")
        if re.search(r"\b(?:branch|tag)\s*=", body):
            raise ContractError(f"Core dependency {name} must use only an exact rev pin")
        revisions = list(REVISION.finditer(body))
        if len(revisions) != 1:
            raise ContractError(f"Core dependency {name} must contain exactly one rev pin")
        records[name] = (index, revisions[0].group("sha"), body)

    missing = sorted(set(CORE_CRATES) - set(records))
    if missing:
        raise ContractError(f"Missing governed Core dependencies: {', '.join(missing)}")
    return records


def update_manifest(cargo_path: Path, core_sha: str) -> tuple[bool, str]:
    original = cargo_path.read_text(encoding="utf-8")
    records = _dependency_records(original)
    previous = {record[1] for record in records.values()}
    if len(previous) != 1:
        raise ContractError("All six Core dependencies must start at one identical revision")
    previous_sha = previous.pop()

    if previous_sha == core_sha:
        return False, previous_sha

    lines = original.splitlines(keepends=True)
    for name in CORE_CRATES:
        index, _, _ = records[name]
        lines[index], replacements = REVISION.subn(
            lambda match: f'{match.group("prefix")}{core_sha}{match.group("suffix")}',
            lines[index],
            count=1,
        )
        if replacements != 1:
            raise ContractError(f"Could not update exact rev pin for {name}")

    updated = "".join(lines)
    updated_records = _dependency_records(updated)
    if {record[1] for record in updated_records.values()} != {core_sha}:
        raise ContractError("Updated Core revisions are not identical")
    cargo_path.write_text(updated, encoding="utf-8", newline="")
    return True, previous_sha


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain a JSON object")
    return value


def application_versions(root: Path) -> dict[str, str]:
    cargo_text = (root / "Cargo.toml").read_text(encoding="utf-8")
    cargo_match = WORKSPACE_VERSION.search(cargo_text)
    cargo = tomllib.loads(cargo_text)
    try:
        workspace_version = cargo["workspace"]["package"]["version"]
        sync_dependency_version = cargo["workspace"]["dependencies"]["marty-sync"]["version"]
    except (KeyError, TypeError) as error:
        raise ContractError("Cargo.toml has incomplete workspace version metadata") from error
    if cargo_match is None or cargo_match.group("version") != workspace_version:
        raise ContractError("Cargo.toml does not contain one exact workspace semantic version")

    tauri = _load_json(root / "src-tauri" / "tauri.conf.json")
    package = _load_json(root / "ui" / "package.json")
    package_lock = _load_json(root / "ui" / "package-lock.json")
    lock_root = package_lock.get("packages", {}).get("")
    if not isinstance(lock_root, dict):
        raise ContractError("ui/package-lock.json has no root package metadata")

    cargo_lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    locked_packages = cargo_lock.get("package")
    if not isinstance(locked_packages, list):
        raise ContractError("Cargo.lock does not contain package records")

    versions = {
        "Cargo.toml": workspace_version,
        "Cargo.toml#workspace.dependencies.marty-sync": sync_dependency_version,
        "src-tauri/tauri.conf.json": str(tauri.get("version", "")),
        "ui/package.json": str(package.get("version", "")),
        "ui/package-lock.json": str(package_lock.get("version", "")),
        "ui/package-lock.json#packages-root": str(lock_root.get("version", "")),
    }
    for name in OWNED_WORKSPACE_PACKAGES:
        matches = [
            package
            for package in locked_packages
            if isinstance(package, dict) and package.get("name") == name
        ]
        if len(matches) != 1 or matches[0].get("source") is not None:
            raise ContractError(f"Cargo.lock must contain exactly one local {name} package")
        versions[f"Cargo.lock#{name}"] = matches[0].get("version")
    if (
        not all(isinstance(value, str) for value in versions.values())
        or len(set(versions.values())) != 1
        or not STABLE_TAG.fullmatch(f"v{next(iter(versions.values()))}")
    ):
        detail = ", ".join(f"{path}={version!r}" for path, version in versions.items())
        raise ContractError(f"Application versions are incomplete or inconsistent: {detail}")
    return versions


def validate_lock(lock_path: Path, core_sha: str) -> None:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ContractError("Cargo.lock does not contain package records")

    for name in CORE_CRATES:
        matches = [package for package in packages if package.get("name") == name]
        if len(matches) != 1:
            raise ContractError(f"Cargo.lock must contain exactly one {name} package")
        source = matches[0].get("source")
        expected = f"git+{CORE_REPOSITORY}?rev={core_sha}#{core_sha}"
        if source != expected:
            raise ContractError(f"Cargo.lock does not bind {name} to the exact Core commit")


def validate_repository(root: Path, core_sha: str) -> str:
    records = _dependency_records((root / "Cargo.toml").read_text(encoding="utf-8"))
    revisions = {record[1] for record in records.values()}
    if revisions != {core_sha}:
        raise ContractError("Cargo.toml does not bind all six Core crates to the requested commit")
    validate_lock(root / "Cargo.lock", core_sha)
    versions = application_versions(root)
    return next(iter(versions.values()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--core-tag", required=True)
    parser.add_argument("--core-sha", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        root = args.root.resolve()
        validate_inputs(args.core_tag, args.core_sha)
        versions_before = application_versions(root)
        application_version = next(iter(versions_before.values()))
        changed = False
        previous_sha = args.core_sha
        if args.write:
            changed, previous_sha = update_manifest(root / "Cargo.toml", args.core_sha)
            if application_versions(root) != versions_before:
                raise ContractError("Dependency automation must not change application versions")
        else:
            application_version = validate_repository(root, args.core_sha)

        print(json.dumps({
            "application_version": application_version,
            "changed": changed,
            "core_tag": args.core_tag,
            "previous_sha": previous_sha,
            "target_sha": args.core_sha,
        }, sort_keys=True))
        return 0
    except (ContractError, OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"dependency update contract failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
