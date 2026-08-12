#!/usr/bin/env python3
"""Execute and bind packaged Marty Verifier startup checks to release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


TARGETS = {
    "x86_64-apple-darwin": "macos",
    "aarch64-apple-darwin": "macos",
    "x86_64-unknown-linux-gnu": "linux",
    "x86_64-pc-windows-msvc": "windows",
}
RUNNER_OS = {"macos": "macOS", "linux": "Linux", "windows": "Windows"}
REQUIRED_CHECKS = {
    "embedded_frontend",
    "configuration_defaults",
    "app_storage_migrations",
    "trust_storage_initialization",
    "runtime_storage_restore",
    "command_registration",
}
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
VERSION_PATTERN = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
PUBLISHABLE_SUFFIXES = (
    ".dmg",
    ".dmg.sig",
    ".app.tar.gz",
    ".app.tar.gz.sig",
    ".AppImage",
    ".AppImage.sig",
    ".AppImage.tar.gz",
    ".AppImage.tar.gz.sig",
    ".deb",
    ".deb.sig",
    ".rpm",
    ".rpm.sig",
    ".msi",
    ".msi.sig",
    ".msi.zip",
    ".msi.zip.sig",
    "-setup.exe",
    "-setup.exe.sig",
    ".nsis.zip",
    ".nsis.zip.sig",
)
MAX_PROCESS_DIAGNOSTIC_CHARS = 2_048
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class SmokeError(RuntimeError):
    """A release-blocking packaged startup validation error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_one(paths: Iterable[Path], description: str) -> Path:
    matches = sorted({path.resolve() for path in paths if path.exists()})
    if len(matches) != 1:
        raise SmokeError(f"expected exactly one {description}, found {len(matches)}")
    return matches[0]


def process_failure_diagnostic(stderr: bytes) -> str:
    detail = stderr.decode("utf-8", errors="replace")
    detail = ANSI_ESCAPE.sub("", detail)
    detail = "".join(character if character.isprintable() else " " for character in detail)
    detail = " ".join(detail.split())
    if not detail:
        return "packaged process produced no stderr diagnostic"
    if len(detail) > MAX_PROCESS_DIAGNOSTIC_CHARS:
        return detail[:MAX_PROCESS_DIAGNOSTIC_CHARS] + "..."
    return detail


def validate_identity(
    source_sha: str, application_version: str, release_version: str, target: str
) -> None:
    if not SHA_PATTERN.fullmatch(source_sha):
        raise SmokeError("source SHA is not a complete hexadecimal object ID")
    if not VERSION_PATTERN.fullmatch(application_version):
        raise SmokeError("application version is invalid")
    allowed_release = re.compile(
        rf"^{re.escape(application_version)}(?:-rc\.(?:0|[1-9]\d*))?$"
    )
    if not allowed_release.fullmatch(release_version):
        raise SmokeError("release version does not match application version")
    if target not in TARGETS:
        raise SmokeError(f"unsupported release target: {target}")


def validate_binary_report(report: dict[str, Any], version: str) -> list[str]:
    if report.get("schema_version") != 1:
        raise SmokeError("binary self-check evidence schema is unsupported")
    if report.get("application") != "marty-verifier":
        raise SmokeError("binary self-check application identity is invalid")
    if report.get("version") != version:
        raise SmokeError("binary self-check version does not match release version")
    if report.get("status") != "passed":
        raise SmokeError("binary self-check did not pass")
    checks = report.get("checks")
    if not isinstance(checks, list) or set(checks) != REQUIRED_CHECKS:
        raise SmokeError("binary self-check did not execute the complete check set")
    if len(checks) != len(REQUIRED_CHECKS):
        raise SmokeError("binary self-check contains duplicate checks")
    return sorted(checks)


def bundle_root(repository: Path, target: str) -> Path:
    return repository / "target" / target / "release" / "bundle"


def resolve_execution(repository: Path, target: str) -> tuple[Path, Path, dict[str, str]]:
    platform = TARGETS[target]
    release_root = repository / "target" / target / "release"
    bundles = bundle_root(repository, target)

    if platform == "macos":
        app = require_one(bundles.glob("macos/*.app"), "macOS application bundle")
        executable = require_one(
            [
                path
                for path in (app / "Contents" / "MacOS").iterdir()
                if path.is_file()
            ],
            "macOS application executable",
        )
        published_payload = require_one(
            bundles.glob("macos/*.app.tar.gz"), "macOS updater archive"
        )
        return executable, published_payload, {}

    if platform == "linux":
        appimage = require_one(bundles.glob("appimage/*.AppImage"), "Linux AppImage")
        return appimage, appimage, {"APPIMAGE_EXTRACT_AND_RUN": "1"}

    executable = require_one(
        [release_root / "marty-verifier.exe"], "Windows application executable"
    )
    return executable, executable, {}


def release_asset_paths(repository: Path, target: str) -> list[Path]:
    root = bundle_root(repository, target)
    if not root.is_dir():
        raise SmokeError("Tauri bundle directory is missing")

    assets = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part.endswith(".app") for part in relative_parts):
            continue
        if not path.name.endswith(PUBLISHABLE_SUFFIXES):
            continue
        assets.append(path.resolve())
    if not assets:
        raise SmokeError("Tauri produced no publishable release assets")
    names = [path.name for path in assets]
    if len(names) != len(set(names)):
        raise SmokeError("Tauri produced duplicate release asset names")
    return sorted(assets, key=lambda path: path.name)


def release_asset_name(source: Path, target: str, application_version: str) -> str:
    macos_arch = {
        "x86_64-apple-darwin": "x64",
        "aarch64-apple-darwin": "aarch64",
    }.get(target)
    if macos_arch is None:
        return source.name

    for suffix in (".app.tar.gz.sig", ".app.tar.gz"):
        if source.name.endswith(suffix):
            stem = source.name[: -len(suffix)]
            if stem.endswith(("_x64", "_aarch64")):
                return source.name
            return f"{stem}_{application_version}_{macos_arch}{suffix}"
    return source.name


def stage(args: argparse.Namespace) -> None:
    validate_identity(
        args.source_sha,
        args.application_version,
        args.release_version,
        args.target,
    )
    expected_runner = RUNNER_OS[TARGETS[args.target]]
    if args.runner_os != expected_runner:
        raise SmokeError("runner OS does not match release target")
    repository = args.repository.resolve()
    output = args.output_dir.resolve()
    if output.exists():
        raise SmokeError("startup smoke output directory already exists")
    assets_dir = output / "assets"
    assets_dir.mkdir(parents=True)

    executable, executed_payload, extra_env = resolve_execution(repository, args.target)
    binary_report_path = output / "binary-self-check.json"
    environment = os.environ.copy()
    environment.update(extra_env)
    try:
        completed = subprocess.run(
            [str(executable), "--self-check", "--report", str(binary_report_path)],
            cwd=repository,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise SmokeError("packaged startup self-check exceeded 90 seconds") from error
    if completed.returncode != 0:
        diagnostic = process_failure_diagnostic(completed.stderr)
        raise SmokeError(
            f"packaged startup self-check exited with code {completed.returncode}: "
            f"{diagnostic}"
        )
    if not binary_report_path.is_file():
        raise SmokeError("packaged application did not produce self-check evidence")
    binary_report = json.loads(binary_report_path.read_text(encoding="utf-8"))
    checks = validate_binary_report(binary_report, args.application_version)
    binary_report_path.unlink()

    release_assets = []
    for source in release_asset_paths(repository, args.target):
        destination = assets_dir / release_asset_name(
            source, args.target, args.application_version
        )
        if destination.exists():
            raise SmokeError("normalized release asset names are not unique")
        shutil.copy2(source, destination)
        release_assets.append(
            {
                "name": source.name,
                "sha256": sha256_file(destination),
                "size": destination.stat().st_size,
            }
        )

    evidence = {
        "schema_version": 1,
        "application": "marty-verifier",
        "status": "passed",
        "source_sha": args.source_sha,
        "version": args.application_version,
        "release_version": args.release_version,
        "runner_os": args.runner_os,
        "target": args.target,
        "executed_binary": {
            "name": executable.name,
            "sha256": sha256_file(executable),
            "size": executable.stat().st_size,
        },
        "packaged_payload": {
            "name": executed_payload.name,
            "sha256": sha256_file(executed_payload),
            "size": executed_payload.stat().st_size,
        },
        "checks": checks,
        "release_assets": release_assets,
    }
    (output / "startup-smoke-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_evidence(input_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    evidence_paths = sorted(input_dir.rglob("startup-smoke-evidence.json"))
    if not evidence_paths:
        raise SmokeError("no packaged startup evidence was downloaded")
    return [
        (path, json.loads(path.read_text(encoding="utf-8")))
        for path in evidence_paths
    ]


def validate_staged_evidence(
    evidence_path: Path,
    evidence: dict[str, Any],
    source_sha: str,
    application_version: str,
    release_version: str,
) -> None:
    target = evidence.get("target")
    validate_identity(source_sha, application_version, release_version, str(target))
    if evidence.get("schema_version") != 1 or evidence.get("status") != "passed":
        raise SmokeError("packaged startup evidence did not pass")
    if evidence.get("application") != "marty-verifier":
        raise SmokeError("packaged startup evidence application is invalid")
    if (
        evidence.get("source_sha") != source_sha
        or evidence.get("version") != application_version
        or evidence.get("release_version") != release_version
    ):
        raise SmokeError("packaged startup evidence identity does not match release")
    expected_runner = RUNNER_OS[TARGETS[str(target)]]
    if evidence.get("runner_os") != expected_runner:
        raise SmokeError("packaged startup evidence runner OS is invalid")
    checks = evidence.get("checks")
    if not isinstance(checks, list) or set(checks) != REQUIRED_CHECKS:
        raise SmokeError("packaged startup evidence has an incomplete check set")
    if len(checks) != len(REQUIRED_CHECKS):
        raise SmokeError("packaged startup evidence contains duplicate checks")

    for field in ["executed_binary", "packaged_payload"]:
        payload = evidence.get(field)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"name", "sha256", "size"}
            or not isinstance(payload["name"], str)
            or Path(payload["name"]).name != payload["name"]
            or not isinstance(payload["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", payload["sha256"])
            or not isinstance(payload["size"], int)
            or payload["size"] <= 0
        ):
            raise SmokeError(f"{field} evidence is malformed")

    assets = evidence.get("release_assets")
    if not isinstance(assets, list) or not assets:
        raise SmokeError("packaged startup evidence has no release assets")
    asset_dir = evidence_path.parent / "assets"
    for item in assets:
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "size"}:
            raise SmokeError("release asset evidence is malformed")
        name = item["name"]
        if not isinstance(name, str) or Path(name).name != name:
            raise SmokeError("release asset name is unsafe")
        path = asset_dir / name
        if not path.is_file():
            raise SmokeError(f"release asset is missing: {name}")
        if path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]:
            raise SmokeError(f"release asset digest mismatch: {name}")


def consolidate(args: argparse.Namespace) -> None:
    expected_targets = set(args.expected_target)
    if expected_targets != set(TARGETS):
        raise SmokeError("consolidation must require the complete release target matrix")
    validate_identity(
        args.source_sha,
        args.application_version,
        args.release_version,
        next(iter(expected_targets)),
    )

    records = load_evidence(args.input_dir.resolve())
    targets = [str(evidence.get("target")) for _, evidence in records]
    if len(targets) != len(set(targets)) or set(targets) != expected_targets:
        raise SmokeError("packaged startup evidence does not exactly match the target matrix")

    output = args.release_dir.resolve()
    if output.exists():
        raise SmokeError("release asset output directory already exists")
    output.mkdir(parents=True)
    aggregate = []
    copied_names: set[str] = set()
    for evidence_path, evidence in sorted(records, key=lambda item: item[1]["target"]):
        validate_staged_evidence(
            evidence_path,
            evidence,
            args.source_sha,
            args.application_version,
            args.release_version,
        )
        for item in evidence["release_assets"]:
            name = item["name"]
            if name in copied_names:
                raise SmokeError(f"duplicate cross-platform release asset: {name}")
            copied_names.add(name)
            shutil.copy2(evidence_path.parent / "assets" / name, output / name)
        aggregate.append(evidence)

    (output / "PACKAGED_STARTUP_EVIDENCE.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "application": "marty-verifier",
                "status": "passed",
                "source_sha": args.source_sha,
                "version": args.application_version,
                "release_version": args.release_version,
                "targets": aggregate,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("--repository", type=Path, required=True)
    stage_parser.add_argument("--source-sha", required=True)
    stage_parser.add_argument("--application-version", required=True)
    stage_parser.add_argument("--release-version", required=True)
    stage_parser.add_argument("--target", required=True)
    stage_parser.add_argument("--runner-os", required=True)
    stage_parser.add_argument("--output-dir", type=Path, required=True)
    stage_parser.set_defaults(action=stage)

    consolidate_parser = commands.add_parser("consolidate")
    consolidate_parser.add_argument("--input-dir", type=Path, required=True)
    consolidate_parser.add_argument("--source-sha", required=True)
    consolidate_parser.add_argument("--application-version", required=True)
    consolidate_parser.add_argument("--release-version", required=True)
    consolidate_parser.add_argument(
        "--expected-target", action="append", default=[], required=True
    )
    consolidate_parser.add_argument("--release-dir", type=Path, required=True)
    consolidate_parser.set_defaults(action=consolidate)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.action(args)
    except (SmokeError, OSError, json.JSONDecodeError) as error:
        print(f"packaged startup smoke failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
