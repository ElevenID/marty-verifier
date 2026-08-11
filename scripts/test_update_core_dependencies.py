#!/usr/bin/env python3
"""Marty-owned contracts for Core dependency-update automation."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("update_core_dependencies.py")
SPEC = importlib.util.spec_from_file_location("update_core_dependencies", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


OLD_SHA = "1" * 40
NEW_SHA = "2" * 40


def cargo_manifest(*, missing: str | None = None, duplicate: str | None = None) -> str:
    lines = [
        "[workspace]\n",
        "[workspace.package]\n",
        'version = "0.1.3"\n',
        "[workspace.dependencies]\n",
        'marty-sync = { version = "0.1.3", path = "crates/marty-sync" }\n',
    ]
    for name in MODULE.CORE_CRATES:
        if name == missing:
            continue
        lines.append(
            f'{name} = {{ git = "{MODULE.CORE_REPOSITORY}", rev = "{OLD_SHA}", features = ["owned"] }}\n'
        )
        if name == duplicate:
            lines.append(
                f'{name} = {{ git = "{MODULE.CORE_REPOSITORY}", rev = "{OLD_SHA}" }}\n'
            )
    return "".join(lines)


def cargo_lock(sha: str) -> str:
    sections = ["version = 4\n"]
    for name in MODULE.OWNED_WORKSPACE_PACKAGES:
        sections.append(
            "\n[[package]]\n"
            f'name = "{name}"\n'
            'version = "0.1.3"\n'
        )
    for name in MODULE.CORE_CRATES:
        sections.append(
            "\n[[package]]\n"
            f'name = "{name}"\n'
            'version = "0.1.0"\n'
            f'source = "git+{MODULE.CORE_REPOSITORY}?rev={sha}#{sha}"\n'
        )
    return "".join(sections)


def write_fixture(root: Path, *, manifest: str | None = None, lock_sha: str = OLD_SHA) -> None:
    (root / "src-tauri").mkdir()
    (root / "ui").mkdir()
    (root / "Cargo.toml").write_text(manifest or cargo_manifest(), encoding="utf-8")
    (root / "Cargo.lock").write_text(cargo_lock(lock_sha), encoding="utf-8")
    (root / "src-tauri" / "tauri.conf.json").write_text(
        json.dumps({"version": "0.1.3"}), encoding="utf-8"
    )
    (root / "ui" / "package.json").write_text(
        json.dumps({"name": "marty-verifier-ui", "version": "0.1.3"}), encoding="utf-8"
    )
    (root / "ui" / "package-lock.json").write_text(
        json.dumps({
            "name": "marty-verifier-ui",
            "version": "0.1.3",
            "packages": {"": {"name": "marty-verifier-ui", "version": "0.1.3"}},
        }),
        encoding="utf-8",
    )


class UpdateCoreDependenciesTests(unittest.TestCase):
    def test_updates_exactly_six_rev_pins_without_changing_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root)
            before_versions = MODULE.application_versions(root)

            changed, previous = MODULE.update_manifest(root / "Cargo.toml", NEW_SHA)

            self.assertTrue(changed)
            self.assertEqual(previous, OLD_SHA)
            records = MODULE._dependency_records((root / "Cargo.toml").read_text(encoding="utf-8"))
            self.assertEqual(set(records), set(MODULE.CORE_CRATES))
            self.assertEqual({record[1] for record in records.values()}, {NEW_SHA})
            self.assertEqual(MODULE.application_versions(root), before_versions)

    def test_same_revision_is_an_idempotent_noop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root)
            before = (root / "Cargo.toml").read_bytes()
            changed, previous = MODULE.update_manifest(root / "Cargo.toml", OLD_SHA)
            self.assertFalse(changed)
            self.assertEqual(previous, OLD_SHA)
            self.assertEqual((root / "Cargo.toml").read_bytes(), before)

    def test_rejects_missing_or_duplicate_core_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, manifest=cargo_manifest(missing="marty-types"))
            with self.assertRaisesRegex(MODULE.ContractError, "Missing governed Core dependencies"):
                MODULE.update_manifest(root / "Cargo.toml", NEW_SHA)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, manifest=cargo_manifest(duplicate="marty-crypto"))
            with self.assertRaisesRegex(MODULE.ContractError, "declared more than once"):
                MODULE.update_manifest(root / "Cargo.toml", NEW_SHA)

    def test_rejects_mixed_or_non_rev_pins(self) -> None:
        mixed = cargo_manifest().replace(OLD_SHA, NEW_SHA, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, manifest=mixed)
            with self.assertRaisesRegex(MODULE.ContractError, "one identical revision"):
                MODULE.update_manifest(root / "Cargo.toml", NEW_SHA)

        tagged = cargo_manifest().replace(f'rev = "{OLD_SHA}"', 'tag = "v0.1.3"', 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, manifest=tagged)
            with self.assertRaisesRegex(MODULE.ContractError, "only an exact rev pin"):
                MODULE.update_manifest(root / "Cargo.toml", NEW_SHA)

    def test_check_requires_exact_lock_sources_for_all_six_crates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, lock_sha=NEW_SHA)
            MODULE.update_manifest(root / "Cargo.toml", NEW_SHA)
            self.assertEqual(MODULE.validate_repository(root, NEW_SHA), "0.1.3")

            stale = (root / "Cargo.lock").read_text(encoding="utf-8").replace(NEW_SHA, OLD_SHA, 2)
            (root / "Cargo.lock").write_text(stale, encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "exact Core commit"):
                MODULE.validate_repository(root, NEW_SHA)

    def test_rejects_prerelease_tags_and_noncanonical_shas(self) -> None:
        MODULE.validate_inputs("v0.1.46", NEW_SHA)
        for tag in ("0.1.46", "v0.1.46-rc.1", "v01.1.46", "v0.1"):
            with self.subTest(tag=tag), self.assertRaises(MODULE.ContractError):
                MODULE.validate_inputs(tag, NEW_SHA)
        with self.assertRaises(MODULE.ContractError):
            MODULE.validate_inputs("v0.1.46", "A" * 40)

    def test_rejects_partial_application_version_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root)
            package = json.loads((root / "ui" / "package.json").read_text(encoding="utf-8"))
            package["version"] = "0.1.4"
            (root / "ui" / "package.json").write_text(json.dumps(package), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "incomplete or inconsistent"):
                MODULE.application_versions(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root)
            stale_lock = (root / "Cargo.lock").read_text(encoding="utf-8").replace(
                'name = "marty-verifier"\nversion = "0.1.3"',
                'name = "marty-verifier"\nversion = "0.1.2"',
                1,
            )
            (root / "Cargo.lock").write_text(stale_lock, encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "incomplete or inconsistent"):
                MODULE.application_versions(root)


class WorkflowContractTests(unittest.TestCase):
    def test_workflow_is_pr_only_and_covers_all_core_crates(self) -> None:
        root = SCRIPT.parents[1]
        workflow = (root / ".github" / "workflows" / "auto-update-deps.yml").read_text(encoding="utf-8")
        for name in MODULE.CORE_CRATES:
            self.assertIn(name, workflow)
        self.assertIn("DEPENDENCY_PR_SECRET_NAME", workflow)
        self.assertIn("secrets[vars.DEPENDENCY_PR_SECRET_NAME]", workflow)
        self.assertNotIn("GH_TOKEN", workflow.split("steps:", 1)[0])
        self.assertIn("gh pr create --draft", workflow)
        self.assertIn('git push origin "$BRANCH"', workflow)
        self.assertIn("Roll back an unpublished exact automation branch", workflow)
        self.assertIn('remote_sha" != "$EXPECTED_SHA', workflow)
        self.assertIn("tag_ref_object_sha", workflow)
        self.assertIn("Core release identity or publication state changed", workflow)
        self.assertIn('startswith("automation/marty-core-")', workflow)
        self.assertIn("--write", workflow)
        self.assertIn("--check", workflow)
        self.assertNotIn("git tag", workflow)
        self.assertNotIn("git push\n", workflow)
        self.assertNotIn("git push --force", workflow)
        self.assertNotIn("Auto-bump version", workflow)
        self.assertNotIn("continue-on-error: true", workflow)
        self.assertNotIn("src-tauri/tauri.conf.json", workflow)
        self.assertNotIn("ui/package.json", workflow)
        self.assertNotIn("ui/package-lock.json", workflow)


if __name__ == "__main__":
    unittest.main()
