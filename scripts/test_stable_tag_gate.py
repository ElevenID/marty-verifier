#!/usr/bin/env python3
"""Marty-owned contracts for immutable Verifier stable-tag preparation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("stable_tag_gate.py")
SPEC = importlib.util.spec_from_file_location("stable_tag_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

RETRY_SCRIPT = Path(__file__).with_name("github_api_retry.py")
RETRY_SPEC = importlib.util.spec_from_file_location("github_api_retry", RETRY_SCRIPT)
assert RETRY_SPEC is not None and RETRY_SPEC.loader is not None
RETRY = importlib.util.module_from_spec(RETRY_SPEC)
RETRY_SPEC.loader.exec_module(RETRY)

COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
POLICY = {
    "schema": GATE.SCHEMA,
    "required_workflows": [
        {"path": ".github/workflows/ci.yml", "event": "push"},
        {"path": "dynamic/github-code-scanning/codeql", "event": "dynamic"},
    ],
}


def run(run_id: int, path: str, event: str, **updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": run_id,
        "path": path,
        "event": event,
        "status": "completed",
        "conclusion": "success",
        "head_sha": COMMIT,
    }
    value.update(updates)
    return value


def payload() -> dict[str, object]:
    return {
        "workflow_runs": [
            run(10, ".github/workflows/ci.yml", "push"),
            run(11, "dynamic/github-code-scanning/codeql", "dynamic"),
        ]
    }


def release_evidence() -> dict[str, object]:
    return {
        "schema": GATE.SCHEMA,
        "repository": "ElevenID/marty-verifier",
        "tag": "v1.2.3",
        "source_sha": COMMIT,
        "preparation_run_id": 42,
        "required_workflows": [
            {"path": ".github/workflows/ci.yml", "event": "push", "run_id": 10, "conclusion": "success"}
        ],
        "tag_object_sha": TAG_OBJECT,
        "peeled_source_sha": COMMIT,
    }


def preparation_run(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": 42,
        "path": GATE.PREPARATION_WORKFLOW,
        "event": "workflow_dispatch",
        "head_sha": COMMIT,
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
    }
    value.update(updates)
    return value


def tag_message() -> str:
    return (
        "Release 1.2.3\n\n"
        f"Stable-Tag-Gate: {GATE.SCHEMA}\n"
        "Preparation-Run: 42\n"
        f"Source-SHA: {COMMIT}\n"
    )


class StableTagEvidenceTests(unittest.TestCase):
    def test_exact_head_terminal_workflows_pass(self) -> None:
        accepted = GATE.validate_workflow_runs(payload(), POLICY, COMMIT, 99)
        self.assertEqual([item["run_id"] for item in accepted], [10, 11])

    def test_latest_pending_failing_or_different_head_workflow_blocks(self) -> None:
        cases = (
            ({"status": "in_progress", "conclusion": None}, "pending"),
            ({"conclusion": "failure"}, "did not succeed"),
            ({"head_sha": "c" * 40}, "missing"),
        )
        for updates, message in cases:
            with self.subTest(message=message):
                document = payload()
                document["workflow_runs"][0].update(updates)
                with self.assertRaisesRegex(GATE.StableTagGateError, message):
                    GATE.validate_workflow_runs(document, POLICY, COMMIT, 99)

        document = payload()
        document["workflow_runs"].append(
            run(12, ".github/workflows/ci.yml", "push", conclusion="failure")
        )
        with self.assertRaisesRegex(GATE.StableTagGateError, "did not succeed"):
            GATE.validate_workflow_runs(document, POLICY, COMMIT, 99)

    def test_duplicate_policy_entry_and_current_run_are_rejected(self) -> None:
        duplicate = {
            "schema": GATE.SCHEMA,
            "required_workflows": [POLICY["required_workflows"][0]] * 2,
        }
        with self.assertRaisesRegex(GATE.StableTagGateError, "duplicate"):
            GATE.validate_workflow_runs(payload(), duplicate, COMMIT, 99)
        with self.assertRaisesRegex(GATE.StableTagGateError, "missing"):
            GATE.validate_workflow_runs(payload(), POLICY, COMMIT, 10)

    def test_exact_annotated_release_proof_passes(self) -> None:
        GATE.validate_release_proof(
            "ElevenID/marty-verifier",
            "v1.2.3",
            COMMIT,
            "tag",
            TAG_OBJECT,
            tag_message(),
            preparation_run(),
            release_evidence(),
        )

    def test_release_proof_rejects_lightweight_tag_or_non_main_preparation(self) -> None:
        with self.assertRaisesRegex(GATE.StableTagGateError, "annotated"):
            GATE.validate_release_proof(
                "ElevenID/marty-verifier",
                "v1.2.3",
                COMMIT,
                "commit",
                TAG_OBJECT,
                tag_message(),
                preparation_run(),
                release_evidence(),
            )
        with self.assertRaisesRegex(GATE.StableTagGateError, "exact successful main"):
            GATE.validate_release_proof(
                "ElevenID/marty-verifier",
                "v1.2.3",
                COMMIT,
                "tag",
                TAG_OBJECT,
                tag_message(),
                preparation_run(head_branch="feature"),
                release_evidence(),
            )

    def test_complete_application_version_state_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src-tauri").mkdir()
            (root / "ui").mkdir()
            (root / "Cargo.toml").write_text(
                '[workspace]\n[workspace.package]\nversion = "1.2.3"\n'
                '[workspace.dependencies]\n'
                'marty-sync = { version = "1.2.3", path = "crates/marty-sync" }\n',
                encoding="utf-8",
            )
            cargo_lock = "version = 4\n" + "".join(
                f'\n[[package]]\nname = "{name}"\nversion = "1.2.3"\n'
                for name in GATE.OWNED_WORKSPACE_PACKAGES
            )
            (root / "Cargo.lock").write_text(cargo_lock, encoding="utf-8")
            (root / "src-tauri" / "tauri.conf.json").write_text(
                json.dumps({"version": "1.2.3"}), encoding="utf-8"
            )
            (root / "ui" / "package.json").write_text(
                json.dumps({"version": "1.2.3"}), encoding="utf-8"
            )
            lock = {"version": "1.2.3", "packages": {"": {"version": "1.2.3"}}}
            (root / "ui" / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            self.assertEqual(set(GATE.application_versions(root).values()), {"1.2.3"})
            GATE.validate_application_version(root, "v1.2.3")

            lock["packages"][""]["version"] = "1.2.2"
            (root / "ui" / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(GATE.StableTagGateError, "complete application version"):
                GATE.validate_application_version(root, "v1.2.3")

            lock["packages"][""]["version"] = "1.2.3"
            (root / "ui" / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            stale_cargo_lock = cargo_lock.replace(
                'name = "marty-verifier"\nversion = "1.2.3"',
                'name = "marty-verifier"\nversion = "1.2.2"',
                1,
            )
            (root / "Cargo.lock").write_text(stale_cargo_lock, encoding="utf-8")
            with self.assertRaisesRegex(GATE.StableTagGateError, "complete application version"):
                GATE.validate_application_version(root, "v1.2.3")


class GitHubApiRetryTests(unittest.TestCase):
    def test_transient_failure_retries_then_returns_payload(self) -> None:
        outcomes = [
            subprocess.CompletedProcess([], 1, b"", b"transient TLS failure"),
            subprocess.CompletedProcess([], 0, b'{"ok":true}', b""),
        ]
        commands: list[list[str]] = []
        delays: list[float] = []

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            commands.append(command)
            return outcomes.pop(0)

        payload = RETRY.request(
            ["repos/ElevenID/marty-verifier/releases"],
            attempts=3,
            initial_delay_seconds=0.5,
            run=fake_run,
            sleep=delays.append,
        )

        self.assertEqual(payload, b'{"ok":true}')
        self.assertEqual(commands, [["gh", "api", "repos/ElevenID/marty-verifier/releases"]] * 2)
        self.assertEqual(delays, [0.5])

    def test_retry_budget_exhaustion_fails_closed(self) -> None:
        attempts = 0

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            nonlocal attempts
            attempts += 1
            self.assertEqual(command[:2], ["gh", "api"])
            return subprocess.CompletedProcess(command, 1, b"", b"still unavailable")

        with self.assertRaisesRegex(RETRY.GitHubApiRetryError, "after 3 attempts"):
            RETRY.request(
                ["repos/ElevenID/marty-verifier/releases"],
                attempts=3,
                initial_delay_seconds=0,
                run=fake_run,
                sleep=lambda _: None,
            )
        self.assertEqual(attempts, 3)

    def test_mutating_api_arguments_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "read-only"):
            RETRY.request(
                ["--method", "DELETE", "repos/ElevenID/marty-verifier/releases/1"],
                run=lambda *_args, **_kwargs: self.fail("request must not execute"),
            )

class StableTagWorkflowContractTests(unittest.TestCase):
    def test_prepare_and_release_workflows_are_evidence_bound(self) -> None:
        root = SCRIPT.parents[1]
        prepare = (root / ".github/workflows/prepare-stable-tag.yml").read_text(encoding="utf-8")
        release = (root / ".github/workflows/release-stable.yml").read_text(encoding="utf-8")
        policy = json.loads((root / ".github/stable-tag-policy.json").read_text(encoding="utf-8"))

        for marker in (
            "git ls-remote --tags",
            "scripts/stable_tag_gate.py prepare",
            "git tag -a",
            "stable-tag-evidence-${{ inputs.tag }}",
            'gh workflow run release-stable.yml --ref "$TAG"',
        ):
            self.assertIn(marker, prepare)
        for marker in (
            "Run the stable workflow from the exact release tag ref",
            "scripts/stable_tag_gate.py validate-release",
            "gh run download",
            "Reject an existing draft or published release",
            "cargo test --locked",
            "Revalidate immutable tag binding",
            "Revalidate immutable tag before final release update",
            "needs.validate-release-source.outputs.commit",
            "needs.validate-release-source.outputs.tag_object",
        ):
            self.assertIn(marker, release)
        self.assertNotIn("steps.version.outputs", release)
        self.assertNotIn("ref: main", release)

        for workflow in (
            prepare,
            release,
            (root / ".github/workflows/release-rc.yml").read_text(encoding="utf-8"),
        ):
            self.assertIn("scripts/github_api_retry.py", workflow)
            self.assertNotIn("--insecure", workflow)

        paths = {item["path"] for item in policy["required_workflows"]}
        self.assertEqual(
            paths,
            {
                ".github/workflows/ci.yml",
                ".github/workflows/test.yml",
                ".github/workflows/open-source-policy.yml",
                ".github/workflows/organization-quality.yml",
                ".github/workflows/license-compliance.yml",
                "dynamic/github-code-scanning/codeql",
            },
        )


if __name__ == "__main__":
    unittest.main()
