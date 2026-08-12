#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("packaged_startup_smoke.py")
SPEC = importlib.util.spec_from_file_location("packaged_startup_smoke", SCRIPT)
assert SPEC and SPEC.loader
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class PackagedStartupSmokeTests(unittest.TestCase):
    def binary_report(self) -> dict:
        return {
            "schema_version": 1,
            "application": "marty-verifier",
            "version": "1.2.3",
            "status": "passed",
            "checks": sorted(SMOKE.REQUIRED_CHECKS),
        }

    def test_binary_report_requires_every_owned_startup_check(self) -> None:
        report = self.binary_report()
        SMOKE.validate_binary_report(report, "1.2.3")
        report["checks"].remove("embedded_frontend")
        with self.assertRaisesRegex(SMOKE.SmokeError, "complete check set"):
            SMOKE.validate_binary_report(report, "1.2.3")

    def test_identity_allows_matching_stable_and_rc_versions(self) -> None:
        source_sha = "a" * 40
        target = "x86_64-unknown-linux-gnu"
        SMOKE.validate_identity(source_sha, "1.2.3", "1.2.3", target)
        SMOKE.validate_identity(source_sha, "1.2.3", "1.2.3-rc.1", target)
        with self.assertRaisesRegex(SMOKE.SmokeError, "does not match"):
            SMOKE.validate_identity(source_sha, "1.2.3", "1.2.4-rc.1", target)

    def test_process_failure_diagnostic_is_sanitized_and_bounded(self) -> None:
        diagnostic = SMOKE.process_failure_diagnostic(
            b"\x1b[31mstartup failed\x1b[0m\n\x00" + b"x" * 4_096
        )
        self.assertTrue(diagnostic.startswith("startup failed "))
        self.assertNotIn("\x1b", diagnostic)
        self.assertNotIn("\n", diagnostic)
        self.assertEqual(len(diagnostic), SMOKE.MAX_PROCESS_DIAGNOSTIC_CHARS + 3)

    def test_process_failure_diagnostic_handles_empty_stderr(self) -> None:
        self.assertEqual(
            SMOKE.process_failure_diagnostic(b""),
            "packaged process produced no stderr diagnostic",
        )

    def write_target(self, root: Path, target: str, content: bytes) -> None:
        target_dir = root / target
        assets = target_dir / "assets"
        assets.mkdir(parents=True)
        asset = assets / f"marty-{target}.bundle"
        asset.write_bytes(content)
        evidence = {
            "schema_version": 1,
            "application": "marty-verifier",
            "status": "passed",
            "source_sha": "a" * 40,
            "version": "1.2.3",
            "release_version": "1.2.3-rc.1",
            "runner_os": SMOKE.RUNNER_OS[SMOKE.TARGETS[target]],
            "target": target,
            "executed_binary": {
                "name": asset.name,
                "sha256": SMOKE.sha256_file(asset),
                "size": len(content),
            },
            "packaged_payload": {
                "name": asset.name,
                "sha256": SMOKE.sha256_file(asset),
                "size": len(content),
            },
            "checks": sorted(SMOKE.REQUIRED_CHECKS),
            "release_assets": [
                {
                    "name": asset.name,
                    "sha256": SMOKE.sha256_file(asset),
                    "size": len(content),
                }
            ],
        }
        (target_dir / "startup-smoke-evidence.json").write_text(
            json.dumps(evidence), encoding="utf-8"
        )

    def test_consolidation_requires_and_binds_all_four_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            for index, target in enumerate(SMOKE.TARGETS):
                self.write_target(inputs, target, f"asset-{index}".encode())
            output = root / "release"
            SMOKE.consolidate(
                Namespace(
                    input_dir=inputs,
                    source_sha="a" * 40,
                    application_version="1.2.3",
                    release_version="1.2.3-rc.1",
                    expected_target=list(SMOKE.TARGETS),
                    release_dir=output,
                )
            )
            aggregate = json.loads(
                (output / "PACKAGED_STARTUP_EVIDENCE.json").read_text()
            )
            self.assertEqual(
                {item["target"] for item in aggregate["targets"]}, set(SMOKE.TARGETS)
            )
            self.assertEqual(aggregate["source_sha"], "a" * 40)
            self.assertEqual(aggregate["version"], "1.2.3")
            self.assertEqual(aggregate["release_version"], "1.2.3-rc.1")

    def test_consolidation_rejects_asset_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            for index, target in enumerate(SMOKE.TARGETS):
                self.write_target(inputs, target, f"asset-{index}".encode())
            first = next(inputs.rglob("*.bundle"))
            first.write_bytes(b"tampered")
            with self.assertRaisesRegex(SMOKE.SmokeError, "digest mismatch"):
                SMOKE.consolidate(
                    Namespace(
                        input_dir=inputs,
                        source_sha="a" * 40,
                        application_version="1.2.3",
                        release_version="1.2.3-rc.1",
                        expected_target=list(SMOKE.TARGETS),
                        release_dir=root / "release",
                    )
                )

    def test_release_assets_preserve_linux_signatures_and_exclude_build_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            bundle = SMOKE.bundle_root(repository, "x86_64-unknown-linux-gnu")
            bundle.mkdir(parents=True)
            for name in [
                "verifier.deb",
                "verifier.deb.sig",
                "verifier.rpm",
                "verifier.rpm.sig",
            ]:
                (bundle / name).write_bytes(name.encode())
            (bundle / "verifier.wixpdb").write_bytes(b"not a release asset")

            names = {
                path.name
                for path in SMOKE.release_asset_paths(
                    repository, "x86_64-unknown-linux-gnu"
                )
            }
            self.assertEqual(
                names,
                {
                    "verifier.deb",
                    "verifier.deb.sig",
                    "verifier.rpm",
                    "verifier.rpm.sig",
                },
            )

    def test_macos_updater_assets_receive_architecture_qualified_names(self) -> None:
        neutral_archive = Path("Marty Verifier.app.tar.gz")
        neutral_signature = Path("Marty Verifier.app.tar.gz.sig")
        cases = {
            "x86_64-apple-darwin": "x64",
            "aarch64-apple-darwin": "aarch64",
        }
        for target, architecture in cases.items():
            with self.subTest(target=target):
                expected = f"Marty.Verifier_1.2.3_{architecture}.app.tar.gz"
                self.assertEqual(
                    SMOKE.release_asset_name(neutral_archive, target, "1.2.3"),
                    expected,
                )
                self.assertEqual(
                    SMOKE.release_asset_name(neutral_signature, target, "1.2.3"),
                    f"{expected}.sig",
                )

        qualified = Path("Marty Verifier_1.2.3_x64.app.tar.gz")
        self.assertEqual(
            SMOKE.release_asset_name(qualified, "x86_64-apple-darwin", "1.2.3"),
            "Marty.Verifier_1.2.3_x64.app.tar.gz",
        )
        self.assertEqual(
            SMOKE.release_asset_name(
                Path("Marty Verifier_1.2.3_amd64.AppImage.tar.gz"),
                "x86_64-unknown-linux-gnu",
                "1.2.3",
            ),
            "Marty.Verifier_1.2.3_amd64.AppImage.tar.gz",
        )
        self.assertEqual(
            SMOKE.release_asset_name(
                Path("Marty Verifier_1.2.3_x64-setup.nsis.zip"),
                "x86_64-pc-windows-msvc",
                "1.2.3",
            ),
            "Marty.Verifier_1.2.3_x64-setup.nsis.zip",
        )

    def test_stage_binds_evidence_to_canonical_release_asset_names(self) -> None:
        cases = {
            "x86_64-apple-darwin": (
                ["Marty Verifier.app.tar.gz", "Marty Verifier.app.tar.gz.sig"],
                {
                    "Marty.Verifier_1.2.3_x64.app.tar.gz",
                    "Marty.Verifier_1.2.3_x64.app.tar.gz.sig",
                },
            ),
            "aarch64-apple-darwin": (
                ["Marty Verifier.app.tar.gz", "Marty Verifier.app.tar.gz.sig"],
                {
                    "Marty.Verifier_1.2.3_aarch64.app.tar.gz",
                    "Marty.Verifier_1.2.3_aarch64.app.tar.gz.sig",
                },
            ),
            "x86_64-unknown-linux-gnu": (
                [
                    "Marty Verifier_1.2.3_amd64.AppImage.tar.gz",
                    "Marty Verifier_1.2.3_amd64.AppImage.tar.gz.sig",
                    "Marty Verifier_1.2.3_amd64.deb",
                ],
                {
                    "Marty.Verifier_1.2.3_amd64.AppImage.tar.gz",
                    "Marty.Verifier_1.2.3_amd64.AppImage.tar.gz.sig",
                    "Marty.Verifier_1.2.3_amd64.deb",
                },
            ),
            "x86_64-pc-windows-msvc": (
                [
                    "Marty Verifier_1.2.3_x64-setup.nsis.zip",
                    "Marty Verifier_1.2.3_x64-setup.nsis.zip.sig",
                    "Marty Verifier_1.2.3_x64_en-US.msi",
                ],
                {
                    "Marty.Verifier_1.2.3_x64-setup.nsis.zip",
                    "Marty.Verifier_1.2.3_x64-setup.nsis.zip.sig",
                    "Marty.Verifier_1.2.3_x64_en-US.msi",
                },
            ),
        }
        for target, (source_names, expected_names) in cases.items():
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                repository = root / "repository"
                bundle = SMOKE.bundle_root(repository, target)
                bundle.mkdir(parents=True)
                for index, name in enumerate(source_names):
                    (bundle / name).write_bytes(f"asset-{target}-{index}".encode())
                executable = repository / "marty-verifier"
                executable.write_bytes(b"executable")
                output = root / "staged"

                def run_self_check(command: list[str], **_: object) -> CompletedProcess:
                    report = Path(command[3])
                    report.write_text(
                        json.dumps(self.binary_report()), encoding="utf-8"
                    )
                    return CompletedProcess(command, 0, stdout=b"", stderr=b"")

                with (
                    patch.object(
                        SMOKE,
                        "resolve_execution",
                        return_value=(executable, executable, {}),
                    ),
                    patch.object(SMOKE.subprocess, "run", side_effect=run_self_check),
                ):
                    SMOKE.stage(
                        Namespace(
                            repository=repository,
                            source_sha="a" * 40,
                            application_version="1.2.3",
                            release_version="1.2.3-rc.1",
                            target=target,
                            runner_os=SMOKE.RUNNER_OS[SMOKE.TARGETS[target]],
                            output_dir=output,
                        )
                    )

                evidence_path = output / "startup-smoke-evidence.json"
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    {asset["name"] for asset in evidence["release_assets"]},
                    expected_names,
                )
                self.assertEqual(
                    {path.name for path in (output / "assets").iterdir()},
                    expected_names,
                )
                SMOKE.validate_staged_evidence(
                    evidence_path,
                    evidence,
                    "a" * 40,
                    "1.2.3",
                    "1.2.3-rc.1",
                )

    def test_release_metadata_binds_exact_canonical_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_dir = root / "release-assets"
            release_dir.mkdir()
            updater_payloads = {
                "darwin-x86_64": "Marty.Verifier_1.2.3_x64.app.tar.gz",
                "darwin-aarch64": "Marty.Verifier_1.2.3_aarch64.app.tar.gz",
                "linux-x86_64": "Marty.Verifier_1.2.3_amd64.AppImage.tar.gz",
                "windows-x86_64": "Marty.Verifier_1.2.3_x64-setup.nsis.zip",
            }
            for platform, name in updater_payloads.items():
                (release_dir / name).write_bytes(f"payload-{platform}".encode())
                (release_dir / f"{name}.sig").write_text(
                    f"signature-{platform}\n", encoding="utf-8"
                )
            evidence = release_dir / "PACKAGED_STARTUP_EVIDENCE.json"
            evidence.write_text('{"status":"passed"}\n', encoding="utf-8")
            sbom = root / "marty-verifier-sbom.json"
            sbom.write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")
            checksums = root / "SHA256SUMS"

            SMOKE.generate_release_metadata(
                Namespace(
                    release_dir=release_dir,
                    repository="ElevenID/marty-verifier",
                    tag="v1.2.3-rc.1",
                    application_version="1.2.3",
                    pub_date="2026-08-12T18:33:26Z",
                    sbom=sbom,
                    checksums=checksums,
                )
            )

            manifest = json.loads((release_dir / "latest.json").read_text())
            self.assertEqual(set(manifest["platforms"]), set(updater_payloads))
            for platform, payload_name in updater_payloads.items():
                entry = manifest["platforms"][platform]
                self.assertEqual(entry["url"].rsplit("/", 1)[1], payload_name)
                self.assertEqual(entry["signature"], f"signature-{platform}")
                self.assertTrue((release_dir / payload_name).is_file())

            inventory = {
                path.name: path
                for path in release_dir.iterdir()
                if path.is_file() and not path.name.endswith(".sig")
            }
            inventory[sbom.name] = sbom
            declared = {}
            for line in checksums.read_text(encoding="utf-8").splitlines():
                digest, name = line.split("  ", 1)
                declared[name] = digest
            self.assertEqual(set(declared), set(inventory))
            for name, path in inventory.items():
                self.assertNotRegex(name, r"\s")
                self.assertEqual(declared[name], SMOKE.sha256_file(path))

    def test_release_metadata_rejects_noncanonical_inventory_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_dir = root / "release-assets"
            release_dir.mkdir()
            (release_dir / "Marty Verifier_1.2.3_x64.app.tar.gz").write_bytes(
                b"payload"
            )
            sbom = root / "marty-verifier-sbom.json"
            sbom.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(SMOKE.SmokeError, "not canonical"):
                SMOKE.generate_release_metadata(
                    Namespace(
                        release_dir=release_dir,
                        repository="ElevenID/marty-verifier",
                        tag="v1.2.3",
                        application_version="1.2.3",
                        pub_date="2026-08-12T18:33:26Z",
                        sbom=sbom,
                        checksums=root / "SHA256SUMS",
                    )
                )

    def test_consolidation_still_rejects_cross_target_name_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            for index, target in enumerate(SMOKE.TARGETS):
                self.write_target(inputs, target, f"asset-{index}".encode())
                target_dir = inputs / target
                evidence_path = target_dir / "startup-smoke-evidence.json"
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                original = target_dir / "assets" / evidence["release_assets"][0]["name"]
                collision = target_dir / "assets" / "same-name.bundle"
                original.rename(collision)
                evidence["release_assets"][0]["name"] = collision.name
                evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            with self.assertRaisesRegex(
                SMOKE.SmokeError, "duplicate cross-platform release asset"
            ):
                SMOKE.consolidate(
                    Namespace(
                        input_dir=inputs,
                        source_sha="a" * 40,
                        application_version="1.2.3",
                        release_version="1.2.3-rc.1",
                        expected_target=list(SMOKE.TARGETS),
                        release_dir=root / "release",
                    )
                )

    def test_release_workflows_publish_only_after_matrix_consolidation(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        workflows = {
            "release-rc.yml": "  create-release:",
            "release-stable.yml": "  create-updater-manifest:",
        }
        for name, final_job_marker in workflows.items():
            with self.subTest(workflow=name):
                text = (repository / ".github" / "workflows" / name).read_text(
                    encoding="utf-8"
                )
                build_job = text.split("  build-tauri:", 1)[1].split(
                    final_job_marker, 1
                )[0]
                self.assertIn("Build Tauri app without publishing", build_job)
                self.assertNotIn("tagName:", build_job)
                self.assertNotIn("releaseName:", build_job)
                self.assertNotIn("releaseDraft:", build_job)
                self.assertNotIn("GITHUB_TOKEN:", build_job)
                self.assertIn("packaged_startup_smoke.py stage", build_job)
                final_job = text.split(final_job_marker, 1)[1]
                self.assertIn("packaged_startup_smoke.py consolidate", final_job)
                self.assertIn("packaged_startup_smoke.py metadata", final_job)
                self.assertLess(
                    final_job.index("packaged_startup_smoke.py consolidate"),
                    final_job.index("packaged_startup_smoke.py metadata"),
                )
                self.assertLess(
                    final_job.index("packaged_startup_smoke.py metadata"),
                    final_job.index("softprops/action-gh-release@"),
                )


if __name__ == "__main__":
    unittest.main()
