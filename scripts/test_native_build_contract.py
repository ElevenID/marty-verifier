#!/usr/bin/env python3

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class NativeBuildContractTests(unittest.TestCase):
    def test_tauri_always_builds_current_production_frontend(self) -> None:
        config = json.loads((ROOT / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
        self.assertEqual(config["build"]["frontendDist"], "../ui/dist")
        self.assertEqual(
            config["build"]["beforeBuildCommand"],
            {"script": "pnpm build:obfuscate", "cwd": "../ui"},
        )
        self.assertEqual(
            config["build"]["beforeDevCommand"],
            {"script": "pnpm dev", "cwd": "../ui"},
        )

    def test_obfuscation_is_cross_platform_and_precedes_packaging(self) -> None:
        package = json.loads((ROOT / "ui" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["scripts"]["obfuscate"], "node scripts/obfuscate.mjs")
        self.assertEqual(
            package["scripts"]["build:obfuscate"],
            "tsc && vite build && node scripts/obfuscate.mjs",
        )
        self.assertEqual(package["scripts"]["tauri"], "cd .. && tauri")
        obfuscator = (ROOT / "ui" / "scripts" / "obfuscate.mjs").read_text(encoding="utf-8")
        self.assertIn("seed: 0x4d415254", obfuscator)
        for wrapper in ("build.bat", "build.sh", "scripts/build-dmg.sh"):
            content = (ROOT / wrapper).read_text(encoding="utf-8")
            self.assertNotIn("run obfuscate", content)
        dmg = (ROOT / "scripts" / "build-dmg.sh").read_text(encoding="utf-8")
        self.assertNotIn("Marty_Verifier_0.1.0", dmg)
        self.assertIn("tauri.conf.json", dmg)

    def test_release_workflows_do_not_duplicate_the_tauri_hook(self) -> None:
        for workflow in ("release-rc.yml", "release-stable.yml"):
            content = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            self.assertNotIn("name: Build frontend", content)
            self.assertIn("tauri-apps/tauri-action@", content)


if __name__ == "__main__":
    unittest.main()
