#!/usr/bin/env python3
"""Synchronize the offline release contract from its sole owner, marty-core.

After reviewing a Core commit, run:
  python scripts/update_stable_tag_contract.py --core-repository ../marty-core --revision <full-sha>
Review and commit the generated module and pin together. CI checks the pinned
digest offline. To verify reproduction from a local Core object database, run
the same command with --check and omit --revision. The source is read with git
show, never from a potentially modified Core working tree. Release execution
does not fetch code or depend on network access. Do not edit the generated copy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent
MODULE = ROOT / "stable_tag_contract.py"
PIN = ROOT / "stable_tag_contract.source.json"
SOURCE_REPOSITORY = "ElevenID/marty-core"
SOURCE_PATH = "scripts/stable_tag_contract.py"


def source_bytes(repository: Path, revision: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Core revision must be a full lowercase commit SHA")
    commit = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", revision + "^{commit}"], text=True
    ).strip()
    if commit != revision:
        raise ValueError("Core revision must identify a commit directly")
    return subprocess.check_output(
        ["git", "-C", str(repository), "show", revision + ":" + SOURCE_PATH]
    )


def verify_pin() -> dict[str, str]:
    pin = json.loads(PIN.read_text(encoding="utf-8"))
    if pin.get("repository") != SOURCE_REPOSITORY or pin.get("path") != SOURCE_PATH:
        raise ValueError("Release contract must come from the canonical Core source")
    if not re.fullmatch(r"[0-9a-f]{40}", pin.get("revision", "")):
        raise ValueError("Release contract requires an immutable Core revision")
    if hashlib.sha256(MODULE.read_bytes()).hexdigest() != pin.get("sha256"):
        raise ValueError("Release contract differs from its pinned source digest")
    return pin


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-repository", type=Path, required=True)
    parser.add_argument("--revision")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        if args.revision:
            parser.error("--check uses the recorded revision; omit --revision")
        pin = verify_pin()
        if source_bytes(args.core_repository, pin["revision"]) != MODULE.read_bytes():
            raise ValueError("Release contract does not reproduce from its Core commit")
        print("Pinned release contract reproduces exactly from Core")
        return
    if not args.revision:
        parser.error("updates require --revision")
    content = source_bytes(args.core_repository, args.revision)
    pin = {
        "repository": SOURCE_REPOSITORY,
        "path": SOURCE_PATH,
        "revision": args.revision,
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    MODULE.write_bytes(content)
    PIN.write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
