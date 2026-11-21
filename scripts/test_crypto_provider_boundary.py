#!/usr/bin/env python3
"""Mutate reviewed metadata to exercise provider/type-identity failures."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import unittest

from check_crypto_provider_boundary import check


FIXTURE = Path(os.environ.get(
    "MARTY_CRYPTO_METADATA",
    Path(__file__).with_name("fixtures") / "jwt-provider-metadata.json",
))
REVIEWED_METADATA = json.loads(FIXTURE.read_text(encoding="utf-8"))


def package(metadata: dict, name: str) -> dict:
    return next(item for item in metadata["packages"] if item["name"] == name)


def node(metadata: dict, name: str) -> dict:
    identity = package(metadata, name)["id"]
    return next(item for item in metadata["resolve"]["nodes"] if item["id"] == identity)


class CryptoProviderBoundaryTests(unittest.TestCase):
    def test_reviewed_metadata_passes(self) -> None:
        check(REVIEWED_METADATA)

    def test_duplicate_package_identities_fail(self) -> None:
        for name in ("jsonwebtoken", "marty-oid4vci", "sd-jwt-rs"):
            with self.subTest(name=name):
                metadata = copy.deepcopy(REVIEWED_METADATA)
                duplicate = package(metadata, name).copy()
                duplicate["id"] += "-second-identity"
                metadata["packages"].append(duplicate)
                with self.assertRaisesRegex(ValueError, "one resolved"):
                    check(metadata)

    def test_other_jwt_major_versions_fail(self) -> None:
        for version in ("10.4.0", "12.0.0"):
            with self.subTest(version=version):
                metadata = copy.deepcopy(REVIEWED_METADATA)
                package(metadata, "jsonwebtoken")["version"] = version
                with self.assertRaisesRegex(ValueError, "jsonwebtoken 11"):
                    check(metadata)

    def test_builtin_jwt_provider_features_fail(self) -> None:
        for feature in ("default", "rust_crypto", "aws_lc_rs"):
            with self.subTest(feature=feature):
                metadata = copy.deepcopy(REVIEWED_METADATA)
                node(metadata, "jsonwebtoken")["features"].append(feature)
                with self.assertRaisesRegex(ValueError, "forbidden default/provider"):
                    check(metadata)

    def test_features_must_be_lists_of_strings(self) -> None:
        for name in ("jsonwebtoken", "sd-jwt-rs", "marty-oid4vci", "marty-crypto", "marty-verification"):
            for malformed in ("kms-only", {"kms-only": True}, None, [1]):
                with self.subTest(name=name, malformed=malformed):
                    metadata = copy.deepcopy(REVIEWED_METADATA)
                    node(metadata, name)["features"] = malformed
                    with self.assertRaisesRegex(ValueError, "features must be a list of strings"):
                        check(metadata)

    def test_divergent_missing_and_duplicate_provider_edges_fail(self) -> None:
        for name in ("marty-oid4vci", "sd-jwt-rs"):
            for mutation in ("different", "missing", "duplicate"):
                with self.subTest(name=name, mutation=mutation):
                    metadata = copy.deepcopy(REVIEWED_METADATA)
                    dependencies = node(metadata, name)["deps"]
                    jwt = next(edge for edge in dependencies if edge["name"] == "jsonwebtoken")
                    if mutation == "different":
                        jwt["pkg"] = "registry+fixture://index#jsonwebtoken@10.4.0"
                    elif mutation == "missing":
                        dependencies.remove(jwt)
                    else:
                        dependencies.append(jwt.copy())
                    with self.assertRaisesRegex(ValueError, "share the resolved JWT"):
                        check(metadata)

    def test_missing_resolved_nodes_fail(self) -> None:
        for name in ("jsonwebtoken", "sd-jwt-rs", "marty-oid4vci", "marty-crypto", "marty-verification"):
            with self.subTest(name=name):
                metadata = copy.deepcopy(REVIEWED_METADATA)
                metadata["resolve"]["nodes"].remove(node(metadata, name))
                with self.assertRaisesRegex(ValueError, "one resolved node"):
                    check(metadata)

    def test_kms_only_roles_cannot_be_removed(self) -> None:
        for name in ("marty-crypto", "marty-verification", "marty-oid4vci"):
            with self.subTest(name=name):
                metadata = copy.deepcopy(REVIEWED_METADATA)
                node(metadata, name)["features"].remove("kms-only")
                with self.assertRaisesRegex(ValueError, "retain its kms-only role"):
                    check(metadata)

    def test_metadata_without_resolution_fails(self) -> None:
        metadata = copy.deepcopy(REVIEWED_METADATA)
        del metadata["resolve"]
        with self.assertRaisesRegex(ValueError, "complete resolved Cargo metadata"):
            check(metadata)


if __name__ == "__main__":
    unittest.main()
