#!/usr/bin/env python3
"""Check the consumer-resolved JWT provider and existing KMS-only roles."""

from __future__ import annotations

import json
import sys
from typing import Any


KMS_ONLY_CRATES = ("marty-crypto", "marty-verification", "marty-oid4vci")
FORBIDDEN_JWT_FEATURES = frozenset({"default", "rust_crypto", "aws_lc_rs"})


def check(metadata: dict[str, Any]) -> None:
    """Validate Cargo metadata, including the final consumer feature union."""
    try:
        packages = metadata["packages"]
        nodes = metadata["resolve"]["nodes"]

        def package(name: str) -> dict[str, Any]:
            selected = [item for item in packages if item["name"] == name]
            if len(selected) != 1:
                raise ValueError(f"Expected one resolved {name} package identity")
            return selected[0]

        def node(selected: dict[str, Any]) -> dict[str, Any]:
            matches = [item for item in nodes if item["id"] == selected["id"]]
            if len(matches) != 1:
                raise ValueError(f"Expected one resolved node for {selected['name']}")
            return matches[0]

        def features(selected: dict[str, Any]) -> set[str]:
            values = node(selected)["features"]
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise ValueError(f"{selected['name']} features must be a list of strings")
            return set(values)

        jwt = package("jsonwebtoken")
        if not isinstance(jwt["version"], str) or not jwt["version"].startswith("11."):
            raise ValueError("The shared JWT provider must use jsonwebtoken 11")
        forbidden = features(jwt) & FORBIDDEN_JWT_FEATURES
        if forbidden:
            raise ValueError(f"JWT enables forbidden default/provider features: {sorted(forbidden)}")

        for name in ("marty-oid4vci", "sd-jwt-rs"):
            selected = package(name)
            features(selected)
            jwt_edges = [
                edge["pkg"]
                for edge in node(selected)["deps"]
                if edge["name"] == "jsonwebtoken" or edge["pkg"] == jwt["id"]
            ]
            if jwt_edges != [jwt["id"]]:
                raise ValueError(f"{name} must share the resolved JWT provider and public types")

        for name in KMS_ONLY_CRATES:
            if "kms-only" not in features(package(name)):
                raise ValueError(f"{name} must retain its kms-only role")
    except (KeyError, TypeError) as error:
        raise ValueError("Expected complete resolved Cargo metadata") from error


def main() -> int:
    try:
        check(json.load(sys.stdin))
    except (ValueError, json.JSONDecodeError) as error:
        print(f"crypto provider boundary failed: {error}", file=sys.stderr)
        return 1
    print("Verified one shared JWT 11 provider with existing KMS-only consumer roles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
