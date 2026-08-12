#!/usr/bin/env python3
"""Run a read-only GitHub API request with bounded, fail-closed retries."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path


class GitHubApiRetryError(RuntimeError):
    """Raised when the bounded GitHub API retry budget is exhausted."""


MUTATING_ARGUMENTS = {
    "-X",
    "--method",
    "-f",
    "--raw-field",
    "-F",
    "--field",
    "--input",
}


def validate_read_only(api_arguments: Sequence[str]) -> None:
    for argument in api_arguments:
        flag = argument.split("=", 1)[0]
        if flag in MUTATING_ARGUMENTS:
            raise ValueError(
                f"GitHub API retry only supports read-only requests: {flag}"
            )


def request(
    api_arguments: Sequence[str],
    *,
    attempts: int = 4,
    initial_delay_seconds: float = 1.0,
    request_timeout_seconds: float = 30.0,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
) -> bytes:
    if not api_arguments:
        raise ValueError("at least one gh api argument is required")
    if attempts < 1:
        raise ValueError("attempts must be positive")
    if initial_delay_seconds < 0 or request_timeout_seconds <= 0:
        raise ValueError("retry delays and request timeout must be valid")
    validate_read_only(api_arguments)

    command = ["gh", "api", *api_arguments]
    last_error = "unknown error"
    for attempt in range(1, attempts + 1):
        try:
            completed = run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=request_timeout_seconds,
                check=False,
            )
            if completed.returncode == 0:
                output = completed.stdout
                return output.encode() if isinstance(output, str) else output
            error = completed.stderr
            last_error = (
                error.decode(errors="replace") if isinstance(error, bytes) else error
            ).strip()
        except subprocess.TimeoutExpired:
            last_error = f"request timed out after {request_timeout_seconds:g} seconds"

        if attempt == attempts:
            break
        delay = initial_delay_seconds * (2 ** (attempt - 1))
        print(
            f"::warning::GitHub API read attempt {attempt}/{attempts} failed; "
            f"retrying in {delay:g}s: {last_error}",
            file=sys.stderr,
        )
        sleep(delay)

    raise GitHubApiRetryError(
        f"GitHub API read failed after {attempts} attempts: {last_error}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--attempts", type=int, default=4)
    parser.add_argument("--initial-delay-seconds", type=float, default=1.0)
    parser.add_argument("--request-timeout-seconds", type=float, default=30.0)
    parser.add_argument("api_arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.api_arguments[:1] == ["--"]:
        args.api_arguments = args.api_arguments[1:]
    if not args.api_arguments:
        parser.error("provide gh api arguments after --")
    return args


def main() -> int:
    args = parse_args()
    try:
        payload = request(
            args.api_arguments,
            attempts=args.attempts,
            initial_delay_seconds=args.initial_delay_seconds,
            request_timeout_seconds=args.request_timeout_seconds,
        )
    except (GitHubApiRetryError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1

    temporary = args.output.with_name(f"{args.output.name}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
