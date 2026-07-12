#!/usr/bin/env python3
"""Probe the three safe untested P9 HTTP reads and retain only schemas."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from tplink_deco_api import DecoClient, get_endpoint

if TYPE_CHECKING:
    from collections.abc import Sequence

_TARGET_NAMES: tuple[str, ...] = (
    "admin.firmware.upgrade.read",
    "admin.cloud.firmware_status.check",
    "admin.cloud.firmware_status.check_upgrade",
)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.68.1")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _password() -> str:
    password = os.environ.pop("DECO_PASSWORD", "")
    return password or getpass.getpass("Deco owner password: ")


def main(argv: Sequence[str] | None = None) -> None:
    """Run the targeted read-only probe with endpoint-level progress."""
    args = _arguments(argv)
    if args.timeout <= 0:
        raise ValueError("Failed to probe P9 HTTP gaps: --timeout must be positive")
    password = _password()
    client = DecoClient(args.host, args.username, password, timeout=args.timeout)
    password = ""
    observations = []
    try:
        client.login()
        print("Authenticated. Probing three safe untested HTTP reads...", flush=True)
        for index, name in enumerate(_TARGET_NAMES, start=1):
            print(f"[endpoint {index}/{len(_TARGET_NAMES)}] {name} ...", end="", flush=True)
            observation = client.observe_endpoint_schema(get_endpoint(name))
            observations.append(observation)
            print(
                f" {observation.status} "
                f"(error_code={observation.error_code!r}, "
                f"schema_paths={len(observation.schema_paths)})",
                flush=True,
            )
    finally:
        client.logout()

    result = {
        "schema_version": 1,
        "observed_at": datetime.now(UTC).isoformat(),
        "model": "P9",
        "probe_kind": "targeted_untested_nonsecret_http_reads",
        "selected_count": len(_TARGET_NAMES),
        "selected_operations": list(_TARGET_NAMES),
        "observations": [observation.to_dict() for observation in observations],
        "sensitive_operations_included": False,
        "binary_operations_included": False,
        "mutation_invoked": False,
        "values_retained": False,
        "raw_values_emitted": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(f"{json.dumps(result, indent=2, sort_keys=True)}\n", encoding="utf-8")
    print(f"Value-free result: {args.output}", flush=True)


if __name__ == "__main__":
    main()
