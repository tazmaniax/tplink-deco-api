#!/usr/bin/env python3
"""Probe newly catalogued TMP reads and retain only schemas and error codes."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from tplink_deco_api import DecoTmpClient, TmpSshConfig, probe_tmp_unverified_reads

if TYPE_CHECKING:
    from collections.abc import Sequence


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.68.1")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--tp-link-id", default=os.environ.get("DECO_TP_LINK_ID", ""))
    parser.add_argument(
        "--host-key-sha256",
        default=os.environ.get("DECO_TMP_HOST_KEY_SHA256", ""),
    )
    parser.add_argument("--include-sensitive", action="store_true")
    parser.add_argument("--max-operations", type=int)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _required(value: str, name: str) -> str:
    if value:
        return value
    raise ValueError(f"Failed to run unverified TMP read probe: {name} is required")


def _password() -> str:
    password = os.environ.pop("DECO_PASSWORD", "")
    return password or getpass.getpass("Deco owner password: ")


def _progress(event: str, index: int, total: int, code: int, name: str, detail: str) -> None:
    if event == "control_start":
        print(f"[control {detail}] 0x{code:04X} {name} ...", end="", flush=True)
    elif event == "start":
        print(
            f"[read {index}/{total}] 0x{code:04X} {name} [{detail}] ...",
            end="",
            flush=True,
        )
    else:
        print(f" {detail}", flush=True)


def main(argv: Sequence[str] | None = None) -> None:
    """Run the read-only probe and write value-free evidence."""
    args = _arguments(argv)
    if args.timeout <= 0:
        raise ValueError("Failed to run unverified TMP read probe: --timeout must be positive")
    password = _password()
    config = TmpSshConfig(
        host=args.host,
        tp_link_id=_required(args.tp_link_id, "TP-Link ID"),
        password=_required(password, "owner password"),
        host_key_sha256=_required(args.host_key_sha256, "pinned host key"),
        timeout=args.timeout,
    )
    password = ""
    print("Credentials received; opening pinned TMP session...", flush=True)
    with DecoTmpClient(config) as client:
        print("TMP session ready; probing newly catalogued reads...", flush=True)
        result = probe_tmp_unverified_reads(
            client,
            include_sensitive=args.include_sensitive,
            max_operations=args.max_operations,
            progress=_progress,
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(f"{json.dumps(result, indent=2, sort_keys=True)}\n", encoding="utf-8")
    print(f"Value-free result: {args.output}", flush=True)


if __name__ == "__main__":
    main()
