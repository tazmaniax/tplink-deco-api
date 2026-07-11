#!/usr/bin/env python3
"""Probe bounded parameterized TMP GETs without retaining source values."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from tplink_deco_api import (
    DecoTmpClient,
    TmpSshConfig,
    probe_tmp_read_contracts,
)


def _required(value: str, name: str) -> str:
    if value:
        return value
    raise ValueError(f"Failed to run TMP contract probe: {name} is required")


def _progress(stage: str, index: int, total: int, code: int, label: str) -> None:
    print(f"[{stage} {index}/{total}] 0x{code:04X} {label} ...", flush=True)


def main() -> int:
    """Run the bounded read-only probe and write only value-free evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.68.1")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--tp-link-id", default=os.environ.get("DECO_TP_LINK_ID", ""))
    parser.add_argument(
        "--host-key-sha256",
        default=os.environ.get("DECO_TMP_HOST_KEY_SHA256", ""),
    )
    parser.add_argument("--include-inferred-iot-module-contract", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    password = os.environ.get("DECO_PASSWORD") or getpass.getpass("Deco owner password: ")
    config = TmpSshConfig(
        host=args.host,
        tp_link_id=_required(args.tp_link_id, "TP-Link ID"),
        password=_required(password, "owner password"),
        host_key_sha256=_required(args.host_key_sha256, "pinned host key"),
        timeout=args.timeout,
    )
    print("Credentials received; opening pinned TMP session...", flush=True)
    with DecoTmpClient(config) as client:
        print("TMP session ready; probing bounded read contracts...", flush=True)
        result = probe_tmp_read_contracts(
            client,
            _progress,
            include_inferred_iot_module_contract=args.include_inferred_iot_module_contract,
        )

    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.output is None:
        print(payload)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{payload}\n", encoding="utf-8")
        print(f"Value-free result: {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
