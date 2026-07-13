#!/usr/bin/env python3
"""Prepare one separately authorized TMP monthly-report current-value no-op."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from tplink_deco_api import DecoTmpClient, TmpSshConfig
from tplink_deco_api.tmp_lab import TmpLabTarget, require_tmp_lab_write_enabled
from tplink_deco_api.tmp_monthly_report_noop_verification import (
    TMP_MONTHLY_REPORT_NOOP_CONFIRMATION,
    verify_tmp_monthly_report_noop,
)

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
    parser.add_argument("--confirm", default="")
    parser.add_argument("--target-model", default=os.environ.get("DECO_TMP_LAB_TARGET_MODEL", ""))
    parser.add_argument(
        "--target-firmware-version",
        default=os.environ.get("DECO_TMP_LAB_TARGET_FIRMWARE", ""),
    )
    parser.add_argument(
        "--target-controller-mac",
        default=os.environ.get("DECO_TMP_LAB_TARGET_MAC", ""),
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _required(value: str, name: str) -> str:
    if value:
        return value
    raise ValueError(f"Failed to run TMP monthly-report no-op verification: {name} is required")


def _password() -> str:
    password = os.environ.pop("DECO_PASSWORD", "")
    return password or getpass.getpass("Deco owner password: ")


def _progress(event: str) -> None:
    labels = {
        "preflight": "[1/3] Reading current monthly-report state...",
        "write": "[2/3] Sending the same current value...",
        "verify": "[3/3] Verifying state remained unchanged...",
        "rollback": "[rollback] Verification failed; restoring preflight value...",
        "rollback_verify": "[rollback] Verifying restored state...",
    }
    print(labels[event], flush=True)


def main(argv: Sequence[str] | None = None) -> None:
    """Run one exact verifier and persist only value-free evidence."""
    args = _arguments(argv)
    if args.timeout <= 0:
        raise ValueError(
            "Failed to run TMP monthly-report no-op verification: --timeout must be positive"
        )
    if args.confirm != TMP_MONTHLY_REPORT_NOOP_CONFIRMATION:
        raise PermissionError(
            "Failed to run TMP monthly-report no-op verification: exact confirmation is required"
        )
    require_tmp_lab_write_enabled()
    target = TmpLabTarget(
        model=_required(args.target_model, "target model"),
        firmware_version=_required(args.target_firmware_version, "target firmware version"),
        controller_mac=_required(args.target_controller_mac, "target controller MAC"),
    )
    password = _password()
    config = TmpSshConfig(
        host=args.host,
        tp_link_id=_required(args.tp_link_id, "TP-Link ID"),
        password=_required(password, "owner password"),
        host_key_sha256=_required(args.host_key_sha256, "pinned host key"),
        timeout=args.timeout,
    )
    password = ""
    print("Authorization matched; opening pinned TMP session...", flush=True)
    with DecoTmpClient(config) as client:
        result = verify_tmp_monthly_report_noop(
            client,
            args.confirm,
            target=target,
            progress=_progress,
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        f"{json.dumps(result.to_dict(), indent=2, sort_keys=True)}\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    print(f"Value-free result: {args.output}", flush=True)
    if not result.verified_noop:
        raise RuntimeError(
            f"Failed to verify TMP monthly-report no-op: result status is {result.status}"
        )


if __name__ == "__main__":
    main()
