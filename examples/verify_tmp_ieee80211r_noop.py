#!/usr/bin/env python3
"""Run the one authorized TMP 802.11r current-value no-op verification."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from tplink_deco_api import (
    TMP_IEEE80211R_NOOP_CONFIRMATION,
    DecoTmpClient,
    TmpSshConfig,
    verify_tmp_ieee80211r_noop,
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
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _required(value: str, name: str) -> str:
    if value:
        return value
    raise ValueError(f"Failed to run TMP 802.11r no-op verification: {name} is required")


def _password() -> str:
    password = os.environ.pop("DECO_PASSWORD", "")
    return password or getpass.getpass("Deco owner password: ")


def _progress(event: str) -> None:
    labels = {
        "preflight": "[1/3] Reading current 802.11r state...",
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
        raise ValueError("Failed to run TMP 802.11r no-op verification: --timeout must be positive")
    if args.confirm != TMP_IEEE80211R_NOOP_CONFIRMATION:
        raise PermissionError(
            "Failed to run TMP 802.11r no-op verification: exact confirmation is required"
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
        result = verify_tmp_ieee80211r_noop(
            client,
            args.confirm,
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
        raise RuntimeError(f"Failed to verify TMP 802.11r no-op: result status is {result.status}")


if __name__ == "__main__":
    main()
