#!/usr/bin/env python3
"""Verify one reversible P9 setting write with an unchanged-value payload."""

from __future__ import annotations

import argparse
import getpass
import os
from collections.abc import Mapping
from typing import TYPE_CHECKING

from tplink_deco_api import DecoClient, get_endpoint

if TYPE_CHECKING:
    from collections.abc import Sequence

    from tplink_deco_api._json import JsonObject, JsonValue

_READS: dict[str, str] = {
    "admin.network.wan_mode.write": "admin.network.wan_mode.read",
    "admin.wireless.ieee80211r.write": "admin.wireless.ieee80211r.read",
    "admin.wireless.beamforming.write": "admin.wireless.beamforming.read",
    "admin.wireless.operation_mode.write": "admin.wireless.operation_mode.read",
    "admin.device.timesetting.write": "admin.device.timesetting.read",
}


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.68.1")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--operation", required=True, choices=tuple(_READS))
    parser.add_argument(
        "--confirm",
        default="",
        help="must exactly equal the selected operation name",
    )
    return parser.parse_args(argv)


def _password() -> str:
    password = os.environ.pop("DECO_PASSWORD", "")
    return password or getpass.getpass("Deco owner password: ")


def _string(data: Mapping[str, JsonValue], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Failed to verify setting mutation: read result lacks {key}")
    return value


def _boolean(data: Mapping[str, JsonValue], key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to verify setting mutation: read result lacks boolean {key}")
    return value


def _state(operation: str, result: JsonObject) -> dict[str, JsonValue]:
    if operation == "admin.network.wan_mode.write":
        wan = result.get("wan")
        if not isinstance(wan, Mapping):
            raise ValueError("Failed to verify setting mutation: read result lacks wan")
        return {"mode": _string(wan, "mode")}
    if operation in {
        "admin.wireless.ieee80211r.write",
        "admin.wireless.beamforming.write",
    }:
        return {"enable": _boolean(result, "enable")}
    if operation == "admin.wireless.operation_mode.write":
        return {"mode": _string(result, "mode")}
    return {
        "timezone": _string(result, "timezone"),
        "continent": _string(result, "continent"),
        "tz_region": _string(result, "tz_region"),
    }


def main(argv: Sequence[str] | None = None) -> None:
    """Send one explicitly confirmed unchanged-value setting mutation."""
    args = _arguments(argv)
    if args.timeout <= 0:
        raise ValueError("Failed to verify setting mutation: --timeout must be positive")
    if args.confirm != args.operation:
        raise PermissionError(
            "Failed to verify setting mutation: --confirm must exactly equal --operation"
        )
    password = _password()
    client = DecoClient(args.host, args.username, password, timeout=args.timeout)
    password = ""
    read_endpoint = get_endpoint(_READS[args.operation])
    mutation_endpoint = get_endpoint(args.operation)
    try:
        client.login()
        before = _state(args.operation, client.call(read_endpoint).result_object())
        response = client.call(mutation_endpoint, before)
        if response.error_code != 0:
            raise RuntimeError(
                "Failed to verify setting mutation: firmware rejected unchanged-value write "
                f"with error_code={response.error_code}"
            )
        after = _state(args.operation, client.call(read_endpoint).result_object())
        if after != before:
            raise RuntimeError("Failed to verify setting mutation: setting changed unexpectedly")
        print(
            f"Mutation accepted with error_code={response.error_code}; "
            "verified setting remained identical."
        )
    finally:
        client.logout()


if __name__ == "__main__":
    main()
