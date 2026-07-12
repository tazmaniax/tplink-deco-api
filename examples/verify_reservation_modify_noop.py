"""Verify P9 address-reservation modify support with an explicitly confirmed no-op."""

from __future__ import annotations

import argparse
import getpass
import os
import re
from typing import TYPE_CHECKING

from tplink_deco_api import DecoClient, get_endpoint

if TYPE_CHECKING:
    from collections.abc import Sequence

_OPERATION = "admin.client.addr_reservation.modify"


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send an existing reservation's unchanged MAC/IP through the P9 modify operation."
        )
    )
    parser.add_argument("--host", default="192.168.68.1")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--timeout", type=float, default=60.0)
    target = parser.add_mutually_exclusive_group()
    target.add_argument(
        "--mac",
        default=os.environ.get("DECO_TEST_RESERVATION_MAC", ""),
        help="existing reservation MAC; defaults to DECO_TEST_RESERVATION_MAC",
    )
    target.add_argument(
        "--select-first",
        action="store_true",
        help="select the lexicographically first existing reservation without displaying it",
    )
    parser.add_argument(
        "--confirm",
        default="",
        help=f"must exactly equal {_OPERATION}",
    )
    return parser.parse_args(argv)


def _normalized_mac(value: str) -> str:
    normalized = value.replace("-", ":").upper()
    if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", normalized) is None:
        raise ValueError("Failed to verify reservation mutation: --mac is invalid")
    return normalized


def _password() -> str:
    password = os.environ.pop("DECO_PASSWORD", "")
    return password or getpass.getpass("Deco owner password: ")


def main(argv: Sequence[str] | None = None) -> None:
    """Run the explicitly confirmed no-op mutation and verify table equality."""
    args = _arguments(argv)
    if args.timeout <= 0:
        raise ValueError("Failed to verify reservation mutation: --timeout must be positive")
    if args.confirm != _OPERATION:
        raise PermissionError(
            f"Failed to verify reservation mutation: --confirm must exactly equal {_OPERATION}"
        )
    if not args.select_first and not args.mac:
        raise ValueError(
            "Failed to verify reservation mutation: --mac or --select-first is required"
        )
    mac = "" if args.select_first else _normalized_mac(args.mac)
    password = _password()
    client = DecoClient(
        args.host,
        args.username,
        password,
        timeout=args.timeout,
    )
    password = ""
    try:
        client.login()
        before = client.get_address_reservations()
        if args.select_first:
            if not before.reservations:
                raise ValueError(
                    "Failed to verify reservation mutation: reservation table is empty"
                )
            mac = min(item.mac for item in before.reservations)
        matches = [reservation for reservation in before.reservations if reservation.mac == mac]
        if len(matches) != 1:
            raise ValueError(
                "Failed to verify reservation mutation: MAC must match exactly one reservation"
            )
        reservation = matches[0]
        before_entries = {(item.mac, item.ip) for item in before.reservations}
        response = client.call(
            get_endpoint(_OPERATION),
            {"mac": reservation.mac, "ip": reservation.ip},
        )
        if response.error_code != 0:
            raise RuntimeError(
                "Failed to verify reservation mutation: firmware rejected unchanged-value "
                f"write with error_code={response.error_code}"
            )
        after = client.get_address_reservations()
        after_entries = {(item.mac, item.ip) for item in after.reservations}
        if before_entries != after_entries:
            raise RuntimeError(
                "Failed to verify reservation mutation: reservation table changed unexpectedly"
            )
        print(
            "Mutation accepted with error_code="
            f"{response.error_code}; reservation table remained identical."
        )
    finally:
        client.logout()


if __name__ == "__main__":
    main()
