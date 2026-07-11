"""Tests for the explicitly confirmed no-op mutation verification harness."""

from __future__ import annotations

from unittest import mock

import pytest
from examples import verify_reservation_modify_noop as example

from tplink_deco_api import AddressReservation, AddressReservationTable, ApiResponse, get_endpoint

_NAME = "admin.client.addr_reservation.modify"
_MAC = "AA:BB:CC:DD:EE:FF"


def test_noop_verifier_rejects_missing_confirmation_before_connecting() -> None:
    with (
        mock.patch.object(example, "DecoClient") as client_type,
        pytest.raises(PermissionError, match="--confirm must exactly equal"),
    ):
        example.main(["--mac", _MAC])

    client_type.assert_not_called()


def test_noop_verifier_rejects_invalid_mac_before_reading_password() -> None:
    with (
        mock.patch.object(example, "_password") as password,
        pytest.raises(ValueError, match="--mac is invalid"),
    ):
        example.main(["--mac", "invalid", "--confirm", _NAME])

    password.assert_not_called()


def test_noop_verifier_calls_modify_with_existing_values_and_verifies_equality(
    capsys: pytest.CaptureFixture[str],
) -> None:
    reservation = AddressReservation(_MAC, "192.168.68.10")
    table = AddressReservationTable((reservation,), 64)
    response = ApiResponse.from_api({"error_code": 0, "result": None})
    client = mock.Mock()
    client.get_address_reservations.side_effect = [table, table]
    client.call.return_value = response

    with (
        mock.patch.object(example, "_password", return_value="secret"),
        mock.patch.object(example, "DecoClient", return_value=client) as client_type,
    ):
        example.main(["--mac", _MAC, "--confirm", _NAME])

    client_type.assert_called_once_with(
        "192.168.68.1",
        "admin",
        "secret",
        timeout=60.0,
    )
    client.login.assert_called_once_with()
    client.call.assert_called_once_with(
        get_endpoint(_NAME),
        {"mac": _MAC, "ip": reservation.ip},
    )
    client.logout.assert_called_once_with()
    assert "reservation table remained identical" in capsys.readouterr().out


def test_noop_verifier_can_select_first_existing_reservation() -> None:
    first = AddressReservation("00:11:22:33:44:55", "192.168.68.11")
    second = AddressReservation(_MAC, "192.168.68.10")
    table = AddressReservationTable((second, first), 64)
    client = mock.Mock()
    client.get_address_reservations.side_effect = [table, table]
    client.call.return_value = ApiResponse.from_api({"error_code": 0, "result": None})

    with (
        mock.patch.object(example, "_password", return_value="secret"),
        mock.patch.object(example, "DecoClient", return_value=client),
    ):
        example.main(["--select-first", "--confirm", _NAME])

    client.call.assert_called_once_with(
        get_endpoint(_NAME),
        {"mac": first.mac, "ip": first.ip},
    )


def test_noop_verifier_fails_if_table_changes() -> None:
    reservation = AddressReservation(_MAC, "192.168.68.10")
    before = AddressReservationTable((reservation,), 64)
    after = AddressReservationTable((), 64)
    client = mock.Mock()
    client.get_address_reservations.side_effect = [before, after]
    client.call.return_value = ApiResponse.from_api({"error_code": 0, "result": None})

    with (
        mock.patch.object(example, "_password", return_value="secret"),
        mock.patch.object(example, "DecoClient", return_value=client),
        pytest.raises(RuntimeError, match="table changed unexpectedly"),
    ):
        example.main(["--mac", _MAC, "--confirm", _NAME])

    client.logout.assert_called_once_with()


def test_noop_verifier_fails_if_firmware_rejects_write() -> None:
    reservation = AddressReservation(_MAC, "192.168.68.10")
    table = AddressReservationTable((reservation,), 64)
    client = mock.Mock()
    client.get_address_reservations.return_value = table
    client.call.return_value = ApiResponse.from_api({"error_code": 1})

    with (
        mock.patch.object(example, "_password", return_value="secret"),
        mock.patch.object(example, "DecoClient", return_value=client),
        pytest.raises(RuntimeError, match="firmware rejected"),
    ):
        example.main(["--mac", _MAC, "--confirm", _NAME])

    assert client.get_address_reservations.call_count == 1
    client.logout.assert_called_once_with()
