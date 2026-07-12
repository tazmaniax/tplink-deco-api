"""Tests for the explicitly confirmed setting no-op verification harness."""

from __future__ import annotations

from unittest import mock

import pytest
from examples import verify_setting_noop as example

from tplink_deco_api import ApiResponse, get_endpoint

_CASES = (
    (
        "admin.network.wan_mode.write",
        {"wan": {"mode": "router"}},
        {"mode": "router"},
    ),
    (
        "admin.wireless.ieee80211r.write",
        {"enable": True},
        {"enable": True},
    ),
    (
        "admin.wireless.beamforming.write",
        {"enable": False},
        {"enable": False},
    ),
    (
        "admin.wireless.operation_mode.write",
        {"mode": "host"},
        {"mode": "host"},
    ),
    (
        "admin.device.timesetting.write",
        {"timezone": "GMT0BST", "continent": "Europe", "tz_region": "London"},
        {"timezone": "GMT0BST", "continent": "Europe", "tz_region": "London"},
    ),
)


def _response(result: object = None, error_code: int = 0) -> ApiResponse:
    return ApiResponse.from_api({"error_code": error_code, "result": result})


def test_setting_noop_rejects_missing_confirmation_before_connecting() -> None:
    operation = _CASES[0][0]
    with (
        mock.patch.object(example, "DecoClient") as client_type,
        pytest.raises(PermissionError, match="--confirm must exactly equal"),
    ):
        example.main(["--operation", operation])

    client_type.assert_not_called()


@pytest.mark.parametrize(("operation", "read_result", "expected_params"), _CASES)
def test_setting_noop_uses_current_values_and_verifies_state(
    operation: str,
    read_result: dict[str, object],
    expected_params: dict[str, object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    read_name = example._READS[operation]
    client = mock.Mock()
    client.call.side_effect = [
        _response(read_result),
        _response(),
        _response(read_result),
    ]
    with (
        mock.patch.object(example, "_password", return_value="secret"),
        mock.patch.object(example, "DecoClient", return_value=client),
    ):
        example.main(["--operation", operation, "--confirm", operation])

    assert client.call.call_args_list == [
        mock.call(get_endpoint(read_name)),
        mock.call(get_endpoint(operation), expected_params),
        mock.call(get_endpoint(read_name)),
    ]
    client.logout.assert_called_once_with()
    assert "verified setting remained identical" in capsys.readouterr().out


def test_setting_noop_fails_when_firmware_rejects_write() -> None:
    operation, read_result, _ = _CASES[1]
    client = mock.Mock()
    client.call.side_effect = [_response(read_result), _response(error_code=1)]
    with (
        mock.patch.object(example, "_password", return_value="secret"),
        mock.patch.object(example, "DecoClient", return_value=client),
        pytest.raises(RuntimeError, match="firmware rejected"),
    ):
        example.main(["--operation", operation, "--confirm", operation])

    client.logout.assert_called_once_with()


def test_setting_noop_fails_when_setting_changes() -> None:
    operation, read_result, _ = _CASES[3]
    client = mock.Mock()
    client.call.side_effect = [
        _response(read_result),
        _response(),
        _response({"mode": "backhaul"}),
    ]
    with (
        mock.patch.object(example, "_password", return_value="secret"),
        mock.patch.object(example, "DecoClient", return_value=client),
        pytest.raises(RuntimeError, match="changed unexpectedly"),
    ):
        example.main(["--operation", operation, "--confirm", operation])

    client.logout.assert_called_once_with()
