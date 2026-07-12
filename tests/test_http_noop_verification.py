"""Tests for scoped P9 HTTP current-value no-op verification."""

from __future__ import annotations

import json
from unittest import mock

import pytest

from tplink_deco_api import (
    HTTP_NOOP_CONFIRMATIONS,
    ApiResponse,
    get_endpoint,
    verify_http_setting_noop,
)

_CASES = (
    (
        "admin.wireless.beamforming.write",
        "admin.wireless.beamforming.read",
        {"enable": False},
    ),
    (
        "admin.wireless.ieee80211r.write",
        "admin.wireless.ieee80211r.read",
        {"enable": True},
    ),
    (
        "admin.device.timesetting.write",
        "admin.device.timesetting.read",
        {"timezone": "GMT0BST", "continent": "Europe", "tz_region": "London"},
    ),
)


def _response(result: object = None, error_code: int = 0) -> ApiResponse:
    return ApiResponse.from_api({"error_code": error_code, "result": result})


def test_http_noop_rejects_unknown_or_unconfirmed_operation_before_request() -> None:
    client = mock.Mock()
    with pytest.raises(ValueError, match="unsupported operation"):
        verify_http_setting_noop(client, "admin.device.reboot.reboot", "wrong")
    with pytest.raises(PermissionError, match="confirmation does not match"):
        verify_http_setting_noop(client, _CASES[0][0], "wrong")
    client.call.assert_not_called()


@pytest.mark.parametrize(("operation", "read_operation", "state"), _CASES)
def test_http_noop_uses_current_state_and_returns_value_free_evidence(
    operation: str,
    read_operation: str,
    state: dict[str, object],
) -> None:
    client = mock.Mock()
    progress = mock.Mock()
    client.call.side_effect = [_response(state), _response(), _response(state)]

    result = verify_http_setting_noop(
        client,
        operation,
        HTTP_NOOP_CONFIRMATIONS[operation],
        progress,
    )

    assert result.verified_noop
    assert result.status == "verified_noop"
    assert result.state_unchanged is True
    assert result.rollback_attempted is False
    assert result.mutation_request_count == 1
    assert client.call.call_args_list == [
        mock.call(get_endpoint(read_operation)),
        mock.call(get_endpoint(operation), state),
        mock.call(get_endpoint(read_operation)),
    ]
    assert progress.call_args_list == [
        mock.call("preflight"),
        mock.call("write"),
        mock.call("verify"),
    ]
    evidence = result.to_dict()
    assert evidence["parameter_keys"] == sorted(state)
    assert evidence["parameter_values_retained"] is False
    assert evidence["response_values_retained"] is False
    assert evidence["different_value_write_invoked"] is False
    serialized = json.dumps(evidence)
    assert all(value not in serialized for value in state.values() if isinstance(value, str))


def test_http_noop_reports_rejected_write_when_state_remains_unchanged() -> None:
    operation, _, state = _CASES[0]
    client = mock.Mock()
    client.call.side_effect = [_response(state), _response(error_code=1), _response(state)]

    result = verify_http_setting_noop(
        client,
        operation,
        HTTP_NOOP_CONFIRMATIONS[operation],
    )

    assert result.status == "write_rejected_or_uncertain_state_unchanged"
    assert not result.verified_noop
    assert result.write_firmware_error_code == 1
    assert result.rollback_attempted is False


def test_http_noop_restores_preflight_state_after_mismatch() -> None:
    operation, read_operation, state = _CASES[1]
    changed = {"enable": not state["enable"]}
    client = mock.Mock()
    client.call.side_effect = [
        _response(state),
        _response(),
        _response(changed),
        _response(),
        _response(state),
    ]

    result = verify_http_setting_noop(
        client,
        operation,
        HTTP_NOOP_CONFIRMATIONS[operation],
    )

    assert result.status == "verification_failed_rollback_confirmed"
    assert not result.verified_noop
    assert result.rollback_attempted is True
    assert result.rollback_verified is True
    assert result.mutation_request_count == 2
    assert client.call.call_args_list[-2:] == [
        mock.call(get_endpoint(operation), state),
        mock.call(get_endpoint(read_operation)),
    ]


def test_http_noop_reports_unconfirmed_rollback_after_post_read_failure() -> None:
    operation, _, state = _CASES[2]
    client = mock.Mock()
    client.call.side_effect = [
        _response(state),
        _response(),
        ValueError("post read failed"),
        _response(),
        ValueError("rollback read failed"),
    ]

    result = verify_http_setting_noop(
        client,
        operation,
        HTTP_NOOP_CONFIRMATIONS[operation],
    )

    assert result.status == "rollback_unconfirmed"
    assert result.post_read_succeeded is False
    assert result.state_unchanged is None
    assert result.rollback_attempted is True
    assert result.rollback_verified is None


def test_http_noop_rejects_invalid_preflight_before_write() -> None:
    operation = _CASES[0][0]
    client = mock.Mock()
    client.call.return_value = _response({"enable": "invalid"})

    with pytest.raises(ValueError, match="lacks boolean enable"):
        verify_http_setting_noop(
            client,
            operation,
            HTTP_NOOP_CONFIRMATIONS[operation],
        )

    client.call.assert_called_once_with(get_endpoint(_CASES[0][1]))
