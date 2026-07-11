"""Tests for the prepared TMP monthly-report current-value verifier."""

from __future__ import annotations

from unittest import mock

import pytest

from tplink_deco_api import (
    TMP_MONTHLY_REPORT_NOOP_CONFIRMATION,
    verify_tmp_monthly_report_noop,
)


def _read(enable: bool) -> dict[str, object]:
    return {"error_code": 0, "result": {"enable": enable}}


def test_monthly_report_verifier_rejects_confirmation_before_any_request() -> None:
    client = mock.Mock()

    with pytest.raises(PermissionError, match="confirmation does not match"):
        verify_tmp_monthly_report_noop(client, "wrong")

    client.request_read_json.assert_not_called()
    client._request_mutation_json.assert_not_called()


def test_monthly_report_verifier_sends_current_value_and_sanitizes_evidence() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(True), _read(True)]
    client._request_mutation_json.return_value = {"error_code": 0}

    result = verify_tmp_monthly_report_noop(
        client,
        TMP_MONTHLY_REPORT_NOOP_CONFIRMATION,
    )

    assert result.verified_noop
    assert client.request_read_json.call_args_list == [mock.call(0x4222), mock.call(0x4222)]
    client._request_mutation_json.assert_called_once_with(0x4223, {"enable": True})
    evidence = result.to_dict()
    assert evidence["operation_name"] == "TMP_APPV2_OP_MONTHLY_REPORT_MGR_SET"
    assert evidence["preflight_name"] == "TMP_APPV2_OP_MONTHLY_REPORT_MGR_GET"
    assert evidence["current_value_source"] == "live_preflight_0x4222"
    assert evidence["same_value_payload"] is True
    assert evidence["parameter_keys"] == ["enable"]
    assert evidence["parameter_values_retained"] is False
    assert evidence["response_values_retained"] is False


def test_monthly_report_verifier_restores_preflight_value_after_mismatch() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(False), _read(True), _read(False)]
    client._request_mutation_json.side_effect = [{"error_code": 0}, {"error_code": 0}]

    result = verify_tmp_monthly_report_noop(
        client,
        TMP_MONTHLY_REPORT_NOOP_CONFIRMATION,
    )

    assert result.status == "verification_failed_rollback_confirmed"
    assert result.rollback_attempted
    assert result.rollback_verified is True
    assert result.mutation_request_count == 2
    assert client._request_mutation_json.call_args_list == [
        mock.call(0x4223, {"enable": False}),
        mock.call(0x4223, {"enable": False}),
    ]
