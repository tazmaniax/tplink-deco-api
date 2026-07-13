"""Tests for the exact TMP 802.11r no-op verifier."""

from __future__ import annotations

from unittest import mock

import pytest

from tplink_deco_api import (
    TMP_IEEE80211R_NOOP_CONFIRMATION,
    DecoError,
)
from tplink_deco_api.tmp_noop_verification import verify_tmp_ieee80211r_noop


@pytest.fixture(autouse=True)
def _authorize_lab_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "tplink_deco_api.tmp_boolean_noop_verification.verify_tmp_lab_target",
        mock.Mock(),
    )


def _read(enable: bool) -> dict[str, object]:
    return {"error_code": 0, "result": {"enable": enable}}


def test_verifier_rejects_confirmation_before_any_request() -> None:
    client = mock.Mock()

    with pytest.raises(PermissionError, match="confirmation does not match"):
        verify_tmp_ieee80211r_noop(client, "wrong")

    client.assert_not_called()
    client.request_read_json.assert_not_called()
    client._request_mutation_json.assert_not_called()


def test_verifier_sends_only_current_value_and_confirms_noop() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(True), _read(True)]
    client._request_mutation_json.return_value = {"error_code": 0}
    events: list[str] = []

    result = verify_tmp_ieee80211r_noop(
        client,
        TMP_IEEE80211R_NOOP_CONFIRMATION,
        progress=events.append,
    )

    assert result.status == "verified_noop"
    assert result.verified_noop
    assert result.mutation_request_count == 1
    assert not result.rollback_attempted
    assert events == ["preflight", "write", "verify"]
    assert client.request_read_json.call_args_list == [mock.call(0x4208), mock.call(0x4208)]
    client._request_mutation_json.assert_called_once_with(0x4209, {"enable": True})
    evidence = result.to_dict()
    assert evidence["same_value_payload"] is True
    assert evidence["parameter_keys"] == ["enable"]
    assert evidence["parameter_values_retained"] is False
    assert "enable" not in {key for key in evidence if key != "parameter_keys"}


def test_verifier_records_rejection_when_state_is_unchanged() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(False), _read(False)]
    client._request_mutation_json.return_value = {"error_code": 1}

    result = verify_tmp_ieee80211r_noop(client, TMP_IEEE80211R_NOOP_CONFIRMATION)

    assert result.status == "write_rejected_or_uncertain_state_unchanged"
    assert result.write_firmware_error_code == 1
    assert result.state_unchanged is True
    assert not result.rollback_attempted


def test_verifier_rolls_back_and_confirms_after_mismatch() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(True), _read(False), _read(True)]
    client._request_mutation_json.side_effect = [
        {"error_code": 0},
        {"error_code": 0},
    ]

    result = verify_tmp_ieee80211r_noop(client, TMP_IEEE80211R_NOOP_CONFIRMATION)

    assert result.status == "verification_failed_rollback_confirmed"
    assert result.rollback_attempted
    assert result.rollback_verified is True
    assert result.mutation_request_count == 2
    assert client._request_mutation_json.call_args_list == [
        mock.call(0x4209, {"enable": True}),
        mock.call(0x4209, {"enable": True}),
    ]


def test_verifier_rolls_back_when_post_read_fails() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(False), DecoError("lost"), _read(False)]
    client._request_mutation_json.side_effect = [DecoError("uncertain"), {"error_code": 0}]

    result = verify_tmp_ieee80211r_noop(client, TMP_IEEE80211R_NOOP_CONFIRMATION)

    assert result.status == "verification_failed_rollback_confirmed"
    assert result.write_error_type == "DecoError"
    assert result.post_read_succeeded is False
    assert result.state_unchanged is None
    assert result.rollback_verified is True


def test_verifier_reports_unconfirmed_rollback_without_values() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(True), _read(False), _read(False)]
    client._request_mutation_json.side_effect = [
        {"error_code": 0},
        {"error_code": 1},
    ]

    result = verify_tmp_ieee80211r_noop(client, TMP_IEEE80211R_NOOP_CONFIRMATION)

    assert result.status == "rollback_unconfirmed"
    assert result.rollback_firmware_error_code == 1
    assert result.rollback_verified is False
    assert result.to_dict()["response_values_retained"] is False


@pytest.mark.parametrize(
    "response",
    [
        {"error_code": 1, "result": {"enable": True}},
        {"error_code": 0, "result": {}},
        {"result": {"enable": True}},
    ],
)
def test_preflight_shape_errors_fail_before_write(response: dict[str, object]) -> None:
    client = mock.Mock()
    client.request_read_json.return_value = response

    with pytest.raises(ValueError, match=r"Failed to verify TMP 802\.11r no-op"):
        verify_tmp_ieee80211r_noop(client, TMP_IEEE80211R_NOOP_CONFIRMATION)

    client._request_mutation_json.assert_not_called()
