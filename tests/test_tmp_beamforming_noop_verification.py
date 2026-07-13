"""Tests for the prepared TMP beamforming current-value verifier."""

from __future__ import annotations

from unittest import mock

import pytest

from tplink_deco_api import (
    TMP_BEAMFORMING_NOOP_CONFIRMATION,
)
from tplink_deco_api.tmp_beamforming_noop_verification import verify_tmp_beamforming_noop


@pytest.fixture(autouse=True)
def _authorize_lab_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "tplink_deco_api.tmp_boolean_noop_verification.verify_tmp_lab_target",
        mock.Mock(),
    )


def _read(enable: bool) -> dict[str, object]:
    return {"error_code": 0, "result": {"enable": enable}}


def test_beamforming_verifier_rejects_confirmation_before_any_request() -> None:
    client = mock.Mock()

    with pytest.raises(PermissionError, match="confirmation does not match"):
        verify_tmp_beamforming_noop(client, "wrong")

    client.request_read_json.assert_not_called()
    client._request_mutation_json.assert_not_called()


def test_beamforming_verifier_sends_current_value_and_sanitizes_evidence() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(False), _read(False)]
    client._request_mutation_json.return_value = {"error_code": 0}

    result = verify_tmp_beamforming_noop(
        client,
        TMP_BEAMFORMING_NOOP_CONFIRMATION,
    )

    assert result.verified_noop
    assert client.request_read_json.call_args_list == [mock.call(0x421B), mock.call(0x421B)]
    client._request_mutation_json.assert_called_once_with(0x421C, {"enable": False})
    assert result.to_dict() == {
        "schema_version": 1,
        "transport": "tmp_appv2_over_ssh",
        "operation_code": 0x421C,
        "operation_hex_code": "0x421C",
        "operation_name": "TMP_APPV2_OP_BEAMFORMING_SET",
        "preflight_code": 0x421B,
        "preflight_hex_code": "0x421B",
        "preflight_name": "TMP_APPV2_OP_BEAMFORMING_GET",
        "verification_code": 0x421B,
        "rollback_code": 0x421C,
        "status": "verified_noop",
        "verified_noop": True,
        "write_firmware_error_code": 0,
        "write_error_type": "",
        "post_read_succeeded": True,
        "state_unchanged": True,
        "rollback_attempted": False,
        "rollback_firmware_error_code": None,
        "rollback_error_type": "",
        "rollback_verified": None,
        "mutation_request_count": 1,
        "same_value_payload": True,
        "current_value_source": "live_preflight_0x421B",
        "parameter_keys": ["enable"],
        "parameter_values_retained": False,
        "response_values_retained": False,
        "raw_values_emitted": False,
        "different_value_write_invoked": False,
    }


def test_beamforming_verifier_restores_preflight_value_after_mismatch() -> None:
    client = mock.Mock()
    client.request_read_json.side_effect = [_read(True), _read(False), _read(True)]
    client._request_mutation_json.side_effect = [{"error_code": 0}, {"error_code": 0}]

    result = verify_tmp_beamforming_noop(
        client,
        TMP_BEAMFORMING_NOOP_CONFIRMATION,
    )

    assert result.status == "verification_failed_rollback_confirmed"
    assert result.rollback_attempted
    assert result.rollback_verified is True
    assert result.mutation_request_count == 2
    assert client._request_mutation_json.call_args_list == [
        mock.call(0x421C, {"enable": True}),
        mock.call(0x421C, {"enable": True}),
    ]
