"""Tests for the prepared TMP beamforming example runner."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest import mock

import pytest
from examples import verify_tmp_beamforming_noop as example

from tplink_deco_api import (
    TMP_BEAMFORMING_NOOP_CONFIRMATION,
    TmpNoopVerificationResult,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _lab_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECO_TMP_LAB_ALLOW_WRITES", "1")
    monkeypatch.setenv("DECO_TMP_LAB_TARGET_MODEL", "P9")
    monkeypatch.setenv("DECO_TMP_LAB_TARGET_FIRMWARE", "test-firmware")
    monkeypatch.setenv("DECO_TMP_LAB_TARGET_MAC", "AA:BB:CC:DD:EE:FF")


def _result(status: str = "verified_noop") -> TmpNoopVerificationResult:
    return TmpNoopVerificationResult(
        status=status,
        operation_code=0x421C,
        preflight_code=0x421B,
        write_firmware_error_code=0,
        write_error_type="",
        post_read_succeeded=True,
        state_unchanged=True,
        rollback_attempted=False,
        rollback_firmware_error_code=None,
        rollback_error_type="",
        rollback_verified=None,
        mutation_request_count=1,
        operation_name="TMP_APPV2_OP_BEAMFORMING_SET",
        preflight_name="TMP_APPV2_OP_BEAMFORMING_GET",
    )


def test_beamforming_example_rejects_before_credentials_or_client() -> None:
    with (
        mock.patch.object(example, "_password") as password,
        mock.patch.object(example, "DecoTmpClient") as client_type,
        pytest.raises(PermissionError, match="exact confirmation"),
    ):
        example.main(["--confirm", "wrong", "--output", "unused.json"])

    password.assert_not_called()
    client_type.assert_not_called()


def test_beamforming_example_writes_owner_only_value_free_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("DECO_PASSWORD", "secret")
    monkeypatch.setenv("DECO_TP_LINK_ID", "owner@example.com")
    monkeypatch.setenv("DECO_TMP_HOST_KEY_SHA256", "SHA256:test")
    output = tmp_path / "evidence.json"
    client = mock.MagicMock()
    result = _result()
    with (
        mock.patch.object(example, "DecoTmpClient", return_value=client),
        mock.patch.object(example, "verify_tmp_beamforming_noop", return_value=result) as verify,
    ):
        example.main(
            [
                "--confirm",
                TMP_BEAMFORMING_NOOP_CONFIRMATION,
                "--output",
                str(output),
            ]
        )

    verify.assert_called_once_with(
        client.__enter__.return_value,
        TMP_BEAMFORMING_NOOP_CONFIRMATION,
        target=mock.ANY,
        progress=example._progress,
    )
    evidence = json.loads(output.read_text())
    assert evidence["operation_hex_code"] == "0x421C"
    assert evidence["parameter_values_retained"] is False
    assert output.stat().st_mode & 0o777 == 0o600


def test_beamforming_example_persists_nonverified_result_before_raising(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("DECO_PASSWORD", "secret")
    monkeypatch.setenv("DECO_TP_LINK_ID", "owner@example.com")
    monkeypatch.setenv("DECO_TMP_HOST_KEY_SHA256", "SHA256:test")
    output = tmp_path / "failure.json"
    client = mock.MagicMock()
    with (
        mock.patch.object(example, "DecoTmpClient", return_value=client),
        mock.patch.object(
            example,
            "verify_tmp_beamforming_noop",
            return_value=_result("rollback_unconfirmed"),
        ),
        pytest.raises(RuntimeError, match="rollback_unconfirmed"),
    ):
        example.main(
            [
                "--confirm",
                TMP_BEAMFORMING_NOOP_CONFIRMATION,
                "--output",
                str(output),
            ]
        )

    assert json.loads(output.read_text())["status"] == "rollback_unconfirmed"
