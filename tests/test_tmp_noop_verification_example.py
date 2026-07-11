"""Tests for the authorized TMP 802.11r example runner."""

from __future__ import annotations

import json
from unittest import mock

import pytest
from examples import verify_tmp_ieee80211r_noop as example

from tplink_deco_api import (
    TMP_IEEE80211R_NOOP_CONFIRMATION,
    TmpNoopVerificationResult,
)


def _result(status: str = "verified_noop") -> TmpNoopVerificationResult:
    return TmpNoopVerificationResult(
        status=status,
        operation_code=0x4209,
        preflight_code=0x4208,
        write_firmware_error_code=0,
        write_error_type="",
        post_read_succeeded=True,
        state_unchanged=True,
        rollback_attempted=False,
        rollback_firmware_error_code=None,
        rollback_error_type="",
        rollback_verified=None,
        mutation_request_count=1,
    )


def test_example_rejects_confirmation_before_credentials_or_client() -> None:
    with (
        mock.patch.object(example, "_password") as password,
        mock.patch.object(example, "DecoTmpClient") as client_type,
        pytest.raises(PermissionError, match="exact confirmation"),
    ):
        example.main(["--confirm", "wrong", "--output", "unused.json"])

    password.assert_not_called()
    client_type.assert_not_called()


def test_example_writes_owner_only_value_free_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: object,
) -> None:
    monkeypatch.setenv("DECO_PASSWORD", "secret")
    monkeypatch.setenv("DECO_TP_LINK_ID", "owner@example.com")
    monkeypatch.setenv("DECO_TMP_HOST_KEY_SHA256", "SHA256:test")
    output = tmp_path / "evidence.json"
    client = mock.MagicMock()
    result = _result()
    with (
        mock.patch.object(example, "DecoTmpClient", return_value=client) as client_type,
        mock.patch.object(example, "verify_tmp_ieee80211r_noop", return_value=result) as verify,
    ):
        example.main(
            [
                "--confirm",
                TMP_IEEE80211R_NOOP_CONFIRMATION,
                "--output",
                str(output),
            ]
        )

    config = client_type.call_args.args[0]
    assert config.password == "secret"
    verify.assert_called_once_with(
        client.__enter__.return_value,
        TMP_IEEE80211R_NOOP_CONFIRMATION,
        progress=example._progress,
    )
    assert json.loads(output.read_text())["verified_noop"] is True
    assert output.stat().st_mode & 0o777 == 0o600


def test_example_persists_failure_before_raising(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: object,
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
            "verify_tmp_ieee80211r_noop",
            return_value=_result("rollback_unconfirmed"),
        ),
        pytest.raises(RuntimeError, match="rollback_unconfirmed"),
    ):
        example.main(
            [
                "--confirm",
                TMP_IEEE80211R_NOOP_CONFIRMATION,
                "--output",
                str(output),
            ]
        )

    assert json.loads(output.read_text())["status"] == "rollback_unconfirmed"
