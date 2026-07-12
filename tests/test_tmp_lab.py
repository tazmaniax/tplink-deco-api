"""Tests for the isolated TMP write-research authorization boundary."""

from __future__ import annotations

from unittest import mock

import pytest

from tplink_deco_api.server import ServerConfig
from tplink_deco_api.service import DecoService
from tplink_deco_api.tmp_lab import TmpLabTarget, verify_tmp_lab_target


def _target() -> TmpLabTarget:
    return TmpLabTarget(
        model="P9",
        firmware_version="1.3.0 Build 20250804 Rel. 58832",
        controller_mac="60:A4:B7:5D:3B:66",
    )


def _identity_response(*, model: str = "P9") -> dict[str, object]:
    return {
        "error_code": 0,
        "result": {
            "device_list": [
                {
                    "role": "master",
                    "device_model": model,
                    "software_ver": "1.3.0 Build 20250804 Rel. 58832",
                    "mac": "60-A4-B7-5D-3B-66",
                }
            ]
        },
    }


def test_lab_gate_rejects_before_router_contact(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DECO_TMP_LAB_ALLOW_WRITES", raising=False)
    client = mock.Mock()

    with pytest.raises(PermissionError, match="DECO_TMP_LAB_ALLOW_WRITES is disabled"):
        verify_tmp_lab_target(client, _target())

    client.request_read_json.assert_not_called()


def test_lab_target_requires_exact_live_controller(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECO_TMP_LAB_ALLOW_WRITES", "1")
    client = mock.Mock()
    client.request_read_json.return_value = _identity_response()

    verify_tmp_lab_target(client, _target())

    client.request_read_json.assert_called_once_with(0x400F)


def test_lab_target_rejects_identity_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECO_TMP_LAB_ALLOW_WRITES", "1")
    client = mock.Mock()
    client.request_read_json.return_value = _identity_response(model="X50")

    with pytest.raises(PermissionError, match="identity does not match"):
        verify_tmp_lab_target(client, _target())


def test_server_rejects_retired_tmp_write_gate() -> None:
    config = ServerConfig(
        host="192.0.2.1",
        username="admin",
        password="secret",
        timeout=60.0,
        allow_tmp_noop_verification=True,
    )

    with pytest.raises(ValueError, match="TMP writes are hard-disabled"):
        config.validate_server()


def test_service_hard_blocks_tmp_write_without_router_contact() -> None:
    service = DecoService(
        ServerConfig(
            host="192.0.2.1",
            username="admin",
            password="secret",
            timeout=60.0,
            allow_mutations=True,
            allow_tmp_reads=True,
            allow_tmp_noop_verification=True,
        )
    )
    service._get_tmp_client = mock.Mock()

    with pytest.raises(PermissionError, match="server-side TMP writes are hard-disabled"):
        service.verify_tmp_ieee80211r_noop("ignored")

    service._get_tmp_client.assert_not_called()
