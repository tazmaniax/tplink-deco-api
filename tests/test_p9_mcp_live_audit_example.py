"""Tests for the value-free live MCP audit runner."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest import mock

import pytest
from examples import p9_mcp_live_audit as example

if TYPE_CHECKING:
    from pathlib import Path


def test_p9_mcp_live_audit_persists_only_schemas_and_digests(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("DECO_PASSWORD", "secret")
    monkeypatch.setenv("DECO_TP_LINK_ID", "owner@example.com")
    monkeypatch.setenv("DECO_TMP_HOST_KEY_SHA256", "SHA256:test")
    output = tmp_path / "audit.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "p9_mcp_live_audit.py",
            "--binary-digests",
            "--complete-tmp-batch",
            "--output",
            str(output),
        ],
    )
    tools = {
        "deco_get_p9_tmp_data": mock.Mock(),
        "deco_discover_p9_binary_reads": mock.Mock(),
        "deco_verify_p9_http_noop": mock.Mock(),
        "deco_plan_capability_mutation": mock.Mock(),
        "deco_verify_setting_noop": mock.Mock(),
        **{f"tool_{index}": mock.Mock() for index in range(43)},
    }
    server = SimpleNamespace(
        _tool_manager=SimpleNamespace(_tools=tools),
        _resource_manager=SimpleNamespace(
            _resources={f"resource_{index}": mock.Mock() for index in range(16)}
        ),
    )
    service = mock.Mock()
    service.discover_p9_binary_reads.return_value = {
        "selected_count": 3,
        "received_count": 2,
        "failed_count": 1,
        "digest_metadata_only": True,
        "binary_content_returned": False,
        "results": [
            {
                "name": "admin.firmware.config.backup",
                "status": "received",
                "size": 100,
                "sha256": "a" * 64,
                "binary_content_returned": False,
            }
        ],
    }
    service.p9_tmp_data.return_value = {
        "available_count": 55,
        "selected_count": 55,
        "parameterized_selected_count": 7,
        "parameterized_resolved_count": 7,
        "request_count": 55,
        "succeeded_count": 55,
        "failed_count": 0,
        "skipped_count": 0,
        "all_available_operations_attempted": True,
        "results": [
            {
                "code": 0x4012,
                "hex_code": "0x4012",
                "name": "TMP_APPV2_OP_CLIENT_LIST_GET",
                "category": "clients",
                "status": "ok",
                "response": {
                    "error_code": 0,
                    "result": {
                        "client_list": [{"owner_id": "private-owner-id", "name": "private-device"}]
                    },
                },
            }
        ],
    }

    with (
        mock.patch.object(example, "create_server", return_value=server),
        mock.patch.object(example, "DecoMcpService", return_value=service),
    ):
        assert example.main() == 0

    payload = json.loads(output.read_text())
    serialized = json.dumps(payload)
    assert payload["registration"]["tool_count"] == 48
    assert payload["registration"]["resource_count"] == 16
    assert payload["binary_digest_audit"]["received_count"] == 2
    tmp_audit = payload["complete_tmp_batch_audit"]
    assert tmp_audit["selected_count"] == 55
    assert tmp_audit["parameterized_resolved_count"] == 7
    assert tmp_audit["response_values_retained"] is False
    assert "$.result.client_list[].owner_id:string" in tmp_audit["observations"][0]["schema_paths"]
    assert "private-owner-id" not in serialized
    assert "private-device" not in serialized
    assert output.stat().st_mode & 0o777 == 0o600
    service.p9_tmp_data.assert_called_once_with(include_parameterized=True)
    service.close.assert_called_once_with()


def test_p9_mcp_live_audit_requires_an_explicit_audit_selection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["p9_mcp_live_audit.py", "--output", str(tmp_path / "audit.json")],
    )
    with pytest.raises(ValueError, match="select at least one audit"):
        example.main()
