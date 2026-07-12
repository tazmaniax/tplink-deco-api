"""Tests for the unverified TMP read example runner."""

from __future__ import annotations

import json
from unittest import mock

from examples import tmp_unverified_read_probe as example


def test_unverified_tmp_example_writes_value_free_result(
    monkeypatch: object,
    tmp_path: object,
    capsys: object,
) -> None:
    monkeypatch.setenv("DECO_PASSWORD", "secret")
    monkeypatch.setenv("DECO_TP_LINK_ID", "owner@example.com")
    monkeypatch.setenv("DECO_TMP_HOST_KEY_SHA256", "SHA256:test")
    output = tmp_path / "result.json"
    result = {
        "selected_operation_count": 1,
        "response_values_retained": False,
        "raw_values_emitted": False,
    }
    client = mock.MagicMock()
    with (
        mock.patch.object(example, "DecoTmpClient", return_value=client) as client_type,
        mock.patch.object(example, "probe_tmp_unverified_reads", return_value=result) as probe,
    ):
        example.main(
            [
                "--host",
                "192.0.2.1",
                "--max-operations",
                "1",
                "--output",
                str(output),
            ]
        )

    config = client_type.call_args.args[0]
    assert config.host == "192.0.2.1"
    assert config.tp_link_id == "owner@example.com"
    assert config.password == "secret"
    assert config.host_key_sha256 == "SHA256:test"
    probe.assert_called_once_with(
        client.__enter__.return_value,
        include_sensitive=False,
        max_operations=1,
        progress=example._progress,
    )
    assert json.loads(output.read_text()) == result
    captured = capsys.readouterr().out
    assert "TMP session ready" in captured
    assert f"Value-free result: {output}" in captured
