"""Tests for the bounded TMP read-contract example runner."""

from __future__ import annotations

import json
from unittest import mock

from examples import tmp_read_contract_probe as example


def test_tmp_contract_example_writes_value_free_result(
    monkeypatch: object,
    tmp_path: object,
    capsys: object,
) -> None:
    monkeypatch.setenv("DECO_PASSWORD", "secret")
    monkeypatch.setenv("DECO_TP_LINK_ID", "owner@example.com")
    monkeypatch.setenv("DECO_TMP_HOST_KEY_SHA256", "SHA256:test")
    output = tmp_path / "result.json"
    monkeypatch.setattr(
        "sys.argv",
        ["tmp_read_contract_probe.py", "--host", "192.0.2.1", "--output", str(output)],
    )
    result = {
        "confirmed_contract_count": 1,
        "source_values_retained": False,
        "raw_values_emitted": False,
    }
    client = mock.MagicMock()
    with (
        mock.patch.object(example, "DecoTmpClient", return_value=client) as client_type,
        mock.patch.object(example, "probe_tmp_read_contracts", return_value=result) as probe,
    ):
        assert example.main() == 0

    config = client_type.call_args.args[0]
    assert config.host == "192.0.2.1"
    assert config.tp_link_id == "owner@example.com"
    assert config.password == "secret"
    assert config.host_key_sha256 == "SHA256:test"
    probe.assert_called_once_with(
        client.__enter__.return_value,
        example._progress,
        include_inferred_iot_module_contract=False,
    )
    assert json.loads(output.read_text()) == result
    captured = capsys.readouterr().out
    assert "TMP session ready" in captured
    assert f"Value-free result: {output}" in captured


def test_tmp_contract_example_forwards_inferred_iot_module_opt_in(
    monkeypatch: object,
) -> None:
    monkeypatch.setenv("DECO_PASSWORD", "secret")
    monkeypatch.setenv("DECO_TP_LINK_ID", "owner@example.com")
    monkeypatch.setenv("DECO_TMP_HOST_KEY_SHA256", "SHA256:test")
    monkeypatch.setattr(
        "sys.argv",
        ["tmp_read_contract_probe.py", "--include-inferred-iot-module-contract"],
    )
    client = mock.MagicMock()
    with (
        mock.patch.object(example, "DecoTmpClient", return_value=client),
        mock.patch.object(
            example,
            "probe_tmp_read_contracts",
            return_value={"mutation_invoked": False},
        ) as probe,
    ):
        assert example.main() == 0

    probe.assert_called_once_with(
        client.__enter__.return_value,
        example._progress,
        include_inferred_iot_module_contract=True,
    )
