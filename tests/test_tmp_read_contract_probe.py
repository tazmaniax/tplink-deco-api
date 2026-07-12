"""Tests for value-free TMP read contract discovery."""

from __future__ import annotations

import json
from unittest import mock

from tplink_deco_api import probe_tmp_read_contracts
from tplink_deco_api.exceptions import TmpProtocolError


def _source_response(opcode: int) -> dict[str, object]:
    responses: dict[int, dict[str, object]] = {
        0x4012: {
            "error_code": 0,
            "result": {
                "client_list": [
                    {
                        "owner_id": "private-owner-id",
                    }
                ]
            },
        },
        0x4029: {
            "error_code": 0,
            "result": {"owner_list": [{"owner_id": "private-owner-id"}]},
        },
        0x4060: {"error_code": 0, "result": {"owner_list": []}},
    }
    return responses[opcode]


def test_tmp_contract_probe_derives_values_but_returns_only_schemas() -> None:
    client = mock.Mock()

    def request(opcode: int, params: object = None) -> dict[str, object]:
        if opcode in {0x4012, 0x4029, 0x4060}:
            return _source_response(opcode)
        if opcode == 0x402D and isinstance(params, dict) and set(params) == {"owner_id"}:
            return {
                "error_code": 0,
                "result": {"name": "private-returned-name", "owner_id": params["owner_id"]},
            }
        if opcode == 0x4049 and params == {"iot_client_list": []}:
            raise TmpProtocolError("firmware rejected request")
        return {"error_code": 1, "msg": "invalid params"}

    client.request_read_json.side_effect = request
    result = probe_tmp_read_contracts(client)

    assert result["source_opcodes"] == [0x4012, 0x4029, 0x4060]
    assert result["source_value_counts"] == {"owner_ids": 1}
    assert result["attempted_count"] == 12
    assert result["confirmed_contract_count"] == 1
    assert result["confirmed_contracts"] == [
        {
            "code": 0x402D,
            "hex_code": "0x402D",
            "name": "TMP_APPV2_OP_OWNER_GET",
            "variant": "owner_id_1",
            "parameter_keys": ["owner_id"],
            "value_source": "owner_list.owner_id",
            "status": "returned_data",
            "schema_paths": [
                "$.error_code:integer",
                "$.result.name:string",
                "$.result.owner_id:string",
                "$.result:object",
                "$:object",
            ],
        }
    ]
    assert result["mutation_invoked"] is False
    assert result["active_scan_invoked"] is False
    assert result["source_values_retained"] is False
    assert result["raw_values_emitted"] is False
    serialized = json.dumps(result)
    assert "private-owner-id" not in serialized
    assert "private-returned-name" not in serialized
    transport = next(
        item for item in result["observations"] if item["variant"] == "apk_empty_iot_client_list"
    )
    assert transport["status"] == "transport_error"
    assert transport["error_type"] == "TmpProtocolError"
    assert "firmware rejected request" not in serialized


def test_tmp_contract_probe_uses_only_static_variants_without_source_values() -> None:
    client = mock.Mock()
    progress = mock.Mock()
    client.request_read_json.side_effect = lambda opcode, params=None: (
        {"error_code": 0, "result": {}} if opcode in {0x4012, 0x4029, 0x4060} else {"error_code": 1}
    )

    result = probe_tmp_read_contracts(client, progress)

    assert result["source_value_counts"] == {"owner_ids": 0}
    assert result["attempted_count"] == 4
    assert all(
        item["value_source"].startswith("deco_android_1.10.5") for item in result["observations"]
    )
    assert progress.call_count == 7
    assert progress.call_args_list[0] == mock.call(
        "source",
        1,
        3,
        0x4012,
        "TMP_APPV2_OP_CLIENT_LIST_GET",
    )
    assert progress.call_args_list[-1] == mock.call(
        "contract",
        4,
        4,
        0x4202,
        "apk_rule_version",
    )


def test_tmp_contract_probe_can_try_bounded_inferred_iot_module_variants() -> None:
    client = mock.Mock()

    def request(opcode: int, params: object = None) -> dict[str, object]:
        if opcode in {0x4012, 0x4029, 0x4060}:
            return {"error_code": 0, "result": {}}
        if opcode == 0x404B and params == {"module": "zigbee"}:
            return {
                "error_code": 0,
                "result": {"client_list": [{"name": "private-device-name"}]},
            }
        return {"error_code": 1}

    client.request_read_json.side_effect = request
    result = probe_tmp_read_contracts(
        client,
        include_inferred_iot_module_contract=True,
    )

    inference = result["inferred_iot_module_contract"]
    assert inference["included"] is True
    assert inference["hex_code"] == "0x404B"
    assert inference["parameter_keys"] == ["module"]
    assert inference["variant_count"] == 11
    assert inference["evidence"].endswith("without_call_site")
    assert result["attempted_count"] == 15
    observations = [item for item in result["observations"] if item["code"] == 0x404B]
    assert len(observations) == 11
    assert all(item["parameter_keys"] == ["module"] for item in observations)
    assert observations[0]["variant"] == "inferred_module_zigbee"
    assert observations[-1]["variant"] == "inferred_module_matter"
    assert result["confirmed_contract_count"] == 1
    serialized = json.dumps(result)
    assert "private-device-name" not in serialized
    assert result["mutation_invoked"] is False
