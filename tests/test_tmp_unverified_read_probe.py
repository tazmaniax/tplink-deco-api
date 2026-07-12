"""Tests for value-free discovery of newly catalogued TMP reads."""

from __future__ import annotations

import json
from dataclasses import replace
from importlib import import_module
from typing import TYPE_CHECKING

import pytest

from tplink_deco_api import TmpProtocolError, get_tmp_opcode, probe_tmp_unverified_reads

if TYPE_CHECKING:
    from collections.abc import Callable


class _Client:
    def __init__(self, response: bytes | Callable[[int, bytes], bytes]) -> None:
        self.response = response
        self.calls: list[tuple[int, bytes]] = []

    def request_read(self, opcode: int, payload: bytes = b"") -> bytes:
        self.calls.append((opcode, payload))
        if callable(self.response):
            return self.response(opcode, payload)
        return self.response


def _set_catalog(monkeypatch: object, *operations: object) -> None:
    module = import_module("tplink_deco_api.tmp_unverified_read_probe")
    monkeypatch.setattr(module, "TMP_OPCODE_CATALOG", (get_tmp_opcode(0x400F), *operations))


def test_probe_excludes_remaining_sensitive_and_set_dispatched_reads_by_default() -> None:
    client = _Client(b'{"error_code":0,"result":{"private_value":"discard-me"}}')
    events: list[tuple[str, int, int, int, str, str]] = []

    result = probe_tmp_unverified_reads(client, progress=lambda *event: events.append(event))

    assert result["schema_version"] == 2
    assert result["catalogued_untested_read_count"] == 0
    assert result["safe_candidate_count"] == 0
    assert result["selected_operation_count"] == 0
    assert result["attempted_operation_count"] == 0
    assert result["attempted_variant_count"] == 0
    assert result["positive_operation_count"] == 0
    assert result["status_counts"] == {}
    assert result["control_opcode"] == 0x400F
    assert result["control_status_counts"] == {"returned_data": 2}
    assert result["session_control_passed"] is True
    assert result["sensitive_operation_count"] == 0
    assert result["excluded_sensitive_operation_count"] == 0
    assert result["excluded_dispatch_set_operation_count"] == 0
    assert result["excluded_dispatch_set_operations"] == []
    assert result["mutation_invoked"] is False
    assert result["destructive_operation_invoked"] is False
    assert result["raw_values_emitted"] is False
    assert "discard-me" not in json.dumps(result)
    assert len(client.calls) == 2
    assert len(events) == 4
    assert events[0][0] == "control_start"
    assert events[1][0] == "control_done"
    assert events[2][0] == "control_start"
    assert events[3][0] == "control_done"


def test_probe_sensitive_opt_in_discards_values_and_retains_only_schemas(
    monkeypatch: object,
) -> None:
    client = _Client(b'{"error_code":0,"result":{"private_value":"discard-me"}}')
    candidate = replace(get_tmp_opcode(0x4092), p9_observation="untested")
    _set_catalog(monkeypatch, candidate)

    result = probe_tmp_unverified_reads(client, include_sensitive=True)

    assert result["selected_operation_count"] == 1
    assert result["attempted_operation_count"] == 1
    assert result["attempted_variant_count"] == 1
    assert result["positive_operation_count"] == 1
    assert result["status_counts"] == {"returned_data": 1}
    assert result["sensitive_operation_count"] == 1
    assert result["excluded_sensitive_operation_count"] == 0
    assert result["control_status_counts"] == {"returned_data": 2}
    assert result["session_control_passed"] is True
    assert len(client.calls) == 3
    assert "discard-me" not in json.dumps(result)


def test_probe_classifies_binary_and_appv2_rejections_without_content(
    monkeypatch: object,
) -> None:
    candidate = replace(get_tmp_opcode(0x4092), p9_observation="untested")
    _set_catalog(monkeypatch, candidate)
    binary = _Client(b"\x00\x01\x02")
    binary_result = probe_tmp_unverified_reads(binary, include_sensitive=True, max_operations=1)

    assert binary_result["selected_operation_count"] == 1
    assert binary_result["status_counts"] == {
        "returned_binary": binary_result["attempted_variant_count"]
    }
    observations = binary_result["observations"]
    assert all(observation["response_size"] == 3 for observation in observations)
    assert all(len(observation["response_sha256"]) == 64 for observation in observations)

    def rejected(opcode: int, _payload: bytes) -> bytes:
        if opcode == 0x400F:
            return b'{"error_code":0,"result":{"device_list":[]}}'
        raise TmpProtocolError("Failed to request TMP operation 0x404E: AppV2 error 12")

    rejected_result = probe_tmp_unverified_reads(
        _Client(rejected), include_sensitive=True, max_operations=1
    )
    assert rejected_result["status_counts"] == {
        "appv2_rejected": rejected_result["attempted_variant_count"]
    }
    assert all(
        observation["appv2_error_code"] == 12 for observation in rejected_result["observations"]
    )


def test_probe_excludes_set_dispatched_get_even_if_misclassified_as_read(
    monkeypatch: object,
) -> None:
    candidate = replace(
        get_tmp_opcode(0x4097),
        safety="read_only",
        p9_observation="untested",
    )
    _set_catalog(monkeypatch, candidate)

    result = probe_tmp_unverified_reads(
        _Client(b'{"error_code":0,"result":{}}'),
        include_sensitive=True,
    )

    assert result["safe_candidate_count"] == 0
    assert result["selected_operation_count"] == 0
    assert result["excluded_dispatch_set_operation_count"] == 1
    assert result["excluded_dispatch_set_operations"][0]["hex_code"] == "0x4097"


def test_probe_rejects_non_positive_operation_limit() -> None:
    with pytest.raises(ValueError, match="limit must be positive"):
        probe_tmp_unverified_reads(_Client(b"{}"), max_operations=0)
