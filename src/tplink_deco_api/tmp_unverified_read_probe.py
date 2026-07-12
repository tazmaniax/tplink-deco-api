"""Bounded, value-free discovery for untested TMP/AppV2 reads."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from ._json import loads
from .exceptions import DecoError
from .tmp_opcode_catalog import TMP_OPCODE_CATALOG

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._json import JsonValue
    from .models import TmpOpcodeSpec
    from .tmp_client import DecoTmpClient

_APPV2_ERROR = re.compile(r"AppV2 error (\d+)")
_CONTROL_OPCODE = 0x400F
_POSITIVE_STATUSES: frozenset[str] = frozenset(
    {"accepted_empty", "returned_binary", "returned_data"}
)


def probe_tmp_unverified_reads(
    client: DecoTmpClient,
    *,
    include_sensitive: bool = False,
    max_operations: int | None = None,
    progress: Callable[[str, int, int, int, str, str], None] | None = None,
) -> dict[str, JsonValue]:
    """Probe untested read-classified opcodes without returning response values."""
    if max_operations is not None and max_operations <= 0:
        raise ValueError("Failed to probe unverified TMP reads: limit must be positive")
    candidates = tuple(
        opcode
        for opcode in TMP_OPCODE_CATALOG
        if opcode.safety == "read_only" and opcode.p9_observation == "untested"
    )
    dispatch_set_operations = tuple(
        opcode for opcode in candidates if "set" in opcode.app_dispatch_methods
    )
    safe_candidates = tuple(
        opcode for opcode in candidates if opcode not in dispatch_set_operations
    )
    selected = tuple(
        opcode for opcode in safe_candidates if include_sensitive or opcode.sensitivity != "secret"
    )
    if max_operations is not None:
        selected = selected[:max_operations]
    variants = tuple(
        (opcode, label, params) for opcode in selected for label, params in _variants(opcode)
    )
    control_operation = next(
        opcode for opcode in TMP_OPCODE_CATALOG if opcode.code == _CONTROL_OPCODE
    )
    control_observations: list[dict[str, JsonValue]] = []
    control_observations.append(
        _run_control(client, control_operation, "before", len(variants), progress)
    )
    observations: list[dict[str, JsonValue]] = []
    for index, (opcode, label, params) in enumerate(variants, start=1):
        if progress is not None:
            progress("start", index, len(variants), opcode.code, opcode.name, label)
        observation = _observe(client, opcode, label, params)
        observations.append(observation)
        if progress is not None:
            progress(
                "done",
                index,
                len(variants),
                opcode.code,
                opcode.name,
                str(observation["status"]),
            )
    control_observations.append(
        _run_control(client, control_operation, "after", len(variants), progress)
    )
    status_counts: dict[str, int] = {}
    for observation in observations:
        status = str(observation["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    attempted_codes: set[int] = set()
    positive_codes: set[int] = set()
    for observation in observations:
        code = observation["code"]
        if not isinstance(code, int) or isinstance(code, bool):
            continue
        attempted_codes.add(code)
        if observation["status"] in _POSITIVE_STATUSES:
            positive_codes.add(code)
    control_status_counts: dict[str, int] = {}
    for observation in control_observations:
        status = str(observation["status"])
        control_status_counts[status] = control_status_counts.get(status, 0) + 1
    return {
        "schema_version": 2,
        "transport": "tmp_appv2_over_ssh",
        "probe_kind": "unverified_read_schema_discovery",
        "registry_source": "TP-Link Deco Android 3.10.215 build 1484",
        "catalogued_untested_read_count": len(candidates),
        "safe_candidate_count": len(safe_candidates),
        "selected_operation_count": len(selected),
        "attempted_operation_count": len(attempted_codes),
        "attempted_variant_count": len(observations),
        "positive_operation_count": len(positive_codes),
        "status_counts": dict(sorted(status_counts.items())),
        "observations": observations,
        "control_opcode": _CONTROL_OPCODE,
        "control_observations": control_observations,
        "control_status_counts": dict(sorted(control_status_counts.items())),
        "session_control_passed": all(
            observation["status"] in _POSITIVE_STATUSES for observation in control_observations
        ),
        "include_sensitive": include_sensitive,
        "sensitive_operation_count": sum(opcode.sensitivity == "secret" for opcode in selected),
        "excluded_sensitive_operation_count": sum(
            opcode.sensitivity == "secret" for opcode in safe_candidates
        )
        if not include_sensitive
        else 0,
        "excluded_dispatch_set_operation_count": len(dispatch_set_operations),
        "excluded_dispatch_set_operations": [
            {
                "code": opcode.code,
                "hex_code": opcode.hex_code,
                "name": opcode.name,
                "app_dispatch_methods": opcode.app_dispatch_methods,
            }
            for opcode in dispatch_set_operations
        ],
        "mutation_invoked": False,
        "destructive_operation_invoked": False,
        "internal_operation_invoked": False,
        "raw_values_emitted": False,
        "response_values_retained": False,
    }


def _run_control(
    client: DecoTmpClient,
    opcode: TmpOpcodeSpec,
    position: str,
    total: int,
    progress: Callable[[str, int, int, int, str, str], None] | None,
) -> dict[str, JsonValue]:
    if progress is not None:
        progress("control_start", 0, total, opcode.code, opcode.name, position)
    observation = _observe(client, opcode, f"control_{position}_json_null", None)
    if progress is not None:
        progress(
            "control_done",
            0,
            total,
            opcode.code,
            opcode.name,
            str(observation["status"]),
        )
    return observation


def _variants(opcode: TmpOpcodeSpec) -> tuple[tuple[str, JsonValue], ...]:
    if opcode.app_contract_status == "static_null_payload":
        return (("json_null", None),)
    return (("json_null", None), ("json_empty_object", {}))


def _observe(
    client: DecoTmpClient,
    opcode: TmpOpcodeSpec,
    variant: str,
    params: JsonValue,
) -> dict[str, JsonValue]:
    base: dict[str, JsonValue] = {
        "code": opcode.code,
        "hex_code": opcode.hex_code,
        "name": opcode.name,
        "category": opcode.category,
        "sensitivity": opcode.sensitivity,
        "variant": variant,
        "parameter_keys": sorted(params) if isinstance(params, Mapping) else [],
        "app_contract_status": opcode.app_contract_status,
        "app_candidate_parameter_keys": opcode.app_candidate_parameter_keys,
    }
    envelope: dict[str, JsonValue] = {
        "configVersion": time.time_ns() // 1_000_000,
        "params": params,
    }
    payload = json.dumps(envelope, separators=(",", ":")).encode()
    try:
        response_bytes = client.request_read(opcode.code, payload)
    except (DecoError, OSError, TimeoutError, ValueError) as exc:
        match = _APPV2_ERROR.search(str(exc))
        return {
            **base,
            "status": "appv2_rejected" if match else "transport_error",
            "error_type": type(exc).__name__,
            "appv2_error_code": int(match.group(1)) if match else None,
            "firmware_error_code": None,
            "response_size": None,
            "response_sha256": "",
            "schema_paths": [],
        }
    response_digest = hashlib.sha256(response_bytes).hexdigest()
    try:
        response = loads(response_bytes)
    except (UnicodeDecodeError, ValueError):
        return {
            **base,
            "status": "returned_binary",
            "error_type": "",
            "appv2_error_code": None,
            "firmware_error_code": None,
            "response_size": len(response_bytes),
            "response_sha256": response_digest,
            "schema_paths": [],
        }
    firmware_error_code = _optional_int(response.get("error_code"))
    result = response.get("result")
    if firmware_error_code == 0:
        status = "returned_data" if _has_data(result) else "accepted_empty"
    else:
        status = "payload_rejected"
    return {
        **base,
        "status": status,
        "error_type": "",
        "appv2_error_code": None,
        "firmware_error_code": firmware_error_code,
        "response_size": None,
        "response_sha256": "",
        "schema_paths": sorted(_schema_paths(response)),
    }


def _optional_int(value: JsonValue) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _has_data(value: JsonValue) -> bool:
    return value not in (None, {}, [], ())


def _schema_paths(value: JsonValue, path: str = "$") -> set[str]:
    output: set[str] = set()
    if isinstance(value, Mapping):
        output.add(f"{path}:object")
        for key, child in value.items():
            output.update(_schema_paths(child, f"{path}.{key}"))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        output.add(f"{path}:array")
        for child in value:
            output.update(_schema_paths(child, f"{path}[]"))
    elif isinstance(value, bool):
        output.add(f"{path}:boolean")
    elif isinstance(value, int):
        output.add(f"{path}:integer")
    elif isinstance(value, float):
        output.add(f"{path}:number")
    elif isinstance(value, str):
        output.add(f"{path}:string")
    elif value is None:
        output.add(f"{path}:null")
    return output
