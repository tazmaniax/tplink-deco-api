"""Bounded, value-free discovery for parameterized TMP read operations."""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import DecoError
from .tmp_opcode_catalog import get_tmp_opcode

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._json import JsonObject, JsonValue
    from .tmp_client import DecoTmpClient

_SOURCE_OPCODES: tuple[int, ...] = (0x4012, 0x4029, 0x4060)
_MAX_SOURCE_VALUES = 3
_MAX_ATTEMPTS = 60
_DECO_ANDROID_APK_SHA256 = "bcf626841307b4eb5ab7e12c178fb078e5dd522e0c805a317bfe103a93566ea8"
_DECO_ANDROID_SIGNING_CERTIFICATE_SHA1 = "c2864363ef24dec324fb6c557c40b8c4aee672e0"
_DECO_ANDROID_3_XAPK_SHA256 = "198115ba07e8893c44e9f7f1cce1494b988d23e1e2e31533a6f85c637841edf8"
_IOT_MODULE_NAMES: tuple[str, ...] = (
    "zigbee",
    "tpra",
    "ble",
    "nest",
    "hue",
    "cloud",
    "network",
    "network_device",
    "notification",
    "tapo",
    "matter",
)


@dataclass(frozen=True)
class _ReadVariant:
    code: int
    label: str
    params: dict[str, JsonValue]
    value_source: str


def probe_tmp_read_contracts(
    client: DecoTmpClient,
    progress: Callable[[str, int, int, int, str], None] | None = None,
    *,
    include_inferred_iot_module_contract: bool = False,
) -> dict[str, JsonValue]:
    """Try bounded GET payloads derived from values already returned by the P9.

    Source identifiers remain in memory. The result contains only source counts,
    parameter-key names, firmware status codes, and response schemas.
    """
    sources: dict[int, JsonObject] = {}
    for index, code in enumerate(_SOURCE_OPCODES, start=1):
        if progress is not None:
            progress("source", index, len(_SOURCE_OPCODES), code, get_tmp_opcode(code).name)
        sources[code] = client.request_read_json(code)
    owner_ids = _unique(
        (
            *_string_values(sources[0x4029], "owner_list", "owner_id"),
            *_string_values(sources[0x4060], "owner_list", "owner_id"),
            *_string_values(sources[0x4012], "client_list", "owner_id"),
        )
    )
    variants = _build_variants(
        owner_ids,
        include_inferred_iot_module_contract=include_inferred_iot_module_contract,
    )
    if len(variants) > _MAX_ATTEMPTS:
        raise ValueError(
            f"Failed to probe TMP read contracts: {len(variants)} exceeds the request budget"
        )

    observations: list[dict[str, JsonValue]] = []
    for index, variant in enumerate(variants, start=1):
        if progress is not None:
            progress("contract", index, len(variants), variant.code, variant.label)
        observations.append(_observe(client, variant))
    confirmed = [
        {
            "code": observation["code"],
            "hex_code": observation["hex_code"],
            "name": observation["name"],
            "variant": observation["variant"],
            "parameter_keys": observation["parameter_keys"],
            "value_source": observation["value_source"],
            "status": observation["status"],
            "schema_paths": observation["schema_paths"],
        }
        for observation in observations
        if observation["status"] in {"returned_data", "accepted_empty"}
    ]
    return {
        "transport": "tmp_appv2_over_ssh",
        "probe_kind": "bounded_read_contract_discovery",
        "source_opcodes": list(_SOURCE_OPCODES),
        "source_value_counts": {
            "owner_ids": len(owner_ids),
        },
        "static_contract_evidence": {
            "application": "TP-Link Deco Android 1.10.5 build 112",
            "apk_sha256": _DECO_ANDROID_APK_SHA256,
            "signing_certificate_sha1": _DECO_ANDROID_SIGNING_CERTIFICATE_SHA1,
            "request_models": [
                "OwnerDefaultWebsiteParams",
                "ObtainIotDeviceParams",
                "CategoryOrRuleListParams",
            ],
        },
        "inferred_iot_module_contract": {
            "included": include_inferred_iot_module_contract,
            "code": 0x404B,
            "hex_code": "0x404B",
            "name": "TMP_APPV2_OP_IOT_CLIENT_LIST_GET_BY_MODULE",
            "parameter_keys": ["module"],
            "variant_count": (
                len(_IOT_MODULE_NAMES) if include_inferred_iot_module_contract else 0
            ),
            "evidence": "opcode_semantics_plus_signed_app_serialized_enum_without_call_site",
            "application": "TP-Link Deco Android 3.10.215 build 1484",
            "xapk_sha256": _DECO_ANDROID_3_XAPK_SHA256,
            "response_values_retained": False,
        },
        "attempt_budget": _MAX_ATTEMPTS,
        "attempted_count": len(observations),
        "confirmed_contract_count": len(confirmed),
        "confirmed_contracts": confirmed,
        "observations": observations,
        "mutation_invoked": False,
        "active_scan_invoked": False,
        "source_values_retained": False,
        "raw_values_emitted": False,
    }


def _build_variants(
    owner_ids: tuple[str, ...],
    *,
    include_inferred_iot_module_contract: bool,
) -> tuple[_ReadVariant, ...]:
    variants: list[_ReadVariant] = []
    for code in (0x402D, 0x402F, 0x4031):
        variants.extend(_value_variants(code, "owner_id", owner_ids, "owner_list.owner_id"))
    variants.extend(_value_variants(0x402D, "id", owner_ids, "owner_list.owner_id"))
    variants.extend(
        (
            _ReadVariant(
                0x403A,
                "apk_cached_version",
                {"version": 1029},
                "deco_android_1.10.5.OwnerDefaultWebsiteParams",
            ),
            _ReadVariant(
                0x4049,
                "apk_empty_iot_client_list",
                {"iot_client_list": []},
                "deco_android_1.10.5.ObtainIotDeviceParams",
            ),
            _ReadVariant(
                0x4201,
                "apk_category_version",
                {"version": 1},
                "deco_android_1.10.5.CategoryOrRuleListParams",
            ),
            _ReadVariant(
                0x4202,
                "apk_rule_version",
                {"version": 1029},
                "deco_android_1.10.5.CategoryOrRuleListParams",
            ),
        )
    )
    if include_inferred_iot_module_contract:
        variants.extend(
            _ReadVariant(
                0x404B,
                f"inferred_module_{module_name}",
                {"module": module_name},
                "deco_android_3.10.215.EnumIotModuleType",
            )
            for module_name in _IOT_MODULE_NAMES
        )
    now = int(time.time())
    for owner_id in owner_ids[:1]:
        for code in (0x402F, 0x4031):
            variants.extend(
                (
                    _ReadVariant(
                        code,
                        "owner_epoch_range",
                        {
                            "owner_id": owner_id,
                            "start_time": now - 86400,
                            "end_time": now,
                        },
                        "owner_list.owner_id",
                    ),
                    _ReadVariant(
                        code,
                        "owner_pagination",
                        {"owner_id": owner_id, "page": 1, "page_size": 20},
                        "owner_list.owner_id",
                    ),
                )
            )
    return tuple(variants)


def _value_variants(
    code: int,
    key: str,
    values: Iterable[str],
    value_source: str,
) -> tuple[_ReadVariant, ...]:
    return tuple(
        _ReadVariant(code, f"{key}_{index}", {key: value}, value_source)
        for index, value in enumerate(values, start=1)
    )


def _observe(client: DecoTmpClient, variant: _ReadVariant) -> dict[str, JsonValue]:
    operation = get_tmp_opcode(variant.code)
    base: dict[str, JsonValue] = {
        "code": variant.code,
        "hex_code": operation.hex_code,
        "name": operation.name,
        "variant": variant.label,
        "parameter_keys": sorted(variant.params),
        "value_source": variant.value_source,
    }
    try:
        response = client.request_read_json(variant.code, variant.params)
    except (DecoError, OSError, TimeoutError, ValueError) as exc:
        return {
            **base,
            "status": "transport_error",
            "error_type": type(exc).__name__,
            "firmware_error_code": None,
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
        "firmware_error_code": firmware_error_code,
        "schema_paths": sorted(_schema_paths(response)),
    }


def _result(payload: JsonObject) -> JsonObject:
    value = payload.get("result")
    return value if isinstance(value, Mapping) else {}


def _string_values(payload: JsonObject, list_name: str, key: str) -> tuple[str, ...]:
    rows = _result(payload).get(list_name)
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return ()
    return tuple(
        value
        for row in rows
        if isinstance(row, Mapping) and isinstance((value := row.get(key)), str) and value
    )


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))[:_MAX_SOURCE_VALUES]


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
