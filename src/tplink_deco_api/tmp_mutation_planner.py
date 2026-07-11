"""Build conservative TMP mutation plans from opcode-pair evidence."""

from __future__ import annotations

from .models import TmpMutationPlan, TmpOpcodeSpec
from .tmp_opcode_catalog import TMP_OPCODE_CATALOG, get_tmp_opcode

_PREFLIGHT_READS: dict[int, int] = {
    0x4005: 0x4004,
    0x4007: 0x4006,
    0x4008: 0x4009,
    0x4013: 0x4012,
    0x4017: 0x4018,
    0x4019: 0x4018,
    0x401B: 0x401A,
    0x4025: 0x4024,
    0x4027: 0x4010,
    0x402A: 0x4029,
    0x402B: 0x4029,
    0x402C: 0x4029,
    0x402E: 0x4039,
    0x4030: 0x4039,
    0x4033: 0x4039,
    0x4034: 0x4039,
    0x4037: 0x4036,
    0x403C: 0x403B,
    0x403E: 0x403D,
    0x403F: 0x403D,
    0x4041: 0x4040,
    0x4042: 0x4040,
    0x4043: 0x4040,
    0x4044: 0x4040,
    0x4051: 0x4050,
    0x4052: 0x4050,
    0x4053: 0x4050,
    0x4054: 0x4050,
    0x4071: 0x4070,
    0x4073: 0x4070,
    0x4074: 0x4070,
    0x4075: 0x4070,
    0x4076: 0x4070,
    0x4077: 0x4070,
    0x4078: 0x4070,
    0x407A: 0x4079,
    0x4082: 0x4080,
    0x4083: 0x4080,
    0x4084: 0x4080,
    0x4086: 0x4080,
    0x4087: 0x4080,
    0x4088: 0x4080,
    0x4089: 0x4080,
    0x408A: 0x4080,
    0x408B: 0x4080,
    0x408D: 0x408C,
    0x408E: 0x4080,
    0x4090: 0x4012,
    0x40A1: 0x40A0,
    0x40B1: 0x40B0,
    0x40B2: 0x40B0,
    0x40B3: 0x40B0,
    0x40C1: 0x40C0,
    0x40C2: 0x40C0,
    0x40C3: 0x40C0,
    0x40D1: 0x40D0,
    0x4209: 0x4208,
    0x420C: 0x4004,
    0x420E: 0x420D,
    0x4212: 0x4211,
    0x4214: 0x4213,
    0x4216: 0x4215,
    0x421A: 0x4219,
    0x421C: 0x421B,
    0x421E: 0x421D,
    0x4220: 0x402F,
    0x4221: 0x40E0,
    0x4223: 0x4222,
    0x4225: 0x4224,
    0x4227: 0x4226,
    0x422A: 0x4229,
    0x422C: 0x422D,
    0x4231: 0x4230,
    0x4232: 0x4230,
    0x4233: 0x4230,
    0x4236: 0x4039,
    0x423B: 0x423A,
    0x423C: 0x423A,
    0x424B: 0x424A,
    0x424D: 0x424C,
    0x4252: 0x4251,
}

_ROLLBACKS: dict[int, int] = {
    0x4017: 0x4019,
    0x4019: 0x4017,
    0x402A: 0x402B,
    0x402B: 0x402A,
    0x4033: 0x4034,
    0x4034: 0x4033,
    0x4041: 0x4042,
    0x4042: 0x4041,
    0x4051: 0x4053,
    0x4053: 0x4051,
    0x4073: 0x4075,
    0x4075: 0x4073,
    0x4076: 0x4078,
    0x4078: 0x4076,
    0x4082: 0x4084,
    0x4084: 0x4082,
    0x40B1: 0x40B3,
    0x40B3: 0x40B1,
    0x40C1: 0x40C3,
    0x40C3: 0x40C1,
    0x4231: 0x4232,
    0x4232: 0x4231,
    0x423B: 0x423C,
    0x423C: 0x423B,
}

_READ_PAIR_SUFFIXES: tuple[str, ...] = (
    "_SET",
    "_ADD",
    "_MODIFY",
    "_REMOVE",
    "_DELETE",
    "_CLEAR",
    "_START",
    "_STOP",
    "_MARK",
    "_BLOCK",
    "_UNBLOCK",
    "_EJECT",
    "_SCAN",
    "_DOWNLOAD",
    "_SWITCH",
    "_WAKE",
)
_INVERSE_SUFFIXES: dict[str, tuple[str, ...]] = {
    "_ADD": ("_REMOVE", "_DELETE"),
    "_REMOVE": ("_ADD",),
    "_DELETE": ("_ADD",),
    "_BLOCK": ("_UNBLOCK",),
    "_UNBLOCK": ("_BLOCK",),
    "_START": ("_STOP",),
    "_STOP": ("_START",),
}
_OPCODES_BY_NAME: dict[str, TmpOpcodeSpec] = {opcode.name: opcode for opcode in TMP_OPCODE_CATALOG}


def build_tmp_mutation_plan(code: int) -> TmpMutationPlan:
    """Build a non-executable plan for one mutation or destructive opcode."""
    operation = get_tmp_opcode(code)
    if operation.safety not in {"mutation", "destructive"}:
        raise ValueError(f"Failed to plan TMP mutation: {operation.name} is {operation.safety}")
    preflight_code, preflight_evidence = _preflight_relationship(code, operation)
    preflight = get_tmp_opcode(preflight_code) if preflight_code is not None else None
    rollback_code, rollback_evidence = _rollback_relationship(
        code,
        operation,
        preflight_code,
    )
    rollback = get_tmp_opcode(rollback_code) if rollback_code is not None else None
    preflight_result_keys = _top_level_result_keys(preflight)
    preflight_missing_candidate_keys = tuple(
        key for key in operation.app_candidate_parameter_keys if key not in preflight_result_keys
    )

    parameter_contract, parameter_contract_evidence = _parameter_contract(operation)
    p9_parameter_contract_verified = (
        operation.p9_mutation_observation == "verified_noop"
        and operation.p9_mutation_firmware_error_code == 0
        and operation.p9_mutation_state_unchanged is True
        and operation.p9_mutation_parameter_keys == operation.app_candidate_parameter_keys
    )
    warnings = (
        ["P9 mutation verified only as a current-value no-op"]
        if operation.p9_mutation_observation == "verified_noop"
        else ["P9 mutation opcode has not been tested"]
    )
    if parameter_contract == "unknown":
        warnings.append("mutation parameter contract is unknown")
    else:
        warnings.append(
            "mutation parameter contract is P9-verified only for the current-value no-op"
            if p9_parameter_contract_verified
            else "mutation parameter contract is static app evidence only"
        )
    if operation.safety == "destructive":
        warnings.append("operation is classified destructive")
    if preflight is None:
        warnings.append("no preflight read relationship is known")
    elif preflight.p9_observation != "returned_data":
        warnings.append(f"P9 preflight read observation is {preflight.p9_observation}")
    elif preflight_missing_candidate_keys:
        warnings.append(
            "P9 preflight schema is missing setter candidate keys: "
            + ", ".join(preflight_missing_candidate_keys)
        )
    if preflight_evidence == "signed_app_opcode_name_pair_inference":
        warnings.append("preflight relationship is inferred from signed-app opcode names")
    if rollback is None:
        warnings.append("no rollback opcode relationship is known")
    elif rollback_evidence == "signed_app_inverse_name_pair_inference":
        warnings.append("rollback relationship is inferred from signed-app opcode names")

    return TmpMutationPlan(
        code=operation.code,
        name=operation.name,
        safety=operation.safety,
        safety_evidence=operation.safety_evidence,
        category=operation.category,
        sensitivity=operation.sensitivity,
        app_set_dispatch_review=operation.app_set_dispatch_review,
        preflight_code=preflight.code if preflight is not None else None,
        preflight_name=preflight.name if preflight is not None else "",
        preflight_observation=(preflight.p9_observation if preflight is not None else "untested"),
        preflight_relationship_evidence=preflight_evidence,
        verification_code=preflight.code if preflight is not None else None,
        verification_name=preflight.name if preflight is not None else "",
        verification_relationship_evidence=preflight_evidence,
        rollback_code=rollback.code if rollback is not None else None,
        rollback_name=rollback.name if rollback is not None else "",
        rollback_relationship_evidence=rollback_evidence,
        rollback_requires_preflight=rollback is not None,
        parameter_contract=parameter_contract,
        parameter_contract_evidence=parameter_contract_evidence,
        p9_parameter_contract_verified=p9_parameter_contract_verified,
        p9_mutation_observation=operation.p9_mutation_observation,
        p9_mutation_firmware_error_code=operation.p9_mutation_firmware_error_code,
        p9_mutation_parameter_keys=operation.p9_mutation_parameter_keys,
        p9_mutation_state_unchanged=operation.p9_mutation_state_unchanged,
        p9_mutation_rollback_attempted=operation.p9_mutation_rollback_attempted,
        p9_mutation_rollback_verified=operation.p9_mutation_rollback_verified,
        p9_mutation_request_count=operation.p9_mutation_request_count,
        p9_mutation_evidence_artifact=operation.p9_mutation_evidence_artifact,
        app_analysis_sources=operation.app_analysis_sources,
        app_contract_sources=operation.app_contract_sources,
        app_dispatch_methods=operation.app_dispatch_methods,
        app_contract_provenance=operation.app_contract_provenance,
        app_request_models=operation.app_request_models,
        app_candidate_parameter_keys=operation.app_candidate_parameter_keys,
        app_call_site_count=operation.app_call_site_count,
        app_contract_sha256=operation.app_contract_sha256,
        evidence=(
            "value_free_p9_live_noop_and_signed_deco_android_static_contracts"
            if operation.p9_mutation_observation != "untested"
            else "opcode_name_pair_inference_and_signed_deco_android_static_contracts"
        ),
        warnings=tuple(warnings),
        preflight_result_keys=preflight_result_keys,
        preflight_missing_candidate_keys=preflight_missing_candidate_keys,
    )


def _top_level_result_keys(operation: TmpOpcodeSpec | None) -> tuple[str, ...]:
    if operation is None or operation.p9_observation != "returned_data":
        return ()
    prefix = "$.result."
    keys: list[str] = []
    for path in operation.p9_schema_paths:
        if not path.startswith(prefix):
            continue
        remainder = path[len(prefix) :]
        key = remainder.split(":", 1)[0].split(".", 1)[0].split("[", 1)[0]
        if key and key not in keys:
            keys.append(key)
    return tuple(keys)


def _parameter_contract(operation: TmpOpcodeSpec) -> tuple[str, str]:
    status = operation.app_contract_status
    if status == "no_app_call_site":
        return "unknown", "none"
    evidence = (
        "signed_deco_android_indirect_virtual_dispatch"
        if operation.app_contract_provenance == "indirect_virtual_dispatch"
        else "signed_deco_android_static_call_site"
    )
    if status == "static_null_payload":
        return "static_app_null_payload", evidence
    if status == "static_model_recovered":
        models = ",".join(operation.app_request_models)
        return (
            f"static_app_request_models:{models}",
            evidence,
        )
    keys = ",".join(operation.app_candidate_parameter_keys)
    return (
        f"static_app_candidate_keys:{keys}",
        evidence,
    )


def _preflight_relationship(
    code: int,
    operation: TmpOpcodeSpec,
) -> tuple[int | None, str]:
    curated = _PREFLIGHT_READS.get(code)
    if curated is not None:
        return curated, "curated_opcode_relationship"
    inferred = _inferred_preflight_code(operation)
    if inferred is not None:
        return inferred, "signed_app_opcode_name_pair_inference"
    return None, ""


def _inferred_preflight_code(operation: TmpOpcodeSpec) -> int | None:
    for suffix in _READ_PAIR_SUFFIXES:
        if not operation.name.endswith(suffix):
            continue
        base_name = operation.name[: -len(suffix)]
        candidate_names = tuple(dict.fromkeys((f"{base_name}_GET", f"{base_name}_LIST_GET")))
        matches = tuple(
            candidate
            for candidate_name in candidate_names
            if (candidate := _OPCODES_BY_NAME.get(candidate_name)) is not None
            and candidate.safety == "read_only"
            and candidate.category == operation.category
        )
        return matches[0].code if len(matches) == 1 else None
    return None


def _rollback_relationship(
    code: int,
    operation: TmpOpcodeSpec,
    preflight_code: int | None,
) -> tuple[int | None, str]:
    paired = _ROLLBACKS.get(code)
    if paired is not None:
        return paired, "curated_opcode_relationship"
    if preflight_code is None:
        return None, ""
    if operation.name.endswith("_SET") or operation.name.endswith("_MODIFY"):
        return code, "preflight_state_restore"
    inverse = _inferred_inverse_code(operation, preflight_code)
    if inverse is not None:
        return inverse, "signed_app_inverse_name_pair_inference"
    return None, ""


def _inferred_inverse_code(operation: TmpOpcodeSpec, preflight_code: int) -> int | None:
    inverse_suffixes: tuple[str, ...] = ()
    for suffix, candidates in _INVERSE_SUFFIXES.items():
        if operation.name.endswith(suffix):
            inverse_suffixes = candidates
            break
    if not inverse_suffixes:
        return None
    matches = tuple(
        candidate
        for candidate in TMP_OPCODE_CATALOG
        if candidate.safety in {"mutation", "destructive"}
        and candidate.category == operation.category
        and any(candidate.name.endswith(suffix) for suffix in inverse_suffixes)
        and _preflight_relationship(candidate.code, candidate)[0] == preflight_code
    )
    return matches[0].code if len(matches) == 1 else None
