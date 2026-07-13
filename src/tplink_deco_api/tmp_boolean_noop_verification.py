"""Shared fail-closed verifier for exact TMP boolean current-value no-ops."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from .exceptions import DecoError
from .models import TmpNoopVerificationResult
from .tmp_lab import TmpLabTarget, verify_tmp_lab_target

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._json import JsonObject
    from .tmp_client import DecoTmpClient

_REQUEST_ERRORS = (DecoError, OSError, TimeoutError, ValueError)


def _verify_tmp_boolean_noop(
    client: DecoTmpClient,
    confirmation: str,
    *,
    expected_confirmation: str,
    label: str,
    read_opcode: int,
    read_name: str,
    write_opcode: int,
    write_name: str,
    target: TmpLabTarget | None,
    progress: Callable[[str], None] | None = None,
) -> TmpNoopVerificationResult:
    if confirmation != expected_confirmation:
        raise PermissionError(f"Failed to verify {label}: confirmation does not match exact scope")
    verify_tmp_lab_target(client, target)
    _progress(progress, "preflight")
    before = _read_enable(client, read_opcode, label)
    _progress(progress, "write")
    write_error_code, write_error_type = _write_enable(client, write_opcode, before)
    _progress(progress, "verify")
    post_succeeded, state_unchanged = _compare_state(client, read_opcode, before, label)
    if post_succeeded and state_unchanged:
        status = (
            "verified_noop"
            if write_error_code == 0 and not write_error_type
            else "write_rejected_or_uncertain_state_unchanged"
        )
        return _result(
            status,
            read_opcode,
            read_name,
            write_opcode,
            write_name,
            write_error_code,
            write_error_type,
            post_succeeded=True,
            state_unchanged=True,
        )

    _progress(progress, "rollback")
    rollback_error_code, rollback_error_type = _write_enable(client, write_opcode, before)
    _progress(progress, "rollback_verify")
    rollback_read_succeeded, rollback_verified = _compare_state(
        client,
        read_opcode,
        before,
        label,
    )
    return _result(
        (
            "verification_failed_rollback_confirmed"
            if rollback_read_succeeded and rollback_verified
            else "rollback_unconfirmed"
        ),
        read_opcode,
        read_name,
        write_opcode,
        write_name,
        write_error_code,
        write_error_type,
        post_succeeded=post_succeeded,
        state_unchanged=state_unchanged,
        rollback_attempted=True,
        rollback_error_code=rollback_error_code,
        rollback_error_type=rollback_error_type,
        rollback_verified=(rollback_verified if rollback_read_succeeded else None),
        mutation_request_count=2,
    )


def _read_enable(client: DecoTmpClient, opcode: int, label: str) -> bool:
    response = client.request_read_json(opcode)
    error_code = _error_code(response, label)
    if error_code != 0:
        raise ValueError(f"Failed to verify {label}: preflight returned error_code={error_code}")
    result = response.get("result")
    if not isinstance(result, Mapping):
        raise ValueError(f"Failed to verify {label}: preflight result is missing")
    enable = result.get("enable")
    if not isinstance(enable, bool):
        raise ValueError(f"Failed to verify {label}: preflight enable is missing")
    return enable


def _write_enable(
    client: DecoTmpClient,
    opcode: int,
    enable: bool,
) -> tuple[int | None, str]:
    try:
        response = client._request_mutation_json(opcode, {"enable": enable})
    except _REQUEST_ERRORS as exc:
        return None, type(exc).__name__
    value = response.get("error_code")
    if not isinstance(value, int) or isinstance(value, bool):
        return None, "InvalidFirmwareResponse"
    return value, ""


def _compare_state(
    client: DecoTmpClient,
    opcode: int,
    before: bool,
    label: str,
) -> tuple[bool, bool | None]:
    try:
        return True, _read_enable(client, opcode, label) == before
    except _REQUEST_ERRORS:
        return False, None


def _error_code(response: JsonObject, label: str) -> int:
    value = response.get("error_code")
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Failed to verify {label}: response error_code is missing")
    return value


def _result(
    status: str,
    read_opcode: int,
    read_name: str,
    write_opcode: int,
    write_name: str,
    write_error_code: int | None,
    write_error_type: str,
    *,
    post_succeeded: bool,
    state_unchanged: bool | None,
    rollback_attempted: bool = False,
    rollback_error_code: int | None = None,
    rollback_error_type: str = "",
    rollback_verified: bool | None = None,
    mutation_request_count: int = 1,
) -> TmpNoopVerificationResult:
    return TmpNoopVerificationResult(
        status=status,
        operation_code=write_opcode,
        preflight_code=read_opcode,
        write_firmware_error_code=write_error_code,
        write_error_type=write_error_type,
        post_read_succeeded=post_succeeded,
        state_unchanged=state_unchanged,
        rollback_attempted=rollback_attempted,
        rollback_firmware_error_code=rollback_error_code,
        rollback_error_type=rollback_error_type,
        rollback_verified=rollback_verified,
        mutation_request_count=mutation_request_count,
        operation_name=write_name,
        preflight_name=read_name,
    )


def _progress(callback: Callable[[str], None] | None, event: str) -> None:
    if callback is not None:
        callback(event)
