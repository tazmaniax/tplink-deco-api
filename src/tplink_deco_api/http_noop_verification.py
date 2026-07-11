"""Verify P9 HTTP settings with their live current values only."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .endpoint_catalog import get_endpoint
from .exceptions import DecoError
from .models import HttpNoopVerificationResult

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._json import JsonObject
    from .client import DecoClient

HTTP_NOOP_CONFIRMATIONS: dict[str, str] = {
    operation: (
        f"I authorize a P9 HTTP current-value no-op verification for {operation}, "
        "with immediate post-read verification and rollback on mismatch."
    )
    for operation in (
        "admin.wireless.beamforming.write",
        "admin.wireless.ieee80211r.write",
        "admin.device.timesetting.write",
    )
}

HTTP_NOOP_PREFLIGHT_OPERATIONS: dict[str, str] = {
    "admin.wireless.beamforming.write": "admin.wireless.beamforming.read",
    "admin.wireless.ieee80211r.write": "admin.wireless.ieee80211r.read",
    "admin.device.timesetting.write": "admin.device.timesetting.read",
}
_REQUEST_ERRORS = (DecoError, OSError, TimeoutError, ValueError)


def verify_http_setting_noop(
    client: DecoClient,
    operation: str,
    confirmation: str,
    progress: Callable[[str], None] | None = None,
) -> HttpNoopVerificationResult:
    """Write one live current setting and verify or restore it immediately."""
    expected = HTTP_NOOP_CONFIRMATIONS.get(operation)
    if expected is None:
        raise ValueError(f"Failed to verify HTTP no-op: unsupported operation {operation!r}")
    if confirmation != expected:
        raise PermissionError(
            "Failed to verify HTTP no-op: confirmation does not match exact scope"
        )
    read_operation = HTTP_NOOP_PREFLIGHT_OPERATIONS[operation]
    _progress(progress, "preflight")
    before = _read_state(client, operation, read_operation)
    _progress(progress, "write")
    write_error_code, write_error_type = _write_state(client, operation, before)
    _progress(progress, "verify")
    post_succeeded, state_unchanged = _compare_state(
        client,
        operation,
        read_operation,
        before,
    )
    if post_succeeded and state_unchanged:
        return _result(
            (
                "verified_noop"
                if write_error_code == 0 and not write_error_type
                else "write_rejected_or_uncertain_state_unchanged"
            ),
            operation,
            read_operation,
            before,
            write_error_code,
            write_error_type,
            post_succeeded=True,
            state_unchanged=True,
        )

    _progress(progress, "rollback")
    rollback_error_code, rollback_error_type = _write_state(client, operation, before)
    _progress(progress, "rollback_verify")
    rollback_read_succeeded, rollback_verified = _compare_state(
        client,
        operation,
        read_operation,
        before,
    )
    return _result(
        (
            "verification_failed_rollback_confirmed"
            if rollback_read_succeeded and rollback_verified
            else "rollback_unconfirmed"
        ),
        operation,
        read_operation,
        before,
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


def _read_state(client: DecoClient, operation: str, read_operation: str) -> JsonObject:
    response = client.call(get_endpoint(read_operation))
    if response.error_code != 0:
        raise ValueError(
            f"Failed to verify HTTP no-op: preflight returned error_code={response.error_code}"
        )
    result = response.result_object()
    if operation in {
        "admin.wireless.beamforming.write",
        "admin.wireless.ieee80211r.write",
    }:
        return {"enable": _boolean(result, "enable")}
    return {
        "timezone": _string(result, "timezone"),
        "continent": _string(result, "continent"),
        "tz_region": _string(result, "tz_region"),
    }


def _write_state(
    client: DecoClient,
    operation: str,
    state: JsonObject,
) -> tuple[int | None, str]:
    try:
        response = client.call(get_endpoint(operation), state)
    except _REQUEST_ERRORS as exc:
        return None, type(exc).__name__
    return response.error_code, ""


def _compare_state(
    client: DecoClient,
    operation: str,
    read_operation: str,
    before: JsonObject,
) -> tuple[bool, bool | None]:
    try:
        return True, _read_state(client, operation, read_operation) == before
    except _REQUEST_ERRORS:
        return False, None


def _string(data: JsonObject, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Failed to verify HTTP no-op: preflight result lacks {key}")
    return value


def _boolean(data: JsonObject, key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Failed to verify HTTP no-op: preflight result lacks boolean {key}")
    return value


def _result(
    status: str,
    operation: str,
    read_operation: str,
    state: JsonObject,
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
) -> HttpNoopVerificationResult:
    return HttpNoopVerificationResult(
        status=status,
        operation_name=operation,
        preflight_name=read_operation,
        parameter_keys=tuple(sorted(state)),
        write_firmware_error_code=write_error_code,
        write_error_type=write_error_type,
        post_read_succeeded=post_succeeded,
        state_unchanged=state_unchanged,
        rollback_attempted=rollback_attempted,
        rollback_firmware_error_code=rollback_error_code,
        rollback_error_type=rollback_error_type,
        rollback_verified=rollback_verified,
        mutation_request_count=mutation_request_count,
    )


def _progress(callback: Callable[[str], None] | None, event: str) -> None:
    if callback is not None:
        callback(event)
