"""Response contract for terminal mutation execution evidence."""

from __future__ import annotations

from dataclasses import dataclass

from .response_dto import ResponseDto


@dataclass(frozen=True)
class MutationExecutionResponse(ResponseDto):
    """Describe value-free verification evidence for one consumed plan."""

    schema_version: int
    transport: str
    operation_name: str
    preflight_name: str
    status: str
    verified_noop: bool
    write_firmware_error_code: int | None
    write_error_type: str
    post_read_succeeded: bool
    state_unchanged: bool | None
    rollback_attempted: bool
    rollback_firmware_error_code: int | None
    rollback_error_type: str
    rollback_verified: bool | None
    mutation_request_count: int
    same_value_payload: bool
    current_value_source: str
    parameter_keys: list[str]
    parameter_values_retained: bool
    response_values_retained: bool
    raw_values_emitted: bool
    different_value_write_invoked: bool
    model: str
    execution_scope: str
    runtime_gates: list[str]
    requires_attention: bool
    capability: str
    selected_interface: str
    selected_operation: str
    fallback_policy: str
    fallback_used: bool
    caller_selected_protocol: bool
    plan_id: str
    plan_consumed: bool
    idempotency_replayed: bool
    verification_name: str | None = None
    rollback_name: str | None = None
    generic_http_noop_execution_supported: bool | None = None
    operation_code: int | None = None
    operation_hex_code: str | None = None
    preflight_code: int | None = None
    preflight_hex_code: str | None = None
    verification_code: int | None = None
    rollback_code: int | None = None
    generic_tmp_mutation_supported: bool | None = None
