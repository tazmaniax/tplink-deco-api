"""Value-free outcome of one explicitly authorized HTTP no-op verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue


@dataclass(frozen=True)
class HttpNoopVerificationResult:
    """Describe a bounded HTTP write outcome without retaining setting values."""

    status: str
    operation_name: str
    preflight_name: str
    parameter_keys: tuple[str, ...]
    write_firmware_error_code: int | None
    write_error_type: str
    post_read_succeeded: bool
    state_unchanged: bool | None
    rollback_attempted: bool
    rollback_firmware_error_code: int | None
    rollback_error_type: str
    rollback_verified: bool | None
    mutation_request_count: int

    @property
    def verified_noop(self) -> bool:
        """Return whether the write succeeded and state remained unchanged."""
        return self.status == "verified_noop"

    def to_dict(self) -> dict[str, JsonValue]:
        """Return sanitized verification evidence."""
        return {
            "schema_version": 1,
            "transport": "encrypted_owner_http",
            "operation_name": self.operation_name,
            "preflight_name": self.preflight_name,
            "verification_name": self.preflight_name,
            "rollback_name": self.operation_name,
            "status": self.status,
            "verified_noop": self.verified_noop,
            "write_firmware_error_code": self.write_firmware_error_code,
            "write_error_type": self.write_error_type,
            "post_read_succeeded": self.post_read_succeeded,
            "state_unchanged": self.state_unchanged,
            "rollback_attempted": self.rollback_attempted,
            "rollback_firmware_error_code": self.rollback_firmware_error_code,
            "rollback_error_type": self.rollback_error_type,
            "rollback_verified": self.rollback_verified,
            "mutation_request_count": self.mutation_request_count,
            "same_value_payload": True,
            "current_value_source": f"live_preflight:{self.preflight_name}",
            "parameter_keys": list(self.parameter_keys),
            "parameter_values_retained": False,
            "response_values_retained": False,
            "raw_values_emitted": False,
            "different_value_write_invoked": False,
        }
