"""Value-free outcome of one explicitly authorized TMP no-op verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue


@dataclass(frozen=True)
class TmpNoopVerificationResult:
    """Describe one bounded write outcome without retaining setting values."""

    status: str
    operation_code: int
    preflight_code: int
    write_firmware_error_code: int | None
    write_error_type: str
    post_read_succeeded: bool
    state_unchanged: bool | None
    rollback_attempted: bool
    rollback_firmware_error_code: int | None
    rollback_error_type: str
    rollback_verified: bool | None
    mutation_request_count: int
    operation_name: str = "TMP_APPV2_OP_11R_SET"
    preflight_name: str = "TMP_APPV2_OP_11R_GET"

    @property
    def verified_noop(self) -> bool:
        """Return whether the write succeeded and state remained unchanged."""
        return self.status == "verified_noop"

    def to_dict(self) -> dict[str, JsonValue]:
        """Return sanitized verification evidence."""
        return {
            "schema_version": 1,
            "transport": "tmp_appv2_over_ssh",
            "operation_code": self.operation_code,
            "operation_hex_code": f"0x{self.operation_code:04X}",
            "operation_name": self.operation_name,
            "preflight_code": self.preflight_code,
            "preflight_hex_code": f"0x{self.preflight_code:04X}",
            "preflight_name": self.preflight_name,
            "verification_code": self.preflight_code,
            "rollback_code": self.operation_code,
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
            "current_value_source": f"live_preflight_0x{self.preflight_code:04X}",
            "parameter_keys": ["enable"],
            "parameter_values_retained": False,
            "response_values_retained": False,
            "raw_values_emitted": False,
            "different_value_write_invoked": False,
        }
