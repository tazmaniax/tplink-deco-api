"""Verify the TMP beamforming write with its live current value only."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .tmp_boolean_noop_verification import _verify_tmp_boolean_noop

if TYPE_CHECKING:
    from collections.abc import Callable

    from .models import TmpNoopVerificationResult
    from .tmp_client import DecoTmpClient
    from .tmp_lab import TmpLabTarget

TMP_BEAMFORMING_NOOP_CONFIRMATION = (
    "I authorize a TMP/AppV2 beamforming no-op write on opcode 0x421C, using the current "
    "value read from 0x421B, with immediate post-read verification and rollback on mismatch."
)


def verify_tmp_beamforming_noop(
    client: DecoTmpClient,
    confirmation: str,
    *,
    target: TmpLabTarget | None = None,
    progress: Callable[[str], None] | None = None,
) -> TmpNoopVerificationResult:
    """Send one exact current-value write and verify or restore the prior state."""
    return _verify_tmp_boolean_noop(
        client,
        confirmation,
        expected_confirmation=TMP_BEAMFORMING_NOOP_CONFIRMATION,
        label="TMP beamforming no-op",
        read_opcode=0x421B,
        read_name="TMP_APPV2_OP_BEAMFORMING_GET",
        write_opcode=0x421C,
        write_name="TMP_APPV2_OP_BEAMFORMING_SET",
        target=target,
        progress=progress,
    )
