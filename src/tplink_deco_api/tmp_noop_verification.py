"""Verify the TMP 802.11r write with its live current value only."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .tmp_boolean_noop_verification import _verify_tmp_boolean_noop

if TYPE_CHECKING:
    from collections.abc import Callable

    from .models import TmpNoopVerificationResult
    from .tmp_client import DecoTmpClient

TMP_IEEE80211R_NOOP_CONFIRMATION = (
    "I authorize a TMP/AppV2 802.11r no-op write on opcode 0x4209, using the current "
    "value read from 0x4208, with immediate post-read verification and rollback on mismatch."
)


def verify_tmp_ieee80211r_noop(
    client: DecoTmpClient,
    confirmation: str,
    *,
    progress: Callable[[str], None] | None = None,
) -> TmpNoopVerificationResult:
    """Send one exact current-value write and verify or restore the prior state."""
    return _verify_tmp_boolean_noop(
        client,
        confirmation,
        expected_confirmation=TMP_IEEE80211R_NOOP_CONFIRMATION,
        label="TMP 802.11r no-op",
        read_opcode=0x4208,
        read_name="TMP_APPV2_OP_11R_GET",
        write_opcode=0x4209,
        write_name="TMP_APPV2_OP_11R_SET",
        progress=progress,
    )
