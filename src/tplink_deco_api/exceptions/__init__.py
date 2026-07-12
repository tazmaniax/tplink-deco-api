"""Public exception hierarchy for the SDK."""

from __future__ import annotations

from .api import ApiError
from .auth import AuthenticationError
from .base import DecoError
from .confirmation import ConfirmationError
from .controller_changed import ControllerChangedError
from .crypto import CryptoError
from .expired_plan import ExpiredPlanError
from .idempotency_conflict import IdempotencyConflictError
from .idempotency_in_progress import IdempotencyInProgressError
from .mutation_ineligible import MutationIneligibleError
from .tmp import TmpProtocolError
from .transport import TransportError
from .unknown_plan import UnknownPlanError

__all__ = [
    "ApiError",
    "AuthenticationError",
    "ConfirmationError",
    "ControllerChangedError",
    "CryptoError",
    "DecoError",
    "ExpiredPlanError",
    "IdempotencyConflictError",
    "IdempotencyInProgressError",
    "MutationIneligibleError",
    "TmpProtocolError",
    "TransportError",
    "UnknownPlanError",
]
