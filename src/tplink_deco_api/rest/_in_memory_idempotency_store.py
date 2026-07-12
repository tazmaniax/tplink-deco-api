"""Bounded process-local idempotency replay for synchronous REST executions."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

from ..exceptions import IdempotencyConflictError, IdempotencyInProgressError
from ._idempotency_record import _IdempotencyRecord

if TYPE_CHECKING:
    from collections.abc import Callable

    from .._json import JsonValue


class _InMemoryIdempotencyStore:
    """Coordinate REST executions and replay successful results within one process."""

    def __init__(self, *, ttl_seconds: float = 600.0, max_records: int = 256) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_records = max_records
        self._records: dict[str, _IdempotencyRecord] = {}
        self._lock = threading.RLock()

    def execute(
        self,
        key: str,
        fingerprint: str,
        operation: Callable[[], dict[str, JsonValue]],
    ) -> tuple[dict[str, JsonValue], bool]:
        """Reserve a key, execute without the store lock, then retain the result."""
        with self._lock:
            now = time.monotonic()
            self._purge(now)
            existing = self._records.get(key)
            if existing is not None:
                if existing.fingerprint != fingerprint:
                    raise IdempotencyConflictError(
                        "Failed to execute mutation: idempotency key identifies another request"
                    )
                if existing.result is None:
                    raise IdempotencyInProgressError(
                        "Failed to execute mutation: idempotent request is already in progress"
                    )
                return dict(existing.result), True
            if len(self._records) >= self._max_records:
                completed = [
                    record_key
                    for record_key, record in self._records.items()
                    if record.result is not None
                ]
                if not completed:
                    raise IdempotencyInProgressError(
                        "Failed to execute mutation: idempotency capacity is in progress"
                    )
                oldest_key = min(completed, key=lambda item: self._records[item].expires_at)
                del self._records[oldest_key]
            self._records[key] = _IdempotencyRecord(
                fingerprint=fingerprint,
                result=None,
                expires_at=now + self._ttl_seconds,
            )
        try:
            result = dict(operation())
        except Exception:
            with self._lock:
                existing = self._records.get(key)
                if existing is not None and existing.fingerprint == fingerprint:
                    del self._records[key]
            raise
        with self._lock:
            self._records[key] = _IdempotencyRecord(
                fingerprint=fingerprint,
                result=result,
                expires_at=time.monotonic() + self._ttl_seconds,
            )
            return dict(result), False

    def _purge(self, now: float) -> None:
        expired = [
            key
            for key, record in self._records.items()
            if record.result is not None and record.expires_at <= now
        ]
        for key in expired:
            del self._records[key]
