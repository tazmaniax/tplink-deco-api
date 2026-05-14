"""Aggregated up/down bandwidth across all connected clients."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .client_device import ClientDevice


@dataclass(frozen=True)
class NetworkTotals:
    """Sum of the up/down speeds reported by all clients."""

    up_speed: int
    down_speed: int

    @classmethod
    def from_clients(cls, clients: Iterable[ClientDevice]) -> NetworkTotals:
        """Sum ``up_speed`` and ``down_speed`` across an iterable of clients."""
        up_total = 0
        down_total = 0
        for client in clients:
            up_total += client.up_speed
            down_total += client.down_speed
        return cls(up_speed=up_total, down_speed=down_total)
