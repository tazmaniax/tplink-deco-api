"""Internal result of resolving Deco controller and mesh identity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonObject
    from ..models import Device
    from ..models.capability_route import CapabilityInterface


@dataclass(frozen=True)
class _DeviceInventoryResolution:
    """Bind one validated inventory to its single successful source."""

    devices: tuple[Device, ...]
    source_interface: CapabilityInterface
    source_operation: str
    attempts: tuple[JsonObject, ...]
    fallback_used: bool
