"""Device operating mode (router/AP) and region info."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, get_object, get_str


@dataclass(frozen=True)
class DeviceMode:
    """Workmode, sysmode and device region as reported by the router."""

    workmode: str
    sysmode: str
    region: str = ""

    @classmethod
    def from_api(cls, data: JsonObject) -> DeviceMode:
        """Build ``DeviceMode`` from a router payload."""
        return cls(
            workmode=get_str(data, "workmode"),
            sysmode=get_str(data, "sysmode"),
            region=get_str(get_object(data, "region"), "device"),
        )
