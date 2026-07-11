"""Static DHCP address reservation."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, get_str
from ._utils import normalize_mac


@dataclass(frozen=True)
class AddressReservation:
    """A reserved IPv4 address assigned to one client MAC address."""

    mac: str
    ip: str

    @classmethod
    def from_api(cls, data: JsonObject) -> AddressReservation:
        """Build ``AddressReservation`` from a router payload."""
        return cls(
            mac=normalize_mac(get_str(data, "mac")),
            ip=get_str(data, "ip"),
        )
