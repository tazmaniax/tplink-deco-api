"""Static DHCP address reservation table."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, get_int
from .address_reservation import AddressReservation


@dataclass(frozen=True)
class AddressReservationTable:
    """Address reservations and the firmware-reported table capacity."""

    reservations: tuple[AddressReservation, ...]
    max_count: int

    @property
    def is_full(self) -> bool:
        """Return whether the table has reached a positive firmware limit."""
        return self.max_count > 0 and len(self.reservations) >= self.max_count

    @classmethod
    def from_api(cls, data: JsonObject) -> AddressReservationTable:
        """Build ``AddressReservationTable`` from a router payload."""
        value = data.get("reservation_list")
        reservations = (
            tuple(AddressReservation.from_api(item) for item in value if isinstance(item, dict))
            if isinstance(value, list)
            else ()
        )
        return cls(
            reservations=reservations,
            max_count=get_int(data, "reservation_list_max_count"),
        )
