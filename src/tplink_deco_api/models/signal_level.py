"""Signal level per Wi-Fi band, as reported by the router."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, get_str


@dataclass(frozen=True)
class SignalLevel:
    """Signal level reading for each radio band."""

    band2_4: str
    band5: str
    band6: str

    @classmethod
    def from_api(cls, data: JsonObject) -> SignalLevel:
        """Build ``SignalLevel`` from a router payload."""
        return cls(
            band2_4=get_str(data, "band2_4", "0"),
            band5=get_str(data, "band5", "0"),
            band6=get_str(data, "band6", "0"),
        )
