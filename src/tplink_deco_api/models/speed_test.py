"""Observed Deco internet speed-test state."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonObject, get_bool, get_int, get_str


@dataclass(frozen=True)
class SpeedTest:
    """Latest internet speed-test result and execution state."""

    down_speed: int
    up_speed: int
    status: str
    ever_tested: bool
    last_speed_test_time: int

    @classmethod
    def from_api(cls, data: JsonObject) -> SpeedTest:
        """Build ``SpeedTest`` from a router payload."""
        return cls(
            down_speed=get_int(data, "down_speed"),
            up_speed=get_int(data, "up_speed"),
            status=get_str(data, "status"),
            ever_tested=get_bool(data, "ever_tested"),
            last_speed_test_time=get_int(data, "last_speed_test_time"),
        )
