"""Response contract for gated WLAN state."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import (  # noqa: TC001 - FastAPI resolves these at runtime.
    JsonDocument,
    JsonSection,
)
from .response_dto import ResponseDto


@dataclass(frozen=True)
class WlanResponse(ResponseDto):
    """Describe WLAN bands and features with explicit password inclusion state."""

    passwords_included: bool
    is_eg: bool
    bands: JsonDocument
    iot: JsonSection
    mlo: JsonSection
    features: JsonSection
