"""Response contract for gated cloud-related router state."""

from __future__ import annotations

from dataclasses import dataclass

from .json_types import JsonData  # noqa: TC001 - FastAPI resolves this at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class CloudResponse(ResponseDto):
    """Describe observed DDNS and cloud-manager state."""

    ddns: JsonData
    manager: JsonData
