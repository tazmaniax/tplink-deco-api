"""Response contract for gated cloud-related router state."""

from __future__ import annotations

from dataclasses import dataclass

from .._json import JsonValue  # noqa: TC001 - FastAPI resolves this annotation at runtime.
from .response_dto import ResponseDto


@dataclass(frozen=True)
class CloudResponse(ResponseDto):
    """Describe observed DDNS and cloud-manager state."""

    ddns: JsonValue
    manager: JsonValue
