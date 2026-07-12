"""Binary payload returned by a Deco download endpoint."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._json import JsonValue


@dataclass(frozen=True)
class BinaryResponse:
    """Preserve downloaded bytes with integrity and content metadata."""

    endpoint: str
    content: bytes
    media_type: str = "application/octet-stream"

    @property
    def size(self) -> int:
        """Return the payload length in bytes."""
        return len(self.content)

    @property
    def sha256(self) -> str:
        """Return a stable digest without exposing the payload itself."""
        return hashlib.sha256(self.content).hexdigest()

    def to_dict(self, *, include_content: bool = False) -> dict[str, JsonValue]:
        """Return metadata and optionally base64-encoded content."""
        result: dict[str, JsonValue] = {
            "endpoint": self.endpoint,
            "media_type": self.media_type,
            "size": self.size,
            "sha256": self.sha256,
        }
        if include_content:
            result["content_base64"] = base64.b64encode(self.content).decode("ascii")
        return result
