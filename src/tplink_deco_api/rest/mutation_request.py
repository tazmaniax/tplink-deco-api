"""REST request model for semantic mutation assessment and planning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import Field

from .._json import JsonValue  # noqa: TC001 - FastAPI resolves this annotation at runtime.


@dataclass(frozen=True)
class MutationRequest:
    """Describe one semantic mutation without selecting a router protocol."""

    name: Annotated[str, Field(min_length=1)]
    mode: Literal["change", "verify_current_value_noop"] = "change"
    changes: dict[str, JsonValue] = field(default_factory=dict)
