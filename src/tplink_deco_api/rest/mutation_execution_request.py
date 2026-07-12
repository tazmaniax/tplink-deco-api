"""REST request model for consuming a semantic mutation plan."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from pydantic import Field


@dataclass(frozen=True)
class MutationExecutionRequest:
    """Supply the exact confirmation associated with a reviewed plan."""

    confirmation: Annotated[str, Field(min_length=1)]
